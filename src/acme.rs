//! Automatic certificate provisioning via ACME HTTP-01 challenges.

use crate::config::{Config, LetsEncryptConfig, ListenConfig, OnOff};
use crate::tls::TlsManager;
use dashmap::DashMap;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{error, info, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

const ACCOUNT_FILE: &str = "account.json";

#[derive(Debug, Clone)]
struct AcmeDomain {
    hostname: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

/// Runtime ACME manager shared with request handling for HTTP-01 responses.
pub struct AcmeManager {
    config: LetsEncryptConfig,
    domains: Vec<AcmeDomain>,
    challenges: DashMap<String, String>,
    tls_manager: Arc<TlsManager>,
}

impl AcmeManager {
    pub fn from_config(config: &Config, tls_manager: Arc<TlsManager>) -> Option<Arc<Self>> {
        if !config.letsencrypt.enabled.is_on() {
            return None;
        }

        let mut domains = Vec::new();
        for (host_name, host_config) in &config.hosts {
            let Some(listen_value) = &host_config.listen else {
                continue;
            };
            let Ok(listen_config) = serde_yaml::from_value::<ListenConfig>(listen_value.clone())
            else {
                continue;
            };
            let Some(ssl) = listen_config.ssl else {
                continue;
            };
            if !ssl.letsencrypt.is_on() {
                continue;
            }

            let hostname = host_name
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(host_name)
                .to_ascii_lowercase();
            let domain_dir = config
                .letsencrypt
                .cache_dir
                .join("live")
                .join(sanitize_domain(&hostname));
            let cert_path = ssl
                .certificate_file
                .unwrap_or_else(|| domain_dir.join("fullchain.pem"));
            let key_path = ssl
                .key_file
                .unwrap_or_else(|| domain_dir.join("privkey.pem"));

            domains.push(AcmeDomain {
                hostname,
                cert_path,
                key_path,
            });
        }

        if domains.is_empty() {
            warn!("letsencrypt.enabled is ON but no hosts have ssl.letsencrypt: ON");
            return None;
        }

        Some(Arc::new(Self {
            config: config.letsencrypt.clone(),
            domains,
            challenges: DashMap::new(),
            tls_manager,
        }))
    }

    pub fn challenge_response(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix("/.well-known/acme-challenge/")?;
        if token.is_empty() || token.contains('/') {
            return None;
        }
        self.challenges.get(token).map(|value| value.clone())
    }

    pub fn load_cached_certificates(&self) {
        for domain in &self.domains {
            if domain.cert_path.exists() && domain.key_path.exists() {
                if let Err(err) = self.tls_manager.load_cert(
                    &domain.hostname,
                    &domain.cert_path,
                    &domain.key_path,
                ) {
                    warn!(
                        "Failed to load cached Let's Encrypt certificate for {}: {}",
                        domain.hostname, err
                    );
                }
            }
        }
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            if !self.config.terms_of_service_agreed.is_on() {
                warn!(
                    "Let's Encrypt provisioning disabled: set letsencrypt.terms-of-service-agreed: ON"
                );
                return;
            }

            self.renew_due_certificates().await;

            let interval = Duration::from_secs(self.config.check_interval_seconds.max(60));
            loop {
                sleep(interval).await;
                self.renew_due_certificates().await;
            }
        });
    }

    async fn renew_due_certificates(&self) {
        let account = match self.load_or_create_account().await {
            Ok(account) => account,
            Err(err) => {
                error!("Let's Encrypt account setup failed: {}", err);
                return;
            }
        };

        for domain in &self.domains {
            if !self.needs_renewal(domain) {
                continue;
            }

            match self.obtain_certificate(&account, domain).await {
                Ok(()) => info!("Let's Encrypt certificate ready for {}", domain.hostname),
                Err(err) => warn!(
                    "Let's Encrypt certificate provisioning failed for {}: {}",
                    domain.hostname, err
                ),
            }
        }
    }

    async fn load_or_create_account(&self) -> anyhow::Result<Account> {
        fs::create_dir_all(&self.config.cache_dir)?;
        let account_path = self.config.cache_dir.join(ACCOUNT_FILE);

        if account_path.exists() {
            let content = fs::read_to_string(&account_path)?;
            let credentials: AccountCredentials = serde_json::from_str(&content)?;
            return Ok(Account::builder()?.from_credentials(credentials).await?);
        }

        let contacts = self
            .config
            .contact
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let directory_url = self.directory_url();
        let (account, credentials) = Account::builder()?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory_url,
                None,
            )
            .await?;

        fs::write(account_path, serde_json::to_string_pretty(&credentials)?)?;
        Ok(account)
    }

    async fn obtain_certificate(
        &self,
        account: &Account,
        domain: &AcmeDomain,
    ) -> anyhow::Result<()> {
        let identifiers = [Identifier::Dns(domain.hostname.clone())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut active_tokens = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                status => anyhow::bail!("unexpected authorization status: {:?}", status),
            }

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no HTTP-01 challenge offered"))?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_string();
            self.challenges.insert(token.clone(), key_authorization);
            active_tokens.push(token);

            challenge.set_ready().await?;
        }

        let status = order.poll_ready(&RetryPolicy::default()).await;
        for token in &active_tokens {
            self.challenges.remove(token);
        }
        let status = status?;
        if status != OrderStatus::Ready {
            anyhow::bail!("unexpected order status: {:?}", status);
        }

        let private_key_pem = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

        if let Some(parent) = domain.cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = domain.key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&domain.cert_path, &cert_chain_pem)?;
        fs::write(&domain.key_path, &private_key_pem)?;
        self.tls_manager
            .load_cert_pem(&domain.hostname, &cert_chain_pem, &private_key_pem)?;

        Ok(())
    }

    fn needs_renewal(&self, domain: &AcmeDomain) -> bool {
        if !domain.cert_path.exists() || !domain.key_path.exists() {
            return true;
        }

        match certificate_not_after(&domain.cert_path) {
            Ok(not_after) => {
                let renew_before =
                    Duration::from_secs(self.config.renew_before_days.saturating_mul(86_400));
                let threshold = SystemTime::now() + renew_before;
                not_after <= threshold
            }
            Err(err) => {
                warn!(
                    "Could not read certificate expiry for {}: {}",
                    domain.hostname, err
                );
                true
            }
        }
    }

    fn directory_url(&self) -> String {
        if let Some(url) = &self.config.directory_url {
            return url.clone();
        }
        if self.config.staging == OnOff::On {
            LetsEncrypt::Staging.url().to_string()
        } else {
            LetsEncrypt::Production.url().to_string()
        }
    }
}

fn certificate_not_after(path: &Path) -> anyhow::Result<SystemTime> {
    let cert_file = fs::File::open(path)?;
    let mut reader = BufReader::new(cert_file);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("certificate file has no certificates"))??;
    let (_, parsed) = X509Certificate::from_der(cert.as_ref())
        .map_err(|err| anyhow::anyhow!("failed to parse certificate: {}", err))?;
    let ts = parsed.validity().not_after.timestamp();
    if ts < 0 {
        anyhow::bail!("certificate expiry is before UNIX epoch");
    }
    Ok(UNIX_EPOCH + Duration::from_secs(ts as u64))
}

fn sanitize_domain(domain: &str) -> String {
    domain
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => ch,
            _ => '_',
        })
        .collect()
}
