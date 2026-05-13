//! Interactive configuration wizard for `pyx menu <config-file>`.

use crate::config::{
    BackendConfig, BasicAuthConfig, Config, HeaderValue, HealthConfig, HostConfig, ListenConfig,
    ListenerType, OnOff, PathConfig, SslConfig, SslSessionResumption, TcpTlsConfig,
};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use indexmap::IndexMap;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use std::io::{self, IsTerminal};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ItemKind {
    Section(SectionKind),
    Field(FieldId),
    Host(String),
    Path { host: String, path: String },
    Backend { host: String, index: usize },
    Contact(usize),
    ListValue(ListFieldId, usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SectionKind {
    Hosts,
    LetsEncryptContacts,
    HostPaths,
    HostBackends,
    HeaderList(ListFieldId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListFieldId {
    GlobalHeaderSet,
    GlobalHeaderSetIfEmpty,
    GlobalHeaderMerge,
    GlobalHeaderUnset,
    HostHeaderSet,
    HostHeaderSetIfEmpty,
    HostHeaderMerge,
    HostHeaderUnset,
    PathHeaderSet,
    PathHeaderSetIfEmpty,
    PathHeaderMerge,
    PathHeaderUnset,
    PathProxyHeaderSet,
    PathProxyHeaderAdd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FieldId {
    GlobalUser,
    GlobalAccessLog,
    GlobalErrorLog,
    GlobalPidFile,
    GlobalNumThreads,
    GlobalFileSendGzip,
    GlobalCompress,
    GlobalLimitRequestBody,
    GlobalHttp2Casper,
    GlobalHttp2Enabled,
    GlobalHttp2IdleTimeout,
    GlobalHttp2MaxConcurrentStreams,
    GlobalHttp2InitialStreamWindow,
    GlobalHttp2InitialConnectionWindow,
    GlobalHttp2MaxFrameSize,
    GlobalHttp3Enabled,
    GlobalHttp3MaxConcurrentStreams,
    GlobalHttp3IdleTimeout,
    GlobalHttp3StreamReceiveWindow,
    GlobalHttp3ConnectionReceiveWindow,
    GlobalProxyPreserveHost,
    GlobalProxyTimeoutIo,
    GlobalProxyTimeoutKeepalive,
    GlobalDurationStats,
    GlobalSslSessionResumptionMode,
    GlobalListenRaw,
    GlobalBasicAuthEnabled,
    GlobalBasicAuthRealm,
    GlobalBasicAuthUsers,
    LetsEncryptEnabled,
    LetsEncryptCacheDir,
    LetsEncryptStaging,
    LetsEncryptDirectoryUrl,
    LetsEncryptTermsAgreed,
    LetsEncryptRenewBeforeDays,
    LetsEncryptCheckIntervalSeconds,
    HostListenHost(String),
    HostListenPort(String),
    HostListenType(String),
    HostSslEnabled(String),
    HostSslMinimumVersion(String),
    HostSslCipherPreference(String),
    HostSslCipherSuite(String),
    HostSslDhFile(String),
    HostSslCertificateFile(String),
    HostSslKeyFile(String),
    HostSslLetsEncrypt(String),
    HostSslOcspUpdateInterval(String),
    HostSslSniFallback(String),
    HostTcpTlsEnabled(String),
    HostTcpTlsCertificateFile(String),
    HostTcpTlsKeyFile(String),
    HostTcpTlsTransparentUpgrade(String),
    HostTcpTlsHandshakeTimeout(String),
    HostHealthInterval(String),
    HostHealthTimeout(String),
    HostHealthUnhealthyThreshold(String),
    HostHealthHealthyThreshold(String),
    HostHealthConnectTimeout(String),
    HostHealthIoTimeout(String),
    HostHealthSigmaThreshold(String),
    HostHealthLatencyAware(String),
    HostBasicAuthEnabled(String),
    HostBasicAuthRealm(String),
    HostBasicAuthUsers(String),
    PathRedirect(String, String),
    PathStatus(String, String),
    PathExpires(String, String),
    PathFileDir(String, String),
    PathFileIndex(String, String),
    PathFileDirlisting(String, String),
    PathProxyReverseUrl(String, String),
    PathProxyPreserveHost(String, String),
    PathBasicAuthEnabled(String, String),
    PathBasicAuthRealm(String, String),
    PathBasicAuthUsers(String, String),
    BackendHost(String, usize),
    BackendPort(String, usize),
    BackendWeight(String, usize),
}

#[derive(Clone, Debug)]
struct MenuItem {
    depth: usize,
    title: String,
    value: String,
    help: String,
    kind: ItemKind,
}

#[derive(Debug)]
enum Mode {
    Normal,
    Editing {
        title: String,
        value: String,
        target: EditTarget,
    },
    ConfirmQuit,
}

#[derive(Clone, Debug)]
enum EditTarget {
    Field(FieldId),
    AddHost,
    RenameHost(String),
    AddPath(String),
    RenamePath(String, String),
    AddBackend(String),
    AddContact,
    EditContact(usize),
    AddListValue(ListFieldId, Option<String>, Option<String>),
    EditListValue(ListFieldId, Option<String>, Option<String>, usize),
}

pub struct MenuApp {
    config_path: PathBuf,
    config: Config,
    items: Vec<MenuItem>,
    selected: usize,
    scroll: usize,
    mode: Mode,
    dirty: bool,
    status: String,
}

/// Run the interactive menu wizard.
pub fn run_menu(path: PathBuf) -> anyhow::Result<()> {
    if !io::stdout().is_terminal() {
        anyhow::bail!("pyx menu requires an interactive terminal");
    }

    let mut terminal = TerminalGuard::enter()?;
    let mut app = MenuApp::load(path)?;

    loop {
        terminal.draw(|frame| draw(frame, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if app.handle_key(key)? {
                break;
            }
        }
    }

    Ok(())
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> anyhow::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    fn draw<F>(&mut self, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut ratatui::Frame<'_>),
    {
        self.terminal.draw(f)?;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

impl MenuApp {
    fn load(path: PathBuf) -> anyhow::Result<Self> {
        let config = if path.exists() {
            Config::load(&path)?
        } else {
            serde_yaml::from_str("hosts: {}\n")?
        };

        let mut app = Self {
            config_path: path,
            config,
            items: Vec::new(),
            selected: 0,
            scroll: 0,
            mode: Mode::Normal,
            dirty: false,
            status: "Use arrows to move, Enter to edit, Space to toggle, a to add, d to delete, Ctrl-S to save, q to quit.".to_string(),
        };
        app.rebuild();
        Ok(app)
    }

    fn rebuild(&mut self) {
        let old_kind = self.items.get(self.selected).map(|item| item.kind.clone());
        self.items = build_items(&self.config);
        if self.items.is_empty() {
            self.selected = 0;
            return;
        }

        self.selected = old_kind
            .and_then(|kind| self.items.iter().position(|item| item.kind == kind))
            .unwrap_or(self.selected.min(self.items.len().saturating_sub(1)));
    }

    fn handle_key(&mut self, key: KeyEvent) -> anyhow::Result<bool> {
        match &mut self.mode {
            Mode::Normal => self.handle_normal_key(key),
            Mode::Editing { value, target, .. } => match key.code {
                KeyCode::Esc => {
                    self.mode = Mode::Normal;
                    self.status = "Edit cancelled.".to_string();
                    Ok(false)
                }
                KeyCode::Enter => {
                    let target = target.clone();
                    let value = value.clone();
                    self.apply_edit(target, value);
                    self.mode = Mode::Normal;
                    self.rebuild();
                    Ok(false)
                }
                KeyCode::Backspace => {
                    value.pop();
                    Ok(false)
                }
                KeyCode::Char(ch) => {
                    value.push(ch);
                    Ok(false)
                }
                _ => Ok(false),
            },
            Mode::ConfirmQuit => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => Ok(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.mode = Mode::Normal;
                    Ok(false)
                }
                _ => Ok(false),
            },
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> anyhow::Result<bool> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save()?;
            return Ok(false);
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.dirty {
                    self.mode = Mode::ConfirmQuit;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.items.len() {
                    self.selected += 1;
                }
                Ok(false)
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Ok(false)
            }
            KeyCode::PageDown => {
                self.selected = (self.selected + 10).min(self.items.len().saturating_sub(1));
                Ok(false)
            }
            KeyCode::PageUp => {
                self.selected = self.selected.saturating_sub(10);
                Ok(false)
            }
            KeyCode::Home => {
                self.selected = 0;
                Ok(false)
            }
            KeyCode::End => {
                self.selected = self.items.len().saturating_sub(1);
                Ok(false)
            }
            KeyCode::Enter => {
                self.start_edit_selected();
                Ok(false)
            }
            KeyCode::Char(' ') => {
                self.toggle_selected();
                Ok(false)
            }
            KeyCode::Char('a') | KeyCode::Char('n') => {
                self.start_add_for_selected();
                Ok(false)
            }
            KeyCode::Char('r') => {
                self.start_rename_selected();
                Ok(false)
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                self.delete_selected();
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    fn selected_item(&self) -> Option<&MenuItem> {
        self.items.get(self.selected)
    }

    fn start_edit_selected(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };

        match item.kind {
            ItemKind::Field(field) => {
                let value = self.field_value(&field);
                if self.is_bool_field(&field) {
                    self.toggle_field(&field);
                    self.rebuild();
                } else {
                    self.mode = Mode::Editing {
                        title: item.title,
                        value,
                        target: EditTarget::Field(field),
                    };
                }
            }
            ItemKind::Contact(index) => {
                self.mode = Mode::Editing {
                    title: "Edit ACME contact".to_string(),
                    value: self.config.letsencrypt.contact[index].clone(),
                    target: EditTarget::EditContact(index),
                };
            }
            ItemKind::ListValue(field, index) => {
                let (host, path) = self.context_from_list_field(field);
                let value = list_value(&self.config, field, host.as_deref(), path.as_deref())
                    .get(index)
                    .cloned()
                    .unwrap_or_default();
                self.mode = Mode::Editing {
                    title: "Edit list value".to_string(),
                    value,
                    target: EditTarget::EditListValue(field, host, path, index),
                };
            }
            _ => self.start_add_for_selected(),
        }
    }

    fn start_add_for_selected(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };

        match item.kind {
            ItemKind::Section(SectionKind::Hosts) => {
                self.mode = Mode::Editing {
                    title: "Add host as domain:port".to_string(),
                    value: "example.com:80".to_string(),
                    target: EditTarget::AddHost,
                };
            }
            ItemKind::Host(_) | ItemKind::Section(SectionKind::HostPaths) => {
                let host = match item.kind {
                    ItemKind::Host(host) => host,
                    _ => nearest_host(&self.items, self.selected).unwrap_or_default(),
                };
                self.mode = Mode::Editing {
                    title: format!("Add path under {host}"),
                    value: "/".to_string(),
                    target: EditTarget::AddPath(host),
                };
            }
            ItemKind::Section(SectionKind::HostBackends) | ItemKind::Backend { .. } => {
                let host = nearest_host(&self.items, self.selected).unwrap_or_default();
                self.mode = Mode::Editing {
                    title: format!("Add backend host:port under {host}"),
                    value: "127.0.0.1:8080".to_string(),
                    target: EditTarget::AddBackend(host),
                };
            }
            ItemKind::Section(SectionKind::LetsEncryptContacts) | ItemKind::Contact(_) => {
                self.mode = Mode::Editing {
                    title: "Add ACME contact".to_string(),
                    value: "mailto:admin@example.com".to_string(),
                    target: EditTarget::AddContact,
                };
            }
            ItemKind::Section(SectionKind::HeaderList(field)) | ItemKind::ListValue(field, _) => {
                let (host, path) = self.context_from_list_field(field);
                self.mode = Mode::Editing {
                    title: "Add header/list value".to_string(),
                    value: field.placeholder().to_string(),
                    target: EditTarget::AddListValue(field, host, path),
                };
            }
            ItemKind::Path { host, .. } => {
                self.mode = Mode::Editing {
                    title: format!("Add path under {host}"),
                    value: "/".to_string(),
                    target: EditTarget::AddPath(host),
                };
            }
            _ => {
                self.status =
                    "Move to Hosts, Paths, Backends, Contacts, or a header list to add entries."
                        .to_string();
            }
        }
    }

    fn start_rename_selected(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };

        match item.kind {
            ItemKind::Host(host) => {
                self.mode = Mode::Editing {
                    title: "Rename host".to_string(),
                    value: host.clone(),
                    target: EditTarget::RenameHost(host),
                };
            }
            ItemKind::Path { host, path } => {
                self.mode = Mode::Editing {
                    title: "Rename path".to_string(),
                    value: path.clone(),
                    target: EditTarget::RenamePath(host, path),
                };
            }
            _ => self.status = "Only hosts and paths can be renamed.".to_string(),
        }
    }

    fn delete_selected(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };

        match item.kind {
            ItemKind::Host(host) => {
                self.config.hosts.shift_remove(&host);
                self.mark_dirty("Host removed.");
            }
            ItemKind::Path { host, path } => {
                if let Some(host_cfg) = self.config.hosts.get_mut(&host) {
                    host_cfg.paths.shift_remove(&path);
                    self.mark_dirty("Path removed.");
                }
            }
            ItemKind::Backend { host, index } => {
                if let Some(host_cfg) = self.config.hosts.get_mut(&host) {
                    if index < host_cfg.backends.len() {
                        host_cfg.backends.remove(index);
                        self.mark_dirty("Backend removed.");
                    }
                }
            }
            ItemKind::Contact(index) => {
                if index < self.config.letsencrypt.contact.len() {
                    self.config.letsencrypt.contact.remove(index);
                    self.mark_dirty("ACME contact removed.");
                }
            }
            ItemKind::ListValue(field, index) => {
                let (host, path) = self.context_from_list_field(field);
                let values =
                    list_value_mut(&mut self.config, field, host.as_deref(), path.as_deref());
                if index < values.0.len() {
                    values.0.remove(index);
                    self.mark_dirty("List value removed.");
                }
            }
            _ => self.status = "This item cannot be deleted.".to_string(),
        }
        self.rebuild();
    }

    fn toggle_selected(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };

        match item.kind {
            ItemKind::Field(field) if self.is_bool_field(&field) => {
                self.toggle_field(&field);
                self.rebuild();
            }
            ItemKind::Field(FieldId::HostSslEnabled(host)) => {
                let host_cfg = ensure_host(&mut self.config, &host);
                if host_cfg
                    .listen
                    .as_ref()
                    .and_then(|value| serde_yaml::from_value::<ListenConfig>(value.clone()).ok())
                    .and_then(|listen| listen.ssl)
                    .is_some()
                {
                    let mut listen = host_listen(host_cfg);
                    listen.ssl = None;
                    set_host_listen(host_cfg, listen);
                } else {
                    let mut listen = host_listen(host_cfg);
                    listen.ssl = Some(default_ssl());
                    set_host_listen(host_cfg, listen);
                }
                self.mark_dirty("TLS listener setting changed.");
                self.rebuild();
            }
            ItemKind::Field(FieldId::HostTcpTlsEnabled(host)) => {
                let host_cfg = ensure_host(&mut self.config, &host);
                if host_cfg.tls.is_some() {
                    host_cfg.tls = None;
                } else {
                    host_cfg.tls = Some(default_tcp_tls());
                }
                self.mark_dirty("TCP TLS setting changed.");
                self.rebuild();
            }
            _ => self.status = "Selected item is not a toggle.".to_string(),
        }
    }

    fn save(&mut self) -> anyhow::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let yaml = serialize_config(&self.config)?;
        std::fs::write(&self.config_path, yaml)?;
        self.dirty = false;
        self.status = format!("Saved {}", self.config_path.display());
        Ok(())
    }

    fn mark_dirty(&mut self, status: impl Into<String>) {
        self.dirty = true;
        self.status = status.into();
    }

    fn apply_edit(&mut self, target: EditTarget, value: String) {
        let value = value.trim().to_string();
        match target {
            EditTarget::Field(field) => self.set_field(field, value),
            EditTarget::AddHost => {
                if !value.is_empty() {
                    self.config
                        .hosts
                        .entry(value.clone())
                        .or_insert_with(default_host);
                    self.mark_dirty(format!("Added host {value}."));
                }
            }
            EditTarget::RenameHost(old) => {
                if !value.is_empty() && value != old {
                    if let Some(host) = self.config.hosts.shift_remove(&old) {
                        self.config.hosts.insert(value.clone(), host);
                        self.mark_dirty(format!("Renamed host to {value}."));
                    }
                }
            }
            EditTarget::AddPath(host) => {
                if !value.is_empty() {
                    ensure_host(&mut self.config, &host)
                        .paths
                        .entry(value.clone())
                        .or_insert_with(default_path);
                    self.mark_dirty(format!("Added path {value}."));
                }
            }
            EditTarget::RenamePath(host, old) => {
                if !value.is_empty() && value != old {
                    let host_cfg = ensure_host(&mut self.config, &host);
                    if let Some(path_cfg) = host_cfg.paths.shift_remove(&old) {
                        host_cfg.paths.insert(value.clone(), path_cfg);
                        self.mark_dirty(format!("Renamed path to {value}."));
                    }
                }
            }
            EditTarget::AddBackend(host) => {
                if let Some(backend) = parse_backend(&value) {
                    ensure_host(&mut self.config, &host).backends.push(backend);
                    self.mark_dirty("Backend added.");
                } else {
                    self.status = "Backend must be host:port.".to_string();
                }
            }
            EditTarget::AddContact => {
                if !value.is_empty() {
                    self.config.letsencrypt.contact.push(value);
                    self.mark_dirty("ACME contact added.");
                }
            }
            EditTarget::EditContact(index) => {
                if let Some(contact) = self.config.letsencrypt.contact.get_mut(index) {
                    *contact = value;
                    self.mark_dirty("ACME contact updated.");
                }
            }
            EditTarget::AddListValue(field, host, path) => {
                if !value.is_empty() {
                    list_value_mut(&mut self.config, field, host.as_deref(), path.as_deref())
                        .0
                        .push(value);
                    self.mark_dirty("List value added.");
                }
            }
            EditTarget::EditListValue(field, host, path, index) => {
                let values =
                    list_value_mut(&mut self.config, field, host.as_deref(), path.as_deref());
                if let Some(existing) = values.0.get_mut(index) {
                    *existing = value;
                    self.mark_dirty("List value updated.");
                }
            }
        }
    }

    fn is_bool_field(&self, field: &FieldId) -> bool {
        matches!(
            field,
            FieldId::GlobalFileSendGzip
                | FieldId::GlobalCompress
                | FieldId::GlobalHttp2Casper
                | FieldId::GlobalHttp2Enabled
                | FieldId::GlobalHttp3Enabled
                | FieldId::GlobalProxyPreserveHost
                | FieldId::GlobalDurationStats
                | FieldId::LetsEncryptEnabled
                | FieldId::LetsEncryptStaging
                | FieldId::LetsEncryptTermsAgreed
                | FieldId::HostSslLetsEncrypt(_)
                | FieldId::HostSslSniFallback(_)
                | FieldId::HostTcpTlsTransparentUpgrade(_)
                | FieldId::HostHealthLatencyAware(_)
                | FieldId::PathStatus(_, _)
                | FieldId::PathFileDirlisting(_, _)
        )
    }

    fn toggle_field(&mut self, field: &FieldId) {
        let next = |value: OnOff| if value.is_on() { OnOff::Off } else { OnOff::On };
        match field {
            FieldId::GlobalFileSendGzip => {
                self.config.file_send_gzip = next(self.config.file_send_gzip)
            }
            FieldId::GlobalCompress => self.config.compress = next(self.config.compress),
            FieldId::GlobalHttp2Casper => self.config.http2_casper = next(self.config.http2_casper),
            FieldId::GlobalHttp2Enabled => {
                self.config.http2_enabled = next(self.config.http2_enabled)
            }
            FieldId::GlobalHttp3Enabled => {
                self.config.http3_enabled = next(self.config.http3_enabled)
            }
            FieldId::GlobalProxyPreserveHost => {
                self.config.proxy_preserve_host = next(self.config.proxy_preserve_host)
            }
            FieldId::GlobalDurationStats => {
                self.config.duration_stats = next(self.config.duration_stats)
            }
            FieldId::LetsEncryptEnabled => {
                self.config.letsencrypt.enabled = next(self.config.letsencrypt.enabled)
            }
            FieldId::LetsEncryptStaging => {
                self.config.letsencrypt.staging = next(self.config.letsencrypt.staging)
            }
            FieldId::LetsEncryptTermsAgreed => {
                self.config.letsencrypt.terms_of_service_agreed =
                    next(self.config.letsencrypt.terms_of_service_agreed)
            }
            FieldId::HostSslLetsEncrypt(host) => {
                update_ssl(ensure_host(&mut self.config, host), |ssl| {
                    ssl.letsencrypt = next(ssl.letsencrypt);
                });
            }
            FieldId::HostSslSniFallback(host) => {
                update_ssl(ensure_host(&mut self.config, host), |ssl| {
                    ssl.sni_fallback = next(ssl.sni_fallback);
                });
            }
            FieldId::HostTcpTlsTransparentUpgrade(host) => {
                ensure_tcp_tls(ensure_host(&mut self.config, host)).transparent_upgrade =
                    next(ensure_tcp_tls(ensure_host(&mut self.config, host)).transparent_upgrade);
            }
            FieldId::HostHealthLatencyAware(host) => {
                ensure_health(ensure_host(&mut self.config, host)).latency_aware =
                    next(ensure_health(ensure_host(&mut self.config, host)).latency_aware);
            }
            FieldId::PathStatus(host, path) => {
                ensure_path(ensure_host(&mut self.config, host), path).status =
                    next(ensure_path(ensure_host(&mut self.config, host), path).status);
            }
            FieldId::PathFileDirlisting(host, path) => {
                ensure_path(ensure_host(&mut self.config, host), path).file_dirlisting =
                    next(ensure_path(ensure_host(&mut self.config, host), path).file_dirlisting);
            }
            _ => {}
        }
        self.mark_dirty("Value toggled.");
    }

    fn field_value(&self, field: &FieldId) -> String {
        match field {
            FieldId::GlobalUser => opt_string(&self.config.user),
            FieldId::GlobalAccessLog => self.config.access_log.display().to_string(),
            FieldId::GlobalErrorLog => self.config.error_log.display().to_string(),
            FieldId::GlobalPidFile => opt_path(&self.config.pid_file),
            FieldId::GlobalNumThreads => self.config.num_threads.to_string(),
            FieldId::GlobalFileSendGzip => onoff(self.config.file_send_gzip),
            FieldId::GlobalCompress => onoff(self.config.compress),
            FieldId::GlobalLimitRequestBody => self.config.limit_request_body.to_string(),
            FieldId::GlobalHttp2Casper => onoff(self.config.http2_casper),
            FieldId::GlobalHttp2Enabled => onoff(self.config.http2_enabled),
            FieldId::GlobalHttp2IdleTimeout => self.config.http2_idle_timeout.to_string(),
            FieldId::GlobalHttp2MaxConcurrentStreams => {
                self.config.http2_max_concurrent_streams.to_string()
            }
            FieldId::GlobalHttp2InitialStreamWindow => {
                self.config.http2_initial_stream_window.to_string()
            }
            FieldId::GlobalHttp2InitialConnectionWindow => {
                self.config.http2_initial_connection_window.to_string()
            }
            FieldId::GlobalHttp2MaxFrameSize => self.config.http2_max_frame_size.to_string(),
            FieldId::GlobalHttp3Enabled => onoff(self.config.http3_enabled),
            FieldId::GlobalHttp3MaxConcurrentStreams => {
                self.config.http3_max_concurrent_streams.to_string()
            }
            FieldId::GlobalHttp3IdleTimeout => self.config.http3_idle_timeout.to_string(),
            FieldId::GlobalHttp3StreamReceiveWindow => {
                self.config.http3_stream_receive_window.to_string()
            }
            FieldId::GlobalHttp3ConnectionReceiveWindow => {
                self.config.http3_connection_receive_window.to_string()
            }
            FieldId::GlobalProxyPreserveHost => onoff(self.config.proxy_preserve_host),
            FieldId::GlobalProxyTimeoutIo => self.config.proxy_timeout_io.to_string(),
            FieldId::GlobalProxyTimeoutKeepalive => self.config.proxy_timeout_keepalive.to_string(),
            FieldId::GlobalDurationStats => onoff(self.config.duration_stats),
            FieldId::GlobalSslSessionResumptionMode => self
                .config
                .ssl_session_resumption
                .as_ref()
                .map(|value| value.mode.clone())
                .unwrap_or_default(),
            FieldId::GlobalListenRaw => self
                .config
                .listen
                .as_ref()
                .map(|value| serde_yaml::to_string(value).unwrap_or_default())
                .unwrap_or_default()
                .trim()
                .to_string(),
            FieldId::GlobalBasicAuthEnabled => basic_auth_enabled(&self.config.basic_auth),
            FieldId::GlobalBasicAuthRealm => basic_auth_realm(&self.config.basic_auth),
            FieldId::GlobalBasicAuthUsers => basic_auth_users(&self.config.basic_auth),
            FieldId::LetsEncryptEnabled => onoff(self.config.letsencrypt.enabled),
            FieldId::LetsEncryptCacheDir => self.config.letsencrypt.cache_dir.display().to_string(),
            FieldId::LetsEncryptStaging => onoff(self.config.letsencrypt.staging),
            FieldId::LetsEncryptDirectoryUrl => opt_string(&self.config.letsencrypt.directory_url),
            FieldId::LetsEncryptTermsAgreed => {
                onoff(self.config.letsencrypt.terms_of_service_agreed)
            }
            FieldId::LetsEncryptRenewBeforeDays => {
                self.config.letsencrypt.renew_before_days.to_string()
            }
            FieldId::LetsEncryptCheckIntervalSeconds => {
                self.config.letsencrypt.check_interval_seconds.to_string()
            }
            FieldId::HostListenHost(host) => host_listen(get_host(&self.config, host)).host,
            FieldId::HostListenPort(host) => {
                host_listen(get_host(&self.config, host)).port.to_string()
            }
            FieldId::HostListenType(host) => {
                match host_listen(get_host(&self.config, host)).listener_type {
                    ListenerType::Http => "http".to_string(),
                    ListenerType::Tcp => "tcp".to_string(),
                }
            }
            FieldId::HostSslEnabled(host) => {
                if host_listen(get_host(&self.config, host)).ssl.is_some() {
                    "ON"
                } else {
                    "OFF"
                }
                .to_string()
            }
            FieldId::HostSslMinimumVersion(host) => {
                opt_ssl(get_host(&self.config, host)).minimum_version
            }
            FieldId::HostSslCipherPreference(host) => {
                opt_ssl(get_host(&self.config, host)).cipher_preference
            }
            FieldId::HostSslCipherSuite(host) => {
                opt_path_string(&opt_ssl(get_host(&self.config, host)).cipher_suite)
            }
            FieldId::HostSslDhFile(host) => {
                opt_path(&opt_ssl(get_host(&self.config, host)).dh_file)
            }
            FieldId::HostSslCertificateFile(host) => {
                opt_path(&opt_ssl(get_host(&self.config, host)).certificate_file)
            }
            FieldId::HostSslKeyFile(host) => {
                opt_path(&opt_ssl(get_host(&self.config, host)).key_file)
            }
            FieldId::HostSslLetsEncrypt(host) => {
                onoff(opt_ssl(get_host(&self.config, host)).letsencrypt)
            }
            FieldId::HostSslOcspUpdateInterval(host) => opt_ssl(get_host(&self.config, host))
                .ocsp_update_interval
                .to_string(),
            FieldId::HostSslSniFallback(host) => {
                onoff(opt_ssl(get_host(&self.config, host)).sni_fallback)
            }
            FieldId::HostTcpTlsEnabled(host) => if get_host(&self.config, host).tls.is_some() {
                "ON"
            } else {
                "OFF"
            }
            .to_string(),
            FieldId::HostTcpTlsCertificateFile(host) => opt_tcp_tls(get_host(&self.config, host))
                .certificate_file
                .display()
                .to_string(),
            FieldId::HostTcpTlsKeyFile(host) => opt_tcp_tls(get_host(&self.config, host))
                .key_file
                .display()
                .to_string(),
            FieldId::HostTcpTlsTransparentUpgrade(host) => {
                onoff(opt_tcp_tls(get_host(&self.config, host)).transparent_upgrade)
            }
            FieldId::HostTcpTlsHandshakeTimeout(host) => opt_tcp_tls(get_host(&self.config, host))
                .handshake_timeout
                .to_string(),
            FieldId::HostHealthInterval(host) => opt_health(get_host(&self.config, host))
                .interval
                .to_string(),
            FieldId::HostHealthTimeout(host) => {
                opt_health(get_host(&self.config, host)).timeout.to_string()
            }
            FieldId::HostHealthUnhealthyThreshold(host) => opt_health(get_host(&self.config, host))
                .unhealthy_threshold
                .to_string(),
            FieldId::HostHealthHealthyThreshold(host) => opt_health(get_host(&self.config, host))
                .healthy_threshold
                .to_string(),
            FieldId::HostHealthConnectTimeout(host) => opt_health(get_host(&self.config, host))
                .connect_timeout
                .to_string(),
            FieldId::HostHealthIoTimeout(host) => opt_health(get_host(&self.config, host))
                .io_timeout
                .to_string(),
            FieldId::HostHealthSigmaThreshold(host) => opt_health(get_host(&self.config, host))
                .sigma_threshold
                .to_string(),
            FieldId::HostHealthLatencyAware(host) => {
                onoff(opt_health(get_host(&self.config, host)).latency_aware)
            }
            FieldId::HostBasicAuthEnabled(host) => {
                basic_auth_enabled(&get_host(&self.config, host).basic_auth)
            }
            FieldId::HostBasicAuthRealm(host) => {
                basic_auth_realm(&get_host(&self.config, host).basic_auth)
            }
            FieldId::HostBasicAuthUsers(host) => {
                basic_auth_users(&get_host(&self.config, host).basic_auth)
            }
            FieldId::PathRedirect(host, path) => {
                opt_string(&get_path(&self.config, host, path).redirect)
            }
            FieldId::PathStatus(host, path) => onoff(get_path(&self.config, host, path).status),
            FieldId::PathExpires(host, path) => {
                opt_string(&get_path(&self.config, host, path).expires)
            }
            FieldId::PathFileDir(host, path) => {
                opt_path(&get_path(&self.config, host, path).file_dir)
            }
            FieldId::PathFileIndex(host, path) => get_path(&self.config, host, path)
                .file_index
                .clone()
                .unwrap_or_default()
                .join(", "),
            FieldId::PathFileDirlisting(host, path) => {
                onoff(get_path(&self.config, host, path).file_dirlisting)
            }
            FieldId::PathProxyReverseUrl(host, path) => {
                opt_string(&get_path(&self.config, host, path).proxy_reverse_url)
            }
            FieldId::PathProxyPreserveHost(host, path) => get_path(&self.config, host, path)
                .proxy_preserve_host
                .map(onoff)
                .unwrap_or_default(),
            FieldId::PathBasicAuthEnabled(host, path) => {
                basic_auth_enabled(&get_path(&self.config, host, path).basic_auth)
            }
            FieldId::PathBasicAuthRealm(host, path) => {
                basic_auth_realm(&get_path(&self.config, host, path).basic_auth)
            }
            FieldId::PathBasicAuthUsers(host, path) => {
                basic_auth_users(&get_path(&self.config, host, path).basic_auth)
            }
            FieldId::BackendHost(host, index) => get_host(&self.config, host)
                .backends
                .get(*index)
                .map(|backend| backend.host.clone())
                .unwrap_or_default(),
            FieldId::BackendPort(host, index) => get_host(&self.config, host)
                .backends
                .get(*index)
                .map(|backend| backend.port.to_string())
                .unwrap_or_default(),
            FieldId::BackendWeight(host, index) => get_host(&self.config, host)
                .backends
                .get(*index)
                .map(|backend| backend.weight.to_string())
                .unwrap_or_default(),
        }
    }

    fn set_field(&mut self, field: FieldId, value: String) {
        match field {
            FieldId::GlobalUser => self.config.user = none_if_empty(value),
            FieldId::GlobalAccessLog => self.config.access_log = PathBuf::from(value),
            FieldId::GlobalErrorLog => self.config.error_log = PathBuf::from(value),
            FieldId::GlobalPidFile => {
                self.config.pid_file = none_if_empty(value).map(PathBuf::from)
            }
            FieldId::GlobalNumThreads => set_parse(value, &mut self.config.num_threads),
            FieldId::GlobalLimitRequestBody => {
                set_parse(value, &mut self.config.limit_request_body)
            }
            FieldId::GlobalHttp2IdleTimeout => {
                set_parse(value, &mut self.config.http2_idle_timeout)
            }
            FieldId::GlobalHttp2MaxConcurrentStreams => {
                set_parse(value, &mut self.config.http2_max_concurrent_streams)
            }
            FieldId::GlobalHttp2InitialStreamWindow => {
                set_parse(value, &mut self.config.http2_initial_stream_window)
            }
            FieldId::GlobalHttp2InitialConnectionWindow => {
                set_parse(value, &mut self.config.http2_initial_connection_window)
            }
            FieldId::GlobalHttp2MaxFrameSize => {
                set_parse(value, &mut self.config.http2_max_frame_size)
            }
            FieldId::GlobalHttp3MaxConcurrentStreams => {
                set_parse(value, &mut self.config.http3_max_concurrent_streams)
            }
            FieldId::GlobalHttp3IdleTimeout => {
                set_parse(value, &mut self.config.http3_idle_timeout)
            }
            FieldId::GlobalHttp3StreamReceiveWindow => {
                set_parse(value, &mut self.config.http3_stream_receive_window)
            }
            FieldId::GlobalHttp3ConnectionReceiveWindow => {
                set_parse(value, &mut self.config.http3_connection_receive_window)
            }
            FieldId::GlobalProxyTimeoutIo => set_parse(value, &mut self.config.proxy_timeout_io),
            FieldId::GlobalProxyTimeoutKeepalive => {
                set_parse(value, &mut self.config.proxy_timeout_keepalive)
            }
            FieldId::GlobalSslSessionResumptionMode => {
                self.config.ssl_session_resumption =
                    none_if_empty(value).map(|mode| SslSessionResumption { mode });
            }
            FieldId::GlobalListenRaw => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    self.config.listen = None;
                } else {
                    match serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
                        Ok(value) => self.config.listen = Some(value),
                        Err(error) => {
                            self.status = format!("Invalid YAML for listen: {error}");
                            return;
                        }
                    }
                }
            }
            FieldId::GlobalBasicAuthEnabled => {
                set_optional_basic_auth_enabled(&mut self.config.basic_auth, value);
            }
            FieldId::GlobalBasicAuthRealm => {
                ensure_basic_auth(&mut self.config.basic_auth).realm = value;
            }
            FieldId::GlobalBasicAuthUsers => {
                set_basic_auth_users(ensure_basic_auth(&mut self.config.basic_auth), &value);
            }
            FieldId::LetsEncryptCacheDir => {
                self.config.letsencrypt.cache_dir = PathBuf::from(value)
            }
            FieldId::LetsEncryptDirectoryUrl => {
                self.config.letsencrypt.directory_url = none_if_empty(value)
            }
            FieldId::LetsEncryptRenewBeforeDays => {
                set_parse(value, &mut self.config.letsencrypt.renew_before_days)
            }
            FieldId::LetsEncryptCheckIntervalSeconds => {
                set_parse(value, &mut self.config.letsencrypt.check_interval_seconds)
            }
            FieldId::HostListenHost(host) => {
                let host_cfg = ensure_host(&mut self.config, &host);
                let mut listen = host_listen(host_cfg);
                listen.host = value;
                set_host_listen(host_cfg, listen);
            }
            FieldId::HostListenPort(host) => {
                let host_cfg = ensure_host(&mut self.config, &host);
                let mut listen = host_listen(host_cfg);
                set_parse(value, &mut listen.port);
                set_host_listen(host_cfg, listen);
            }
            FieldId::HostListenType(host) => {
                let host_cfg = ensure_host(&mut self.config, &host);
                let mut listen = host_listen(host_cfg);
                listen.listener_type = if value.eq_ignore_ascii_case("tcp") {
                    ListenerType::Tcp
                } else {
                    ListenerType::Http
                };
                set_host_listen(host_cfg, listen);
            }
            FieldId::HostSslMinimumVersion(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.minimum_version = value.clone()
                });
            }
            FieldId::HostSslCipherPreference(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.cipher_preference = value.clone()
                });
            }
            FieldId::HostSslCipherSuite(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.cipher_suite = none_if_empty(value.clone())
                });
            }
            FieldId::HostSslDhFile(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.dh_file = none_if_empty(value.clone()).map(PathBuf::from)
                });
            }
            FieldId::HostSslCertificateFile(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.certificate_file = none_if_empty(value.clone()).map(PathBuf::from)
                });
            }
            FieldId::HostSslKeyFile(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    ssl.key_file = none_if_empty(value.clone()).map(PathBuf::from)
                });
            }
            FieldId::HostSslOcspUpdateInterval(host) => {
                update_ssl(ensure_host(&mut self.config, &host), |ssl| {
                    set_parse(value.clone(), &mut ssl.ocsp_update_interval)
                });
            }
            FieldId::HostTcpTlsCertificateFile(host) => {
                ensure_tcp_tls(ensure_host(&mut self.config, &host)).certificate_file =
                    PathBuf::from(value)
            }
            FieldId::HostTcpTlsKeyFile(host) => {
                ensure_tcp_tls(ensure_host(&mut self.config, &host)).key_file = PathBuf::from(value)
            }
            FieldId::HostTcpTlsHandshakeTimeout(host) => set_parse(
                value,
                &mut ensure_tcp_tls(ensure_host(&mut self.config, &host)).handshake_timeout,
            ),
            FieldId::HostHealthInterval(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).interval,
            ),
            FieldId::HostHealthTimeout(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).timeout,
            ),
            FieldId::HostHealthUnhealthyThreshold(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).unhealthy_threshold,
            ),
            FieldId::HostHealthHealthyThreshold(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).healthy_threshold,
            ),
            FieldId::HostHealthConnectTimeout(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).connect_timeout,
            ),
            FieldId::HostHealthIoTimeout(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).io_timeout,
            ),
            FieldId::HostHealthSigmaThreshold(host) => set_parse(
                value,
                &mut ensure_health(ensure_host(&mut self.config, &host)).sigma_threshold,
            ),
            FieldId::HostBasicAuthEnabled(host) => {
                set_optional_basic_auth_enabled(
                    &mut ensure_host(&mut self.config, &host).basic_auth,
                    value,
                );
            }
            FieldId::HostBasicAuthRealm(host) => {
                ensure_basic_auth(&mut ensure_host(&mut self.config, &host).basic_auth).realm =
                    value;
            }
            FieldId::HostBasicAuthUsers(host) => {
                set_basic_auth_users(
                    ensure_basic_auth(&mut ensure_host(&mut self.config, &host).basic_auth),
                    &value,
                );
            }
            FieldId::PathRedirect(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).redirect =
                    none_if_empty(value)
            }
            FieldId::PathExpires(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).expires =
                    none_if_empty(value)
            }
            FieldId::PathFileDir(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).file_dir =
                    none_if_empty(value).map(PathBuf::from)
            }
            FieldId::PathFileIndex(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).file_index =
                    comma_list(value);
            }
            FieldId::PathProxyReverseUrl(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).proxy_reverse_url =
                    none_if_empty(value);
            }
            FieldId::PathProxyPreserveHost(host, path) => {
                ensure_path(ensure_host(&mut self.config, &host), &path).proxy_preserve_host =
                    if value.trim().is_empty() {
                        None
                    } else {
                        Some(parse_onoff(&value))
                    };
            }
            FieldId::PathBasicAuthEnabled(host, path) => {
                set_optional_basic_auth_enabled(
                    &mut ensure_path(ensure_host(&mut self.config, &host), &path).basic_auth,
                    value,
                );
            }
            FieldId::PathBasicAuthRealm(host, path) => {
                ensure_basic_auth(
                    &mut ensure_path(ensure_host(&mut self.config, &host), &path).basic_auth,
                )
                .realm = value;
            }
            FieldId::PathBasicAuthUsers(host, path) => {
                set_basic_auth_users(
                    ensure_basic_auth(
                        &mut ensure_path(ensure_host(&mut self.config, &host), &path).basic_auth,
                    ),
                    &value,
                );
            }
            FieldId::BackendHost(host, index) => {
                if let Some(backend) = ensure_host(&mut self.config, &host).backends.get_mut(index)
                {
                    backend.host = value;
                }
            }
            FieldId::BackendPort(host, index) => {
                if let Some(backend) = ensure_host(&mut self.config, &host).backends.get_mut(index)
                {
                    set_parse(value, &mut backend.port);
                }
            }
            FieldId::BackendWeight(host, index) => {
                if let Some(backend) = ensure_host(&mut self.config, &host).backends.get_mut(index)
                {
                    set_parse(value, &mut backend.weight);
                }
            }
            field if self.is_bool_field(&field) => self.toggle_field(&field),
            _ => {}
        }
        self.mark_dirty("Value updated.");
    }

    fn context_from_list_field(&self, field: ListFieldId) -> (Option<String>, Option<String>) {
        let host = nearest_host(&self.items, self.selected);
        let path = nearest_path(&self.items, self.selected).map(|(_, path)| path);
        match field {
            ListFieldId::GlobalHeaderSet
            | ListFieldId::GlobalHeaderSetIfEmpty
            | ListFieldId::GlobalHeaderMerge
            | ListFieldId::GlobalHeaderUnset => (None, None),
            ListFieldId::HostHeaderSet
            | ListFieldId::HostHeaderSetIfEmpty
            | ListFieldId::HostHeaderMerge
            | ListFieldId::HostHeaderUnset => (host, None),
            _ => (host, path),
        }
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut MenuApp) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(area);

    let title = format!(
        " pyx config menu: {}{} ",
        app.config_path.display(),
        if app.dirty { " *" } else { "" }
    );
    frame.render_widget(
        Paragraph::new("Arrows/j/k move  Enter edit  Space toggle  a add  r rename  d delete  Ctrl-S save  q quit")
            .block(Block::default().title(title).borders(Borders::ALL)),
        chunks[0],
    );

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);

    draw_list(frame, app, body[0]);
    draw_details(frame, app, body[1]);

    frame.render_widget(
        Paragraph::new(app.status.clone())
            .wrap(Wrap { trim: true })
            .block(Block::default().title("Status").borders(Borders::ALL)),
        chunks[2],
    );

    match &app.mode {
        Mode::Editing { title, value, .. } => draw_edit_modal(frame, area, title, value),
        Mode::ConfirmQuit => draw_confirm_quit(frame, area),
        Mode::Normal => {}
    }
}

fn draw_list(frame: &mut ratatui::Frame<'_>, app: &mut MenuApp, area: Rect) {
    let height = area.height.saturating_sub(2).max(1) as usize;
    if app.selected < app.scroll {
        app.scroll = app.selected;
    } else if app.selected >= app.scroll + height {
        app.scroll = app.selected.saturating_sub(height - 1);
    }

    let visible_items: Vec<ListItem<'_>> = app
        .items
        .iter()
        .skip(app.scroll)
        .take(height)
        .map(|item| {
            let indent = "  ".repeat(item.depth);
            let style = match item.kind {
                ItemKind::Section(_) | ItemKind::Host(_) | ItemKind::Path { .. } => {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                }
                _ => Style::default(),
            };
            ListItem::new(Line::from(vec![
                Span::raw(indent),
                Span::styled(item.title.clone(), style),
                Span::raw(if item.value.is_empty() { "" } else { "  " }),
                Span::styled(item.value.clone(), Style::default().fg(Color::Yellow)),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.selected.saturating_sub(app.scroll)));
    let list = List::new(visible_items)
        .block(
            Block::default()
                .title("Configuration")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
    frame.render_stateful_widget(list, area, &mut state);

    if app.items.len() > height {
        let mut scrollbar = ScrollbarState::new(app.items.len()).position(app.scroll);
        frame.render_stateful_widget(
            Scrollbar::default().orientation(ScrollbarOrientation::VerticalRight),
            area,
            &mut scrollbar,
        );
    }
}

fn draw_details(frame: &mut ratatui::Frame<'_>, app: &MenuApp, area: Rect) {
    let Some(item) = app.selected_item() else {
        return;
    };
    let details = vec![
        Line::from(vec![
            Span::styled("Selected: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(item.title.clone()),
        ]),
        Line::from(vec![
            Span::styled("Value: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if item.value.is_empty() {
                "(empty)".to_string()
            } else {
                item.value.clone()
            }),
        ]),
        Line::raw(""),
        Line::from(item.help.clone()),
        Line::raw(""),
        Line::from(
            "Tip: empty optional values are omitted from the YAML. Use list sections to add repeated headers, contacts, paths, and backends.",
        ),
    ];
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(Block::default().title("Details").borders(Borders::ALL)),
        area,
    );
}

fn draw_edit_modal(frame: &mut ratatui::Frame<'_>, area: Rect, title: &str, value: &str) {
    let modal = centered_rect(70, 20, area);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new(value.to_string())
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        modal,
    );
}

fn draw_confirm_quit(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let modal = centered_rect(60, 20, area);
    frame.render_widget(Clear, modal);
    frame.render_widget(
        Paragraph::new("Unsaved changes will be lost. Quit? y/N")
            .block(Block::default().title("Confirm").borders(Borders::ALL)),
        modal,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn build_items(config: &Config) -> Vec<MenuItem> {
    let mut items = Vec::new();
    push_section(
        &mut items,
        0,
        "Global",
        "Process, protocol, proxy, logging, and headers.",
        SectionKind::HeaderList(ListFieldId::GlobalHeaderSet),
    );
    push_field(
        &mut items,
        1,
        "user",
        "Informational runtime user.",
        FieldId::GlobalUser,
        config,
    );
    push_field(
        &mut items,
        1,
        "access-log",
        "Access log path.",
        FieldId::GlobalAccessLog,
        config,
    );
    push_field(
        &mut items,
        1,
        "error-log",
        "Error log path.",
        FieldId::GlobalErrorLog,
        config,
    );
    push_field(
        &mut items,
        1,
        "pid-file",
        "Optional PID file path.",
        FieldId::GlobalPidFile,
        config,
    );
    push_field(
        &mut items,
        1,
        "num-threads",
        "Worker thread count.",
        FieldId::GlobalNumThreads,
        config,
    );
    push_field(
        &mut items,
        1,
        "file.send-gzip",
        "Serve precompressed gzip files.",
        FieldId::GlobalFileSendGzip,
        config,
    );
    push_field(
        &mut items,
        1,
        "compress",
        "Enable response compression.",
        FieldId::GlobalCompress,
        config,
    );
    push_field(
        &mut items,
        1,
        "limit-request-body",
        "Maximum request body size in bytes.",
        FieldId::GlobalLimitRequestBody,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-casper",
        "HTTP/2 CASPER compatibility toggle.",
        FieldId::GlobalHttp2Casper,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-enabled",
        "Advertise and serve HTTP/2 on TLS listeners.",
        FieldId::GlobalHttp2Enabled,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-idle-timeout",
        "HTTP/2 idle timeout in seconds.",
        FieldId::GlobalHttp2IdleTimeout,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-max-concurrent-streams",
        "HTTP/2 max concurrent streams.",
        FieldId::GlobalHttp2MaxConcurrentStreams,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-initial-stream-window",
        "HTTP/2 stream flow-control window.",
        FieldId::GlobalHttp2InitialStreamWindow,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-initial-connection-window",
        "HTTP/2 connection flow-control window.",
        FieldId::GlobalHttp2InitialConnectionWindow,
        config,
    );
    push_field(
        &mut items,
        1,
        "http2-max-frame-size",
        "HTTP/2 frame size.",
        FieldId::GlobalHttp2MaxFrameSize,
        config,
    );
    push_field(
        &mut items,
        1,
        "http3-enabled",
        "Enable QUIC/HTTP/3 listeners for TLS hosts.",
        FieldId::GlobalHttp3Enabled,
        config,
    );
    push_field(
        &mut items,
        1,
        "http3-max-concurrent-streams",
        "HTTP/3 max concurrent streams.",
        FieldId::GlobalHttp3MaxConcurrentStreams,
        config,
    );
    push_field(
        &mut items,
        1,
        "http3-idle-timeout",
        "HTTP/3 idle timeout in seconds.",
        FieldId::GlobalHttp3IdleTimeout,
        config,
    );
    push_field(
        &mut items,
        1,
        "http3-stream-receive-window",
        "HTTP/3 stream receive window.",
        FieldId::GlobalHttp3StreamReceiveWindow,
        config,
    );
    push_field(
        &mut items,
        1,
        "http3-connection-receive-window",
        "HTTP/3 connection receive window.",
        FieldId::GlobalHttp3ConnectionReceiveWindow,
        config,
    );
    push_field(
        &mut items,
        1,
        "proxy.preserve-host",
        "Forward original Host header by default.",
        FieldId::GlobalProxyPreserveHost,
        config,
    );
    push_field(
        &mut items,
        1,
        "proxy.timeout.io",
        "Proxy I/O timeout in milliseconds.",
        FieldId::GlobalProxyTimeoutIo,
        config,
    );
    push_field(
        &mut items,
        1,
        "proxy.timeout.keepalive",
        "Proxy keepalive timeout in milliseconds.",
        FieldId::GlobalProxyTimeoutKeepalive,
        config,
    );
    push_field(
        &mut items,
        1,
        "duration-stats",
        "Enable duration stats.",
        FieldId::GlobalDurationStats,
        config,
    );
    push_field(
        &mut items,
        1,
        "ssl-session-resumption.mode",
        "Optional SSL session resumption mode.",
        FieldId::GlobalSslSessionResumptionMode,
        config,
    );
    push_field(
        &mut items,
        1,
        "listen",
        "Raw YAML for global listen directives and anchors.",
        FieldId::GlobalListenRaw,
        config,
    );
    push_field(
        &mut items,
        1,
        "basic-auth.enabled",
        "ON/OFF enables global Basic auth; empty removes it.",
        FieldId::GlobalBasicAuthEnabled,
        config,
    );
    push_field(
        &mut items,
        1,
        "basic-auth.realm",
        "Global Basic auth realm.",
        FieldId::GlobalBasicAuthRealm,
        config,
    );
    push_field(
        &mut items,
        1,
        "basic-auth.users",
        "Comma-separated user:password pairs.",
        FieldId::GlobalBasicAuthUsers,
        config,
    );
    push_header_sections(&mut items, 1, config, None, None);

    push_section(
        &mut items,
        0,
        "Let's Encrypt",
        "Automatic ACME certificate provisioning and renewal.",
        SectionKind::LetsEncryptContacts,
    );
    push_field(
        &mut items,
        1,
        "enabled",
        "Enable ACME provisioning globally.",
        FieldId::LetsEncryptEnabled,
        config,
    );
    push_field(
        &mut items,
        1,
        "cache-dir",
        "ACME account and certificate cache directory.",
        FieldId::LetsEncryptCacheDir,
        config,
    );
    push_field(
        &mut items,
        1,
        "staging",
        "Use Let's Encrypt staging.",
        FieldId::LetsEncryptStaging,
        config,
    );
    push_field(
        &mut items,
        1,
        "directory-url",
        "Optional custom ACME directory URL.",
        FieldId::LetsEncryptDirectoryUrl,
        config,
    );
    push_field(
        &mut items,
        1,
        "terms-of-service-agreed",
        "Required for account creation.",
        FieldId::LetsEncryptTermsAgreed,
        config,
    );
    push_field(
        &mut items,
        1,
        "renew-before-days",
        "Renew this many days before certificate expiry.",
        FieldId::LetsEncryptRenewBeforeDays,
        config,
    );
    push_field(
        &mut items,
        1,
        "check-interval-seconds",
        "Background renewal check interval.",
        FieldId::LetsEncryptCheckIntervalSeconds,
        config,
    );
    push_section(
        &mut items,
        1,
        "contacts",
        "Press a to add mailto: contacts.",
        SectionKind::LetsEncryptContacts,
    );
    for (index, contact) in config.letsencrypt.contact.iter().enumerate() {
        items.push(MenuItem {
            depth: 2,
            title: format!("contact[{index}]"),
            value: contact.clone(),
            help: "ACME account contact URI. Press Enter to edit or d to delete.".to_string(),
            kind: ItemKind::Contact(index),
        });
    }

    push_section(
        &mut items,
        0,
        "Hosts",
        "Virtual hosts. Press a to add a domain:port host.",
        SectionKind::Hosts,
    );
    for (host_name, host) in &config.hosts {
        items.push(MenuItem {
            depth: 1,
            title: host_name.clone(),
            value: host_summary(host),
            help: "Host container. Press r to rename, a to add a path, d to delete.".to_string(),
            kind: ItemKind::Host(host_name.clone()),
        });
        let listen = host_listen(host);
        push_field(
            &mut items,
            2,
            "listen.host",
            "Bind address for this host listener.",
            FieldId::HostListenHost(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "listen.port",
            "Bind port for this host listener.",
            FieldId::HostListenPort(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "listen.type",
            "http or tcp.",
            FieldId::HostListenType(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "listen.ssl",
            "Toggle TLS listener settings.",
            FieldId::HostSslEnabled(host_name.clone()),
            config,
        );
        if listen.ssl.is_some() {
            push_field(
                &mut items,
                3,
                "ssl.minimum-version",
                "Minimum TLS version.",
                FieldId::HostSslMinimumVersion(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.cipher-preference",
                "server or client cipher preference.",
                FieldId::HostSslCipherPreference(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.cipher-suite",
                "Optional cipher suite override.",
                FieldId::HostSslCipherSuite(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.dh-file",
                "Optional DH parameters file.",
                FieldId::HostSslDhFile(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.certificate-file",
                "Manual certificate file.",
                FieldId::HostSslCertificateFile(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.key-file",
                "Manual private key file.",
                FieldId::HostSslKeyFile(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.letsencrypt",
                "Use automatic ACME certificate for this host.",
                FieldId::HostSslLetsEncrypt(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.ocsp-update-interval",
                "OCSP update interval.",
                FieldId::HostSslOcspUpdateInterval(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "ssl.sni-fallback",
                "Default certificate fallback for unknown SNI.",
                FieldId::HostSslSniFallback(host_name.clone()),
                config,
            );
        }
        push_header_sections(&mut items, 2, config, Some(host_name.clone()), None);

        push_section(
            &mut items,
            2,
            "paths",
            "HTTP routes. Press a to add a path.",
            SectionKind::HostPaths,
        );
        for (path_name, path) in &host.paths {
            items.push(MenuItem {
                depth: 3,
                title: path_name.clone(),
                value: path_summary(path),
                help: "Route path. Press r to rename, Enter to inspect, d to delete.".to_string(),
                kind: ItemKind::Path {
                    host: host_name.clone(),
                    path: path_name.clone(),
                },
            });
            push_field(
                &mut items,
                4,
                "redirect",
                "Redirect URL; takes precedence for this path.",
                FieldId::PathRedirect(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "status",
                "Serve built-in status endpoint.",
                FieldId::PathStatus(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "expires",
                "h2o-style expires value.",
                FieldId::PathExpires(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "file.dir",
                "Static file directory.",
                FieldId::PathFileDir(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "file.index",
                "Comma-separated index files.",
                FieldId::PathFileIndex(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "file.dirlisting",
                "Enable directory listings.",
                FieldId::PathFileDirlisting(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "proxy.reverse.url",
                "Reverse proxy upstream URL.",
                FieldId::PathProxyReverseUrl(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "proxy.preserve-host",
                "Override preserve-host for this path.",
                FieldId::PathProxyPreserveHost(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "basic-auth.enabled",
                "ON/OFF overrides inherited auth; empty inherits.",
                FieldId::PathBasicAuthEnabled(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "basic-auth.realm",
                "Path Basic auth realm.",
                FieldId::PathBasicAuthRealm(host_name.clone(), path_name.clone()),
                config,
            );
            push_field(
                &mut items,
                4,
                "basic-auth.users",
                "Comma-separated user:password pairs.",
                FieldId::PathBasicAuthUsers(host_name.clone(), path_name.clone()),
                config,
            );
            push_header_sections(
                &mut items,
                4,
                config,
                Some(host_name.clone()),
                Some(path_name.clone()),
            );
        }

        push_section(
            &mut items,
            2,
            "tcp.backends",
            "TCP backends. Press a to add host:port.",
            SectionKind::HostBackends,
        );
        for (index, backend) in host.backends.iter().enumerate() {
            items.push(MenuItem {
                depth: 3,
                title: format!("backend[{index}]"),
                value: format!(
                    "{}:{} weight {}",
                    backend.host, backend.port, backend.weight
                ),
                help: "TCP backend. Press d to delete.".to_string(),
                kind: ItemKind::Backend {
                    host: host_name.clone(),
                    index,
                },
            });
            push_field(
                &mut items,
                4,
                "host",
                "Backend host.",
                FieldId::BackendHost(host_name.clone(), index),
                config,
            );
            push_field(
                &mut items,
                4,
                "port",
                "Backend port.",
                FieldId::BackendPort(host_name.clone(), index),
                config,
            );
            push_field(
                &mut items,
                4,
                "weight",
                "Backend load-balancing weight.",
                FieldId::BackendWeight(host_name.clone(), index),
                config,
            );
        }
        push_field(
            &mut items,
            2,
            "tcp.tls",
            "Toggle TCP TLS settings.",
            FieldId::HostTcpTlsEnabled(host_name.clone()),
            config,
        );
        if host.tls.is_some() {
            push_field(
                &mut items,
                3,
                "tcp.tls.certificate-file",
                "TCP TLS certificate file.",
                FieldId::HostTcpTlsCertificateFile(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "tcp.tls.key-file",
                "TCP TLS private key file.",
                FieldId::HostTcpTlsKeyFile(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "tcp.tls.transparent-upgrade",
                "Auto-detect TLS vs plaintext.",
                FieldId::HostTcpTlsTransparentUpgrade(host_name.clone()),
                config,
            );
            push_field(
                &mut items,
                3,
                "tcp.tls.handshake-timeout",
                "TLS handshake timeout in milliseconds.",
                FieldId::HostTcpTlsHandshakeTimeout(host_name.clone()),
                config,
            );
        }
        push_field(
            &mut items,
            2,
            "health.interval",
            "TCP health check interval.",
            FieldId::HostHealthInterval(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.timeout",
            "TCP health check timeout.",
            FieldId::HostHealthTimeout(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.unhealthy-threshold",
            "Failures before unhealthy.",
            FieldId::HostHealthUnhealthyThreshold(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.healthy-threshold",
            "Successes before healthy.",
            FieldId::HostHealthHealthyThreshold(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.connect-timeout",
            "Backend connect timeout.",
            FieldId::HostHealthConnectTimeout(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.io-timeout",
            "Backend I/O timeout.",
            FieldId::HostHealthIoTimeout(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.sigma-threshold",
            "Latency sigma threshold.",
            FieldId::HostHealthSigmaThreshold(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "health.latency-aware",
            "Enable latency-aware weighting.",
            FieldId::HostHealthLatencyAware(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "basic-auth.enabled",
            "ON/OFF overrides inherited auth; empty inherits.",
            FieldId::HostBasicAuthEnabled(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "basic-auth.realm",
            "Host Basic auth realm.",
            FieldId::HostBasicAuthRealm(host_name.clone()),
            config,
        );
        push_field(
            &mut items,
            2,
            "basic-auth.users",
            "Comma-separated user:password pairs.",
            FieldId::HostBasicAuthUsers(host_name.clone()),
            config,
        );
    }

    items
}

fn push_section(
    items: &mut Vec<MenuItem>,
    depth: usize,
    title: &str,
    help: &str,
    kind: SectionKind,
) {
    items.push(MenuItem {
        depth,
        title: title.to_string(),
        value: String::new(),
        help: help.to_string(),
        kind: ItemKind::Section(kind),
    });
}

fn push_field(
    items: &mut Vec<MenuItem>,
    depth: usize,
    title: &str,
    help: &str,
    field: FieldId,
    config: &Config,
) {
    let app = MenuApp {
        config_path: PathBuf::new(),
        config: config.clone(),
        items: Vec::new(),
        selected: 0,
        scroll: 0,
        mode: Mode::Normal,
        dirty: false,
        status: String::new(),
    };
    let value = app.field_value(&field);
    items.push(MenuItem {
        depth,
        title: title.to_string(),
        value,
        help: help.to_string(),
        kind: ItemKind::Field(field),
    });
}

fn push_header_sections(
    items: &mut Vec<MenuItem>,
    depth: usize,
    config: &Config,
    host: Option<String>,
    path: Option<String>,
) {
    let fields = match (&host, &path) {
        (None, None) => [
            ListFieldId::GlobalHeaderSet,
            ListFieldId::GlobalHeaderSetIfEmpty,
            ListFieldId::GlobalHeaderMerge,
            ListFieldId::GlobalHeaderUnset,
        ],
        (Some(_), None) => [
            ListFieldId::HostHeaderSet,
            ListFieldId::HostHeaderSetIfEmpty,
            ListFieldId::HostHeaderMerge,
            ListFieldId::HostHeaderUnset,
        ],
        (Some(_), Some(_)) => [
            ListFieldId::PathHeaderSet,
            ListFieldId::PathHeaderSetIfEmpty,
            ListFieldId::PathHeaderMerge,
            ListFieldId::PathHeaderUnset,
        ],
        _ => return,
    };

    for field in fields {
        let values = list_value(config, field, host.as_deref(), path.as_deref());
        push_section(
            items,
            depth,
            field.title(),
            "Repeated list. Press a to add, Enter to edit an item, d to delete.",
            SectionKind::HeaderList(field),
        );
        for (index, value) in values.iter().enumerate() {
            items.push(MenuItem {
                depth: depth + 1,
                title: format!("{}[{index}]", field.title()),
                value: value.clone(),
                help: "Press Enter to edit or d to delete.".to_string(),
                kind: ItemKind::ListValue(field, index),
            });
        }
    }

    if host.is_some() && path.is_some() {
        for field in [
            ListFieldId::PathProxyHeaderSet,
            ListFieldId::PathProxyHeaderAdd,
        ] {
            let values = list_value(config, field, host.as_deref(), path.as_deref());
            push_section(
                items,
                depth,
                field.title(),
                "Proxy request header list. Press a to add.",
                SectionKind::HeaderList(field),
            );
            for (index, value) in values.iter().enumerate() {
                items.push(MenuItem {
                    depth: depth + 1,
                    title: format!("{}[{index}]", field.title()),
                    value: value.clone(),
                    help: "Press Enter to edit or d to delete.".to_string(),
                    kind: ItemKind::ListValue(field, index),
                });
            }
        }
    }
}

impl ListFieldId {
    fn title(self) -> &'static str {
        match self {
            ListFieldId::GlobalHeaderSet
            | ListFieldId::HostHeaderSet
            | ListFieldId::PathHeaderSet => "header.set",
            ListFieldId::GlobalHeaderSetIfEmpty
            | ListFieldId::HostHeaderSetIfEmpty
            | ListFieldId::PathHeaderSetIfEmpty => "header.setifempty",
            ListFieldId::GlobalHeaderMerge
            | ListFieldId::HostHeaderMerge
            | ListFieldId::PathHeaderMerge => "header.merge",
            ListFieldId::GlobalHeaderUnset
            | ListFieldId::HostHeaderUnset
            | ListFieldId::PathHeaderUnset => "header.unset",
            ListFieldId::PathProxyHeaderSet => "proxy.header.set",
            ListFieldId::PathProxyHeaderAdd => "proxy.header.add",
        }
    }

    fn placeholder(self) -> &'static str {
        match self {
            ListFieldId::GlobalHeaderUnset
            | ListFieldId::HostHeaderUnset
            | ListFieldId::PathHeaderUnset => "X-Powered-By",
            _ => "X-Header: value",
        }
    }
}

fn list_value<'a>(
    config: &'a Config,
    field: ListFieldId,
    host: Option<&str>,
    path: Option<&str>,
) -> &'a Vec<String> {
    match field {
        ListFieldId::GlobalHeaderSet => &config.header_set.0,
        ListFieldId::GlobalHeaderSetIfEmpty => &config.header_setifempty.0,
        ListFieldId::GlobalHeaderMerge => &config.header_merge.0,
        ListFieldId::GlobalHeaderUnset => &config.header_unset.0,
        ListFieldId::HostHeaderSet => &get_host(config, host.unwrap_or_default()).header_set.0,
        ListFieldId::HostHeaderSetIfEmpty => {
            &get_host(config, host.unwrap_or_default())
                .header_setifempty
                .0
        }
        ListFieldId::HostHeaderMerge => &get_host(config, host.unwrap_or_default()).header_merge.0,
        ListFieldId::HostHeaderUnset => &get_host(config, host.unwrap_or_default()).header_unset.0,
        ListFieldId::PathHeaderSet => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .header_set
                .0
        }
        ListFieldId::PathHeaderSetIfEmpty => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .header_setifempty
                .0
        }
        ListFieldId::PathHeaderMerge => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .header_merge
                .0
        }
        ListFieldId::PathHeaderUnset => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .header_unset
                .0
        }
        ListFieldId::PathProxyHeaderSet => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .proxy_header_set
                .0
        }
        ListFieldId::PathProxyHeaderAdd => {
            &get_path(config, host.unwrap_or_default(), path.unwrap_or_default())
                .proxy_header_add
                .0
        }
    }
}

fn list_value_mut<'a>(
    config: &'a mut Config,
    field: ListFieldId,
    host: Option<&str>,
    path: Option<&str>,
) -> &'a mut HeaderValue {
    match field {
        ListFieldId::GlobalHeaderSet => &mut config.header_set,
        ListFieldId::GlobalHeaderSetIfEmpty => &mut config.header_setifempty,
        ListFieldId::GlobalHeaderMerge => &mut config.header_merge,
        ListFieldId::GlobalHeaderUnset => &mut config.header_unset,
        ListFieldId::HostHeaderSet => &mut ensure_host(config, host.unwrap_or_default()).header_set,
        ListFieldId::HostHeaderSetIfEmpty => {
            &mut ensure_host(config, host.unwrap_or_default()).header_setifempty
        }
        ListFieldId::HostHeaderMerge => {
            &mut ensure_host(config, host.unwrap_or_default()).header_merge
        }
        ListFieldId::HostHeaderUnset => {
            &mut ensure_host(config, host.unwrap_or_default()).header_unset
        }
        ListFieldId::PathHeaderSet => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .header_set
        }
        ListFieldId::PathHeaderSetIfEmpty => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .header_setifempty
        }
        ListFieldId::PathHeaderMerge => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .header_merge
        }
        ListFieldId::PathHeaderUnset => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .header_unset
        }
        ListFieldId::PathProxyHeaderSet => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .proxy_header_set
        }
        ListFieldId::PathProxyHeaderAdd => {
            &mut ensure_path(
                ensure_host(config, host.unwrap_or_default()),
                path.unwrap_or_default(),
            )
            .proxy_header_add
        }
    }
}

fn serialize_config(config: &Config) -> anyhow::Result<String> {
    let yaml = serde_yaml::to_string(config)?;
    Ok(yaml)
}

fn parse_backend(value: &str) -> Option<BackendConfig> {
    let (host, port) = value.rsplit_once(':')?;
    Some(BackendConfig {
        host: host.to_string(),
        port: port.parse().ok()?,
        weight: 100,
    })
}

fn get_host<'a>(config: &'a Config, host: &str) -> &'a HostConfig {
    config.hosts.get(host).unwrap_or_else(|| {
        config
            .hosts
            .values()
            .next()
            .expect("host lookup requires an existing host")
    })
}

fn ensure_host<'a>(config: &'a mut Config, host: &str) -> &'a mut HostConfig {
    config
        .hosts
        .entry(host.to_string())
        .or_insert_with(default_host)
}

fn get_path<'a>(config: &'a Config, host: &str, path: &str) -> &'a PathConfig {
    get_host(config, host).paths.get(path).unwrap_or_else(|| {
        get_host(config, host)
            .paths
            .values()
            .next()
            .unwrap_or(&EMPTY_PATH)
    })
}

static EMPTY_PATH: PathConfig = PathConfig {
    redirect: None,
    status: OnOff::Off,
    expires: None,
    file_dir: None,
    file_index: None,
    file_dirlisting: OnOff::Off,
    proxy_reverse_url: None,
    proxy_preserve_host: None,
    basic_auth: None,
    header_set: HeaderValue(Vec::new()),
    header_setifempty: HeaderValue(Vec::new()),
    header_unset: HeaderValue(Vec::new()),
    header_merge: HeaderValue(Vec::new()),
    proxy_header_add: HeaderValue(Vec::new()),
    proxy_header_set: HeaderValue(Vec::new()),
};

fn ensure_path<'a>(host: &'a mut HostConfig, path: &str) -> &'a mut PathConfig {
    host.paths
        .entry(path.to_string())
        .or_insert_with(default_path)
}

fn default_host() -> HostConfig {
    HostConfig {
        listen: Some(serde_yaml::to_value(default_listen()).expect("default listen serializes")),
        paths: IndexMap::new(),
        backends: Vec::new(),
        health: None,
        tls: None,
        basic_auth: None,
        header_set: HeaderValue::default(),
        header_setifempty: HeaderValue::default(),
        header_unset: HeaderValue::default(),
        header_merge: HeaderValue::default(),
    }
}

fn default_path() -> PathConfig {
    PathConfig {
        status: OnOff::On,
        ..PathConfig::default()
    }
}

fn default_listen() -> ListenConfig {
    ListenConfig {
        host: "0.0.0.0".to_string(),
        port: 80,
        listener_type: ListenerType::Http,
        ssl: None,
    }
}

fn default_ssl() -> SslConfig {
    SslConfig {
        minimum_version: "TLSv1.2".to_string(),
        cipher_preference: "server".to_string(),
        cipher_suite: None,
        dh_file: None,
        certificate_file: None,
        key_file: None,
        letsencrypt: OnOff::Off,
        ocsp_update_interval: 0,
        sni_fallback: OnOff::Off,
    }
}

fn default_tcp_tls() -> TcpTlsConfig {
    TcpTlsConfig {
        certificate_file: PathBuf::from("/etc/ssl/certs/server.crt"),
        key_file: PathBuf::from("/etc/ssl/private/server.key"),
        transparent_upgrade: OnOff::Off,
        handshake_timeout: 10000,
    }
}

fn host_listen(host: &HostConfig) -> ListenConfig {
    host.listen
        .as_ref()
        .and_then(|value| serde_yaml::from_value::<ListenConfig>(value.clone()).ok())
        .unwrap_or_else(default_listen)
}

fn set_host_listen(host: &mut HostConfig, listen: ListenConfig) {
    host.listen = Some(serde_yaml::to_value(listen).expect("listen serializes"));
}

fn opt_ssl(host: &HostConfig) -> SslConfig {
    host_listen(host).ssl.unwrap_or_else(default_ssl)
}

fn update_ssl(host: &mut HostConfig, mut update: impl FnMut(&mut SslConfig)) {
    let mut listen = host_listen(host);
    let mut ssl = listen.ssl.unwrap_or_else(default_ssl);
    update(&mut ssl);
    listen.ssl = Some(ssl);
    set_host_listen(host, listen);
}

fn ensure_tcp_tls(host: &mut HostConfig) -> &mut TcpTlsConfig {
    if host.tls.is_none() {
        host.tls = Some(default_tcp_tls());
    }
    host.tls.as_mut().unwrap()
}

fn opt_tcp_tls(host: &HostConfig) -> TcpTlsConfig {
    host.tls.clone().unwrap_or_else(default_tcp_tls)
}

fn ensure_health(host: &mut HostConfig) -> &mut HealthConfig {
    if host.health.is_none() {
        host.health = Some(HealthConfig::default());
    }
    host.health.as_mut().unwrap()
}

fn opt_health(host: &HostConfig) -> HealthConfig {
    host.health.clone().unwrap_or_default()
}

fn ensure_basic_auth(auth: &mut Option<BasicAuthConfig>) -> &mut BasicAuthConfig {
    auth.get_or_insert_with(default_basic_auth)
}

fn default_basic_auth() -> BasicAuthConfig {
    BasicAuthConfig {
        enabled: OnOff::On,
        realm: "pyx".to_string(),
        users: IndexMap::new(),
    }
}

fn basic_auth_enabled(auth: &Option<BasicAuthConfig>) -> String {
    auth.as_ref()
        .map(|auth| onoff(auth.enabled))
        .unwrap_or_default()
}

fn basic_auth_realm(auth: &Option<BasicAuthConfig>) -> String {
    auth.as_ref()
        .map(|auth| auth.realm.clone())
        .unwrap_or_default()
}

fn basic_auth_users(auth: &Option<BasicAuthConfig>) -> String {
    auth.as_ref()
        .map(|auth| {
            auth.users
                .iter()
                .map(|(user, password)| format!("{user}:{password}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn set_optional_basic_auth_enabled(auth: &mut Option<BasicAuthConfig>, value: String) {
    if value.trim().is_empty() {
        *auth = None;
    } else {
        ensure_basic_auth(auth).enabled = parse_onoff(&value);
    }
}

fn set_basic_auth_users(auth: &mut BasicAuthConfig, value: &str) {
    auth.users.clear();
    for pair in value.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        if let Some((user, password)) = pair.split_once(':') {
            let user = user.trim();
            if !user.is_empty() {
                auth.users
                    .insert(user.to_string(), password.trim().to_string());
            }
        }
    }
}

fn host_summary(host: &HostConfig) -> String {
    let listen = host_listen(host);
    let kind = match listen.listener_type {
        ListenerType::Http => "http",
        ListenerType::Tcp => "tcp",
    };
    format!(
        "{}:{} {kind} {} paths {} backends",
        listen.host,
        listen.port,
        host.paths.len(),
        host.backends.len()
    )
}

fn path_summary(path: &PathConfig) -> String {
    if path.status.is_on() {
        "status".to_string()
    } else if let Some(url) = &path.redirect {
        format!("redirect {url}")
    } else if let Some(dir) = &path.file_dir {
        format!("files {}", dir.display())
    } else if let Some(upstream) = &path.proxy_reverse_url {
        format!("proxy {upstream}")
    } else {
        "no action".to_string()
    }
}

fn nearest_host(items: &[MenuItem], selected: usize) -> Option<String> {
    items[..=selected.min(items.len().saturating_sub(1))]
        .iter()
        .rev()
        .find_map(|item| match &item.kind {
            ItemKind::Host(host) => Some(host.clone()),
            ItemKind::Path { host, .. } | ItemKind::Backend { host, .. } => Some(host.clone()),
            _ => None,
        })
}

fn nearest_path(items: &[MenuItem], selected: usize) -> Option<(String, String)> {
    items[..=selected.min(items.len().saturating_sub(1))]
        .iter()
        .rev()
        .find_map(|item| match &item.kind {
            ItemKind::Path { host, path } => Some((host.clone(), path.clone())),
            _ => None,
        })
}

fn onoff(value: OnOff) -> String {
    if value.is_on() { "ON" } else { "OFF" }.to_string()
}

fn parse_onoff(value: &str) -> OnOff {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => OnOff::On,
        _ => OnOff::Off,
    }
}

fn opt_string(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn opt_path(value: &Option<PathBuf>) -> String {
    value
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

fn opt_path_string(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

fn none_if_empty(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn comma_list(value: String) -> Option<Vec<String>> {
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn set_parse<T>(value: String, target: &mut T)
where
    T: std::str::FromStr,
{
    if let Ok(parsed) = value.parse::<T>() {
        *target = parsed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LetsEncryptConfig;

    fn test_config() -> Config {
        serde_yaml::from_str("hosts: {}\n").unwrap()
    }

    #[test]
    fn add_host_and_path_mutates_config() {
        let mut app = MenuApp {
            config_path: PathBuf::from("test.yaml"),
            config: test_config(),
            items: Vec::new(),
            selected: 0,
            scroll: 0,
            mode: Mode::Normal,
            dirty: false,
            status: String::new(),
        };

        app.apply_edit(EditTarget::AddHost, "example.com:443".to_string());
        app.apply_edit(
            EditTarget::AddPath("example.com:443".to_string()),
            "/api".to_string(),
        );

        assert!(app.config.hosts.contains_key("example.com:443"));
        assert!(
            app.config.hosts["example.com:443"]
                .paths
                .contains_key("/api")
        );
        assert!(app.dirty);
    }

    #[test]
    fn serialize_output_can_be_loaded_and_resolved() {
        let mut config = test_config();
        config.letsencrypt = LetsEncryptConfig {
            enabled: OnOff::On,
            terms_of_service_agreed: OnOff::On,
            ..LetsEncryptConfig::default()
        };
        let host = ensure_host(&mut config, "example.com:443");
        let mut listen = host_listen(host);
        listen.port = 443;
        listen.ssl = Some(SslConfig {
            letsencrypt: OnOff::On,
            ..default_ssl()
        });
        set_host_listen(host, listen);
        host.paths.insert("/".to_string(), default_path());

        let yaml = serialize_config(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        parsed.resolve().unwrap();
        assert!(yaml.contains("letsencrypt"));
        assert!(yaml.contains("example.com:443"));
    }

    #[test]
    fn global_listen_raw_yaml_is_editable() {
        let mut app = MenuApp {
            config_path: PathBuf::from("test.yaml"),
            config: test_config(),
            items: Vec::new(),
            selected: 0,
            scroll: 0,
            mode: Mode::Normal,
            dirty: false,
            status: String::new(),
        };

        app.set_field(
            FieldId::GlobalListenRaw,
            "{ host: 127.0.0.1, port: 8080 }".to_string(),
        );

        let listen = app.config.listen.as_ref().unwrap();
        assert_eq!(listen["host"].as_str(), Some("127.0.0.1"));
        assert_eq!(listen["port"].as_i64(), Some(8080));
    }

    #[test]
    fn backend_parser_requires_host_port() {
        let backend = parse_backend("127.0.0.1:8080").unwrap();
        assert_eq!(backend.host, "127.0.0.1");
        assert_eq!(backend.port, 8080);
        assert!(parse_backend("missing-port").is_none());
    }
}
