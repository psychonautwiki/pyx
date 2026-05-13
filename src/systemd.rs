//! systemd unit installation helpers.

use anyhow::{Context, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_UNIT_SUFFIX: &str = ".service";

#[derive(Debug)]
pub struct InstallOptions {
    pub config_file: PathBuf,
    pub name: String,
    pub unit_dir: PathBuf,
    pub enable: bool,
    pub start: bool,
}

#[derive(Debug)]
pub struct RemoveOptions {
    pub name: String,
    pub unit_dir: PathBuf,
    pub stop: bool,
    pub disable: bool,
}

pub fn install(options: InstallOptions) -> anyhow::Result<()> {
    let unit_name = normalize_unit_name(&options.name)?;
    let unit_path = options.unit_dir.join(&unit_name);
    let binary = std::env::current_exe()
        .context("failed to determine current executable")?
        .canonicalize()
        .context("failed to canonicalize current executable")?;
    let config_file = options.config_file.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize config file '{}'",
            options.config_file.display()
        )
    })?;
    let unit = render_unit(&unit_name, &binary, &config_file);

    fs::create_dir_all(&options.unit_dir).with_context(|| {
        format!(
            "failed to create systemd unit directory '{}'",
            options.unit_dir.display()
        )
    })?;
    fs::write(&unit_path, unit)
        .with_context(|| format!("failed to write systemd unit '{}'", unit_path.display()))?;

    println!("Wrote {}", unit_path.display());
    run_systemctl(&["daemon-reload"])?;

    if options.enable {
        run_systemctl(&["enable", &unit_name])?;
    }

    if options.start {
        run_systemctl(&["restart", &unit_name])?;
    }

    println!("Installed {unit_name} for config {}", config_file.display());
    Ok(())
}

pub fn remove(options: RemoveOptions) -> anyhow::Result<()> {
    let unit_name = normalize_unit_name(&options.name)?;
    let unit_path = options.unit_dir.join(&unit_name);

    if options.stop {
        run_systemctl(&["stop", &unit_name])?;
    }

    if options.disable {
        run_systemctl(&["disable", &unit_name])?;
    }

    match fs::remove_file(&unit_path) {
        Ok(()) => println!("Removed {}", unit_path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("Unit file was already absent: {}", unit_path.display());
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to remove systemd unit '{}'", unit_path.display())
            });
        }
    }

    run_systemctl(&["daemon-reload"])?;
    let _ = run_systemctl(&["reset-failed", &unit_name]);

    println!("Removed {unit_name}");
    Ok(())
}

fn render_unit(unit_name: &str, binary: &Path, config_file: &Path) -> String {
    format!(
        "\
[Unit]
Description=pyx reverse proxy ({unit_name})
Documentation=https://github.com/psychonautwiki/pyx
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={} --config {}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
",
        systemd_escape_arg(binary),
        systemd_escape_arg(config_file)
    )
}

fn normalize_unit_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("systemd unit name cannot be empty");
    }

    let unit_name = if name.ends_with(DEFAULT_UNIT_SUFFIX) {
        name.to_string()
    } else {
        format!("{name}{DEFAULT_UNIT_SUFFIX}")
    };

    if !unit_name.chars().all(is_valid_unit_char) {
        bail!(
            "invalid systemd unit name '{unit_name}'; use letters, numbers, '.', '_', '-', or '@'"
        );
    }

    Ok(unit_name)
}

fn is_valid_unit_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@')
}

fn systemd_escape_arg(path: &Path) -> String {
    let raw = path.as_os_str().to_string_lossy();
    raw.bytes()
        .flat_map(|byte| match byte {
            b'/' | b'.' | b'_' | b'-' | b'@' | b':' | b'+' | b'=' | b',' => {
                vec![byte as char]
            }
            b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' => vec![byte as char],
            _ => format!("\\x{byte:02x}").chars().collect(),
        })
        .collect()
}

fn run_systemctl(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("failed to run systemctl {}", args.join(" ")))?;

    if !status.success() {
        bail!("systemctl {} failed with {status}", args.join(" "));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_name_adds_service_suffix() {
        assert_eq!(normalize_unit_name("pyx").unwrap(), "pyx.service");
        assert_eq!(
            normalize_unit_name("pyx-custom.service").unwrap(),
            "pyx-custom.service"
        );
    }

    #[test]
    fn unit_name_rejects_unsafe_names() {
        assert!(normalize_unit_name("").is_err());
        assert!(normalize_unit_name("../pyx").is_err());
        assert!(normalize_unit_name("pyx;reboot").is_err());
    }

    #[test]
    fn unit_uses_specific_config_file() {
        let unit = render_unit(
            "pyx-example.service",
            Path::new("/usr/bin/pyx"),
            Path::new("/etc/pyx/example.yaml"),
        );

        assert!(unit.contains("ExecStart=/usr/bin/pyx --config /etc/pyx/example.yaml"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unit_escapes_paths_for_systemd_exec() {
        let unit = render_unit(
            "pyx-example.service",
            Path::new("/opt/pyx current/pyx"),
            Path::new("/etc/pyx/example config.yaml"),
        );

        assert!(unit.contains("/opt/pyx\\x20current/pyx"));
        assert!(unit.contains("/etc/pyx/example\\x20config.yaml"));
    }
}
