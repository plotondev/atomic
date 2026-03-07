use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

use crate::config;

pub enum TlsMode {
    Auto { domain: String },
    Custom { cert_path: String, key_path: String },
    None,
}

impl TlsMode {
    pub fn from_credentials(creds: &crate::credentials::Credentials) -> Self {
        if creds.no_tls {
            TlsMode::None
        } else if let (Some(cert), Some(key)) = (&creds.tls_cert, &creds.tls_key) {
            TlsMode::Custom {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }
        } else {
            TlsMode::Auto {
                domain: creds.domain.clone(),
            }
        }
    }
}

pub async fn resolve_rustls_config(mode: &TlsMode) -> Result<RustlsConfig> {
    match mode {
        TlsMode::Custom { cert_path, key_path } => {
            info!("Loading TLS cert from {}", cert_path);
            RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .context("Failed to load TLS cert/key")
        }
        TlsMode::Auto { domain } => {
            let tls_dir = config::tls_dir()?;
            std::fs::create_dir_all(&tls_dir)?;
            let cert_path = tls_dir.join("fullchain.pem");
            let key_path = tls_dir.join("key.pem");

            if !cert_path.exists() || !key_path.exists() {
                issue_cert(domain, &tls_dir)?;
            }

            RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .context("Failed to load TLS cert")
        }
        TlsMode::None => {
            unreachable!("resolve_rustls_config called with TlsMode::None")
        }
    }
}

// Install acme.sh if not present, issue cert, install to ~/.atomic/tls/
fn issue_cert(domain: &str, tls_dir: &Path) -> Result<()> {
    // Defense-in-depth: validate domain even though init.rs already checks
    if !domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        anyhow::bail!("Domain contains invalid characters: {domain}");
    }

    ensure_acme_sh()?;
    let acme_sh = acme_sh_path()?;

    info!("Issuing TLS cert for {} via acme.sh", domain);

    // Issue using standalone mode (binds :80 for HTTP-01 challenge)
    let output = Command::new(&acme_sh)
        .args([
            "--issue",
            "-d", domain,
            "--standalone",
            "--server", "letsencrypt",
        ])
        .output()
        .context("Failed to run acme.sh --issue")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        // acme.sh returns 2 if cert already exists and is still valid
        if !stdout.contains("Cert success") && !stderr.contains("already") && output.status.code() != Some(2) {
            anyhow::bail!(
                "acme.sh --issue failed (exit {}):\n{}\n{}",
                output.status,
                stdout,
                stderr
            );
        }
    }

    // Install cert files to our tls dir
    let output = Command::new(&acme_sh)
        .args([
            "--install-cert",
            "-d", domain,
            "--fullchain-file", &tls_dir.join("fullchain.pem").to_string_lossy(),
            "--key-file", &tls_dir.join("key.pem").to_string_lossy(),
        ])
        .output()
        .context("Failed to run acme.sh --install-cert")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("acme.sh --install-cert failed: {stderr}");
    }

    info!("TLS cert installed to {}", tls_dir.display());
    Ok(())
}

fn ensure_acme_sh() -> Result<()> {
    if acme_sh_path().is_ok() {
        return Ok(());
    }

    info!("Installing acme.sh...");
    let home = dirs::home_dir().context("No home directory")?;
    let acme_home = home.join(".acme.sh");

    // Download the script first, then run it with proper argument separation
    // to avoid shell injection via the home directory path.
    let download = Command::new("curl")
        .args(["-fsSL", "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh"])
        .output()
        .context("Failed to download acme.sh. Is curl available?")?;

    if !download.status.success() {
        let stderr = String::from_utf8_lossy(&download.stderr);
        anyhow::bail!("Failed to download acme.sh: {stderr}");
    }

    let output = Command::new("sh")
        .arg("-s")
        .arg("--")
        .arg("--install-online")
        .arg("--home")
        .arg(&acme_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(&download.stdout)?;
            }
            child.wait_with_output()
        })
        .context("Failed to install acme.sh")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "acme.sh install failed.\n\
             You can install it manually: curl https://get.acme.sh | sh\n\
             stdout: {stdout}\n\
             stderr: {stderr}"
        );
    }

    // Verify it's there now
    acme_sh_path().context(
        "acme.sh installed but not found. Try installing manually: curl https://get.acme.sh | sh"
    )?;
    info!("acme.sh installed");
    Ok(())
}

fn acme_sh_path() -> Result<std::path::PathBuf> {
    // Check common locations
    let home = dirs::home_dir().context("No home directory")?;
    let candidates = [
        home.join(".acme.sh/acme.sh"),
        std::path::PathBuf::from("/usr/local/bin/acme.sh"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    // Try PATH
    let output = Command::new("which")
        .arg("acme.sh")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(std::path::PathBuf::from(path));
            }
        }
    }

    anyhow::bail!("acme.sh not found")
}

// acme.sh sets up its own cron job for renewal. But if atomic manages the server,
// we should reload the cert when acme.sh renews it. This task checks every 12h.
pub fn spawn_renewal_watcher(rustls_config: RustlsConfig) {
    let check_interval = std::time::Duration::from_secs(12 * 3600);

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(check_interval).await;

            let tls_dir = match config::tls_dir() {
                Ok(d) => d,
                Err(e) => {
                    warn!("Cert reload check failed: {}", e);
                    continue;
                }
            };

            let cert_path = tls_dir.join("fullchain.pem");
            let key_path = tls_dir.join("key.pem");

            // Hot-reload: if acme.sh renewed the cert on disk, pick it up
            match rustls_config.reload_from_pem_file(&cert_path, &key_path).await {
                Ok(()) => info!("TLS cert reloaded"),
                Err(e) => warn!("TLS cert reload failed: {}", e),
            }
        }
    });
}
