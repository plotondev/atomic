use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

use crate::agent_json::AgentJson;
use crate::config;
use crate::credentials::Credentials;
use crate::crypto::signing;

pub fn run(
    domain: &str,
    port: u16,
    no_tls: bool,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    force: bool,
    proxy: bool,
) -> Result<()> {
    // Validate domain format
    if domain.len() > 253 {
        bail!("Domain is too long (max 253 characters)");
    }
    if !domain.contains('.') {
        bail!("Domain must contain at least one dot (e.g., agent.example.com)");
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.starts_with('-') {
        bail!("Domain must not start or end with a dot or hyphen");
    }
    if domain.contains("..") {
        bail!("Domain must not contain consecutive dots");
    }
    if !domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        bail!("Domain contains invalid characters (only alphanumeric, hyphens, and dots allowed)");
    }

    // Validate TLS cert/key must be provided as a pair
    match (&tls_cert, &tls_key) {
        (Some(_), None) => bail!("--tls-cert requires --tls-key"),
        (None, Some(_)) => bail!("--tls-key requires --tls-cert"),
        _ => {}
    }
    if let Some(ref cert_path) = tls_cert {
        if !std::path::Path::new(cert_path).exists() {
            bail!("TLS certificate file not found: {cert_path}");
        }
    }
    if let Some(ref key_path) = tls_key {
        if !std::path::Path::new(key_path).exists() {
            bail!("TLS key file not found: {key_path}");
        }
    }

    let atomic_dir = config::atomic_dir()?;

    if atomic_dir.exists() && !force {
        let creds_path = config::credentials_path()?;
        if creds_path.exists() {
            bail!(
                "Identity already exists at {}. Use --force to overwrite.",
                atomic_dir.display()
            );
        }
    }

    config::ensure_atomic_dir()?;

    info!("Generating Ed25519 keypair...");
    let (signing_key, verifying_key) = signing::generate_keypair();

    let credentials = Credentials::new(
        domain.to_string(),
        &signing_key,
        &verifying_key,
        port,
        no_tls,
        tls_cert,
        tls_key,
        proxy,
    );
    let creds_path = config::credentials_path()?;
    credentials.save(&creds_path)?;
    info!("Credentials written to {}", creds_path.display());

    let base_url = credentials.base_url();
    let agent = AgentJson::new(domain, &credentials.public_key, &base_url);
    let agent_path = config::agent_json_path()?;
    agent.save(&agent_path)?;
    info!("agent.json written to {}", agent_path.display());

    let deposits_path = config::deposits_log_path()?;
    if !deposits_path.exists() {
        config::write_secure(&deposits_path, b"")?;
    }

    println!("Agent identity initialized for {domain}");
    println!("  Domain:     {domain}");
    println!("  Public Key: {}", credentials.public_key);
    println!("  Base URL:   {base_url}");

    spawn_server()?;

    Ok(())
}

// Fork off `atomic serve` in the background, log to ~/.atomic/atomic.log
fn spawn_server() -> Result<()> {
    let log_path = config::log_path()?;
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open log file {}", log_path.display()))?;

    let stderr_log = log_file
        .try_clone()
        .context("Failed to clone log file handle")?;

    let exe = std::env::current_exe().context("Failed to resolve current executable path")?;

    let child = Command::new(exe)
        .arg("serve")
        .stdout(log_file)
        .stderr(stderr_log)
        .stdin(std::process::Stdio::null())
        .spawn()
        .context("Failed to spawn server process")?;

    let child_pid = child.id();

    // Brief wait to catch immediate failures (port in use, missing files, etc.)
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if the process is still alive
    let alive = Command::new("kill")
        .args(["-0", &child_pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !alive {
        anyhow::bail!(
            "Server exited immediately after starting. Check logs at {}",
            log_path.display()
        );
    }

    println!("Server started (PID {child_pid})");
    println!("  Logs: {}", log_path.display());
    println!();
    println!("Stop with: atomic stop");

    Ok(())
}
