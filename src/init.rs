use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::info;

use crate::agent_json::AgentJson;
use crate::config;
use crate::credentials::Credentials;
use crate::crypto::signing;
use crate::vault::VaultStore;

pub fn run(domain: &str, port: u16, no_tls: bool, force: bool) -> Result<()> {
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

    let credentials = Credentials::new(domain.to_string(), &signing_key, &verifying_key, port, no_tls);
    let creds_path = config::credentials_path()?;
    credentials.save(&creds_path)?;
    info!("Credentials written to {}", creds_path.display());

    let base_url = credentials.base_url();
    let agent = AgentJson::new(domain, &credentials.public_key, &base_url);
    let agent_path = config::agent_json_path()?;
    agent.save(&agent_path)?;
    info!("agent.json written to {}", agent_path.display());

    let vault_path = config::vault_path()?;
    if !vault_path.exists() {
        let vault = VaultStore::new(signing_key.to_bytes().to_vec());
        vault.save(&vault_path)?;
        info!("Empty vault created at {}", vault_path.display());
    }

    let deposits_path = config::deposits_log_path()?;
    if !deposits_path.exists() {
        std::fs::write(&deposits_path, "")
            .with_context(|| format!("Failed to create {}", deposits_path.display()))?;
    }

    println!("Agent identity initialized for {}", domain);
    println!("  Domain:     {}", domain);
    println!("  Public Key: {}", credentials.public_key);
    println!("  Base URL:   {}", base_url);

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

    println!("Server started (PID {})", child.id());
    println!("  Logs: {}", log_path.display());
    println!();
    println!("Stop with: atomic stop");

    Ok(())
}
