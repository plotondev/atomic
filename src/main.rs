mod agent_json;
mod cli;
mod config;
mod credentials;
mod crypto;
mod db;
mod deposit;
mod init;
mod server;
mod sign;
mod tls;
mod vault;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command, VaultCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("atomic=info".parse()?))
        .init();

    // Enable jemalloc background thread for aggressive memory purging.
    // Ensures freed allocations (including zeroed key material) are returned
    // to the OS promptly instead of lingering in allocator caches.
    #[cfg(feature = "jemalloc")]
    {
        if let Err(e) = tikv_jemalloc_ctl::background_thread::write(true) {
            tracing::warn!("Failed to enable jemalloc background thread: {e}");
        }
    }

    // Panic hook removed: file I/O in panic handlers is async-signal-unsafe
    // (deadlock risk if panic occurred during malloc or file operation).
    // The kernel automatically releases flock on the PID file when the process exits.
    // Temp files from write_secure are cleaned on next startup or OS reboot.

    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            domain,
            port,
            no_tls,
            tls_cert,
            tls_key,
            proxy,
            force,
        } => {
            init::run(&domain, port, no_tls, tls_cert, tls_key, force, proxy)?;
        }

        Command::Serve => {
            let creds_path = config::credentials_path()?;
            let creds = credentials::Credentials::load(&creds_path)?;
            server::run_server(creds).await?;
        }

        Command::Stop => {
            use fs2::FileExt;

            let pid_path = config::pid_path()?;
            if !pid_path.exists() {
                anyhow::bail!("No running server found (no PID file)");
            }

            // Use flock to atomically determine if the server process is alive.
            // The running server holds an exclusive flock on the PID file.
            // This eliminates the TOCTOU race window from ps/kill -0 checks.
            let pid_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pid_path)
                .context("Failed to open PID file")?;

            match pid_file.try_lock_exclusive() {
                Ok(()) => {
                    // We got the lock — the server process is dead (kernel released its lock).
                    drop(pid_file);
                    let _ = std::fs::remove_file(&pid_path);
                    println!("Cleaned up stale PID file (server was not running)");
                }
                Err(_) => {
                    // Lock held by live server process — read PID and send SIGTERM.
                    let pid_str = std::fs::read_to_string(&pid_path)?;
                    let pid: i32 = pid_str.trim().parse().context("Invalid PID file")?;
                    if pid <= 0 {
                        anyhow::bail!("Invalid PID {pid} in PID file");
                    }

                    let status = std::process::Command::new("kill")
                        .arg(pid.to_string())
                        .status()
                        .context("Failed to send SIGTERM")?;

                    if status.success() {
                        println!("Server stopped (PID {pid})");
                    } else {
                        println!("Failed to stop server (PID {pid})");
                    }
                }
            }
        }

        Command::Whoami => {
            let creds_path = config::credentials_path()?;
            let creds = credentials::Credentials::load(&creds_path)?;
            let agent_path = config::agent_json_path()?;
            let agent = agent_json::AgentJson::load(&agent_path)?;
            println!("Domain:     {}", creds.domain);
            println!("Public Key: {}", creds.public_key);
            println!("Status:     {}", agent.status);
            println!("Created:    {}", agent.created_at);
        }

        Command::Status => {
            let creds_path = config::credentials_path()?;
            let creds = credentials::Credentials::load(&creds_path)?;
            let vault_count = vault::vault_count()?;
            println!("Domain:   {}", creds.domain);
            println!("Port:     {}", creds.port);
            println!("TLS:      {}", if creds.no_tls { "disabled" } else { "enabled" });
            println!("Vault:    {vault_count} secrets");
        }

        Command::Verify { domain } => {
            let url = format!("https://{domain}/.well-known/agent.json");
            println!("Fetching {url}...");
            let resp = reqwest::get(&url).await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to fetch agent.json: HTTP {}", resp.status());
            }
            let agent: agent_json::AgentJson = resp.json().await?;
            println!("  Domain:     {}", agent.id);
            println!("  Public Key: {}", agent.public_key);
            println!("  Status:     {}", agent.status);
            println!("  Created:    {}", agent.created_at);
            if agent.id != domain {
                println!("  WARNING:    agent.id '{}' does not match requested domain '{}'", agent.id, domain);
                println!("  Result:     DOMAIN MISMATCH");
            } else if agent.status == "active" {
                println!("  Result:     VALID");
            } else {
                println!("  Result:     {}", agent.status.to_uppercase());
            }
        }

        Command::DepositUrl { label, expires } => {
            let creds_path = config::credentials_path()?;
            let creds = credentials::Credentials::load(&creds_path)?;
            let signing_key = creds.signing_key()?;
            let duration = std::time::Duration::from_secs(expires);
            let token = deposit::create_signed_token(&label, duration, &signing_key)?;
            let url = format!("{}/d/{}", creds.base_url(), token);
            println!("{url}");
        }

        Command::Deposits { label } => {
            deposit::list_deposits(label.as_deref())?;
        }

        Command::Vault { command } => {
            let creds = credentials::Credentials::load(&config::credentials_path()?)?;
            let sk = creds.signing_key()?;
            let vault_key = crypto::vault::derive_vault_key(&sk.to_bytes())?;
            match command {
                VaultCommand::Set { label, value } => {
                    let value = match value {
                        Some(v) => v,
                        None => {
                            use std::io::Read;
                            let mut buf = String::new();
                            std::io::stdin().read_to_string(&mut buf)?;
                            let v = buf.trim_end_matches('\n').to_string();
                            if v.is_empty() {
                                anyhow::bail!("No value provided (pass as argument or pipe via stdin)");
                            }
                            v
                        }
                    };
                    vault::cmd_set(&label, &value, &vault_key)?
                }
                VaultCommand::Get { label } => vault::cmd_get(&label, &vault_key)?,
                VaultCommand::List => vault::cmd_list()?,
                VaultCommand::Delete { label } => vault::cmd_delete(&label)?,
            }
        }

        Command::Sign { dry_run, command } => {
            sign::run(&command, dry_run)?;
        }
    }

    Ok(())
}
