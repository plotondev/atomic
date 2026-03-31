mod agent_json;
mod cli;
mod config;
mod credentials;
mod crypto;
mod db;
mod deposit;
mod init;
mod magic_link;
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

use cli::{Cli, Command, KeyCommand, MagicLinkCommand, ServiceCommand, VaultCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("atomic=info".parse()?))
        .init();

    // Clean up PID file and temp files on panic (best-effort).
    // With panic=abort in release, the hook still runs before the process terminates.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("atomic: fatal panic: {info}");
        if let Ok(path) = config::pid_path() {
            let _ = std::fs::remove_file(path);
        }
        // Clean temp files left by write_secure (atomic write pattern)
        if let Ok(dir) = config::atomic_dir() {
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.contains(".tmp.") {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }));

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
            let pid_path = config::pid_path()?;
            if !pid_path.exists() {
                anyhow::bail!("No running server found (no PID file)");
            }
            let pid_str = std::fs::read_to_string(&pid_path)?;
            let pid: i32 = pid_str.trim().parse().context("Invalid PID file")?;
            if pid <= 0 {
                let _ = std::fs::remove_file(&pid_path);
                anyhow::bail!("Invalid PID {pid} in PID file (removed)");
            }

            // Verify the PID belongs to an atomic process before killing
            let ps_output = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output();
            if let Ok(output) = ps_output {
                let comm = String::from_utf8_lossy(&output.stdout);
                let comm = comm.trim();
                if !comm.is_empty() && !comm.contains("atomic") {
                    let _ = std::fs::remove_file(&pid_path);
                    anyhow::bail!(
                        "PID {pid} belongs to '{comm}', not atomic (stale PID file removed)"
                    );
                }
            }

            // Verify process still alive immediately before kill to minimize PID reuse window
            let probe = std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status();
            if !probe.map(|s| s.success()).unwrap_or(false) {
                let _ = std::fs::remove_file(&pid_path);
                anyhow::bail!("PID {pid} no longer exists (stale PID file removed)");
            }

            // Send SIGTERM
            let status = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status()
                .context("Failed to send stop signal")?;

            if status.success() {
                let _ = std::fs::remove_file(&pid_path);
                println!("Server stopped (PID {pid})");
            } else {
                // Process might already be gone
                let _ = std::fs::remove_file(&pid_path);
                println!("Server process {pid} not found (cleaned up stale PID file)");
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
            let duration = deposit::parse_duration(&expires)?;
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

        Command::MagicLink { command } => match command {
            MagicLinkCommand::Host { code, expires } => {
                magic_link::host(&code, &expires)?;
            }
            MagicLinkCommand::List => {
                magic_link::list()?;
            }
        },

        Command::Sign { dry_run, command } => {
            sign::run(&command, dry_run)?;
        }

        Command::Key { command } => match command {
            KeyCommand::Rotate => println!("Key rotation not yet implemented (PLO-58)"),
            KeyCommand::Revoke => println!("Key revocation not yet implemented (PLO-58)"),
        },

        Command::Service { command } => match command {
            ServiceCommand::Install => println!("Service install not yet implemented (PLO-59)"),
            ServiceCommand::Uninstall => {
                println!("Service uninstall not yet implemented (PLO-59)")
            }
            ServiceCommand::Status => println!("Service status not yet implemented (PLO-59)"),
        },
    }

    Ok(())
}
