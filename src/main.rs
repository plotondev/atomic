mod agent_json;
mod cli;
mod config;
mod credentials;
mod crypto;
mod deposit;
mod init;
mod server;
mod vault;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command, KeyCommand, ServiceCommand, VaultCommand};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("atomic=info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            domain,
            port,
            no_tls,
            force,
            ..
        } => {
            init::run(&domain, port, no_tls, force)?;
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

            // Send SIGTERM
            let status = std::process::Command::new("kill")
                .arg(pid.to_string())
                .status()
                .context("Failed to send stop signal")?;

            if status.success() {
                let _ = std::fs::remove_file(&pid_path);
                println!("Server stopped (PID {})", pid);
            } else {
                // Process might already be gone
                let _ = std::fs::remove_file(&pid_path);
                println!("Server process {} not found (cleaned up stale PID file)", pid);
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
            let (store, _) = vault::load_vault()?;
            println!("Domain:   {}", creds.domain);
            println!("Port:     {}", creds.port);
            println!("TLS:      {}", if creds.no_tls { "disabled" } else { "enabled" });
            println!("Vault:    {} secrets", store.len());
        }

        Command::Verify { domain } => {
            let url = format!("https://{}/.well-known/agent.json", domain);
            println!("Fetching {}...", url);
            let resp = reqwest::get(&url).await?;
            if !resp.status().is_success() {
                anyhow::bail!("Failed to fetch agent.json: HTTP {}", resp.status());
            }
            let agent: agent_json::AgentJson = resp.json().await?;
            println!("  Domain:     {}", agent.id);
            println!("  Public Key: {}", agent.public_key);
            println!("  Status:     {}", agent.status);
            println!("  Created:    {}", agent.created_at);
            if agent.status == "active" {
                println!("  Result:     VALID");
            } else {
                println!("  Result:     {}", agent.status.to_uppercase());
            }
        }

        Command::DepositUrl { label, expires } => {
            let creds_path = config::credentials_path()?;
            let creds = credentials::Credentials::load(&creds_path)?;
            let duration = deposit::parse_duration(&expires)?;
            let dm = deposit::DepositManager::new(100);
            let token = dm.create_deposit_url(label, duration).await?;
            let url = format!("{}/d/{}", creds.base_url(), token);
            println!("{}", url);
        }

        Command::Deposits => {
            let log_path = config::deposits_log_path()?;
            if !log_path.exists() {
                println!("No deposits yet.");
                return Ok(());
            }
            let content = std::fs::read_to_string(&log_path)?;
            if content.is_empty() {
                println!("No deposits yet.");
            } else {
                print!("{}", content);
            }
        }

        Command::Vault { command } => match command {
            VaultCommand::Set { label, value } => vault::cmd_set(&label, &value)?,
            VaultCommand::Get { label } => vault::cmd_get(&label)?,
            VaultCommand::List => vault::cmd_list()?,
            VaultCommand::Delete { label } => vault::cmd_delete(&label)?,
        },

        Command::Sign { dry_run: _, command: _ } => {
            println!("Sign command not yet implemented (PLO-56)");
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
