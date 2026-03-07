use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn atomic_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".atomic"))
}

pub fn credentials_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("credentials"))
}

pub fn agent_json_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("agent.json"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("vault.enc"))
}

pub fn deposits_log_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("deposits.log"))
}

pub fn tls_dir() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("tls"))
}

pub fn pid_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("atomic.pid"))
}

pub fn log_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("atomic.log"))
}

pub fn ensure_atomic_dir() -> Result<PathBuf> {
    let dir = atomic_dir()?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
    }
    Ok(dir)
}
