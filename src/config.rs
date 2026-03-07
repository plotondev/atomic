use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Atomic write: write to .tmp, set perms, then rename into place.
    // Prevents race where another process reads with default permissions.
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, data)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&tmp_path, perms)
        .with_context(|| format!("Failed to set permissions on {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), path.display()))?;
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_secure_correct_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("atomic_test_ws_{}", std::process::id()));
        write_secure(&tmp, b"secret data").unwrap();
        let metadata = std::fs::metadata(&tmp).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&tmp).unwrap(), b"secret data");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn write_secure_no_tmp_leftover() {
        let tmp = std::env::temp_dir().join(format!("atomic_test_ws2_{}", std::process::id()));
        write_secure(&tmp, b"data").unwrap();
        assert!(!tmp.with_extension("tmp").exists());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn atomic_dir_under_home() {
        let dir = atomic_dir().unwrap();
        let home = dirs::home_dir().unwrap();
        assert!(dir.starts_with(&home));
        assert!(dir.ends_with(".atomic"));
    }
}
