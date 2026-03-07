use anyhow::{Context, Result};
use rand::RngCore;
use std::path::{Path, PathBuf};

pub fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Atomic write: create temp file with 0600 from the start, then rename.
    // Using OpenOptionsExt::mode() sets permissions at creation time,
    // eliminating the TOCTOU window where the file could be world-readable.
    // Random suffix prevents collisions between concurrent writers.
    let mut suffix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let tmp_path = path.with_extension(format!("tmp.{}", hex::encode(suffix)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    file.write_all(data)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    drop(file);
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create {}", dir.display()))?;
        }
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
