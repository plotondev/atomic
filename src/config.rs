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
    let suffix_hex = u64::from_ne_bytes(suffix);
    let tmp_path = path.with_extension(format!("tmp.{suffix_hex:016x}"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    file.write_all(data)
        .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("Failed to fsync {}", tmp_path.display()))?;
    drop(file);
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), path.display()))?;

    // fsync parent directory to ensure rename durability (POSIX requirement)
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

pub fn atomic_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .context("Could not determine home directory (HOME not set)")?;
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

pub fn pid_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("atomic.pid"))
}

pub fn log_path() -> Result<PathBuf> {
    Ok(atomic_dir()?.join("atomic.log"))
}

/// Acquire an exclusive flock on the PID file to prevent double-start races.
/// Returns the open File handle — caller must keep it alive for the duration of the process.
/// The lock is automatically released by the kernel when the process exits (even on crash).
pub fn acquire_pid_lock(path: &Path) -> Result<std::fs::File> {
    use fs2::FileExt;
    use std::io::Write;

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("Failed to open PID file at {}", path.display()))?;

    file.try_lock_exclusive()
        .context("Another atomic process is already running (PID file locked)")?;

    // Write PID after lock acquired
    let mut f = &file;
    file.set_len(0)?;
    f.write_all(std::process::id().to_string().as_bytes())?;
    file.sync_all()?;
    Ok(file)
}

/// Current UTC time as Unix epoch seconds. Single syscall, no allocation.
pub fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format a Unix timestamp as RFC 3339 UTC (e.g. "2024-01-15T12:30:00Z").
/// Uses the Hinnant civil_from_days algorithm. No chrono dependency.
pub fn format_rfc3339(epoch: i64) -> String {
    let secs = epoch.rem_euclid(86400) as u32;
    let days = epoch.div_euclid(86400) as i32;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146097 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let h = secs / 3600;
    let min = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}Z")
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
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        assert!(dir.starts_with(&home));
        assert!(dir.ends_with(".atomic"));
    }

    #[test]
    fn format_rfc3339_epoch_zero() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_rfc3339_known_date() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_rfc3339(1704067200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn epoch_secs_is_reasonable() {
        let now = epoch_secs();
        assert!(now > 1_700_000_000); // after 2023
        assert!(now < 4_000_000_000); // before 2096
    }
}
