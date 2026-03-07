use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::crypto::vault as crypto_vault;

// Labeled key-value secrets, encrypted as a single blob on disk.
pub struct VaultStore {
    secrets: BTreeMap<String, String>,
    vault_key: [u8; 32],
}

impl VaultStore {
    pub fn new(private_key_bytes: Vec<u8>) -> Self {
        let vault_key = crypto_vault::derive_vault_key(&private_key_bytes)
            .expect("Key derivation should not fail");
        Self {
            secrets: BTreeMap::new(),
            vault_key,
        }
    }

    pub fn load(path: &Path, private_key_bytes: &[u8]) -> Result<Self> {
        let vault_key = crypto_vault::derive_vault_key(private_key_bytes)?;
        let encrypted = std::fs::read(path)
            .with_context(|| format!("Failed to read vault at {}", path.display()))?;

        if encrypted.is_empty() {
            return Ok(Self {
                secrets: BTreeMap::new(),
                vault_key,
            });
        }

        let plaintext = crypto_vault::decrypt(&vault_key, &encrypted)?;
        let secrets: BTreeMap<String, String> =
            serde_json::from_slice(&plaintext).context("Failed to parse vault contents")?;

        Ok(Self { secrets, vault_key })
    }

    // Write to .tmp then rename, so a crash mid-write doesn't corrupt the vault.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec(&self.secrets).context("Failed to serialize vault")?;
        let encrypted = crypto_vault::encrypt(&self.vault_key, &json)?;

        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &encrypted)
            .with_context(|| format!("Failed to write {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("Failed to rename {} to {}", tmp_path.display(), path.display()))?;

        Ok(())
    }

    pub fn set(&mut self, label: String, value: String) {
        self.secrets.insert(label, value);
    }

    pub fn get(&self, label: &str) -> Option<&str> {
        self.secrets.get(label).map(|s| s.as_str())
    }

    pub fn delete(&mut self, label: &str) -> bool {
        self.secrets.remove(label).is_some()
    }

    pub fn labels(&self) -> Vec<&str> {
        self.secrets.keys().map(|s| s.as_str()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }
}

pub fn load_vault() -> Result<(VaultStore, std::path::PathBuf)> {
    let creds = crate::credentials::Credentials::load(&crate::config::credentials_path()?)?;
    let signing_key = creds.signing_key()?;
    let vault_path = crate::config::vault_path()?;
    let store = VaultStore::load(&vault_path, &signing_key.to_bytes())?;
    Ok((store, vault_path))
}

pub fn cmd_set(label: &str, value: &str) -> Result<()> {
    let (mut store, vault_path) = load_vault()?;
    store.set(label.to_string(), value.to_string());
    store.save(&vault_path)?;
    println!("Stored '{}'", label);
    Ok(())
}

pub fn cmd_get(label: &str) -> Result<()> {
    let (store, _) = load_vault()?;
    match store.get(label) {
        Some(value) => {
            print!("{}", value); // no trailing newline, so it works in $()
            Ok(())
        }
        None => bail!("Label '{}' not found in vault", label),
    }
}

pub fn cmd_list() -> Result<()> {
    let (store, _) = load_vault()?;
    if store.is_empty() {
        println!("Vault is empty");
        return Ok(());
    }
    for label in store.labels() {
        println!("{}", label);
    }
    Ok(())
}

pub fn cmd_delete(label: &str) -> Result<()> {
    let (mut store, vault_path) = load_vault()?;
    if store.delete(label) {
        store.save(&vault_path)?;
        println!("Deleted '{}'", label);
    } else {
        bail!("Label '{}' not found in vault", label);
    }
    Ok(())
}
