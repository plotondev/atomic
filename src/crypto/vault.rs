use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

const NONCE_SIZE: usize = 12;

// HKDF with "atomic-vault" context, so the vault key differs from the signing key.
pub fn derive_vault_key(private_key_bytes: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, private_key_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"atomic-vault", &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

// Output: 12-byte nonce prepended to ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// Expects 12-byte nonce prepended to ciphertext (same format encrypt() produces).
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_SIZE {
        anyhow::bail!("Encrypted data too short");
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong key or corrupted data)"))
        .context("Vault decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"secret data here";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let encrypted = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let key = [42u8; 32];
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn derive_vault_key_is_deterministic() {
        let private_key = [1u8; 32];
        let key = derive_vault_key(&private_key).unwrap();
        assert_ne!(key, [0u8; 32]);
        let key2 = derive_vault_key(&private_key).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn decrypt_empty_data() {
        let key = [42u8; 32];
        assert!(decrypt(&key, &[]).is_err());
    }

    #[test]
    fn decrypt_too_short() {
        let key = [42u8; 32];
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = [42u8; 32];
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn derive_vault_key_differs_for_different_inputs() {
        let k1 = derive_vault_key(&[1u8; 32]).unwrap();
        let k2 = derive_vault_key(&[2u8; 32]).unwrap();
        assert_ne!(k1, k2);
    }
}
