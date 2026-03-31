use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

const NONCE_SIZE: usize = 12;
const HKDF_SALT: &[u8] = b"atomic-v1";
const MAX_CIPHERTEXT_SIZE: usize = 16 * 1024 * 1024; // 16 MB

// HKDF with salt and "atomic-vault" context, so the vault key differs from the signing key.
pub fn derive_vault_key(private_key_bytes: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), private_key_bytes);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"atomic-vault", key.as_mut())
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
// Returns Zeroizing<Vec<u8>> so plaintext is wiped from memory on drop.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_SIZE {
        anyhow::bail!("Encrypted data too short");
    }
    if data.len() > MAX_CIPHERTEXT_SIZE {
        anyhow::bail!("Encrypted data too large");
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong key or corrupted data)"))
        .context("Vault decryption failed")?;

    Ok(Zeroizing::new(plaintext))
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
        assert_eq!(plaintext.as_slice(), &*decrypted);
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
        assert_ne!(*key, [0u8; 32]);
        let key2 = derive_vault_key(&private_key).unwrap();
        assert_eq!(*key, *key2);
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
    fn decrypt_oversized_rejected() {
        let key = [42u8; 32];
        let oversized = vec![0u8; MAX_CIPHERTEXT_SIZE + 1];
        let err = decrypt(&key, &oversized).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        let key = [42u8; 32];
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert!((*decrypted).is_empty());
    }

    #[test]
    fn derive_vault_key_differs_for_different_inputs() {
        let k1 = derive_vault_key(&[1u8; 32]).unwrap();
        let k2 = derive_vault_key(&[2u8; 32]).unwrap();
        assert_ne!(k1, k2);
    }
}
