pub mod signing;
pub mod vault;

/// Zero-allocation error type for cryptographic operations.
/// Prevents information leakage — no file paths, key IDs, or internal details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
    #[error("key derivation failed")]
    KeyDerivationFailed,
    #[error("encryption failed")]
    EncryptionFailed,
}
