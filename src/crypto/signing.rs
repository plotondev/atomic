use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use super::CryptoError;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verify a signature. Used by the verify command (PLO-57) and in tests.
#[allow(dead_code)]
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

// Wire format: "ed25519:<base64 bytes>"
pub fn encode_public_key(verifying_key: &VerifyingKey) -> String {
    format!("ed25519:{}", Base64::encode_string(verifying_key.as_bytes()))
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey, CryptoError> {
    let b64 = encoded
        .strip_prefix("ed25519:")
        .ok_or(CryptoError::InvalidKey)?;
    // Stack-allocated decode: no heap allocation for 32-byte key.
    let mut buf = [0u8; 32];
    let decoded = Base64::decode(b64, &mut buf).map_err(|_| CryptoError::InvalidKey)?;
    if decoded.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    VerifyingKey::from_bytes(&buf).map_err(|_| CryptoError::InvalidKey)
}

pub fn encode_private_key(signing_key: &SigningKey) -> String {
    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    Base64::encode_string(&*key_bytes)
}

pub fn decode_private_key(encoded: &str) -> Result<SigningKey, CryptoError> {
    // Stack-allocated decode directly into Zeroizing — no intermediate Vec.
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    let decoded = Base64::decode(encoded, key_bytes.as_mut()).map_err(|_| CryptoError::InvalidKey)?;
    if decoded.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }
    Ok(SigningKey::from_bytes(&key_bytes))
}

pub fn encode_signature(signature: &Signature) -> String {
    Base64::encode_string(&signature.to_bytes())
}

#[allow(dead_code)]
pub fn decode_signature(encoded: &str) -> Result<Signature, CryptoError> {
    // Stack-allocated decode: no heap allocation for 64-byte signature.
    let mut buf = [0u8; 64];
    let decoded = Base64::decode(encoded, &mut buf).map_err(|_| CryptoError::InvalidSignature)?;
    if decoded.len() != 64 {
        return Err(CryptoError::InvalidSignature);
    }
    Ok(Signature::from_bytes(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"hello world";
        let signature = sign(&signing_key, message);
        assert!(verify(&verifying_key, message, &signature));
    }

    #[test]
    fn wrong_message_rejects() {
        let (signing_key, verifying_key) = generate_keypair();
        let signature = sign(&signing_key, b"hello world");
        assert!(!verify(&verifying_key, b"wrong message", &signature));
    }

    #[test]
    fn wrong_key_rejects() {
        let (signing_key, _) = generate_keypair();
        let (_, other_verifying_key) = generate_keypair();
        let signature = sign(&signing_key, b"hello world");
        assert!(!verify(&other_verifying_key, b"hello world", &signature));
    }

    #[test]
    fn public_key_encode_decode() {
        let (_, verifying_key) = generate_keypair();
        let encoded = encode_public_key(&verifying_key);
        assert!(encoded.starts_with("ed25519:"));
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(verifying_key, decoded);
    }

    #[test]
    fn private_key_encode_decode() {
        let (signing_key, _) = generate_keypair();
        let encoded = encode_private_key(&signing_key);
        let decoded = decode_private_key(&encoded).unwrap();
        assert_eq!(signing_key.to_bytes(), decoded.to_bytes());
    }

    #[test]
    fn signature_encode_decode() {
        let (signing_key, _) = generate_keypair();
        let signature = sign(&signing_key, b"test");
        let encoded = encode_signature(&signature);
        let decoded = decode_signature(&encoded).unwrap();
        assert_eq!(signature, decoded);
    }

    #[test]
    fn decode_public_key_missing_prefix() {
        assert!(decode_public_key("rsa:AAAA").is_err());
        assert!(decode_public_key("AAAA").is_err());
    }

    #[test]
    fn decode_public_key_invalid_base64() {
        assert!(decode_public_key("ed25519:not-valid!!!").is_err());
    }

    #[test]
    fn decode_public_key_wrong_length() {
        let short = Base64::encode_string(&[0u8; 16]); // 16 bytes, need 32
        assert!(decode_public_key(&format!("ed25519:{short}")).is_err());
    }

    #[test]
    fn decode_private_key_invalid_base64() {
        assert!(decode_private_key("not-valid!!!").is_err());
    }

    #[test]
    fn decode_private_key_wrong_length() {
        let short = Base64::encode_string(&[0u8; 16]);
        assert!(decode_private_key(&short).is_err());
    }

    #[test]
    fn decode_signature_wrong_length() {
        let short = Base64::encode_string(&[0u8; 32]); // 32 bytes, need 64
        assert!(decode_signature(&short).is_err());
    }

    #[test]
    fn sign_verify_empty_message() {
        let (sk, vk) = generate_keypair();
        let sig = sign(&sk, b"");
        assert!(verify(&vk, b"", &sig));
    }
}
