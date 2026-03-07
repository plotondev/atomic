use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

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
    format!("ed25519:{}", BASE64.encode(verifying_key.as_bytes()))
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey> {
    let b64 = encoded
        .strip_prefix("ed25519:")
        .context("Public key must start with 'ed25519:'")?;
    let bytes = BASE64.decode(b64).context("Invalid base64 in public key")?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes).context("Invalid Ed25519 public key")
}

pub fn encode_private_key(signing_key: &SigningKey) -> String {
    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    BASE64.encode(&*key_bytes)
}

pub fn decode_private_key(encoded: &str) -> Result<SigningKey> {
    let bytes = Zeroizing::new(BASE64.decode(encoded).context("Invalid base64 in private key")?);
    if bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes");
    }
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&key_bytes))
}

pub fn encode_signature(signature: &Signature) -> String {
    BASE64.encode(signature.to_bytes())
}

#[allow(dead_code)]
pub fn decode_signature(encoded: &str) -> Result<Signature> {
    let bytes = BASE64.decode(encoded).context("Invalid base64 in signature")?;
    let sig_bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    Ok(Signature::from_bytes(&sig_bytes))
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
        let short = BASE64.encode([0u8; 16]); // 16 bytes, need 32
        assert!(decode_public_key(&format!("ed25519:{short}")).is_err());
    }

    #[test]
    fn decode_private_key_invalid_base64() {
        assert!(decode_private_key("not-valid!!!").is_err());
    }

    #[test]
    fn decode_private_key_wrong_length() {
        let short = BASE64.encode([0u8; 16]);
        assert!(decode_private_key(&short).is_err());
    }

    #[test]
    fn decode_signature_wrong_length() {
        let short = BASE64.encode([0u8; 32]); // 32 bytes, need 64
        assert!(decode_signature(&short).is_err());
    }

    #[test]
    fn sign_verify_empty_message() {
        let (sk, vk) = generate_keypair();
        let sig = sign(&sk, b"");
        assert!(verify(&vk, b"", &sig));
    }
}
