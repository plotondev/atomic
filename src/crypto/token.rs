use rand::RngCore;

// "dt_" prefix + 32 random bytes as hex = 67 chars total
pub fn generate_deposit_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("dt_{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_has_correct_format() {
        let token = generate_deposit_token();
        assert!(token.starts_with("dt_"));
        assert_eq!(token.len(), 67); // dt_ (3) + 64 hex chars
    }

    #[test]
    fn tokens_dont_repeat() {
        let t1 = generate_deposit_token();
        let t2 = generate_deposit_token();
        assert_ne!(t1, t2);
    }
}
