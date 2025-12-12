use crate::state::HmacKey;
use subtle::ConstantTimeEq;

pub fn compute_code_hmac(key: &HmacKey, code: &str) -> String {
    // Clone the key and use it
    use hmac::Mac;
    let mut mac = key.clone();
    mac.update(code.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

pub fn verify_code_hmac(key: &HmacKey, code: &str, expected_hmac: &str) -> bool {
    let computed = compute_code_hmac(key, code);
    let computed_bytes = hex::decode(&computed).unwrap_or_default();
    let expected_bytes = hex::decode(expected_hmac).unwrap_or_default();

    // Constant-time comparison
    computed_bytes.ct_eq(&expected_bytes).into()
}

pub fn get_code_hmac_prefix(hmac: &str, length: usize) -> String {
    hmac.chars().take(length).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;

    #[test]
    fn test_hmac_computation() {
        use crate::state::HmacKey;
        let key: HmacKey = Hmac::<Sha256>::new_from_slice(b"test_key").unwrap();
        let code = "123456";
        let hmac1 = compute_code_hmac(&key, code);
        let hmac2 = compute_code_hmac(&key, code);

        assert_eq!(hmac1, hmac2);
        assert!(!hmac1.is_empty());
    }

    #[test]
    fn test_hmac_verification() {
        use crate::state::HmacKey;
        let key: HmacKey = Hmac::<Sha256>::new_from_slice(b"test_key").unwrap();
        let code = "123456";
        let hmac = compute_code_hmac(&key, code);

        assert!(verify_code_hmac(&key, code, &hmac));
        assert!(!verify_code_hmac(&key, "654321", &hmac));
    }

    #[test]
    fn test_prefix_extraction() {
        let hmac = "abcdef1234567890";
        assert_eq!(get_code_hmac_prefix(hmac, 3), "abc");
        assert_eq!(get_code_hmac_prefix(hmac, 6), "abcdef");
    }
}
