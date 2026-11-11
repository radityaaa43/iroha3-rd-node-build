#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_hash_accepts_exactly_64_hex_characters_and_lowercases_them() {
        let lower = "ab".repeat(32);
        assert_eq!(check_hash(&lower).unwrap(), lower);
        assert_eq!(check_hash(&"AB".repeat(32)).unwrap(), lower);
        assert_eq!(check_hash(&format!("{}{}", "0123456789abcdef".repeat(3), "0123456789ABCDEF")).unwrap(), "0123456789abcdef".repeat(4));
    }

    #[test]
    fn check_hash_refuses_everything_else() {
        let ok = "ab".repeat(32);
        for bad in [
            "".to_owned(),
            "ab".repeat(31),
            "ab".repeat(33),
            format!("0x{}", &ok[2..]),
            format!("{}zz", &ok[2..]),
            format!("../{}", &ok[3..]),
            format!("{ok}?x=1"),
            format!(" {}", &ok[1..]),
            "é".repeat(32),
        ] {
            assert!(check_hash(&bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn wrap_puts_the_hash_and_the_unchanged_transaction_json_in_one_object() {
        let hash = "cd".repeat(32);
        let body = wrap(&hash, r#"{"result":{"Ok":[]},"n":1}"#);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({"hash": hash, "transaction": {"result": {"Ok": []}, "n": 1}}));
    }
}
