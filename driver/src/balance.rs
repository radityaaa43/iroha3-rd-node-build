#[cfg(test)]
mod tests {
    use super::*;

    const RD: &str = "7onbjg2gRXveoAAUFsohCZyGW98t";

    #[test]
    fn a_base58_asset_definition_id_is_accepted() {
        assert!(check_asset(RD).is_ok());
        assert!(check_asset("6TEAJqbb8oEPmLncoNiMRbLEK6tw").is_ok());
    }

    #[test]
    fn anything_else_is_refused_aliases_empty_garbage_and_path_tricks() {
        for bad in ["", "rd#wonderland.ds-rd", "xor#universal", "../x", "7onbj g2g", "0OIl", &format!("{RD}&account=x"), &format!("{RD}%00")] {
            assert!(check_asset(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_query_names_exactly_one_parameter_asset() {
        assert_eq!(asset_param("/balance?asset=abc").unwrap(), "abc");
        for bad in ["/balance", "/balance?", "/balance?asset=", "/balance?account=x", "/balance?asset=a&asset=b", "/balance?asset=a&account=x", "/balance?asset=a&", "/balance?asse=a"] {
            assert!(asset_param(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn wrap_puts_account_asset_and_the_unchanged_asset_json_in_one_object() {
        let body = wrap("acct", RD, r#"{"id":"x","value":"5"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({"account": "acct", "asset": RD, "balance": {"id": "x", "value": "5"}}));
    }
}
