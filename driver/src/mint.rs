#[cfg(test)]
mod tests {
    use iroha::data_model::{
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        isi::{InstructionBox, Mint},
    };
    use iroha_crypto::KeyPair;

    use super::*;
    use crate::config::{Config, signing_key};

    fn key(seed: u8) -> KeyPair {
        signing_key(&[seed; 32])
    }

    fn account(seed: u8) -> AccountId {
        AccountId::new(key(seed).public_key().clone())
    }

    /// Valid asset definition id literal (UUIDv4 bytes), distinct per `n`.
    fn asset_literal(n: u8) -> String {
        AssetDefinitionId::from_uuid_bytes([n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]).unwrap().to_string()
    }

    fn asset(n: u8) -> AssetDefinitionId {
        asset_literal(n).parse().unwrap()
    }

    /// Mint policy of a BI driver: assets 1 (cap 1000) and 2 (cap 50).
    fn policy() -> MintPolicy {
        MintPolicy { allowed: vec![(asset(1), 1000), (asset(2), 50)] }
    }

    /// Request terms for the account made from `seed`.
    fn terms(seed: u8, asset_id: &str, amount: &str) -> MintTerms {
        MintTerms { to: key(seed).public_key().to_string(), asset: asset_id.to_owned(), amount: amount.to_owned() }
    }

    #[test]
    fn check_mint_accepts_an_allowed_asset_within_its_cap() {
        let to = account(3);
        assert_eq!(check_mint(&terms(3, &asset_literal(1), "1000"), &policy()).unwrap(), (to.clone(), asset(1), 1000));
        assert_eq!(check_mint(&terms(3, &asset_literal(2), "1"), &policy()).unwrap(), (to, asset(2), 1));
    }

    #[test]
    fn check_mint_refuses_an_asset_that_is_not_in_the_policy() {
        assert!(check_mint(&terms(3, &asset_literal(9), "5"), &policy()).is_err());
    }

    #[test]
    fn check_mint_refuses_zero_non_numeric_and_over_cap_amounts() {
        for bad in ["0", "000", "", "abc", "-5", "+5", "1.5", "1e3", " 5", "0x10", "1001", "340282366920938463463374607431768211456"] {
            assert!(check_mint(&terms(3, &asset_literal(1), bad), &policy()).is_err(), "amount {bad:?} must be refused");
        }
        assert!(check_mint(&terms(3, &asset_literal(2), "51"), &policy()).is_err(), "the cap is per asset");
    }

    #[test]
    fn check_mint_refuses_a_bad_destination_and_a_bad_asset_literal() {
        let ok = terms(3, &asset_literal(1), "5");
        assert!(check_mint(&MintTerms { to: "not-a-key".to_owned(), ..ok.clone() }, &policy()).is_err());
        assert!(check_mint(&MintTerms { to: String::new(), ..ok.clone() }, &policy()).is_err());
        assert!(check_mint(&MintTerms { asset: "rd#wonderland.ds-rd".to_owned(), ..ok }, &policy()).is_err());
    }

    #[test]
    fn an_empty_policy_refuses_everything() {
        assert!(check_mint(&terms(3, &asset_literal(1), "1"), &MintPolicy { allowed: vec![] }).is_err());
    }

    #[test]
    fn build_mint_is_one_native_mint_of_the_amount_to_the_destinations_asset() {
        let to = account(3);
        let built = build_mint(&to, &asset(1), 250);
        assert_eq!(built, InstructionBox::from(Mint::asset_quantity(250u128, AssetId::new(asset(1), to))));
    }

    fn config(extra: &str) -> Config {
        let text = format!(
            r#"
chain = "c"
network_id_file = "/n"
account_domain = "d"
peers_json = "/p.json"
key_dir = "/k"
fee_asset = "f"
auditor_url = "a:1"
{extra}
[torii]
bi = "http://bi:8080"
[assets]
rd = "{}"
dfabi = "{}"
[lanes]
rd = 1
dfabi = 2
"#,
            asset_literal(1),
            asset_literal(2)
        );
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn policy_is_none_unless_the_config_enables_mint() {
        assert!(policy_of(&config("")).unwrap().is_none());
        assert!(policy_of(&config("mint_enabled = false")).unwrap().is_none());
    }

    #[test]
    fn policy_of_an_enabled_config_allows_exactly_rd_and_dfabi_up_to_the_auditor_caps() {
        let p = policy_of(&config("mint_enabled = true")).unwrap().unwrap();
        assert_eq!(p.allowed, vec![(asset(1), 1_000_000), (asset(2), 10_000)]);
    }

    #[test]
    fn an_enabled_config_with_an_unparsable_asset_is_an_error_not_a_silent_allow_all() {
        let mut c = config("mint_enabled = true");
        c.assets.rd = "rd#wonderland.ds-rd".to_owned();
        assert!(policy_of(&c).is_err());
    }
}
