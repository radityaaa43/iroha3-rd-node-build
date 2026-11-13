#[cfg(test)]
mod tests {
    use std::path::Path;

    use iroha::data_model::{
        account::AccountId,
        nexus::{PrivateSettlementAuditViewKeyAuthorizationV1, PrivateSettlementRouteV1},
    };
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    use super::*;

    fn config_in(dir: &Path) -> Config {
        let text = format!(
            r#"
chain = "c"
network_id_file = "/n"
account_domain = "d"
peers_json = "/p.json"
key_dir = "{}"
fee_asset = "f"
auditor_url = "a:1"
party = "bank-a"
[torii]
bi = "http://bi:8080"
bank-a = "http://bank-a:8080"
[assets]
rd = "r"
dfabi = "d"
[lanes]
rd = 1
dfabi = 2
"#,
            dir.display()
        );
        toml::from_str(&text).unwrap()
    }

    /// The prepared leg has no norito codec upstream (it is a native client-side value), so the wire form is `statement.proof.capsule`, each hex.
    #[test]
    fn a_prepared_leg_is_three_hex_parts_and_anything_else_is_refused() {
        for bad in ["", "ab", "ab.cd", "ab.cd.ef.01", "zz.zz.zz", "ab..cd", "abcd.abcd.abcd"] {
            assert!(decode_prepared(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn address_signs_output_zero_with_the_own_seed_and_the_one_time_recipient_keys() {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-aps-real-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bank-a.seed"), hex::encode([7u8; 32])).unwrap();
        let keys = NoteKeys { spend: [3; 32], view: [4; 32] };
        std::fs::write(dir.join("bank-a.note"), format!("{}{}", hex::encode(keys.spend), hex::encode(keys.view))).unwrap();
        let cfg = Mutex::new(config_in(&dir));
        let backend = RealBackend::new(&cfg);
        let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"aps-real-test")));
        let route = PrivateSettlementRouteV1 { dataspace_id: DataSpaceId::new(1), lane_id: LaneId::new(1), lane_incarnation: Hash::new(b"aps-real-test") };
        let (bundle, pool) = ([0xbb; 32], [0x01; 32]);
        let req = AddressReq {
            bundle_id: hex::encode(bundle),
            pool_id: hex::encode(pool),
            leg_ordinal: 0,
            route: enc(&route).unwrap(),
            expiry_height: 99,
            network_id: network_id.to_string(),
        };
        let answer = backend.address(&req).unwrap();
        let one_time = keys.one_time(&bundle, &pool, 0);
        assert_eq!(answer.authority, hex::encode(one_time.authority().unwrap()));
        assert_eq!(answer.view_public, hex::encode(one_time.view_public().unwrap()));
        let authorization: PrivateSettlementAuditViewKeyAuthorizationV1 = dec(&answer.authorization).unwrap();
        assert_eq!(authorization.body.authorized_account, AccountId::new(signing_key(&[7; 32]).public_key().clone()));
        assert_eq!((authorization.body.output_ordinal, authorization.body.leg_ordinal, authorization.body.expiry_height, authorization.body.output_active), (0, 0, 99, true));
        assert!(authorization.signatures.iter().any(|entry| entry.signature.verify(&entry.signer, &authorization.body).is_ok()), "signed by the own seed");
        assert_eq!(backend.own_key().unwrap(), signing_key(&[7; 32]).public_key().to_string());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn address_refuses_a_malformed_bundle_before_reading_any_key() {
        let cfg = Mutex::new(config_in(Path::new("/nonexistent")));
        let backend = RealBackend::new(&cfg);
        let req = AddressReq { bundle_id: "zz".into(), pool_id: hex::encode([1u8; 32]), leg_ordinal: 0, route: "0a".into(), expiry_height: 1, network_id: "x".into() };
        let error = format!("{:#}", backend.address(&req).unwrap_err());
        assert!(!error.contains(".seed") && !error.contains(".note"), "{error}");
    }
}
