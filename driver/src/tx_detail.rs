//! `GET /tx/{hash}`: the transaction detail as the driver's OWN account may read it (iroha3 PLAN S18 window B, ANALYST Q16).
//!
//! One signed QUERY (`Client::get_transaction_details`, iroha@071e281e crates/iroha/src/query.rs:546) with the config's own
//! client.toml key: no transaction is submitted, no key material is read or returned, and nothing beyond what that key's query
//! returns is added. A bank driver therefore sees only its own view; when Torii refuses (permission, not found) the upstream
//! message is returned unchanged as a 502, never a filtered success. On the BI driver the same route reads everything BI may
//! read (CanReadAllLedgerData): it must sit behind BI's gateway OPA, allowed for the BI lens caller only (window B, mTLS).
//! Every call is logged by the server loop (`METHOD path -> status`).

use std::str::FromStr;

use eyre::{Result, ensure, eyre};
use iroha::data_model::transaction::TransactionEntrypoint;
use iroha_crypto::HashOf;

use crate::config::Config;

/// The entrypoint hash of the request path: exactly 64 hex characters, returned lower-case.
pub fn check_hash(text: &str) -> Result<String> {
    ensure!(text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()), "transaction hash must be exactly 64 hex characters");
    Ok(text.to_ascii_lowercase())
}

/// `{"hash": <hash>, "transaction": <the transaction JSON as Torii returned it>}`.
pub fn wrap(hash: &str, transaction_json: &str) -> String {
    format!(r#"{{"hash":"{hash}","transaction":{transaction_json}}}"#)
}

/// Run the signed query with the config's own account and return the JSON body of the 200 answer.
pub fn fetch(cfg: &Config, hash: &str) -> Result<String> {
    let hash = check_hash(hash)?;
    let entrypoint = HashOf::<TransactionEntrypoint>::from_str(&hash).map_err(|e| eyre!("transaction hash: {e}"))?;
    let config = iroha::config::Config::load_file(&cfg.client_toml).map_err(|e| eyre!("load {}: {e:?}", cfg.client_toml.display()))?;
    let client = iroha::client::Client::builder(config).build()?;
    let details = client.get_transaction_details(entrypoint).map_err(|e| eyre!("{e}"))?;
    let json = norito::json::to_json(&details.transaction).map_err(|e| eyre!("encode transaction: {e}"))?;
    Ok(wrap(&details.hash, &json))
}

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
