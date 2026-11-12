//! `GET /balance?asset=<Base58 id>`: the balance of the driver's OWN account for one asset (iroha3 S18 / ANALYST Q16 pattern, same class as
//! `GET /tx`). ONE signed `FindAssetById` query (iroha@071e281e crates/iroha/src/query.rs `query_single`) with the config's own client.toml
//! key for its OWN account: the request can name only the asset, never an account; nothing is submitted, no key material is read or
//! returned, nothing is added to what the query returns, and an upstream refusal (e.g. a restricted dataspace the key may not read) is
//! returned unchanged as a 502. The keyless Torii routes show NO genesis asset state (empty lists), so this signed read is the way to
//! see a balance. On the BI driver the same query is BI's own view; a read-all view stays behind BI's gateway OPA (BI-lens caller only).

use std::str::FromStr;

use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    query::asset::prelude::FindAssetById,
};

use crate::config::Config;

/// A Base58 asset definition id (no alias, no separator): letters and digits only, and it must parse.
pub fn check_asset(text: &str) -> Result<AssetDefinitionId> {
    ensure!(!text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric()), "asset must be a Base58 asset definition id");
    AssetDefinitionId::from_str(text).map_err(|e| eyre!("asset {text:?}: {e}"))
}

/// The value of the one allowed query parameter `asset` from a request path like `/balance?asset=<id>`.
pub fn asset_param(path: &str) -> Result<String> {
    let (_, query) = path.split_once('?').ok_or_else(|| eyre!("missing ?asset=<Base58 asset id>"))?;
    let pairs: Vec<&str> = query.split('&').collect();
    ensure!(pairs.len() == 1, "exactly one query parameter, asset, is allowed");
    let (key, value) = pairs[0].split_once('=').ok_or_else(|| eyre!("missing ?asset=<Base58 asset id>"))?;
    ensure!(key == "asset" && !value.is_empty(), "the only query parameter is asset=<Base58 asset id>");
    Ok(value.to_owned())
}

/// `{"account": <own account>, "asset": <id>, "balance": <the asset as Torii returned it>}`.
pub fn wrap(account: &str, asset: &str, asset_json: &str) -> String {
    format!(r#"{{"account":"{account}","asset":"{asset}","balance":{asset_json}}}"#)
}

/// Run the signed query with the config's own account and return the JSON body of the 200 answer.
pub fn fetch(cfg: &Config, asset: &str) -> Result<String> {
    let definition = check_asset(asset)?;
    let config = iroha::config::Config::load_file(&cfg.client_toml).map_err(|e| eyre!("load {}: {e:?}", cfg.client_toml.display()))?;
    let account = AccountId::new(config.key_pair.public_key().clone());
    let client = iroha::client::Client::builder(config).build()?;
    // RD/DFABI: the `#dataspace:<home>` bucket (a Global id finds nothing); the fee asset: Global.
    let scope = crate::dvp_native::home_scope(cfg, &definition);
    let found = client.query_single(FindAssetById::new(AssetId::with_scope(definition, account.clone(), scope))).map_err(|e| eyre!("{e}"))?;
    let json = norito::json::to_json(&found).map_err(|e| eyre!("encode asset: {e}"))?;
    Ok(wrap(&account.to_string(), asset, &json))
}

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

    /// RD and DFABI balances sit in the `#dataspace:<home>` bucket; a Global id finds nothing (live: 404 "Failed to find
    /// asset" for every party after Applied mints; FindAssetById reads the exact key, iroha@071e281e isi/asset.rs:8217).
    #[test]
    fn the_query_names_the_scoped_bucket_not_the_global_one() {
        let src = include_str!("balance.rs");
        let fetch = &src[src.find("pub fn fetch").unwrap()..src.find("#[cfg(test)]").unwrap()];
        assert!(fetch.contains("AssetId::with_scope(") && fetch.contains("home_scope(cfg"), "fetch must query the scoped bucket");
        assert!(!fetch.contains("AssetId::new("), "a Global id never finds a DataspaceRestricted balance");
    }

    #[test]
    fn wrap_puts_account_asset_and_the_unchanged_asset_json_in_one_object() {
        let body = wrap("acct", RD, r#"{"id":"x","value":"5"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({"account": "acct", "asset": RD, "balance": {"id": "x", "value": "5"}}));
    }
}
