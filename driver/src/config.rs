use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use eyre::{Result, WrapErr, eyre};
use iroha::blocking::Client;
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair};
use serde::Deserialize;
use url::Url;

/// One TOML file shared by the coordinator (`dvp`) and `bi-auditor`.
#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(skip)]
    pub path: PathBuf,
    pub chain: String,
    /// genesis.expected_hash (network id), as in client.toml.
    pub network_id_file: PathBuf,
    pub account_domain: String,
    /// Operator client.toml: the sponsor (CanEnactGovernance, holds the fee asset).
    /// Coordinator only; the auditor never reads it.
    #[serde(default)]
    pub client_toml: PathBuf,
    /// The party that runs this process: its Torii is the sponsor's submit target (iroha3 PLAN S10). Default `bi`, the
    /// old single-operator behaviour; each bank's own driver sets its own name.
    #[serde(default = "default_party")]
    pub party: String,
    /// network/public/peers.json: party, BLS public key and PoP of each validator.
    pub peers_json: PathBuf,
    /// Directory with `<name>.seed` files (hex, 32 bytes).
    pub key_dir: PathBuf,
    pub fee_asset: String,
    /// Long-lived pool index written by `pool-init` and appended by every finalized bundle.
    #[serde(default = "default_pools_file")]
    pub pools_file: PathBuf,
    /// host:port of bi-auditor.
    pub auditor_url: String,
    /// Party -> Torii base URL, all four validators.
    pub torii: BTreeMap<String, Url>,
    pub assets: Assets,
    pub lanes: Lanes,
    #[serde(default)]
    pub auditor: AuditorConfig,
    /// Only the BI driver sets this (S18, K6): enables `mint` / `POST /mint` for RD and DFABI. Absent = refused.
    #[serde(default)]
    pub mint_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct Assets {
    pub rd: String,
    pub dfabi: String,
}

/// Lane ids. Dataspace id equals lane id in network/nexus.toml (ds-rd 1, ds-dfabi 2).
#[derive(Debug, Deserialize)]
pub struct Lanes {
    pub rd: u32,
    pub dfabi: u32,
}

#[derive(Debug, Deserialize)]
pub struct AuditorConfig {
    pub listen: String,
    pub store_dir: PathBuf,
    pub max_rd: u128,
    pub max_dfabi: u128,
    /// Wallet public keys (`ed0120...`) accepted as payer or recipient.
    pub parties: Vec<String>,
}

impl Default for AuditorConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8090".into(),
            store_dir: "/audit-store".into(),
            max_rd: 1_000_000,
            max_dfabi: 10_000,
            parties: Vec::new(),
        }
    }
}

fn default_party() -> String {
    "bi".into()
}

fn default_pools_file() -> PathBuf {
    "/pools/pools.json".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        let mut config: Self = toml::from_str(&text).wrap_err("parse config")?;
        config.path = path.to_path_buf();
        Ok(config)
    }

    pub fn torii(&self, party: &str) -> Result<&Url> {
        self.torii.get(party).ok_or_else(|| eyre!("no torii for {party}"))
    }

    /// Torii of the acting party (`party`).
    pub fn acting_torii(&self) -> Result<&Url> {
        self.torii(&self.party)
    }

    /// Sponsor of a command = the acting party: its client.toml key, submitting to its OWN Torii.
    pub fn acting_sponsor(&self) -> Result<(Client, KeyPair)> {
        self.sponsor(&self.party)
    }

    /// Sponsor client (operator client.toml) bound to `party`'s Torii, plus its key.
    pub fn sponsor(&self, party: &str) -> Result<(Client, KeyPair)> {
        let mut config = iroha::config::Config::load_file(&self.client_toml)
            .map_err(|e| eyre!("load {}: {e:?}", self.client_toml.display()))?;
        config.torii_api_url = self.torii(party)?.clone();
        let key = config.key_pair.clone();
        Ok((Client::new(config)?, key))
    }

    /// Client whose account is `key` itself (the auditor: no operator key in its pod).
    pub fn client_with_key(&self, party: &str, key: &KeyPair) -> Result<Client> {
        let mut account = toml::Table::new();
        account.insert("domain".into(), self.account_domain.clone().into());
        account.insert(
            "private_key".into(),
            ExposedPrivateKey(key.private_key().clone()).to_string().into(),
        );
        account.insert("public_key".into(), key.public_key().to_string().into());
        let mut table = toml::Table::new();
        table.insert("chain".into(), self.chain.clone().into());
        table.insert(
            "network_id_file".into(),
            self.network_id_file.display().to_string().into(),
        );
        table.insert("torii_url".into(), self.torii(party)?.to_string().into());
        table.insert("account".into(), account.into());
        let config = iroha::config::Config::load_table(&self.path, table)
            .map_err(|e| eyre!("build client config: {e:?}"))?;
        Client::new(config)
    }

    /// `<key_dir>/<name>.note`: hex spend secret followed by hex view secret (64 bytes).
    pub fn note_keys(&self, name: &str) -> Result<crate::wallet::NoteKeys> {
        let path = self.key_dir.join(format!("{name}.note"));
        let text = std::fs::read_to_string(&path).wrap_err_with(|| format!("read {}", path.display()))?;
        let bytes = hex::decode(text.trim()).wrap_err("note key is not hex")?;
        eyre::ensure!(bytes.len() == 64, "{} is not 64 bytes", path.display());
        Ok(crate::wallet::NoteKeys { spend: bytes[..32].try_into()?, view: bytes[32..].try_into()? })
    }

    pub fn seed(&self, name: &str) -> Result<[u8; 32]> {
        read_seed(&self.key_dir.join(format!("{name}.seed")))
    }
}

pub fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let bytes = hex::decode(text.trim()).wrap_err("seed is not hex")?;
    bytes
        .try_into()
        .map_err(|_| eyre!("{} is not 32 bytes", path.display()))
}

/// Ed25519 key of a wallet or the auditor, derived from its seed.
pub fn signing_key(seed: &[u8; 32]) -> KeyPair {
    KeyPair::from_seed(seed.to_vec(), Algorithm::Ed25519)
}

#[cfg(test)]
mod tests {
    use super::*;

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
bank-a = "http://bank-a:8080"
bank-b = "http://bank-b:8080"
bank-c = "http://bank-c:8080"
[assets]
rd = "r"
dfabi = "d"
[lanes]
rd = 1
dfabi = 2
"#
        );
        toml::from_str(&text).unwrap()
    }

    #[test]
    fn the_acting_party_defaults_to_bi_so_existing_configs_keep_their_behaviour() {
        let cfg = config("");
        assert_eq!(cfg.party, "bi");
        assert_eq!(cfg.acting_torii().unwrap().as_str(), "http://bi:8080/");
    }

    #[test]
    fn sponsor_is_acting_party() {
        for party in ["bi", "bank-a", "bank-b", "bank-c"] {
            let cfg = config(&format!("party = \"{party}\""));
            assert_eq!(cfg.party, party);
            assert_eq!(cfg.acting_torii().unwrap().as_str(), format!("http://{party}:8080/"), "{party} submits to its OWN Torii");
        }
    }

    #[test]
    fn an_acting_party_without_a_torii_entry_is_an_error() {
        let cfg = config("party = \"bank-z\"");
        assert!(cfg.acting_torii().is_err());
    }

    /// No command may name BI's Torii for the sponsor again: the sponsor of a command is the acting party (iroha3 PLAN S10).
    #[test]
    fn no_command_hardcodes_the_bi_sponsor() {
        for (file, text) in [("aps.rs", include_str!("aps.rs")), ("pools.rs", include_str!("pools.rs"))] {
            assert!(!text.contains("sponsor(\"bi\")"), "{file} still calls cfg.sponsor(\"bi\")");
        }
    }
}
