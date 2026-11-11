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
    /// k-of-n audit policy (iroha3 PLAN S11). Absent = one auditor (`auditor_url`), one approval, the old behaviour.
    #[serde(default)]
    pub audit: Option<AuditSection>,
    /// Only the BI driver sets this (S18, K6): enables `mint` / `POST /mint` for RD and DFABI. Absent = refused.
    #[serde(default)]
    pub mint_enabled: bool,
}

/// `[audit]`: the auditors that must approve and how many.
#[derive(Debug, Deserialize)]
pub struct AuditSection {
    pub min_approvals: Option<usize>,
    /// host:port of each auditor (BI, org A, org B), the order of the policy's auditor list.
    pub auditor_urls: Option<Vec<String>>,
}

/// The validated policy: 1 <= k <= n, distinct auditors.
#[derive(Debug, PartialEq, Eq)]
pub struct AuditPolicy {
    pub min_approvals: usize,
    pub auditor_urls: Vec<String>,
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

    /// The audit policy from `[audit]`, or the single `auditor_url` with one approval when the section is absent.
    pub fn audit_policy(&self) -> Result<AuditPolicy> {
        let Some(section) = &self.audit else {
            return Ok(AuditPolicy { min_approvals: 1, auditor_urls: vec![self.auditor_url.clone()] });
        };
        let urls = section.auditor_urls.clone().ok_or_else(|| eyre!("[audit] needs auditor_urls"))?;
        let k = section.min_approvals.ok_or_else(|| eyre!("[audit] needs min_approvals"))?;
        eyre::ensure!(!urls.is_empty(), "[audit] auditor_urls is empty");
        eyre::ensure!((1..=urls.len()).contains(&k), "[audit] min_approvals {k} must be between 1 and the {} auditors", urls.len());
        let distinct: std::collections::BTreeSet<_> = urls.iter().collect();
        eyre::ensure!(distinct.len() == urls.len(), "[audit] auditor_urls has a duplicate");
        Ok(AuditPolicy { min_approvals: k, auditor_urls: urls })
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

    #[test]
    fn audit_policy_defaults_to_the_single_auditor_url_with_one_approval() {
        let policy = config("").audit_policy().unwrap();
        assert_eq!((policy.min_approvals, policy.auditor_urls), (1, vec!["a:1".to_owned()]));
    }

    #[test]
    fn policy_from_config_two_of_three_parses() {
        let cfg = config("[audit]\nmin_approvals = 2\nauditor_urls = [\"bi:8090\", \"a:8090\", \"b:8090\"]\n");
        let policy = cfg.audit_policy().unwrap();
        assert_eq!(policy.min_approvals, 2);
        assert_eq!(policy.auditor_urls, ["bi:8090", "a:8090", "b:8090"]);
    }

    #[test]
    fn policy_from_config_refuses_k_zero_k_above_n_no_auditor_and_duplicates() {
        for bad in [
            "[audit]\nmin_approvals = 0\nauditor_urls = [\"bi:8090\"]\n",
            "[audit]\nmin_approvals = 4\nauditor_urls = [\"bi:8090\", \"a:8090\", \"b:8090\"]\n",
            "[audit]\nmin_approvals = 1\nauditor_urls = []\n",
            "[audit]\nmin_approvals = 1\nauditor_urls = [\"bi:8090\", \"bi:8090\"]\n",
            "[audit]\nmin_approvals = 1\n",
        ] {
            assert!(config(bad).audit_policy().is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_auditor_identity_defaults_to_bi_auditor() {
        let cfg = config("");
        assert_eq!(cfg.auditor.key_name, "bi-auditor");
        assert_eq!(cfg.auditor_hybrid_path(), std::path::PathBuf::from("/k/bi-auditor.hybrid"));
    }

    #[test]
    fn an_org_auditor_names_its_own_key_files_and_acts_as_its_own_party() {
        let cfg = config(
            "party = \"bank-a\"\n[auditor]\nkey_name = \"bank-a-auditor\"\nlisten = \"0.0.0.0:8090\"\nstore_dir = \"/audit-store\"\nmax_rd = 1\nmax_dfabi = 1\nparties = []\n",
        );
        assert_eq!(cfg.auditor.key_name, "bank-a-auditor");
        assert_eq!(cfg.auditor_hybrid_path(), std::path::PathBuf::from("/k/bank-a-auditor.hybrid"));
        assert_eq!(cfg.acting_torii().unwrap().as_str(), "http://bank-a:8080/");
    }

    #[test]
    fn an_auditor_key_name_may_not_leave_the_key_dir() {
        for bad in ["../x", "a/b", "", ".hidden"] {
            let cfg = config(&format!("[auditor]\nkey_name = \"{bad}\"\nlisten = \"x\"\nstore_dir = \"/s\"\nmax_rd = 1\nmax_dfabi = 1\nparties = []\n"));
            assert!(cfg.auditor_key_name().is_err(), "{bad:?} must be refused");
        }
        assert_eq!(config("").auditor_key_name().unwrap(), "bi-auditor");
    }
}
