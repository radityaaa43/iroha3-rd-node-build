//! `rd-dfabi keys client-toml`: derive a bank's OWN client.toml from its `<name>.seed` (iroha3 PLAN S17, docs/server-mode.md).
//!
//! The per-bank server (`server.rs`) signs with `Config.client_toml`, which holds the same ed25519 key as the seed (`signing_key`).
//! The bank derives that file in its own custody; the private key is written only into the 0600 file and never printed.

use std::{io::Write, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}};

use eyre::{Result, bail, ensure, eyre};
use iroha_crypto::ExposedPrivateKey;
use url::Url;

use crate::config::{read_seed, signing_key};

fn plain(label: &str, value: &str, allowed: impl Fn(char) -> bool) -> Result<()> {
    ensure!(!value.is_empty() && value.chars().all(allowed), "{label} {value:?} has characters outside the allowed set");
    Ok(())
}

/// client.toml text for the key of `seed`. Inputs are validated against a strict character set (no TOML injection).
pub fn render(seed: &[u8; 32], torii: &str, chain: &str, network_id_file: &str, domain: &str) -> Result<String> {
    let _ = (seed, torii, chain, network_id_file, domain);
    bail!("render: not implemented")
}

/// Read `<dir>/<name>.seed`, write `<dir>/client.toml` (mode 0600, never overwritten). Returns the path; nothing secret is printed.
pub fn write(dir: &Path, name: &str, torii: &str, chain: &str, network_id_file: &str, domain: &str) -> Result<PathBuf> {
    let seed = read_seed(&dir.join(format!("{name}.seed")))?;
    let text = render(&seed, torii, chain, network_id_file, domain)?;
    let path = dir.join("client.toml");
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
        .map_err(|e| eyre!("{}: {e} (never overwritten)", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, str::FromStr};

    use super::*;

    const SEED: [u8; 32] = [7; 32];
    const CHAIN: &str = "11111111-2222-4333-8444-555555555555";

    fn render_ok() -> String {
        render(&SEED, "http://bi-0.bi.rd-iroha3-bi.svc.cluster.local:8080/", CHAIN, "/genesis/genesis.expected_hash", "wonderland.universal").unwrap()
    }

    #[test]
    fn client_toml_parses_and_carries_the_seed_key() {
        let text = render_ok();
        let table: toml::Table = text.parse().unwrap();
        assert_eq!(table["chain"].as_str(), Some(CHAIN));
        assert_eq!(table["network_id_file"].as_str(), Some("/genesis/genesis.expected_hash"));
        assert_eq!(table["torii_url"].as_str(), Some("http://bi-0.bi.rd-iroha3-bi.svc.cluster.local:8080/"));
        let account = table["account"].as_table().unwrap();
        assert_eq!(account["domain"].as_str(), Some("wonderland.universal"));
        assert_eq!(account["public_key"].as_str().unwrap(), signing_key(&SEED).public_key().to_string());
        let private = ExposedPrivateKey::from_str(account["private_key"].as_str().unwrap()).unwrap();
        assert_eq!(private.0, *signing_key(&SEED).private_key(), "the file holds the key derived from the seed");
        assert_eq!(table["transaction"]["time_to_live_ms"].as_integer(), Some(600000));
    }

    #[test]
    fn a_different_seed_gives_a_different_key() {
        let other = render(&[8; 32], "http://t:8080/", CHAIN, "/g/h", "d").unwrap();
        assert_ne!(other, render(&SEED, "http://t:8080/", CHAIN, "/g/h", "d").unwrap());
    }

    #[test]
    fn unsafe_or_malformed_inputs_are_refused() {
        let ok = |t: &str, c: &str, n: &str, d: &str| render(&SEED, t, c, n, d);
        assert!(ok("http://t:8080/", CHAIN, "/g/h", "d").is_ok());
        for bad in ["ftp://t/", "not a url", "http://t:8080/\"x", "http://t:8080/\nx = 1", ""] {
            assert!(ok(bad, CHAIN, "/g/h", "d").is_err(), "torii {bad:?}");
        }
        for bad in ["", "chain\"", "x\ny", "zz zz"] {
            assert!(ok("http://t:8080/", bad, "/g/h", "d").is_err(), "chain {bad:?}");
        }
        for bad in ["", "/g/h\"", "/g h", "/g/h\n"] {
            assert!(ok("http://t:8080/", CHAIN, bad, "d").is_err(), "network id file {bad:?}");
        }
        for bad in ["", "d\"", "a b"] {
            assert!(ok("http://t:8080/", CHAIN, "/g/h", bad).is_err(), "domain {bad:?}");
        }
    }

    #[test]
    fn write_creates_a_0600_client_toml_next_to_the_seed_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-ct-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bi.seed"), hex::encode(SEED)).unwrap();
        let path = write(&dir, "bi", "http://t:8080/", CHAIN, "/g/h", "wonderland.universal").unwrap();
        assert_eq!(path, dir.join("client.toml"));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), render(&SEED, "http://t:8080/", CHAIN, "/g/h", "wonderland.universal").unwrap());
        assert!(write(&dir, "bi", "http://t:8080/", CHAIN, "/g/h", "wonderland.universal").is_err(), "second write must refuse");
        assert!(write(&dir, "missing", "http://t:8080/", CHAIN, "/g/h", "wonderland.universal").is_err(), "no seed, no file");
    }
}
