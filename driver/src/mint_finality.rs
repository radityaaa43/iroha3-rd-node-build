//! KAGEMUSHA mint-finality epoch keys, per organisation (iroha3 PLAN S2/S5, user decision "iroha A").
//!
//! Each org derives its OWN public triple from its OWN seed in its OWN custody; only the public triples are collected,
//! and `roster` builds the parameters file `kagami genesis generate --kagemusha-mint-finality-parameters` loads.
//! Derivation is `derive_kagemusha_mint_finality_validator_keys_v1(seed, epoch, PeerId)` of iroha_core at the pinned
//! iroha@071e281e; the same function with epoch N+1 and the same seed is the rotation route.
//! The seed is raw 32 bytes (the format a launcher hands the node, irohad/src/taira_runtime_signer.rs:434-442), mode 0600,
//! never printed.

use std::{
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    str::FromStr,
};

use eyre::{Result, bail, eyre};
use iroha::data_model::isi::kagemusha_v1::{
    KAGEMUSHA_CHAIN_VERSION_V1, KagemushaMintFinalityEpochRosterTemplateV1, KagemushaMintFinalityGenesisParametersV1,
    KagemushaMintFinalityValidatorKeysV1,
};
use iroha_core::zk::kagemusha_v1_recursion::{
    derive_kagemusha_mint_finality_validator_keys_v1, validate_kagemusha_mint_finality_genesis_parameter_keys_v1,
};
use iroha_crypto::{Algorithm, PublicKey};
use iroha_model_base::peer::PeerId;
use zeroize::Zeroizing;

fn seed_path(dir: &Path, name: &str) -> std::path::PathBuf {
    dir.join(format!("{name}.mint-finality.seed"))
}

/// Existing seed (exactly 32 raw bytes, mode 0600, non-zero) or a new one made with `create_new`: never overwritten.
fn load_or_create_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(mut file) => {
            let mut seed = Zeroizing::new([0u8; 32]);
            while seed.iter().all(|b| *b == 0) {
                *seed = rand::random();
            }
            file.write_all(&*seed)?;
            Ok(seed)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::metadata(path)?;
            if meta.len() != 32 || meta.permissions().mode() & 0o777 != 0o600 {
                bail!("{} must be exactly 32 raw bytes with mode 600", path.display());
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            std::fs::File::open(path)?.read_exact(&mut *seed)?;
            if seed.iter().all(|b| *b == 0) {
                bail!("{} holds an all-zero seed", path.display());
            }
            Ok(seed)
        }
        Err(error) => Err(error.into()),
    }
}

/// Create `<dir>/<name>.mint-finality.seed` if absent (32 random non-zero bytes, mode 0600), derive the public triple
/// for `peer` (a BLS public key) at `epoch`, and return it as JSON. Never returns or prints the seed.
pub fn mint_finality(dir: &Path, name: &str, peer: &str, epoch: u64) -> Result<String> {
    let key = PublicKey::from_str(peer).map_err(|error| eyre!("peer public key: {error}"))?;
    if key.algorithm() != Algorithm::BlsNormal {
        bail!("the peer key must be a BLS (bls_normal) public key, got {}", key.algorithm());
    }
    let seed = load_or_create_seed(&seed_path(dir, name))?;
    let keys = derive_kagemusha_mint_finality_validator_keys_v1(&seed, epoch, PeerId::new(key))
        .map_err(|error| eyre!("derive mint-finality keys: {error}"))?;
    Ok(norito::json::to_json_pretty(&keys)?)
}

/// Build the parameters file from the public triples of all peers: sorted by PeerId, epoch 0, no next epoch, validated.
pub fn roster(out: &Path, triples: &[&Path]) -> Result<()> {
    let mut validators = triples
        .iter()
        .map(|path| {
            let bytes = std::fs::read(path).map_err(|error| eyre!("read {}: {error}", path.display()))?;
            norito::json::from_slice::<KagemushaMintFinalityValidatorKeysV1>(&bytes)
                .map_err(|error| eyre!("{} is not a public triple: {error}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    validators.sort_by(|a, b| a.validator.cmp(&b.validator));
    let parameters = KagemushaMintFinalityGenesisParametersV1 {
        epoch_roster: KagemushaMintFinalityEpochRosterTemplateV1 { version: KAGEMUSHA_CHAIN_VERSION_V1, epoch: 0, validators },
        next_epoch_roster: None,
    };
    parameters.validate().map_err(|error| eyre!("invalid mint-finality roster: {error}"))?;
    validate_kagemusha_mint_finality_genesis_parameter_keys_v1(&parameters)
        .map_err(|error| eyre!("invalid mint-finality curve keys: {error}"))?;
    std::fs::write(out, norito::json::to_json_pretty(&parameters)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyPair;

    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-mf-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bls() -> PublicKey {
        KeyPair::random_with_algorithm(Algorithm::BlsNormal).public_key().clone()
    }

    fn seed_of(dir: &Path, name: &str) -> Zeroizing<[u8; 32]> {
        let bytes = std::fs::read(dir.join(format!("{name}.mint-finality.seed"))).unwrap();
        Zeroizing::new(bytes.try_into().expect("seed file is exactly 32 raw bytes"))
    }

    #[test]
    fn seed_is_32_nonzero_bytes_mode_0600_and_never_printed() {
        let dir = temp_dir();
        let pk = bls();
        let out = mint_finality(&dir, "bi", &pk.to_string(), 0).unwrap();
        let path = dir.join("bi.mint-finality.seed");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let seed = seed_of(&dir, "bi");
        assert!(seed.iter().any(|b| *b != 0), "seed must be non-zero");
        assert!(!out.contains(&hex::encode(*seed)), "the seed must not appear in the output");
    }

    #[test]
    fn public_triple_equals_the_pinned_upstream_derivation() {
        let dir = temp_dir();
        let pk = bls();
        let out = mint_finality(&dir, "bi", &pk.to_string(), 0).unwrap();
        let seed = seed_of(&dir, "bi");
        let want = derive_kagemusha_mint_finality_validator_keys_v1(&seed, 0, PeerId::new(pk)).unwrap();
        let got: KagemushaMintFinalityValidatorKeysV1 = norito::json::from_slice(out.as_bytes()).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn rerun_reuses_the_seed_and_epoch_n_plus_1_changes_only_the_keys() {
        let dir = temp_dir();
        let pk = bls();
        let e0 = mint_finality(&dir, "bi", &pk.to_string(), 0).unwrap();
        let seed0 = seed_of(&dir, "bi");
        assert_eq!(e0, mint_finality(&dir, "bi", &pk.to_string(), 0).unwrap(), "same seed, same epoch, same triple");
        assert_eq!(*seed0, *seed_of(&dir, "bi"), "the existing seed is never overwritten");
        let e1 = mint_finality(&dir, "bi", &pk.to_string(), 1).unwrap();
        assert_ne!(e0, e1, "epoch 1 is a different triple from the same seed");
    }

    #[test]
    fn a_non_bls_peer_key_is_refused() {
        let dir = temp_dir();
        let ed = KeyPair::random_with_algorithm(Algorithm::Ed25519).public_key().to_string();
        let err = mint_finality(&dir, "bi", &ed, 0).unwrap_err().to_string();
        assert!(err.contains("BLS"), "{err}");
        assert!(!dir.join("bi.mint-finality.seed").exists(), "no seed written for a refused key");
    }

    fn four_triples(dir: &Path) -> (Vec<std::path::PathBuf>, Vec<PublicKey>) {
        let mut files = vec![];
        let mut pks = vec![];
        for name in ["bi", "bank-a", "bank-b", "bank-c"] {
            let org = dir.join(name);
            std::fs::create_dir_all(&org).unwrap();
            let pk = bls();
            let json = mint_finality(&org, name, &pk.to_string(), 0).unwrap();
            let file = dir.join(format!("{name}.mint-finality-public.json"));
            std::fs::write(&file, json).unwrap();
            files.push(file);
            pks.push(pk);
        }
        (files, pks)
    }

    #[test]
    fn roster_is_sorted_by_peer_id_epoch_zero_valid_and_loadable() {
        let dir = temp_dir();
        let (files, _) = four_triples(&dir);
        let refs = files.iter().map(|f| f.as_path()).collect::<Vec<_>>();
        let out = dir.join("params.json");
        roster(&out, &refs).unwrap();
        let params: KagemushaMintFinalityGenesisParametersV1 = norito::json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(params.epoch_roster.version, KAGEMUSHA_CHAIN_VERSION_V1);
        assert_eq!(params.epoch_roster.epoch, 0);
        assert!(params.next_epoch_roster.is_none());
        let ids = params.epoch_roster.validators.iter().map(|v| v.validator.clone()).collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "roster sorted by PeerId");
        params.validate().unwrap();
        validate_kagemusha_mint_finality_genesis_parameter_keys_v1(&params).unwrap();
        // the order of the input files must not matter
        let mut rev = refs.clone();
        rev.reverse();
        let out2 = dir.join("params2.json");
        roster(&out2, &rev).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&out2).unwrap());
    }

    #[test]
    fn roster_refuses_three_triples_and_a_duplicate() {
        let dir = temp_dir();
        let (files, _) = four_triples(&dir);
        let refs = files.iter().map(|f| f.as_path()).collect::<Vec<_>>();
        assert!(roster(&dir.join("o1.json"), &refs[..3]).is_err(), "3 validators is not 3f+1");
        let dup = [refs[0], refs[0], refs[1], refs[2]];
        assert!(roster(&dir.join("o2.json"), &dup).is_err(), "a repeated validator");
    }
}
