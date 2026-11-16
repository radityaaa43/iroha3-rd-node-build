//! The coordinator's bundles in flight, one JSON file each in `<pools file dir>/inflight/`, so a restarted driver carries every
//! one to its end (`pools::resume`, task 6 / design 4.5).
//!
//! Public material only: the bundle id, its two pools, the manifest, the proved legs (proofs, public statements and audit
//! capsules already encrypted to the auditors) and the last phase the nodes made durable. No seed, note key, witness, amount,
//! party or asset (official docs: secret witnesses never go into durable coordination records). No certificate either: a
//! resumed bundle recovers its Prepare and Commit certificates from the nodes (`recover_or_*`), never from a local file.

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use eyre::Result;
use serde::{Deserialize, Serialize};

use crate::{config::Config, pools::PoolKey};

/// The last phase the nodes made durable. Ordered: a bundle runs the phases after its own.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// Legs proved; nothing is known to be uploaded and nothing is reserved yet.
    Proved,
    /// Every leg uploaded; `manifest` is the final one (availability certificate digests filled in).
    Uploaded,
    /// The Prepare registration is applied: Prepare certificates are durable on the nodes and both pools are reserved.
    Registered,
    /// Commit certificates are durable on the nodes; the finalization carrier may be in flight.
    Committed,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Inflight {
    pub bundle_id: String,
    pub keys: [PoolKey; 2],
    /// norito hex of `AtomicPrivateSettlementV1`.
    pub manifest: String,
    /// Each leg as `aps_real::encode_prepared` writes it (`statement.proof.capsule`, hex).
    pub prepared: Vec<String>,
    pub phase: Phase,
}

/// `<pools file dir>/inflight`.
pub fn dir(cfg: &Config) -> PathBuf {
    cfg.pools_file.with_file_name("inflight")
}

/// Write through a temp file + rename: a crash leaves the previous phase, never half a file.
pub fn save(dir: &Path, f: &Inflight) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let file = dir.join(format!("{}.json", f.bundle_id));
    let tmp = file.with_extension("json.tmp");
    let mut out = std::fs::File::create(&tmp)?;
    out.write_all(serde_json::to_string(f)?.as_bytes())?;
    out.sync_all()?;
    std::fs::rename(&tmp, &file)?;
    // The rename itself survives a power loss only once the directory is synced.
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Every bundle a previous run left in flight. The temp file of an interrupted save is skipped, and so is a file that cannot be read
/// (logged by name only): one damaged file must not keep the other bundles from resuming.
pub fn load_all(dir: &Path) -> Result<Vec<Inflight>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            match std::fs::read_to_string(&path).ok().and_then(|text| serde_json::from_str(&text).ok()) {
                Some(f) => all.push(f),
                None => eprintln!("inflight: skipping unreadable {}", path.file_name().unwrap_or_default().to_string_lossy()),
            }
        }
    }
    Ok(all)
}

/// The bundle has an end on record: it is no longer in flight. Removing a bundle that is not listed is not an error.
pub fn remove(dir: &Path, id: &str) -> Result<()> {
    match std::fs::remove_file(dir.join(format!("{id}.json"))) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::{Cell, RefCell};

    use iroha::{
        client::PrivateSettlementLifecycleDtoV1,
        data_model::{
            account::AccountId,
            nexus::{AtomicPrivateSettlementV1, PrivateSettlementAbortReasonV1, PrivateSettlementRouteV1},
        },
    };
    use iroha_crypto::{Hash, HybridKeyPair};
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    use super::*;
    use crate::{
        aps::{
            EXPIRY_BLOCKS, Leg, LegNotes, Nodes, Spend, bounded_fee_for, committee_authority, continue_bundle, enc, fixture_key,
            funding, govern, on_big_stack, prepare_leg, proof_manifest, rnd, test_manifest,
        },
        aps_real::encode_prepared,
        config::signing_key,
        pools::Asset,
    };

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("rd-dfabi-inflight-{}", rand::random::<u64>()))
    }

    /// A real proved leg goes into the in-flight file; nothing that file holds names a seed, a note key, the amount or a party.
    #[test]
    fn inflight_roundtrip_has_no_secrets() {
        let route = |lane: u32| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(lane)),
            lane_id: LaneId::new(lane),
            lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
        };
        let peers = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/peers.json"));
        let (authority, _) = committee_authority(peers, route(1)).unwrap();
        let network_id = iroha::data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(
            b"rd-dfabi-selftest-network",
        )));
        let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
        let encryption = iroha::data_model::nexus::PrivateSettlementHybridPublicKeyV1::from_hybrid(HybridKeyPair::generate(&mut rng).unwrap().public());
        let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
            .into_iter()
            .map(|(lane, asset)| govern(route(lane), asset.parse().unwrap(), 100, 100 + EXPIRY_BLOCKS, fixture_key(0x30).public_key(), &encryption).unwrap())
            .collect::<Vec<_>>();
        let sponsor = fixture_key(0x31);
        let salt = rnd();
        let manifest = proof_manifest(
            network_id,
            101,
            100 + EXPIRY_BLOCKS,
            AccountId::new(sponsor.public_key().clone()),
            bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw").unwrap(),
            &governed,
            salt,
        )
        .unwrap();
        // Amounts no hex string carries by chance.
        let (funded, amount) = (1_234_567_890_123u128, 987_654_321u128);
        let (payer_seed, recipient_seed) = ([0x52; 32], [0x53; 32]);
        let leg = Leg {
            lane: 1,
            asset: governed[0].governance.body.asset_definition_id.clone(),
            payer: signing_key(&payer_seed),
            recipient: signing_key(&recipient_seed),
            funding: funded,
            amount,
        };
        let notes = LegNotes::random();
        let source = funding(funded).unwrap();
        let spend_secret = source.spending_secret;
        let authority_digest = authority.digest().unwrap();
        let prepared = on_big_stack(|| {
            prepare_leg(0, &leg, &governed[0], Spend::Bootstrap(source), &notes, &manifest, authority_digest, &sponsor, salt)
        })
        .unwrap();
        let f = Inflight {
            bundle_id: hex::encode(manifest.bundle_id.as_ref()),
            keys: [PoolKey { lane: 1, asset: Asset::Rd }, PoolKey { lane: 2, asset: Asset::Dfabi }],
            manifest: enc(&manifest).unwrap(),
            prepared: vec![encode_prepared(&prepared).unwrap()],
            phase: Phase::Registered,
        };
        let dir = temp_dir();
        save(&dir, &f).unwrap();
        assert_eq!(load_all(&dir).unwrap(), vec![f.clone()]);

        let text = std::fs::read_to_string(dir.join(format!("{}.json", f.bundle_id))).unwrap().to_lowercase();
        let party = |key: &iroha_crypto::KeyPair| [key.public_key().to_string(), AccountId::new(key.public_key().clone()).to_string()];
        let mut secrets = vec![hex::encode(payer_seed), hex::encode(recipient_seed), hex::encode(spend_secret), amount.to_string(), funded.to_string()];
        for keys in [&notes.recipient, &notes.change, &notes.sponsor] {
            secrets.extend([hex::encode(keys.spend), hex::encode(keys.view)]);
        }
        secrets.extend(party(&leg.payer));
        secrets.extend(party(&leg.recipient));
        for secret in secrets {
            // A key's string form starts with its multihash prefix; its key bytes alone must not appear either.
            let secret = secret.to_lowercase();
            let bare = secret.strip_prefix("ed0120").unwrap_or(&secret);
            assert!(!text.contains(bare), "the in-flight file carries {secret}");
        }

        remove(&dir, &f.bundle_id).unwrap();
        remove(&dir, &f.bundle_id).unwrap();
        assert!(load_all(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A fake chain: every call in order, and how many carriers (registration, finalization, abort) were submitted.
    pub(crate) struct FakeNodes {
        pub status: Option<PrivateSettlementLifecycleDtoV1>,
        pub calls: RefCell<Vec<&'static str>>,
        pub carriers: Cell<usize>,
        /// The nodes no longer hold a Prepare certificate and the bundle is past its expiry.
        pub expired: bool,
        /// Torii refuses the finalization carrier (an earlier run's one is already queued).
        pub finalize_fails: bool,
    }

    impl FakeNodes {
        pub(crate) fn new(status: Option<PrivateSettlementLifecycleDtoV1>) -> Self {
            Self { status, calls: RefCell::default(), carriers: Cell::new(0), expired: false, finalize_fails: false }
        }

        fn call(&self, name: &'static str) {
            self.calls.borrow_mut().push(name);
        }

        fn carrier(&self, name: &'static str) {
            self.call(name);
            self.carriers.set(self.carriers.get() + 1);
        }
    }

    impl Nodes for FakeNodes {
        type Barrier = ();
        type Commits = ();

        fn status(&self, _manifest: &AtomicPrivateSettlementV1) -> Option<PrivateSettlementLifecycleDtoV1> {
            self.status
        }

        fn upload(&self, provisional: &AtomicPrivateSettlementV1) -> Result<AtomicPrivateSettlementV1> {
            self.call("upload");
            Ok(provisional.clone())
        }

        fn audited(&self, _manifest: &AtomicPrivateSettlementV1) -> Result<bool> {
            self.call("audit");
            Ok(true)
        }

        fn prepare(&self, _manifest: &AtomicPrivateSettlementV1) -> Result<()> {
            self.call("prepare");
            if self.expired { Err(eyre::eyre!("no Prepare quorum")) } else { Ok(()) }
        }

        fn register(&self, _barrier: &()) -> Result<()> {
            self.carrier("register");
            Ok(())
        }

        fn commit(&self, _barrier: &()) -> Result<()> {
            self.call("commit");
            Ok(())
        }

        fn finalize(&self, _barrier: &(), _commits: &()) -> Result<String> {
            if self.finalize_fails {
                self.call("finalize refused");
                eyre::bail!("a finalization is already queued");
            }
            self.carrier("finalize");
            Ok("finalize-tx".to_owned())
        }

        fn abort(&self, _manifest: &AtomicPrivateSettlementV1, reason: PrivateSettlementAbortReasonV1) -> Result<String> {
            if self.expired && reason != PrivateSettlementAbortReasonV1::Expired {
                self.call("abort refused");
                eyre::bail!("past expiry");
            }
            self.carrier("abort");
            Ok("abort-tx".to_owned())
        }

        fn receipt(&self, _manifest: &AtomicPrivateSettlementV1) -> Result<(&'static str, u64)> {
            Ok((if self.calls.borrow().contains(&"abort") { "aborted" } else { "finalized" }, 7))
        }
    }

    /// Run `continue_bundle` from `phase` on `nodes`; returns the outcome and the phases saved.
    fn resume(nodes: &FakeNodes, phase: Phase) -> (Option<(&'static str, String, u64)>, Vec<Phase>) {
        let mut saved = Vec::new();
        let ended = continue_bundle(nodes, test_manifest(), phase, &Cell::new(false), &mut |phase, _| {
            saved.push(phase);
            Ok(())
        })
        .unwrap();
        (ended.map(|s| (s.outcome, s.carrier_tx, s.height)), saved)
    }

    /// Restart after the Prepare registration: the Prepare and Commit certificates come from the nodes again and only the
    /// finalization carrier is submitted (a second registration would conflict with the applied one).
    #[test]
    fn resume_after_registration_submits_one_carrier() {
        let nodes = FakeNodes::new(Some(PrivateSettlementLifecycleDtoV1::Prepared));
        let (ended, saved) = resume(&nodes, Phase::Registered);
        assert_eq!(nodes.carriers.get(), 1);
        assert_eq!(*nodes.calls.borrow(), ["prepare", "commit", "finalize"]);
        assert_eq!(saved, [Phase::Committed]);
        assert_eq!(ended, Some(("finalized", "finalize-tx".to_owned(), 7)));
    }

    /// A bundle resumed after its expiry (no Prepare quorum left) still gets a terminal record: the `Expired` abort marker.
    #[test]
    fn a_bundle_resumed_past_its_expiry_is_aborted_as_expired() {
        let nodes = FakeNodes { expired: true, ..FakeNodes::new(Some(PrivateSettlementLifecycleDtoV1::Prepared)) };
        let aborted = Cell::new(false);
        let error = continue_bundle(&nodes, test_manifest(), Phase::Registered, &aborted, &mut |_, _| Ok(())).err().unwrap();
        assert!(error.to_string().contains("no Prepare quorum"), "{error:#}");
        assert!(aborted.get(), "the bundle ended aborted: nothing moved, nothing stays reserved");
        assert_eq!(*nodes.calls.borrow(), ["prepare", "abort refused", "abort"]);
    }

    /// Restart after the Commit: the finalization an earlier run queued lands. A refused resubmit reads the receipt first, so the
    /// bundle is recorded finalized and no abort races it.
    #[test]
    fn a_refused_finalization_on_resume_reads_the_receipt_before_aborting() {
        let nodes = FakeNodes { finalize_fails: true, ..FakeNodes::new(Some(PrivateSettlementLifecycleDtoV1::CommitCertified)) };
        let (ended, saved) = resume(&nodes, Phase::Committed);
        assert_eq!(ended, Some(("finalized", String::new(), 7)));
        assert_eq!(nodes.carriers.get(), 0, "no abort carrier: {:?}", nodes.calls.borrow());
        assert_eq!(*nodes.calls.borrow(), ["prepare", "commit", "finalize refused"]);
        assert!(saved.is_empty());
    }

    /// A zero-length file (a crash mid-write on a filesystem that lost the data) is skipped; the other bundles still resume.
    #[test]
    fn an_unreadable_inflight_file_is_skipped() {
        let dir = temp_dir();
        let good = Inflight {
            bundle_id: "ab".repeat(32),
            keys: [PoolKey { lane: 1, asset: Asset::Rd }, PoolKey { lane: 2, asset: Asset::Dfabi }],
            manifest: "00".into(),
            prepared: Vec::new(),
            phase: Phase::Uploaded,
        };
        save(&dir, &good).unwrap();
        std::fs::write(dir.join(format!("{}.json", "cd".repeat(32))), "").unwrap();
        assert_eq!(load_all(&dir).unwrap(), vec![good]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resume_follows_the_saved_phase_and_the_nodes() {
        // The nodes already ended it: only its end is read, nothing is submitted.
        let nodes = FakeNodes::new(Some(PrivateSettlementLifecycleDtoV1::Finalized));
        let (ended, _) = resume(&nodes, Phase::Committed);
        assert_eq!((nodes.carriers.get(), nodes.calls.borrow().len()), (0, 0));
        assert_eq!(ended, Some(("finalized", String::new(), 7)), "the carrier tx of an earlier run is not known");
        // Never prepared: nothing reserved, nothing to do on the chain.
        let nodes = FakeNodes::new(None);
        assert_eq!(resume(&nodes, Phase::Proved), (None, Vec::new()));
        assert!(nodes.calls.borrow().is_empty());
        // Uploaded: audit, prepare, register, commit, finalize; two carriers.
        let nodes = FakeNodes::new(Some(PrivateSettlementLifecycleDtoV1::Collecting));
        let (_, saved) = resume(&nodes, Phase::Uploaded);
        assert_eq!(*nodes.calls.borrow(), ["audit", "prepare", "register", "commit", "finalize"]);
        assert_eq!((nodes.carriers.get(), saved), (2, vec![Phase::Registered, Phase::Committed]));
    }
}
