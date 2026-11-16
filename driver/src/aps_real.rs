//! The real `ApsBackend` of a driver (plan 2026-11-13-04, task T2): keys, pools and chain, on the driver's own config.
//!
//! Party side: `address` signs the output-0 authorization with the own seed (`aps_split::sign_output_key`) and `prove_leg` proves
//! the own leg alone (`pools::prove_split_leg`, `aps_split::prepare_leg_split`). Coordinator side (BI): `begin_bundle`,
//! `sponsor_output` and `settle` (`aps::settle`). Nothing here reads another party's key.


use eyre::{Result, bail, eyre};
use iroha::data_model::{
    NetworkId,
    nexus::{AtomicPrivateSettlementV1, PrivateSettlementAuditOutputRoleV1},
};
use iroha_core::privacy_engines::atomic_private_settlement::{
    AtomicPrivateSettlementPreparedLegV1, AtomicPrivateSettlementPreparedProofV1, complete_atomic_private_settlement_prepared_leg_v1,
};
use iroha_crypto::{Hash, PublicKey};

use crate::{
    aps::{dec, enc},
    aps_http::{AddressReq, ApsBackend, BundleCtx, BundleLists, LegCtx, LegReq, OutputKey, Settled, SponsorOutput},
    aps_split::{self, OutputCtx},
    config::{Config, signing_key},
    plan::Capacity,
    pools::{self, Asset, PoolKey},
    wallet::NoteKeys,
};

/// Reads the config without a lock: a guard held across a leg proof (~12 s) or a settle (~80 s) made BI's `GET /aps/bundles`
/// wait, and every bank asks it before proving its leg, so the two legs ran one after the other. The APS path is serialized by
/// `Aps` itself (`submit_lock`: one bundle, `prove_lock`: one own proof).
pub struct RealBackend<'a> {
    cfg: &'a Config,
}

impl<'a> RealBackend<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Self { cfg }
    }

    fn cfg(&self) -> &'a Config {
        self.cfg
    }
}

fn bytes32(text: &str) -> Result<[u8; 32]> {
    hex::decode(text)?.try_into().map_err(|_| eyre!("not 32 bytes"))
}

/// What every output authorization of the leg binds (`AddressReq` carries it for the recipient and for the sponsor).
fn output_ctx(req: &AddressReq) -> Result<OutputCtx> {
    Ok(OutputCtx {
        network_id: req.network_id.parse::<NetworkId>().map_err(|e| eyre!("network_id: {e}"))?,
        bundle_id: Hash::prehashed(bytes32(&req.bundle_id)?),
        leg_ordinal: req.leg_ordinal,
        route: dec(&req.route)?,
        expiry_height: req.expiry_height,
    })
}

fn to_wire(key: aps_split::OutputKey) -> Result<OutputKey> {
    Ok(OutputKey { authority: hex::encode(key.authority), view_public: hex::encode(key.view_public), authorization: enc(&key.authorization)? })
}

fn from_wire(authority: &str, view_public: &str, authorization: &str, active: bool) -> Result<aps_split::OutputKey> {
    Ok(aps_split::OutputKey { authority: bytes32(authority)?, view_public: bytes32(view_public)?, authorization: dec(authorization)?, active })
}

/// `AtomicPrivateSettlementPreparedLegV1` is a native client-side value without a norito codec: on the wire it is
/// `statement.proof.capsule`, each hex, and the delta is derived again on the way in (`complete_..._prepared_leg_v1`).
fn encode_prepared(leg: &AtomicPrivateSettlementPreparedLegV1) -> Result<String> {
    Ok(format!("{}.{}.{}", enc(&leg.statement)?, hex::encode(&leg.proof), enc(&leg.audit_capsule)?))
}

fn decode_prepared(text: &str) -> Result<AtomicPrivateSettlementPreparedLegV1> {
    let parts: Vec<&str> = text.split('.').collect();
    let [statement, proof, capsule] = parts.as_slice() else {
        bail!("prepared leg: expected statement.proof.capsule");
    };
    Ok(complete_atomic_private_settlement_prepared_leg_v1(AtomicPrivateSettlementPreparedProofV1 {
        statement: dec(statement)?,
        proof: hex::decode(proof)?,
        audit_capsule: dec(capsule)?,
    })?)
}

impl ApsBackend for RealBackend<'_> {
    fn own_key(&self) -> Result<String> {
        let cfg = self.cfg();
        Ok(signing_key(&cfg.seed(&cfg.party)?).public_key().to_string())
    }

    fn address(&self, req: &AddressReq) -> Result<OutputKey> {
        // Refused before any key is read.
        let ctx = output_ctx(req)?;
        let (bundle, pool) = (bytes32(&req.bundle_id)?, bytes32(&req.pool_id)?);
        let cfg = self.cfg();
        let signer = signing_key(&cfg.seed(&cfg.party)?);
        // The same one-time keys the owner re-derives when it scans (`NoteKeys::one_time`, role 0 = recipient).
        let notes = cfg.note_keys(&cfg.party)?.one_time(&bundle, &pool, 0);
        to_wire(aps_split::sign_output_key(&signer, &ctx, 0, PrivateSettlementAuditOutputRoleV1::SettlementRecipient, &notes, true)?)
    }

    fn sponsor_output(&self, ctx: &AddressReq, active: bool) -> Result<SponsorOutput> {
        let ctx = output_ctx(ctx)?;
        let (_, sponsor_key) = self.cfg().acting_sponsor()?;
        let notes = NoteKeys::random();
        let key = aps_split::sign_output_key(&sponsor_key, &ctx, 2, PrivateSettlementAuditOutputRoleV1::SponsorReimbursement, &notes, active)?;
        let key = to_wire(key)?;
        Ok(SponsorOutput { authority: key.authority, view_public: key.view_public, authorization: key.authorization, active })
    }

    fn capacity(&self, asset: Asset) -> Result<Vec<(u32, Capacity)>> {
        let cfg = self.cfg();
        let pools = pools::unspent_values(cfg, &cfg.party, asset)?;
        Ok(pools.into_iter().map(|(lane, values)| (lane, Capacity::of(&values))).collect())
    }

    fn begin_bundle(&self, keys: [PoolKey; 2]) -> Result<BundleCtx> {
        let start = pools::begin_bundle(self.cfg(), keys)?;
        let leg = |index: usize| -> Result<LegCtx> {
            let (key, route, pool, digest) = &start.legs[index];
            Ok(LegCtx {
                pool_id: hex::encode(pool),
                route: enc(route)?,
                authority_digest: hex::encode(digest.as_ref()),
                lane: key.lane,
                asset: key.asset.name().to_owned(),
            })
        };
        Ok(BundleCtx {
            bundle_id: hex::encode(start.manifest.bundle_id.as_ref()),
            manifest: enc(&start.manifest)?,
            salt: hex::encode(start.salt),
            expiry_height: start.manifest.expiry_height,
            network_id: start.manifest.network_id.to_string(),
            legs: [leg(0)?, leg(1)?],
        })
    }

    fn prove_leg(&self, req: &LegReq) -> Result<String> {
        let leg = pools::SplitLeg {
            ordinal: usize::from(req.ordinal),
            manifest: dec::<AtomicPrivateSettlementV1>(&req.manifest)?,
            authority_digest: Hash::prehashed(bytes32(&req.authority_digest)?),
            reimbursement_salt: bytes32(&req.salt)?,
            recipient: req.recipient.parse::<PublicKey>().map_err(|e| eyre!("recipient: {e}"))?,
            amount: req.amount.parse()?,
            recipient_output: from_wire(&req.recipient_output.authority, &req.recipient_output.view_public, &req.recipient_output.authorization, true)?,
            sponsor_output: from_wire(
                &req.sponsor_output.authority,
                &req.sponsor_output.view_public,
                &req.sponsor_output.authorization,
                req.sponsor_output.active,
            )?,
        };
        let key = PoolKey { lane: req.lane, asset: Asset::parse(&req.asset)? };
        let cfg = self.cfg();
        encode_prepared(&pools::prove_split_leg(cfg, &cfg.party, key, &leg)?)
    }

    fn is_leg_pool(&self, req: &LegReq) -> Result<bool> {
        let Ok(manifest) = dec::<AtomicPrivateSettlementV1>(&req.manifest) else {
            return Ok(false);
        };
        let pools = pools::PoolFile::load(&self.cfg().pools_file)?;
        Ok(pools::is_leg_pool(&pools, PoolKey { lane: req.lane, asset: Asset::parse(&req.asset)? }, &manifest, usize::from(req.ordinal)))
    }

    fn settle(&self, bundle: &BundleCtx, prepared: &[String; 2]) -> Result<Option<Settled>> {
        let manifest = dec::<AtomicPrivateSettlementV1>(&bundle.manifest)?;
        let legs = [decode_prepared(&prepared[0])?, decode_prepared(&prepared[1])?];
        let key = |leg: &LegCtx| Ok::<_, eyre::Report>(PoolKey { lane: leg.lane, asset: Asset::parse(&leg.asset)? });
        let done = pools::settle_bundle(self.cfg(), [key(&bundle.legs[0])?, key(&bundle.legs[1])?], manifest, &legs)?;
        Ok(done.map(|(carrier_tx, height)| Settled { carrier_tx, height }))
    }

    fn bundles(&self) -> Result<BundleLists> {
        let cfg = self.cfg();
        pools::fill_kept_heights(&cfg)?;
        let file = pools::PoolFile::load(&cfg.pools_file)?;
        let mut lists = BundleLists::default();
        for (asset, ids) in [(Asset::Rd, &mut lists.rd), (Asset::Dfabi, &mut lists.dfabi)] {
            for bundle in file.finalized(asset) {
                ids.push(bundle.id.clone());
                lists.heights.insert(bundle.id, bundle.height);
            }
        }
        lists.carriers = file.carriers;
        Ok(lists)
    }

    fn merge_bundles(&self, lists: &BundleLists) -> Result<()> {
        let cfg = self.cfg();
        // The lists name no lane: each id goes to every pool of its asset, and `history()` applies a bundle only where it has a leg.
        pools::PoolFile::update(&cfg.pools_file, |file| {
            for (asset, ids) in [(Asset::Rd, &lists.rd), (Asset::Dfabi, &lists.dfabi)] {
                for key in file.keys(asset) {
                    file.merge_finalized(key, ids, &lists.heights)?;
                }
            }
            file.merge_carriers(&lists.carriers);
            Ok(())
        })
    }

    fn wallet(&self) -> Result<serde_json::Value> {
        let cfg = self.cfg();
        pools::wallet_json(&cfg, &cfg.party)
    }
}

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
        let cfg = config_in(&dir);
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
    fn reimbursement_output_belongs_to_the_sponsor() {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-aps-real-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let bi = NoteKeys { spend: [5; 32], view: [6; 32] };
        std::fs::write(dir.join("bank-a.note"), format!("{}{}", hex::encode(bi.spend), hex::encode(bi.view))).unwrap();
        let sponsor_dir = crate::config::test_client_dir(9, "http://sponsor-own:1/");
        let sponsor = NoteKeys { spend: [3; 32], view: [4; 32] };
        std::fs::write(sponsor_dir.join("sponsor.note"), format!("{}{}", hex::encode(sponsor.spend), hex::encode(sponsor.view))).unwrap();
        let mut cfg = config_in(&dir);
        cfg.aps.sponsor = Some(crate::config::SponsorConfig { name: "sponsor".into(), dir: sponsor_dir });
        let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"aps-real-test")));
        let route = PrivateSettlementRouteV1 { dataspace_id: DataSpaceId::new(1), lane_id: LaneId::new(1), lane_incarnation: Hash::new(b"aps-real-test") };
        let (bundle, pool) = ([0xbb; 32], [0x01; 32]);
        let req = AddressReq { bundle_id: hex::encode(bundle), pool_id: hex::encode(pool), leg_ordinal: 0, route: enc(&route).unwrap(), expiry_height: 99, network_id: network_id.to_string() };
        let out = RealBackend::new(&cfg).sponsor_output(&req, true).unwrap();
        // The output is addressed to the sponsor's one-time keys (role 2), which only the sponsor's note keys derive.
        let mine = sponsor.one_time(&bundle, &pool, 2);
        assert_eq!((out.authority, out.view_public), (hex::encode(mine.authority().unwrap()), hex::encode(mine.view_public().unwrap())));
        let theirs = bi.one_time(&bundle, &pool, 2);
        assert_ne!(hex::encode(theirs.authority().unwrap()), hex::encode(mine.authority().unwrap()), "BI's keys do not open it");
        let authorization: PrivateSettlementAuditViewKeyAuthorizationV1 = dec(&out.authorization).unwrap();
        assert_eq!(authorization.body.authorized_account, AccountId::new(signing_key(&[9; 32]).public_key().clone()), "authorized by the sponsor key");
        assert_eq!((authorization.body.output_ordinal, authorization.body.output_active), (2, true));
    }

    #[test]
    fn address_refuses_a_malformed_bundle_before_reading_any_key() {
        let cfg = config_in(Path::new("/nonexistent"));
        let backend = RealBackend::new(&cfg);
        let req = AddressReq { bundle_id: "zz".into(), pool_id: hex::encode([1u8; 32]), leg_ordinal: 0, route: "0a".into(), expiry_height: 1, network_id: "x".into() };
        let error = format!("{:#}", backend.address(&req).unwrap_err());
        assert!(!error.contains(".seed") && !error.contains(".note"), "{error}");
    }
}
