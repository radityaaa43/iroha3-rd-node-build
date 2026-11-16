//! Long-lived settlement pools: every Lensa flow is one bundle in the same two pools.
//!
//! `pool-init` / `pool-add` activate pools per dataspace lane (an RD pool and/or a DFABI pool), each with an
//! origin note owned by BI (its issuance reserve). Every later operation spends one live note of
//! the payer (`Spend::Continue`, path from the client-side tree) into the recipient's and the
//! payer's note keys. The pools file holds only public material (route, policy, governance,
//! origin commitments, finalized bundle ids); note openings and secrets stay in the key dir.

use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet, HashSet},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

use eyre::{Result, WrapErr, bail, ensure, eyre};
use iroha::{
    blocking::Client,
    client::{AccountTransactionDraft, PrivateSettlementBundleReceiptResponseV1},
    data_model::{
        account::AccountId,
        isi::private_settlement::ActivatePrivateSettlementPoolV1,
        nexus::{
            AtomicPrivateSettlementV1, PrivateSettlementAuditNoteOpeningV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementReceiptV1, PrivateSettlementRouteV1,
        },
        privacy::{PrivacyCommitmentV1, PrivacyPoolIdV1, PrivacyProtocolIdV1},
    },
};
use iroha_core::privacy_engines::atomic_private_settlement::AtomicPrivateSettlementPreparedLegV1;
use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::{
    metadata::Metadata,
    topology::{DataSpaceId, LaneId},
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::{
    aps::{
        Committee, EXPIRY_BLOCKS, Expect, Governed, Leg, LegNotes, Options, SPONSOR_REIMBURSEMENT, Spend, auditor_call,
        bounded_fee, committee, dec, enc, funding_with_secret, govern_until, on_big_stack, peak_rss, prepare_leg,
        proof_manifest, rnd, settle,
    },
    aps_split::{LegPayer, OutputKey, prepare_leg_split},
    auditor::Keys,
    config::{Config, signing_key},
    history::PoolHistory,
    wallet::{pick_note, pick_notes, scan},
};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Asset {
    Rd,
    Dfabi,
}

impl Asset {
    pub fn parse(text: &str) -> Result<Self> {
        match text {
            "rd" => Ok(Self::Rd),
            "dfabi" => Ok(Self::Dfabi),
            other => bail!("asset {other}: rd or dfabi"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Rd => "rd",
            Self::Dfabi => "dfabi",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Rd => Self::Dfabi,
            Self::Dfabi => Self::Rd,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BundleRef {
    pub id: String,
    /// 0 while in flight (recorded before submission, so a finalized bundle is never lost).
    pub height: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PoolRecord {
    pub pool_id: String,
    pub route: String,
    pub policy: String,
    pub governance: String,
    /// The two activation commitments (hex), in activation order.
    pub origin: Vec<String>,
    /// Finalized bundles that touched this pool, in ledger order.
    pub bundles: Vec<BundleRef>,
}

/// A pool is addressed by the dataspace lane it lives in and the asset it holds.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct PoolKey {
    pub lane: u32,
    pub asset: Asset,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PoolEntry {
    pub lane: u32,
    pub asset: Asset,
    #[serde(flatten)]
    pub record: PoolRecord,
}

#[derive(Clone)]
pub struct PoolFile {
    pub pools: Vec<PoolEntry>,
    /// bundle id -> its finalization carrier tx hash (the tx the chain knows; the bundle id is not a tx). Known only for bundles
    /// finalized since this field exists; the coordinator records it and party drivers merge it from `GET /aps/bundles`.
    pub carriers: BTreeMap<String, String>,
}

impl PoolFile {
    /// Reads the v2 shape `{version, pools, carriers}` and the legacy `{rd, dfabi, carriers}` (lane = the one in the record's route).
    pub fn load(path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            version: Option<u32>,
            pools: Option<Vec<PoolEntry>>,
            rd: Option<PoolRecord>,
            dfabi: Option<PoolRecord>,
            #[serde(default)]
            carriers: BTreeMap<String, String>,
        }
        let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        let raw: Raw = serde_json::from_str(&text)?;
        let legacy = |asset, record: PoolRecord| -> Result<PoolEntry> {
            let lane = dec::<PrivateSettlementRouteV1>(&record.route)?.lane_id.as_u32();
            Ok(PoolEntry { lane, asset, record })
        };
        let pools = match raw {
            Raw { version, pools: Some(pools), rd: None, dfabi: None, .. } => {
                ensure!(version == Some(2), "{}: pool file version {version:?}, expected 2", path.display());
                pools
            }
            Raw { version, pools: None, rd: Some(rd), dfabi: Some(dfabi), .. } => {
                ensure!(version.is_none(), "{}: a legacy pool file has no version, found {version:?}", path.display());
                vec![legacy(Asset::Rd, rd)?, legacy(Asset::Dfabi, dfabi)?]
            }
            _ => bail!("{}: neither a v2 pool file nor the legacy {{rd, dfabi}} one", path.display()),
        };
        let file = Self { pools, carriers: raw.carriers };
        let keys: std::collections::BTreeSet<_> = file.pools.iter().map(PoolEntry::key).collect();
        ensure!(keys.len() == file.pools.len(), "{}: two pools share one (lane, asset)", path.display());
        Ok(file)
    }

    /// Write through a temp file + rename: a crash never leaves a half-written index.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::json!({ "version": 2, "pools": self.pools, "carriers": self.carriers });
        std::fs::write(&tmp, serde_json::to_string_pretty(&json)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Read-modify-write for a run that held its copy for minutes: another run may have added a bundle meanwhile.
    pub fn update(path: &Path, change: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        let _lock = Self::lock(path)?;
        let mut pools = Self::load(path)?;
        change(&mut pools)?;
        pools.save(path)
    }

    /// A separate lock file: save() renames over pools.json, which would drop a lock held on it. Released when dropped.
    fn lock(path: &Path) -> Result<std::fs::File> {
        let lock = std::fs::OpenOptions::new().create(true).append(true).open(path.with_extension("json.lock"))?;
        lock.lock()?;
        Ok(lock)
    }

    /// Append new pools (creating the file when there is none) under the lock. A key already present is refused.
    pub fn add(path: &Path, entries: Vec<PoolEntry>) -> Result<()> {
        let _lock = Self::lock(path)?;
        let mut file = if path.exists() { Self::load(path)? } else { Self { pools: Vec::new(), carriers: BTreeMap::new() } };
        for entry in entries {
            let key = entry.key();
            ensure!(file.get(key).is_err(), "{} pool in lane {} already exists", key.asset.name(), key.lane);
            file.pools.push(entry);
        }
        file.save(path)
    }

    /// The finalized bundles (height > 0) of every pool of the asset, in ledger order: what a party driver needs to rebuild the history.
    pub fn finalized(&self, asset: Asset) -> Vec<BundleRef> {
        let mut bundles: Vec<BundleRef> = Vec::new();
        let mut seen = HashSet::new();
        for entry in self.pools.iter().filter(|entry| entry.asset == asset) {
            for bundle in entry.record.bundles.iter().filter(|bundle| bundle.height > 0) {
                if seen.insert(bundle.id.as_str()) {
                    bundles.push(bundle.clone());
                }
            }
        }
        bundles.sort_by_key(|bundle| bundle.height);
        bundles
    }

    /// Add the finalized bundles another driver listed (`ids`; `heights` may name a height per id) that are not here yet, after the
    /// ones here. `history()` sorts by the chain's finalized height and trusts only receipts it reads from the chain.
    /// Add the carrier tx of bundles another driver listed; a carrier already known here is kept.
    pub fn merge_carriers(&mut self, carriers: &BTreeMap<String, String>) {
        for (id, carrier_tx) in carriers {
            self.carriers.entry(id.clone()).or_insert_with(|| carrier_tx.clone());
        }
    }

    /// A key that names no pool is an error: callers take their keys from `keys()`.
    pub fn merge_finalized(&mut self, key: PoolKey, ids: &[String], heights: &BTreeMap<String, u64>) -> Result<()> {
        let Some(entry) = self.pools.iter_mut().find(|entry| entry.key() == key) else {
            bail!("no {} pool in lane {} to merge into", key.asset.name(), key.lane);
        };
        let bundles = &mut entry.record.bundles;
        for id in ids {
            let height = heights.get(id).copied().unwrap_or(0);
            match bundles.iter().position(|bundle| bundle.id == *id) {
                Some(known) => {
                    if bundles[known].height == 0 {
                        bundles[known].height = height;
                    }
                }
                None => bundles.push(BundleRef { id: id.clone(), height }),
            }
        }
        Ok(())
    }

    /// Ids still at height 0 in any pool: in flight, or kept after the coordinator stopped waiting for every node's receipt.
    pub fn kept(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for bundle in self.pools.iter().flat_map(|entry| &entry.record.bundles) {
            if bundle.height == 0 && !ids.contains(&bundle.id) {
                ids.push(bundle.id.clone());
            }
        }
        ids
    }

    /// Set the height of the height-0 bundles that `heights` names (the chain finalized them after the coordinator stopped waiting).
    pub fn fill_heights(&mut self, heights: &BTreeMap<String, u64>) {
        for bundle in self.pools.iter_mut().flat_map(|entry| &mut entry.record.bundles) {
            if bundle.height == 0 {
                bundle.height = heights.get(&bundle.id).copied().unwrap_or(0);
            }
        }
    }

    pub fn get(&self, key: PoolKey) -> Result<&PoolRecord> {
        self.pools
            .iter()
            .find(|entry| entry.key() == key)
            .map(|entry| &entry.record)
            .ok_or_else(|| eyre!("no {} pool in lane {}", key.asset.name(), key.lane))
    }

    /// The keys of the asset's pools, by lane.
    pub fn keys(&self, asset: Asset) -> Vec<PoolKey> {
        let mut keys: Vec<_> = self.pools.iter().map(PoolEntry::key).filter(|key| key.asset == asset).collect();
        keys.sort();
        keys
    }

    /// Where the code still means "the" pool of an asset: it exists once. Later steps choose among several.
    fn sole(&self, asset: Asset) -> Result<&PoolRecord> {
        let keys = self.keys(asset);
        ensure!(keys.len() == 1, "{} {} pools in the pools file, expected one", keys.len(), asset.name());
        self.get(keys[0])
    }
}

impl PoolEntry {
    fn key(&self) -> PoolKey {
        PoolKey { lane: self.lane, asset: self.asset }
    }
}

/// Coordinator: give every height-0 bundle the chain has finalized its height, so `GET /aps/bundles` lists it. Receipts are read
/// outside the pools-file lock; a bundle still in flight has no finalized receipt and stays 0.
pub fn fill_kept_heights(cfg: &Config) -> Result<()> {
    let kept = PoolFile::load(&cfg.pools_file)?.kept();
    if kept.is_empty() {
        return Ok(());
    }
    let (client, _) = cfg.acting_sponsor()?;
    let mut heights = BTreeMap::new();
    for id in kept {
        if let Some(receipt) = finalized_receipt(&client, &receipt_cache(cfg), &id)? {
            heights.insert(id, receipt.finalized_height);
        }
    }
    if heights.is_empty() {
        return Ok(());
    }
    PoolFile::update(&cfg.pools_file, |file| Ok(file.fill_heights(&heights)))
}

impl PoolRecord {
    fn governed(&self) -> Result<Governed> {
        Ok(Governed { route: dec(&self.route)?, policy: dec(&self.policy)?, governance: dec(&self.governance)? })
    }

    fn pool_id(&self) -> Result<PrivacyPoolIdV1> {
        Ok(PrivacyPoolIdV1::new(hex32(&self.pool_id)?))
    }

    /// Rebuild the pool from the chain: origin, then the delta for this pool of every listed bundle
    /// that finalized, in finalization order. Aborted or in-flight bundles moved nothing.
    pub fn history(&self, client: &Client, cache: &Path) -> Result<PoolHistory> {
        let pool_id = self.pool_id()?;
        let origin = self.origin.iter().map(|c| Ok(PrivacyCommitmentV1::new(hex32(c)?))).collect::<Result<Vec<_>>>()?;
        let mut history = PoolHistory::new(pool_id, &origin)?;
        let mut finalized = Vec::new();
        for bundle in &self.bundles {
            if let Some(receipt) = finalized_receipt(client, cache, &bundle.id)? {
                finalized.push(receipt);
            }
        }
        finalized.sort_by_key(|receipt| receipt.finalized_height);
        for receipt in finalized {
            let leg = receipt
                .legs
                .iter()
                .find(|leg| leg.delta.pool_id == pool_id)
                .ok_or_else(|| eyre!("a finalized bundle has no leg in this pool"))?;
            history.apply(&leg.delta, receipt.finalized_height)?;
        }
        Ok(history)
    }
}

/// A finalized receipt is immutable public data: cached on disk once read.
fn finalized_receipt(client: &Client, cache: &Path, id: &str) -> Result<Option<PrivateSettlementReceiptV1>> {
    let file = cache.join(format!("{id}.norito.hex"));
    if let Some(receipt) = read_cached(&file)? {
        return Ok(Some(receipt));
    }
    match client.client().private_settlement_bundle_receipt_v1(Hash::prehashed(hex32(id)?))? {
        PrivateSettlementBundleReceiptResponseV1::Finalized(receipt) => {
            store_cached(cache, &file, &enc(&receipt)?)?;
            Ok(Some(receipt))
        }
        _ => Ok(None),
    }
}

fn read_cached(file: &Path) -> Result<Option<PrivateSettlementReceiptV1>> {
    // A missing or damaged file is a miss: the caller refetches and rewrites it.
    Ok(std::fs::read_to_string(file).ok().and_then(|text| dec(text.trim()).ok()))
}

/// Write via a temp file and rename, so a reader never sees half a file. The temp name is random:
/// every driver container is PID 1, so a pid would not tell two containers apart.
fn store_cached(cache: &Path, file: &Path, text: &str) -> Result<()> {
    std::fs::create_dir_all(cache)?;
    let tmp = file.with_extension(format!("{:016x}.tmp", rand::random::<u64>()));
    std::fs::write(&tmp, text)?;
    std::fs::rename(tmp, file)?;
    Ok(())
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    hex::decode(text)?.try_into().map_err(|_| eyre!("not 32 bytes"))
}

fn write_secret(path: &Path, text: &str) -> Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .wrap_err_with(|| format!("create {}", path.display()))?
        .write_all(text.as_bytes())?;
    Ok(())
}

fn receipt_cache(cfg: &Config) -> PathBuf {
    cfg.pools_file.with_file_name("receipts")
}

fn origin_note_path(cfg: &Config, key: PoolKey) -> PathBuf {
    cfg.key_dir.join(format!("bi.origin-{}-{}.note", key.lane, key.asset.name()))
}

/// The origin note file to read: the pool's own, else (only for the lane the first deployment used) `bi.origin-<asset>.note`.
fn origin_note_file(cfg: &Config, key: PoolKey) -> PathBuf {
    let current = origin_note_path(cfg, key);
    let legacy = cfg.key_dir.join(format!("bi.origin-{}.note", key.asset.name()));
    if !current.exists() && key.lane == lane_of(cfg, key.asset) && legacy.exists() { legacy } else { current }
}

/// BI's origin (reserve) note of a pool; other parties have none.
fn origin_notes(cfg: &Config, party: &str, asset: Asset) -> Result<Vec<PrivateSettlementAuditNoteOpeningV1>> {
    if party != "bi" {
        return Ok(Vec::new());
    }
    Ok(vec![dec(std::fs::read_to_string(origin_note_file(cfg, PoolKey { lane: lane_of(cfg, asset), asset }))?.trim())?])
}

fn lane_of(cfg: &Config, asset: Asset) -> u32 {
    match asset {
        Asset::Rd => cfg.lanes.rd,
        Asset::Dfabi => cfg.lanes.dfabi,
    }
}

fn asset_id(cfg: &Config, asset: Asset) -> &str {
    match asset {
        Asset::Rd => &cfg.assets.rd,
        Asset::Dfabi => &cfg.assets.dfabi,
    }
}

fn route(client: &Client, lane: u32) -> Result<PrivateSettlementRouteV1> {
    let status = client.client().get_lane_lifecycle_status()?;
    status.validate().wrap_err("lane lifecycle status")?;
    let lane_id = LaneId::new(lane);
    let incarnation = status
        .incarnations
        .iter()
        .find(|entry| entry.lane_id == lane_id)
        .ok_or_else(|| eyre!("lane {lane} has no active incarnation"))?
        .incarnation;
    Ok(PrivateSettlementRouteV1 { dataspace_id: DataSpaceId::new(u64::from(lane)), lane_id, lane_incarnation: incarnation })
}

/// Activate pools in ONE dataspace (`lane`), one per `(asset, reserve)`, each holding a BI reserve note: ONE transaction with
/// one `ActivatePrivateSettlementPoolV1` per pool, in an order shuffled with `rng` (the position of an instruction must not
/// tell which asset it is). One transaction must stay inside ONE dataspace: each activation routes to its own dataspace
/// (queue/router.rs `ActivatePrivateSettlementPoolV1 => route.dataspace_id`), and two dataspaces in one transaction become a
/// cross-dataspace NativeAmx plan that never got a lane payload on this cluster: queued forever, no block, 300 s timeout
/// (see `aps.rs`, the same reason it activates one transaction per pool). Hence one call per lane.
/// Refuses a key already in the pools file, and an origin note file that exists, before any network call.
pub fn pool_add(cfg: &Config, lane: u32, reserves: &[(Asset, u128)], rng: &mut impl rand::Rng) -> Result<Vec<PoolKey>> {
    ensure!(!reserves.is_empty(), "pool-add: no reserve given for lane {lane}");
    let assets: BTreeSet<_> = reserves.iter().map(|(asset, _)| *asset).collect();
    ensure!(assets.len() == reserves.len(), "pool-add: an asset twice in lane {lane}");
    if cfg.pools_file.exists() {
        let file = PoolFile::load(&cfg.pools_file)?;
        for asset in &assets {
            ensure!(file.get(PoolKey { lane, asset: *asset }).is_err(), "{} pool in lane {lane} already exists", asset.name());
        }
    }
    for asset in &assets {
        let note = origin_note_path(cfg, PoolKey { lane, asset: *asset });
        ensure!(!note.exists(), "{} exists: no pool is recorded for it, move it away first", note.display());
    }
    let (sponsor, _) = cfg.acting_sponsor()?;
    let caps = sponsor.client().get_privacy_capabilities()?;
    ensure!(
        caps.protocols.iter().any(|row| row.protocol_id == PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 && row.activation.is_some()),
        "IVM private-note capability is not activated"
    );
    let (auditors, min_approvals) = crate::aps::auditors_from_config(cfg)?;
    let bi = cfg.note_keys("bi")?;
    let fee = bounded_fee(cfg)?;
    let lane_route = route(&sponsor, lane)?;
    let mut activations = Vec::new();
    let mut pending = Vec::new();
    for (asset, reserve) in activation_order(reserves, rng) {
        let governed = crate::aps::govern_with(lane_route, asset_id(cfg, asset).parse()?, caps.committed_height, None, &auditors, min_approvals)?;
        let funding = funding_with_secret(reserve, bi.spend)?;
        activations.push(ActivatePrivateSettlementPoolV1::from_restricted(&governed.governance, funding.activation_commitments().to_vec())?);
        pending.push((asset, governed, funding));
    }
    let account = sponsor.account_client();
    let tx = account
        .prepare_transaction(AccountTransactionDraft::new(activations, fee, Metadata::default()))
        .and_then(|payload| account.sign_transaction(payload))
        .wrap_err("build pool activation")?;
    let hash = sponsor.submit_transaction_and_wait(&tx).wrap_err_with(|| format!("activate pools of lane {lane}"))?;
    println!("pool_activation_tx={hash} lane={lane}");
    let mut entries = Vec::new();
    for (asset, governed, funding) in pending {
        write_secret(&origin_note_path(cfg, PoolKey { lane, asset }), &enc(&funding.opening)?)?;
        let record = PoolRecord {
            pool_id: hex::encode(governed.governance.body.pool_id.as_ref()),
            route: enc(&governed.route)?,
            policy: enc(&governed.policy)?,
            governance: enc(&governed.governance)?,
            origin: funding.input_commitments.iter().map(|c| hex::encode(c.as_bytes())).collect(),
            bundles: Vec::new(),
        };
        println!("pool_json={}", serde_json::json!({ "lane": lane, "asset": asset.name(), "pool_id": record.pool_id }));
        entries.push(PoolEntry { lane, asset, record });
    }
    let keys = entries.iter().map(PoolEntry::key).collect();
    PoolFile::add(&cfg.pools_file, entries)?;
    Ok(keys)
}

/// One-time: activate the pools of every lane in `plan` (one `pool_add` per lane, lanes in shuffled order). Needs no pools file.
pub fn pool_init(cfg: &Config, plan: &[(u32, Vec<(Asset, u128)>)], rng: &mut impl rand::Rng) -> Result<()> {
    ensure!(!cfg.pools_file.exists(), "{} exists: pools are initialized once", cfg.pools_file.display());
    ensure!(!plan.is_empty(), "pool-init: no lane given");
    let mut lanes = BTreeSet::new();
    for (lane, _) in plan {
        ensure!(lanes.insert(*lane), "pool-init: lane {lane} twice");
    }
    let mut order: Vec<_> = plan.iter().collect();
    order.shuffle(rng);
    for (lane, reserves) in order {
        pool_add(cfg, *lane, reserves, rng)?;
    }
    Ok(())
}

/// The order the activations go into the transaction.
fn activation_order(reserves: &[(Asset, u128)], rng: &mut impl rand::Rng) -> Vec<(Asset, u128)> {
    let mut order = reserves.to_vec();
    order.shuffle(rng);
    order
}

/// `--lane N [--rd A] [--dfabi B]` groups, in the order given: each amount belongs to the last `--lane` before it.
pub fn parse_plan(rest: &[&str]) -> Result<Vec<(u32, Vec<(Asset, u128)>)>> {
    let mut plan: Vec<(u32, Vec<(Asset, u128)>)> = Vec::new();
    let mut args = rest.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| eyre!("{flag} needs a value"))?;
        if *flag == "--lane" {
            let lane = value.parse().wrap_err_with(|| format!("--lane {value}"))?;
            ensure!(plan.iter().all(|(known, _)| *known != lane), "--lane {lane} twice");
            plan.push((lane, Vec::new()));
            continue;
        }
        let asset = Asset::parse(flag.strip_prefix("--").ok_or_else(|| eyre!("unexpected {flag}"))?)?;
        let (_, reserves) = plan.last_mut().ok_or_else(|| eyre!("{flag} before any --lane"))?;
        ensure!(reserves.iter().all(|(known, _)| *known != asset), "{flag} twice in one lane");
        reserves.push((asset, value.parse().wrap_err_with(|| format!("{flag} {value}"))?));
    }
    ensure!(!plan.is_empty(), "at least one --lane");
    ensure!(plan.iter().all(|(_, reserves)| !reserves.is_empty()), "every --lane needs --rd and/or --dfabi");
    Ok(plan)
}

/// One payment inside a shared-pool bundle.
pub struct LegSpec {
    pub asset: Asset,
    pub payer: String,
    pub recipient: String,
    pub amount: u128,
}

/// `pay`: the asset's leg carries the payment; the other pool gets BI -> BI 1 (APS needs two
/// dataspaces). Legs are always [RD, DFABI] (leg 0 also pays the sponsor's reimbursement).
pub fn pay(cfg: &Config, asset: Asset, from: &str, to: &str, amount: u128, options: &Options) -> Result<()> {
    let main = LegSpec { asset, payer: from.into(), recipient: to.into(), amount };
    let companion = LegSpec { asset: asset.other(), payer: "bi".into(), recipient: "bi".into(), amount: 1 };
    let legs = if asset == Asset::Rd { [main, companion] } else { [companion, main] };
    run_bundle(cfg, legs, options, "pay")
}

/// DvP on the shared pools: RD buyer -> seller, DFABI seller -> buyer.
pub fn dvp(cfg: &Config, buyer: &str, seller: &str, rd: u128, dfabi: u128, options: &Options) -> Result<()> {
    run_bundle(
        cfg,
        [
            LegSpec { asset: Asset::Rd, payer: buyer.into(), recipient: seller.into(), amount: rd },
            LegSpec { asset: Asset::Dfabi, payer: seller.into(), recipient: buyer.into(), amount: dfabi },
        ],
        options,
        "dvp",
    )
}

fn run_bundle(cfg: &Config, legs: [LegSpec; 2], options: &Options, kind: &str) -> Result<()> {
    ensure!(legs[0].asset == Asset::Rd && legs[1].asset == Asset::Dfabi, "legs must be [rd, dfabi]");
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (sponsor, sponsor_key) = cfg.acting_sponsor()?;
    let mut spends = Vec::new();
    let mut governed = Vec::new();
    for (ordinal, leg) in legs.iter().enumerate() {
        let record = pools.sole(leg.asset)?;
        let history = record.history(&sponsor, &receipt_cache(cfg))?;
        let keys = cfg.note_keys(&leg.payer)?;
        let (unspent, _) = scan(&history, &keys, &origin_notes(cfg, &leg.payer, leg.asset)?)?;
        let reimbursement = if ordinal == 0 { SPONSOR_REIMBURSEMENT } else { 0 };
        // Refused before any proving or on-chain write; no amounts in the message (logs).
        let note = pick_note(&unspent, leg.amount + reimbursement)
            .wrap_err_with(|| format!("leg {ordinal}: insufficient payer note (rejected before proving)"))?;
        spends.push((note, keys, history));
        governed.push(record.governed()?);
    }
    let committees = committees_of(cfg, &governed)?;
    let network_id = *sponsor.client().network_id();
    let height = sponsor.client().get_privacy_capabilities()?.committed_height;
    let salt = rnd();
    let manifest = proof_manifest(
        network_id,
        height,
        height + EXPIRY_BLOCKS,
        AccountId::new(sponsor_key.public_key().clone()),
        bounded_fee(cfg)?,
        &governed,
        salt,
    )?;
    println!("bundle_id={}", hex::encode(manifest.bundle_id.as_ref()));
    let started = Instant::now();
    let mut prepared = Vec::new();
    for (ordinal, (leg, (note, keys, history))) in legs.iter().zip(spends).enumerate() {
        let wallet = |party: &str| Ok::<_, eyre::Report>(signing_key(&cfg.seed(party)?));
        let spec = Leg {
            lane: lane_of(cfg, leg.asset),
            asset: asset_id(cfg, leg.asset).parse()?,
            payer: wallet(&leg.payer)?,
            recipient: wallet(&leg.recipient)?,
            funding: note.opening.value,
            amount: leg.amount,
        };
        let (bundle, pool) = (*manifest.bundle_id.as_ref(), *governed[ordinal].governance.body.pool_id.as_ref());
        let notes = LegNotes { recipient: cfg.note_keys(&leg.recipient)?.one_time(&bundle, &pool, 0), change: keys.one_time(&bundle, &pool, 1) };
        let spend = Spend::Continue { opening: note.opening, secret: keys.spend, tree: history.tree, epoch: history.epoch, extra: None };
        let authority_digest = committees[ordinal].authority.digest()?;
        prepared.push(on_big_stack(|| {
            prepare_leg(ordinal, &spec, &governed[ordinal], spend, &notes, &manifest, authority_digest, &sponsor_key, salt)
        })?);
        println!("leg {ordinal} proved after {:?} {}", started.elapsed(), peak_rss());
    }
    settle_recorded(cfg, &sponsor, manifest, &prepared, &governed, &committees, started, options)?;
    println!("kind={kind}");
    Ok(())
}

fn committees_of(cfg: &Config, governed: &[Governed]) -> Result<Vec<Committee>> {
    governed
        .iter()
        .map(|g| {
            let (authority, endpoints) = committee(cfg, g.route)?;
            Ok(Committee { authority, endpoints })
        })
        .collect()
}

/// List the bundle as in flight in pools.json (recorded before submission, so a finalized bundle is never lost), settle it, record how it ended.
#[allow(clippy::too_many_arguments)]
fn settle_recorded(
    cfg: &Config,
    sponsor: &Client,
    manifest: AtomicPrivateSettlementV1,
    prepared: &[AtomicPrivateSettlementPreparedLegV1],
    governed: &[Governed],
    committees: &[Committee],
    started: Instant,
    options: &Options,
) -> Result<Option<(String, u64)>> {
    let id = hex::encode(manifest.bundle_id.as_ref());
    PoolFile::update(&cfg.pools_file, |pools| {
        for entry in &mut pools.pools {
            entry.record.bundles.push(BundleRef { id: id.clone(), height: 0 });
        }
        Ok(())
    })?;
    let aborted = Cell::new(false);
    let outcome = settle(cfg, sponsor, manifest, prepared, governed, committees, started, options, &aborted);
    let end = bundle_end(&outcome, aborted.get());
    PoolFile::update(&cfg.pools_file, |pools| Ok(record_end(pools, &id, &end)))?;
    outcome
}

/// What the coordinator fixes before any party signs or proves: the manifest and, per leg ([rd, dfabi]), its route, pool and committee digest.
pub(crate) struct BundleStart {
    pub manifest: AtomicPrivateSettlementV1,
    pub salt: [u8; 32],
    pub legs: Vec<(PrivateSettlementRouteV1, [u8; 32], Hash)>,
}

/// Coordinator: the manifest of a new bundle over the RD and DFABI pools (`run_bundle` up to the legs, with no payer's secret).
pub(crate) fn begin_bundle(cfg: &Config) -> Result<BundleStart> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (sponsor, sponsor_key) = cfg.acting_sponsor()?;
    let governed = [pools.sole(Asset::Rd)?.governed()?, pools.sole(Asset::Dfabi)?.governed()?];
    let committees = committees_of(cfg, &governed)?;
    let network_id = *sponsor.client().network_id();
    let height = sponsor.client().get_privacy_capabilities()?.committed_height;
    let salt = rnd();
    let manifest = proof_manifest(
        network_id,
        height,
        height + EXPIRY_BLOCKS,
        AccountId::new(sponsor_key.public_key().clone()),
        bounded_fee(cfg)?,
        &governed,
        salt,
    )?;
    let legs = governed
        .iter()
        .zip(&committees)
        .map(|(g, c)| {
            let pool: [u8; 32] = *g.governance.body.pool_id.as_ref();
            Ok((g.route, pool, c.authority.digest()?))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BundleStart { manifest, salt, legs })
}

/// Coordinator: settle a bundle whose legs the parties proved (the tail of `run_bundle`). An audit rejection aborts the
/// bundle and is `None`, not an error.
pub(crate) fn settle_bundle(cfg: &Config, manifest: AtomicPrivateSettlementV1, prepared: &[AtomicPrivateSettlementPreparedLegV1]) -> Result<Option<(String, u64)>> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (sponsor, _) = cfg.acting_sponsor()?;
    let governed = [pools.sole(Asset::Rd)?.governed()?, pools.sole(Asset::Dfabi)?.governed()?];
    let committees = committees_of(cfg, &governed)?;
    let options = Options { expect: Expect::Either, replay: false };
    settle_recorded(cfg, &sponsor, manifest, prepared, &governed, &committees, Instant::now(), &options)
}

/// One leg as `POST /aps/leg` hands it to the payer.
pub(crate) struct SplitLeg {
    pub ordinal: usize,
    pub manifest: AtomicPrivateSettlementV1,
    pub authority_digest: Hash,
    pub reimbursement_salt: [u8; 32],
    pub recipient: PublicKey,
    pub amount: u128,
    pub recipient_output: OutputKey,
    pub sponsor_output: OutputKey,
}

/// Payer side of one leg of a bundle the coordinator built: scan the own notes, pick one, prove with the own secrets only
/// (`aps_split::prepare_leg_split`); the recipient's and the sponsor's outputs arrive signed by their owners.
pub(crate) fn prove_split_leg(cfg: &Config, payer: &str, asset: Asset, leg: &SplitLeg) -> Result<AtomicPrivateSettlementPreparedLegV1> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let record = pools.sole(asset)?;
    let (client, _) = cfg.sponsor(payer)?;
    let history = record.history(&client, &receipt_cache(cfg))?;
    let keys = cfg.note_keys(payer)?;
    let (unspent, _) = scan(&history, &keys, &origin_notes(cfg, payer, asset)?)?;
    let reimbursement = if leg.ordinal == 0 { SPONSOR_REIMBURSEMENT } else { 0 };
    // Refused before any proving; no amounts in the message (logs).
    let mut notes = pick_notes(&unspent, leg.amount + reimbursement)
        .wrap_err_with(|| format!("leg {}: insufficient payer note (rejected before proving)", leg.ordinal))?
        .into_iter();
    let (note, extra) = (notes.next().ok_or_else(|| eyre!("no note picked"))?, notes.next().map(|n| n.opening));
    let governed = record.governed()?;
    let (bundle, pool) = (*leg.manifest.bundle_id.as_ref(), *governed.governance.body.pool_id.as_ref());
    let change = keys.one_time(&bundle, &pool, 1);
    let sponsor = leg.manifest.sponsor.try_signatory().ok_or_else(|| eyre!("the manifest sponsor is not a single-key account"))?;
    let spec = LegPayer {
        lane: lane_of(cfg, asset),
        asset: asset_id(cfg, asset).parse()?,
        payer: signing_key(&cfg.seed(payer)?),
        recipient: leg.recipient.clone(),
        amount: leg.amount,
    };
    let spend = Spend::Continue { opening: note.opening, secret: keys.spend, tree: history.tree, epoch: history.epoch, extra };
    on_big_stack(|| {
        prepare_leg_split(
            leg.ordinal,
            &spec,
            &governed,
            spend,
            &change,
            &leg.recipient_output,
            &leg.sponsor_output,
            sponsor,
            &leg.manifest,
            leg.authority_digest,
            leg.reimbursement_salt,
        )
    })
}

/// How a bundle ended, for pools.json.
enum BundleEnd {
    /// Finalized height and the carrier tx hash.
    Finalized(u64, String),
    /// It moved nothing (aborted): no entry.
    Dropped,
    /// A failure whose abort also failed stays listed; history() reads its final state from the chain.
    Kept,
}

/// `aborted`: a failed stage was aborted successfully, so the bundle moved nothing.
fn bundle_end(outcome: &Result<Option<(String, u64)>>, aborted: bool) -> BundleEnd {
    match outcome {
        Ok(Some((carrier_tx, height))) => BundleEnd::Finalized(*height, carrier_tx.clone()),
        Ok(None) => BundleEnd::Dropped,
        Err(_) if aborted => BundleEnd::Dropped,
        Err(_) => BundleEnd::Kept,
    }
}

fn record_end(pools: &mut PoolFile, id: &str, end: &BundleEnd) {
    if let BundleEnd::Finalized(_, carrier_tx) = end {
        pools.carriers.insert(id.to_owned(), carrier_tx.clone());
    }
    for entry in &mut pools.pools {
        let bundles = &mut entry.record.bundles;
        match end {
            BundleEnd::Finalized(height, _) => bundles.iter_mut().filter(|b| b.id == id).for_each(|b| b.height = *height),
            BundleEnd::Dropped => bundles.retain(|b| b.id != id),
            BundleEnd::Kept => {}
        }
    }
}

/// `wallet --party P`: balances and per-bundle movements read from both pools on chain.
pub fn wallet(cfg: &Config, party: &str) -> Result<()> {
    println!("wallet_json={}", wallet_json(cfg, party)?);
    Ok(())
}

/// The wallet of `party` as JSON: the `wallet_json=` line of the CLI and `GET /aps/wallet`.
pub fn wallet_json(cfg: &Config, party: &str) -> Result<serde_json::Value> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (client, _) = cfg.sponsor(party)?;
    let keys = cfg.note_keys(party)?;
    let mut balances = serde_json::Map::new();
    let mut items = Vec::new();
    for asset in [Asset::Rd, Asset::Dfabi] {
        let mut balance = 0u128;
        for key in pools.keys(asset) {
            let record = pools.get(key)?;
            let history = record.history(&client, &receipt_cache(cfg))?;
            let (unspent, spent) = scan(&history, &keys, &origin_notes(cfg, party, asset)?)?;
            balance += unspent.iter().map(|n| n.opening.value).sum::<u128>();
            for bundle in &record.bundles {
                let received: u128 = unspent
                    .iter()
                    .chain(spent.iter().map(|(n, _)| n))
                    .filter(|n| n.bundle_id.as_deref() == Some(bundle.id.as_str()))
                    .map(|n| n.opening.value)
                    .sum();
                let paid: u128 = spent.iter().filter(|(_, by)| *by == bundle.id).map(|(n, _)| n.opening.value).sum();
                items.extend(item_json(asset, bundle, received, paid, pools.carriers.get(&bundle.id).map(String::as_str)));
            }
        }
        balances.insert(asset.name().into(), balance.to_string().into());
    }
    items.sort_by_key(|i| std::cmp::Reverse(i["height"].as_u64()));
    Ok(serde_json::json!({ "party": party, "balances": balances, "items": items }))
}

/// One wallet row for a bundle, or None when nothing visible moved. The payer of the RD leg (leg 0) also
/// reimbursed the sponsor 1 RD: `amount` is the leg without it.
fn item_json(asset: Asset, bundle: &BundleRef, received: u128, paid: u128, carrier_tx: Option<&str>) -> Option<serde_json::Value> {
    let fee = if asset == Asset::Rd && paid > 0 { SPONSOR_REIMBURSEMENT } else { 0 };
    let (direction, amount) = if paid > received { ("out", paid - received - fee) } else { ("in", received - paid) };
    (amount > 0).then(|| {
        serde_json::json!({
            "bundle_id": bundle.id, "height": bundle.height, "asset": asset.name(),
            "direction": direction, "amount": amount.to_string(), "fee": fee.to_string(), "carrier_tx": carrier_tx,
        })
    })
}

/// Debug aid for gate G3: rebuild one pool and print its head (no amounts).
pub fn pool_history(cfg: &Config, asset: Asset) -> Result<()> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (client, _) = cfg.acting_sponsor()?;
    for key in pools.keys(asset) {
        let history = pools.get(key)?.history(&client, &receipt_cache(cfg))?;
        println!(
            "pool_history asset={} epoch={} leaves={} root={}",
            asset.name(),
            history.epoch,
            history.tree.len(),
            hex::encode(history.root().as_bytes())
        );
    }
    Ok(())
}


/// Abort a stuck bundle (prepared but never registered) to release the pool reservations.
pub fn abort_bundle(cfg: &Config, bundle: &str) -> Result<()> {
    let (sponsor, _) = cfg.acting_sponsor()?;
    let status = sponsor.client().private_settlement_bundle_status_v1(Hash::prehashed(hex32(bundle)?))?;
    let manifest = status.manifest.ok_or_else(|| eyre!("the node retains no manifest for this bundle"))?;
    crate::aps::abort_bundle(cfg, sponsor.client(), &manifest)?;
    println!("aborted bundle={bundle}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("rd-dfabi-cache-{}", rand::random::<u64>()))
    }

    /// Lensa runs several driver containers at once; each may cache the same new receipt.
    #[test]
    fn two_writers_of_the_same_receipt_both_succeed() {
        let cache = temp_dir();
        let text = "ab".repeat(6500);
        for round in 0..2000 {
            let file = cache.join(format!("{round}.norito.hex"));
            let start = Arc::new(Barrier::new(2));
            let writers: Vec<_> = (0..2)
                .map(|_| {
                    let (cache, file, text, start) = (cache.clone(), file.clone(), text.clone(), start.clone());
                    std::thread::spawn(move || {
                        start.wait();
                        store_cached(&cache, &file, &text)
                    })
                })
                .collect();
            for writer in writers {
                writer.join().unwrap().unwrap_or_else(|e| panic!("round {round}: {e:#}"));
            }
            assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
        }
        std::fs::remove_dir_all(cache).unwrap();
    }

    /// A damaged cache file is a miss (refetched and rewritten), not an error.
    #[test]
    fn undecodable_cache_file_is_a_miss() {
        let cache = temp_dir();
        std::fs::create_dir_all(&cache).unwrap();
        let file = cache.join("x.norito.hex");
        std::fs::write(&file, "not a receipt").unwrap();
        assert!(read_cached(&file).unwrap().is_none());
        std::fs::remove_dir_all(cache).unwrap();
    }

    /// A bundle kept at height 0 (a node had not finalized when the coordinator stopped waiting) reaches the parties once the
    /// chain's receipt names its height; a bundle still in flight stays 0 and a known height is never overwritten.
    #[test]
    fn kept_bundle_gets_its_finalized_height() {
        let bundles = [("a", 5), ("kept", 0), ("live", 0)];
        let mut file = PoolFile { pools: vec![entry(1, Asset::Rd, &bundles), entry(2, Asset::Dfabi, &bundles)], carriers: BTreeMap::new() };
        assert_eq!(file.kept(), vec!["kept".to_string(), "live".to_string()]);
        file.fill_heights(&BTreeMap::from([("kept".to_string(), 271), ("a".to_string(), 9)]));
        for asset in [Asset::Rd, Asset::Dfabi] {
            let got: Vec<_> = file.finalized(asset).into_iter().map(|b| (b.id, b.height)).collect();
            assert_eq!(got, vec![("a".to_string(), 5), ("kept".to_string(), 271)]);
        }
        assert_eq!(file.kept(), vec!["live".to_string()]);
    }

    /// The two pools of today's chain, empty: RD in lane 1, DFABI in lane 2.
    fn two_pools() -> PoolFile {
        PoolFile { pools: vec![entry(1, Asset::Rd, &[]), entry(2, Asset::Dfabi, &[])], carriers: BTreeMap::new() }
    }

    #[test]
    fn wallet_item_carries_sponsor_fee() {
        let bundle = BundleRef { id: "b".into(), height: 7 };
        // RD payer: spent a note of 2000, got 999 change back, paid 1000 + 1 reimbursement.
        let rd_out = item_json(Asset::Rd, &bundle, 999, 2000, None).unwrap();
        assert_eq!((rd_out["direction"].as_str(), rd_out["amount"].as_str(), rd_out["fee"].as_str()), (Some("out"), Some("1000"), Some("1")));
        // RD recipient pays no fee.
        let rd_in = item_json(Asset::Rd, &bundle, 1000, 0, None).unwrap();
        assert_eq!((rd_in["direction"].as_str(), rd_in["fee"].as_str()), (Some("in"), Some("0")));
        // Only leg 0 (RD) carries the reimbursement.
        let dfabi_out = item_json(Asset::Dfabi, &bundle, 49, 50, None).unwrap();
        assert_eq!((dfabi_out["amount"].as_str(), dfabi_out["fee"].as_str()), (Some("1"), Some("0")));
        // BI's companion RD leg (BI -> BI 1): only the fee left, so no row.
        assert!(item_json(Asset::Rd, &bundle, 1999, 2000, None).is_none());
    }

    /// Lensa runs several driver containers on one pools.json; each finishing bundle must keep the others' entries.
    #[test]
    fn concurrent_updates_keep_every_bundle() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        two_pools().save(&path).unwrap();
        let writers: Vec<_> = (0..4)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        PoolFile::update(&path, |p| Ok(p.pools[0].record.bundles.push(BundleRef { id: format!("{t}-{i}"), height: 0 }))).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert_eq!(PoolFile::load(&path).unwrap().pools[0].record.bundles.len(), 200);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A party driver starts with no bundles and learns BI's finalized list: no duplicates, its own order kept, heights filled in.
    #[test]
    fn merging_the_coordinators_finalized_bundles_adds_the_missing_ones_once() {
        let mut pools = two_pools();
        let (rd, dfabi) = (PoolKey { lane: 1, asset: Asset::Rd }, PoolKey { lane: 2, asset: Asset::Dfabi });
        pools.pools[0].record.bundles = vec![BundleRef { id: "a".into(), height: 3 }, BundleRef { id: "p".into(), height: 0 }];
        let ids: Vec<String> = ["a", "b", "p"].iter().map(|id| id.to_string()).collect();
        let heights = std::collections::BTreeMap::from([("a".to_owned(), 3), ("b".to_owned(), 5), ("p".to_owned(), 7)]);
        pools.merge_finalized(rd, &ids, &heights).unwrap();
        pools.merge_finalized(rd, &ids, &heights).unwrap();
        let merged: Vec<_> = pools.get(rd).unwrap().bundles.iter().map(|b| (b.id.as_str(), b.height)).collect();
        assert_eq!(merged, [("a", 3), ("p", 7), ("b", 5)]);
        assert!(pools.get(dfabi).unwrap().bundles.is_empty());
        pools.merge_finalized(dfabi, &["z".to_owned()], &heights).unwrap();
        let z = &pools.get(dfabi).unwrap().bundles[0];
        assert_eq!((z.id.as_str(), z.height), ("z", 0), "an unknown height stays 0");
    }

    #[test]
    fn only_finalized_bundles_are_listed() {
        let mut pools = two_pools();
        pools.pools[0].record.bundles = vec![BundleRef { id: "a".into(), height: 3 }, BundleRef { id: "inflight".into(), height: 0 }, BundleRef { id: "b".into(), height: 4 }];
        let ids: Vec<_> = pools.finalized(Asset::Rd).into_iter().map(|b| b.id).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    fn listed(id: &str) -> PoolFile {
        let mut pools = two_pools();
        for pool in pools.pools.iter_mut().map(|e| &mut e.record) {
            pool.bundles.push(BundleRef { id: id.into(), height: 0 });
        }
        pools
    }

    /// A stage failed after Prepare and the abort worked: nothing moved, so no entry stays at height 0.
    #[test]
    fn a_successful_abort_after_a_failed_stage_leaves_no_entry() {
        let failed: Result<Option<(String, u64)>> = Err(eyre!("register prepare"));
        let mut pools = listed("b");
        record_end(&mut pools, "b", &bundle_end(&failed, true));
        assert!(pools.pools.iter().all(|e| e.record.bundles.is_empty()));
    }

    #[test]
    fn a_failed_abort_keeps_the_entry_and_a_finalized_bundle_gets_its_height() {
        let failed: Result<Option<(String, u64)>> = Err(eyre!("register prepare"));
        let mut pools = listed("b");
        record_end(&mut pools, "b", &bundle_end(&failed, false));
        assert_eq!(pools.pools.iter().map(|e| e.record.bundles.len()).collect::<Vec<_>>(), [1, 1]);
        let done: Result<Option<(String, u64)>> = Ok(Some(("b".into(), 42)));
        record_end(&mut pools, "b", &bundle_end(&done, false));
        assert_eq!(pools.pools.iter().map(|e| e.record.bundles[0].height).collect::<Vec<_>>(), [42, 42]);
    }

    /// The chain knows a bundle only by its carrier tx (status, receipt view); the bundle id is not a tx hash.
    #[test]
    fn a_finalized_bundle_records_its_carrier_tx() {
        let mut pools = listed("b");
        let done: Result<Option<(String, u64)>> = Ok(Some(("c0ffee".into(), 42)));
        record_end(&mut pools, "b", &bundle_end(&done, false));
        assert_eq!(pools.carriers.get("b").map(String::as_str), Some("c0ffee"));
        let failed: Result<Option<(String, u64)>> = Err(eyre!("register prepare"));
        let mut kept = listed("k");
        record_end(&mut kept, "k", &bundle_end(&failed, false));
        assert!(kept.carriers.is_empty());
    }

    #[test]
    fn wallet_item_names_its_carrier_tx() {
        let bundle = BundleRef { id: "b".into(), height: 7 };
        let known = item_json(Asset::Rd, &bundle, 1000, 0, Some("c0ffee")).unwrap();
        assert_eq!(known["carrier_tx"].as_str(), Some("c0ffee"));
        let unknown = item_json(Asset::Rd, &bundle, 1000, 0, None).unwrap();
        assert!(unknown["carrier_tx"].is_null(), "{unknown}");
    }

    #[test]
    fn merged_carriers_fill_only_unknown_ids() {
        let mut pools = listed("a");
        pools.carriers.insert("a".into(), "x".into());
        pools.merge_carriers(&BTreeMap::from([("a".to_owned(), "y".to_owned()), ("b".to_owned(), "z".to_owned())]));
        assert_eq!(pools.carriers, BTreeMap::from([("a".to_owned(), "x".to_owned()), ("b".to_owned(), "z".to_owned())]));
    }

    fn route_hex(lane: u32) -> String {
        enc(&PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(lane)),
            lane_id: LaneId::new(lane),
            lane_incarnation: Hash::prehashed([0; 32]),
        })
        .unwrap()
    }

    fn entry(lane: u32, asset: Asset, bundles: &[(&str, u64)]) -> PoolEntry {
        let record = PoolRecord {
            pool_id: format!("{lane:02x}").repeat(32),
            route: route_hex(lane),
            policy: String::new(),
            governance: String::new(),
            origin: vec![],
            bundles: bundles.iter().map(|(id, height)| BundleRef { id: (*id).into(), height: *height }).collect(),
        };
        PoolEntry { lane, asset, record }
    }

    fn ids(bundles: Vec<BundleRef>) -> Vec<(String, u64)> {
        bundles.into_iter().map(|b| (b.id, b.height)).collect()
    }

    /// The chain's live pools.json is `{rd, dfabi, carriers}`: the lane comes from each record's route.
    #[test]
    fn legacy_pool_file_loads() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        let rd = entry(1, Asset::Rd, &[("a", 3), ("b", 0)]).record;
        let dfabi = entry(2, Asset::Dfabi, &[("a", 3)]).record;
        let legacy = serde_json::json!({ "rd": rd, "dfabi": dfabi, "carriers": { "a": "c0ffee" } });
        std::fs::write(&path, legacy.to_string()).unwrap();
        let file = PoolFile::load(&path).unwrap();
        assert_eq!(file.keys(Asset::Rd), [PoolKey { lane: 1, asset: Asset::Rd }]);
        assert_eq!(file.keys(Asset::Dfabi), [PoolKey { lane: 2, asset: Asset::Dfabi }]);
        assert_eq!(file.carriers.get("a").map(String::as_str), Some("c0ffee"));
        assert_eq!(ids(file.finalized(Asset::Rd)), [("a".to_string(), 3)]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn four_pools_roundtrip() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        let file = PoolFile {
            pools: vec![
                entry(1, Asset::Rd, &[("a", 3)]),
                entry(2, Asset::Dfabi, &[("a", 3)]),
                entry(3, Asset::Rd, &[("b", 4)]),
                entry(4, Asset::Dfabi, &[("b", 4)]),
            ],
            carriers: BTreeMap::from([("a".to_owned(), "x".to_owned())]),
        };
        file.save(&path).unwrap();
        let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["version"], 2);
        let back = PoolFile::load(&path).unwrap();
        assert_eq!(serde_json::to_value(&back.pools).unwrap(), serde_json::to_value(&file.pools).unwrap());
        assert_eq!(back.carriers, file.carriers);
        assert_eq!(back.keys(Asset::Rd), [PoolKey { lane: 1, asset: Asset::Rd }, PoolKey { lane: 3, asset: Asset::Rd }]);
        assert!(back.get(PoolKey { lane: 4, asset: Asset::Dfabi }).is_ok());
        assert!(back.get(PoolKey { lane: 4, asset: Asset::Rd }).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn finalized_unions_pools_by_height() {
        let file = PoolFile {
            pools: vec![entry(1, Asset::Rd, &[("a", 2), ("c", 6), ("live", 0)]), entry(3, Asset::Rd, &[("b", 4), ("d", 8)])],
            carriers: BTreeMap::new(),
        };
        let got = ids(file.finalized(Asset::Rd));
        assert_eq!(got, [("a".to_string(), 2), ("b".to_string(), 4), ("c".to_string(), 6), ("d".to_string(), 8)]);
        assert!(file.finalized(Asset::Dfabi).is_empty());
    }

    fn rng(seed: u64) -> rand::rngs::StdRng {
        rand::SeedableRng::seed_from_u64(seed)
    }

    /// Both orders of two activations occur: the order of the instructions in the transaction must not tell which asset is which.
    #[test]
    fn activation_order_is_shuffled() {
        let reserves = [(Asset::Rd, 5), (Asset::Dfabi, 7)];
        let mut firsts = std::collections::BTreeSet::new();
        for seed in 0..64 {
            let order = activation_order(&reserves, &mut rng(seed));
            let mut sorted = order.clone();
            sorted.sort();
            assert_eq!(sorted, reserves, "the same reserves, only reordered");
            firsts.insert(order[0].0);
        }
        assert_eq!(firsts, [Asset::Rd, Asset::Dfabi].into());
    }

    /// Unreachable Torii and no client.toml: any network use fails with another message than the ones asserted below.
    fn offline_config(dir: &Path) -> Config {
        let text = format!(
            r#"
chain = "c"
network_id_file = "/n"
account_domain = "d"
peers_json = "/p.json"
key_dir = "{dir}"
pools_file = "{dir}/pools.json"
fee_asset = "f"
auditor_url = "a:1"
[torii]
bi = "http://127.0.0.1:9"
[assets]
rd = "r"
dfabi = "d"
[lanes]
rd = 1
dfabi = 2
"#,
            dir = dir.display()
        );
        toml::from_str(&text).unwrap()
    }

    fn error_of<T>(result: Result<T>) -> String {
        format!("{:#}", result.err().expect("expected an error"))
    }

    #[test]
    fn pool_add_refuses_existing_key() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = offline_config(&dir);
        PoolFile { pools: vec![entry(1, Asset::Rd, &[])], carriers: BTreeMap::new() }.save(&cfg.pools_file).unwrap();
        let refused = error_of(pool_add(&cfg, 1, &[(Asset::Rd, 5)], &mut rng(0)));
        assert!(refused.contains("already"), "{refused}");
        // One taken key refuses the whole transaction, whatever order the reserves are listed in.
        let refused = error_of(pool_add(&cfg, 1, &[(Asset::Dfabi, 7), (Asset::Rd, 5)], &mut rng(0)));
        assert!(refused.contains("already"), "{refused}");
        // Another lane is free: it gets past the key check (and stops at the missing client.toml).
        let free = error_of(pool_add(&cfg, 2, &[(Asset::Rd, 5)], &mut rng(0)));
        assert!(!free.contains("already"), "{free}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pool_add_refuses_an_empty_or_repeated_reserve_list() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = offline_config(&dir);
        let none = error_of(pool_add(&cfg, 1, &[], &mut rng(0)));
        assert!(none.contains("no reserve"), "{none}");
        let twice = error_of(pool_add(&cfg, 1, &[(Asset::Rd, 1), (Asset::Rd, 2)], &mut rng(0)));
        assert!(twice.contains("twice"), "{twice}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pool_init_refuses_an_existing_pools_file_and_a_repeated_lane() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = offline_config(&dir);
        let plan = vec![(1, vec![(Asset::Rd, 5)]), (1, vec![(Asset::Dfabi, 7)])];
        let twice = error_of(pool_init(&cfg, &plan, &mut rng(0)));
        assert!(twice.contains("lane 1 twice"), "{twice}");
        two_pools().save(&cfg.pools_file).unwrap();
        let exists = error_of(pool_init(&cfg, &[(1, vec![(Asset::Rd, 5)])], &mut rng(0)));
        assert!(exists.contains("exists"), "{exists}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn adding_pools_creates_the_file_appends_and_refuses_a_taken_key() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        PoolFile::add(&path, vec![entry(1, Asset::Rd, &[]), entry(1, Asset::Dfabi, &[])]).unwrap();
        PoolFile::add(&path, vec![entry(2, Asset::Rd, &[])]).unwrap();
        let file = PoolFile::load(&path).unwrap();
        assert_eq!(file.keys(Asset::Rd).iter().map(|key| key.lane).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(file.keys(Asset::Dfabi).len(), 1);
        let taken = error_of(PoolFile::add(&path, vec![entry(3, Asset::Rd, &[]), entry(1, Asset::Rd, &[])]));
        assert!(taken.contains("already"), "{taken}");
        assert_eq!(PoolFile::load(&path).unwrap().pools.len(), 3, "a refused add changes nothing");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn plan(args: &str) -> Result<Vec<(u32, Vec<(Asset, u128)>)>> {
        parse_plan(&args.split_whitespace().collect::<Vec<_>>())
    }

    #[test]
    fn the_plan_groups_amounts_under_their_lane() {
        let got = plan("--lane 1 --rd 10 --dfabi 20 --lane 2 --dfabi 30").unwrap();
        assert_eq!(got, [(1, vec![(Asset::Rd, 10), (Asset::Dfabi, 20)]), (2, vec![(Asset::Dfabi, 30)])]);
    }

    #[test]
    fn a_malformed_plan_is_refused() {
        for bad in [
            "",
            "--rd 10",
            "--lane 1",
            "--lane 1 --rd 10 --rd 11",
            "--lane 1 --rd 10 --lane 1 --dfabi 5",
            "--lane 1 --rd",
            "--lane x --rd 10",
            "--lane 1 --rd ten",
            "--lane 1 --other 10",
        ] {
            assert!(plan(bad).is_err(), "{bad:?}");
        }
    }

    /// New pools keep `bi.origin-<lane>-<asset>.note`; the file of the first deployment (`bi.origin-<asset>.note`) still serves the lane it was written for.
    #[test]
    fn the_origin_note_file_falls_back_to_the_legacy_name_only_for_the_legacy_lane() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = offline_config(&dir);
        let (legacy_lane, other_lane) = (PoolKey { lane: 1, asset: Asset::Rd }, PoolKey { lane: 3, asset: Asset::Rd });
        assert_eq!(origin_note_file(&cfg, legacy_lane), dir.join("bi.origin-1-rd.note"), "nothing on disk: the new name");
        std::fs::write(dir.join("bi.origin-rd.note"), "x").unwrap();
        assert_eq!(origin_note_file(&cfg, legacy_lane), dir.join("bi.origin-rd.note"));
        assert_eq!(origin_note_file(&cfg, other_lane), dir.join("bi.origin-3-rd.note"));
        std::fs::write(dir.join("bi.origin-1-rd.note"), "y").unwrap();
        assert_eq!(origin_note_file(&cfg, legacy_lane), dir.join("bi.origin-1-rd.note"), "the new name wins");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Task 1 follow-ups.
    #[test]
    fn legacy_load_save_keeps_everything() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        let rd = entry(1, Asset::Rd, &[("a", 3), ("b", 0), ("c", 5)]).record;
        let dfabi = entry(2, Asset::Dfabi, &[("a", 3), ("c", 5)]).record;
        let legacy = serde_json::json!({ "rd": rd, "dfabi": dfabi, "carriers": { "a": "x", "c": "y" } });
        std::fs::write(&path, legacy.to_string()).unwrap();
        PoolFile::load(&path).unwrap().save(&path).unwrap();
        let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved["version"], 2);
        let back = PoolFile::load(&path).unwrap();
        let bundles = |asset| {
            let key = back.keys(asset)[0];
            back.get(key).unwrap().bundles.iter().map(|b| (b.id.clone(), b.height)).collect::<Vec<_>>()
        };
        assert_eq!(bundles(Asset::Rd), [("a".to_string(), 3), ("b".to_string(), 0), ("c".to_string(), 5)]);
        assert_eq!(bundles(Asset::Dfabi), [("a".to_string(), 3), ("c".to_string(), 5)]);
        assert_eq!(back.carriers, BTreeMap::from([("a".to_owned(), "x".to_owned()), ("c".to_owned(), "y".to_owned())]));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_v2_file_must_say_version_2_and_a_legacy_one_has_none() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pools.json");
        let pools = serde_json::to_value(two_pools().pools).unwrap();
        for (version, ok) in [(Some(2), true), (Some(3), false), (Some(1), false), (None, false)] {
            let mut file = serde_json::json!({ "pools": pools, "carriers": {} });
            if let Some(version) = version {
                file["version"] = version.into();
            }
            std::fs::write(&path, file.to_string()).unwrap();
            let loaded = PoolFile::load(&path);
            assert_eq!(loaded.is_ok(), ok, "version {version:?}");
            if let Err(err) = loaded {
                assert!(format!("{err:#}").contains("version"), "{err:#}");
            }
        }
        let rd = entry(1, Asset::Rd, &[]).record;
        let dfabi = entry(2, Asset::Dfabi, &[]).record;
        std::fs::write(&path, serde_json::json!({ "version": 2, "rd": rd, "dfabi": dfabi }).to_string()).unwrap();
        assert!(PoolFile::load(&path).is_err(), "a legacy file has no version");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn merging_into_a_key_that_names_no_pool_is_an_error() {
        let mut pools = two_pools();
        let missing = PoolKey { lane: 9, asset: Asset::Rd };
        let err = error_of(pools.merge_finalized(missing, &["a".to_owned()], &BTreeMap::new()));
        assert!(err.contains("lane 9"), "{err}");
        assert!(pools.pools.iter().all(|e| e.record.bundles.is_empty()));
    }

    #[test]
    fn finalized_lists_a_bundle_of_several_pools_once() {
        let file = PoolFile {
            pools: vec![entry(1, Asset::Rd, &[("a", 2), ("c", 6)]), entry(3, Asset::Rd, &[("c", 6), ("b", 4)])],
            carriers: BTreeMap::new(),
        };
        assert_eq!(ids(file.finalized(Asset::Rd)), [("a".to_string(), 2), ("b".to_string(), 4), ("c".to_string(), 6)]);
    }
}
