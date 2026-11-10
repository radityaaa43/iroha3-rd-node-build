//! Long-lived settlement pools: every Lensa flow is one bundle in the same two pools.
//!
//! `pool-init` activates one RD pool (ds-rd) and one DFABI pool (ds-dfabi) once, each with an
//! origin note owned by BI (its issuance reserve). Every later operation spends one live note of
//! the payer (`Spend::Continue`, path from the client-side tree) into the recipient's and the
//! payer's note keys. The pools file holds only public material (route, policy, governance,
//! origin commitments, finalized bundle ids); note openings and secrets stay in the key dir.

use std::{
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
            PrivateSettlementAuditNoteOpeningV1, PrivateSettlementHybridPublicKeyV1, PrivateSettlementReceiptV1,
            PrivateSettlementRouteV1,
        },
        privacy::{PrivacyCommitmentV1, PrivacyPoolIdV1, PrivacyProtocolIdV1},
    },
};
use iroha_crypto::{Hash, PublicKey};
use iroha_model_base::{
    metadata::Metadata,
    topology::{DataSpaceId, LaneId},
};
use serde::{Deserialize, Serialize};

use crate::{
    aps::{
        Committee, EXPIRY_BLOCKS, Governed, Leg, LegNotes, Options, SPONSOR_REIMBURSEMENT, Spend, auditor_call,
        bounded_fee, committee, dec, enc, funding_with_secret, govern_until, on_big_stack, peak_rss, prepare_leg,
        proof_manifest, rnd, settle,
    },
    auditor::Keys,
    config::{Config, signing_key},
    history::PoolHistory,
    wallet::{pick_note, scan},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

    fn name(self) -> &'static str {
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

#[derive(Serialize, Deserialize, Clone)]
pub struct PoolFile {
    pub rd: PoolRecord,
    pub dfabi: PoolRecord,
}

impl PoolFile {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Write through a temp file + rename: a crash never leaves a half-written index.
    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn get(&self, asset: Asset) -> &PoolRecord {
        match asset {
            Asset::Rd => &self.rd,
            Asset::Dfabi => &self.dfabi,
        }
    }

    fn get_mut(&mut self, asset: Asset) -> &mut PoolRecord {
        match asset {
            Asset::Rd => &mut self.rd,
            Asset::Dfabi => &mut self.dfabi,
        }
    }
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
    if let Ok(text) = std::fs::read_to_string(&file) {
        return Ok(Some(dec(text.trim())?));
    }
    match client.client().private_settlement_bundle_receipt_v1(Hash::prehashed(hex32(id)?))? {
        PrivateSettlementBundleReceiptResponseV1::Finalized(receipt) => {
            std::fs::create_dir_all(cache)?;
            let tmp = file.with_extension("tmp");
            std::fs::write(&tmp, enc(&receipt)?)?;
            std::fs::rename(tmp, &file)?;
            Ok(Some(receipt))
        }
        _ => Ok(None),
    }
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

fn origin_note_path(cfg: &Config, asset: Asset) -> PathBuf {
    cfg.key_dir.join(format!("bi.origin-{}.note", asset.name()))
}

/// BI's origin (reserve) note of a pool; other parties have none.
fn origin_notes(cfg: &Config, party: &str, asset: Asset) -> Result<Vec<PrivateSettlementAuditNoteOpeningV1>> {
    if party != "bi" {
        return Ok(Vec::new());
    }
    Ok(vec![dec(std::fs::read_to_string(origin_note_path(cfg, asset))?.trim())?])
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

fn auditor_keys(cfg: &Config) -> Result<(PublicKey, PrivateSettlementHybridPublicKeyV1)> {
    let keys: Keys = auditor_call(cfg, "GET", "/keys", "")?;
    Ok((keys.signing.parse()?, dec(&keys.encryption)?))
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

/// One-time: activate the RD and DFABI pools, each holding a BI reserve note.
pub fn pool_init(cfg: &Config, rd_reserve: u128, dfabi_reserve: u128) -> Result<()> {
    ensure!(!cfg.pools_file.exists(), "{} exists: pools are initialized once", cfg.pools_file.display());
    let (sponsor, _) = cfg.sponsor("bi")?;
    let caps = sponsor.client().get_privacy_capabilities()?;
    ensure!(
        caps.protocols.iter().any(|row| row.protocol_id == PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1 && row.activation.is_some()),
        "IVM private-note capability is not activated"
    );
    let (auditor_key, auditor_encryption) = auditor_keys(cfg)?;
    let bi = cfg.note_keys("bi")?;
    let fee = bounded_fee(cfg)?;
    let account = sponsor.account_client();
    let mut records = Vec::new();
    for (asset, reserve) in [(Asset::Rd, rd_reserve), (Asset::Dfabi, dfabi_reserve)] {
        let route = route(&sponsor, lane_of(cfg, asset))?;
        let governed = govern_until(route, asset_id(cfg, asset).parse()?, caps.committed_height, None, &auditor_key, &auditor_encryption)?;
        let funding = funding_with_secret(reserve, bi.spend)?;
        let activation = ActivatePrivateSettlementPoolV1::from_restricted(&governed.governance, funding.activation_commitments().to_vec())?;
        let tx = account
            .prepare_transaction(AccountTransactionDraft::new(vec![activation], fee.clone(), Metadata::default()))
            .and_then(|payload| account.sign_transaction(payload))
            .wrap_err("build pool activation")?;
        let hash = sponsor.submit_transaction_and_wait(&tx).wrap_err_with(|| format!("activate {} pool", asset.name()))?;
        println!("pool_activation_tx={hash} asset={}", asset.name());
        write_secret(&origin_note_path(cfg, asset), &enc(&funding.opening)?)?;
        records.push(PoolRecord {
            pool_id: hex::encode(governed.governance.body.pool_id.as_ref()),
            route: enc(&governed.route)?,
            policy: enc(&governed.policy)?,
            governance: enc(&governed.governance)?,
            origin: funding.input_commitments.iter().map(|c| hex::encode(c.as_bytes())).collect(),
            bundles: Vec::new(),
        });
    }
    let dfabi = records.pop().expect("two pools");
    let rd = records.pop().expect("two pools");
    let file = PoolFile { rd, dfabi };
    file.save(&cfg.pools_file)?;
    println!("pool_init_json={}", serde_json::json!({ "rd": file.rd.pool_id, "dfabi": file.dfabi.pool_id }));
    Ok(())
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
    let mut pools = PoolFile::load(&cfg.pools_file)?;
    let (sponsor, sponsor_key) = cfg.sponsor("bi")?;
    let mut spends = Vec::new();
    let mut governed = Vec::new();
    for (ordinal, leg) in legs.iter().enumerate() {
        let record = pools.get(leg.asset);
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
    let committees = governed
        .iter()
        .map(|g| {
            let (authority, endpoints) = committee(cfg, g.route)?;
            Ok(Committee { authority, endpoints })
        })
        .collect::<Result<Vec<_>>>()?;
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
        let spend = Spend::Continue { opening: note.opening, secret: keys.spend, tree: history.tree, epoch: history.epoch };
        let authority_digest = committees[ordinal].authority.digest()?;
        prepared.push(on_big_stack(|| {
            prepare_leg(ordinal, &spec, &governed[ordinal], spend, &notes, &manifest, authority_digest, &sponsor_key, salt)
        })?);
        println!("leg {ordinal} proved after {:?} {}", started.elapsed(), peak_rss());
    }
    let id = hex::encode(manifest.bundle_id.as_ref());
    for asset in [Asset::Rd, Asset::Dfabi] {
        pools.get_mut(asset).bundles.push(BundleRef { id: id.clone(), height: 0 });
    }
    pools.save(&cfg.pools_file)?;
    let outcome = settle(cfg, &sponsor, manifest, &prepared, &governed, &committees, started, options);
    for asset in [Asset::Rd, Asset::Dfabi] {
        let bundles = &mut pools.get_mut(asset).bundles;
        match &outcome {
            Ok(Some((_, height))) => bundles.iter_mut().filter(|b| b.id == id).for_each(|b| b.height = *height),
            // aborted (or failed and aborted): it moved nothing; a failure whose abort also failed
            // stays listed and history() reads its final state from the chain
            Ok(None) => bundles.retain(|b| b.id != id),
            Err(_) => {}
        }
    }
    pools.save(&cfg.pools_file)?;
    outcome?;
    println!("kind={kind}");
    Ok(())
}

/// `wallet --party P`: balances and per-bundle movements read from both pools on chain.
pub fn wallet(cfg: &Config, party: &str) -> Result<()> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (client, _) = cfg.sponsor(party)?;
    let keys = cfg.note_keys(party)?;
    let mut balances = serde_json::Map::new();
    let mut items = Vec::new();
    for asset in [Asset::Rd, Asset::Dfabi] {
        let history = pools.get(asset).history(&client, &receipt_cache(cfg))?;
        let (unspent, spent) = scan(&history, &keys, &origin_notes(cfg, party, asset)?)?;
        let balance: u128 = unspent.iter().map(|n| n.opening.value).sum();
        balances.insert(asset.name().into(), balance.to_string().into());
        for bundle in &pools.get(asset).bundles {
            let received: u128 = unspent
                .iter()
                .chain(spent.iter().map(|(n, _)| n))
                .filter(|n| n.bundle_id.as_deref() == Some(bundle.id.as_str()))
                .map(|n| n.opening.value)
                .sum();
            let paid: u128 = spent.iter().filter(|(_, by)| *by == bundle.id).map(|(n, _)| n.opening.value).sum();
            // The payer of the RD leg (leg 0) also reimbursed the sponsor 1.
            let fee = if asset == Asset::Rd && paid > 0 { SPONSOR_REIMBURSEMENT } else { 0 };
            let (direction, amount) = if paid > received {
                ("out", paid - received - fee)
            } else {
                ("in", received - paid)
            };
            if amount > 0 {
                items.push(serde_json::json!({
                    "bundle_id": bundle.id, "height": bundle.height, "asset": asset.name(),
                    "direction": direction, "amount": amount.to_string(),
                }));
            }
        }
    }
    items.sort_by_key(|i| std::cmp::Reverse(i["height"].as_u64()));
    println!("wallet_json={}", serde_json::json!({ "party": party, "balances": balances, "items": items }));
    Ok(())
}

/// Debug aid for gate G3: rebuild one pool and print its head (no amounts).
pub fn pool_history(cfg: &Config, asset: Asset) -> Result<()> {
    let pools = PoolFile::load(&cfg.pools_file)?;
    let (client, _) = cfg.sponsor("bi")?;
    let history = pools.get(asset).history(&client, &receipt_cache(cfg))?;
    println!(
        "pool_history asset={} epoch={} leaves={} root={}",
        asset.name(),
        history.epoch,
        history.tree.len(),
        hex::encode(history.root().as_bytes())
    );
    Ok(())
}


/// Abort a stuck bundle (prepared but never registered) to release the pool reservations.
pub fn abort_bundle(cfg: &Config, bundle: &str) -> Result<()> {
    let (sponsor, _) = cfg.sponsor("bi")?;
    let status = sponsor.client().private_settlement_bundle_status_v1(Hash::prehashed(hex32(bundle)?))?;
    let manifest = status.manifest.ok_or_else(|| eyre!("the node retains no manifest for this bundle"))?;
    crate::aps::abort_bundle(cfg, sponsor.client(), &manifest)?;
    println!("aborted bundle={bundle}");
    Ok(())
}
