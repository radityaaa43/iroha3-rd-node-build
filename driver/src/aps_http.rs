//! APS HTTP side of a per-org driver (plan 2026-11-13-04, task T2).
//!
//! `POST /aps/intent`, `POST /aps/address`, `POST /aps/leg`, `POST /aps/capacity`, `GET /aps/wallet` and `POST /aps/submit`. A leg is
//! split per key holder: the recipient signs its own output authorization (`/aps/address`), the payer proves its own leg (`/aps/leg`,
//! only after the one-shot intent that its Lensa registered with `/aps/intent`), and BI (`[aps] coordinator`) walks the parties
//! through one bundle at a time (`/aps/submit`): it asks the payers what each pool can carry (`/aps/capacity`), plans the two pools
//! (`plan`), then collects addresses and legs. Every other driver forwards its `/aps/submit` to BI over the mTLS client. Nothing secret is read from a request or
//! written to a response: all chain, proving and key work sits behind `ApsBackend`, all calls to another party behind `Peer`.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Mutex,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    config::{ApsConfig, TlsConfig},
    dvp_native, http,
    plan::{self, Capacity, PlanError, Request},
    pools::{Asset, PoolKey},
};

/// How long a registered intent stays usable (a restart forgets all of them: Lensa repeats the flow).
pub const INTENT_TTL: Duration = Duration::from_secs(15 * 60);

/// Body of `POST /aps/address` (coordinator -> recipient). Also the context of the sponsor's output 2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressReq {
    pub bundle_id: String,
    pub pool_id: String,
    pub leg_ordinal: u8,
    /// norito hex (`aps::enc`).
    pub route: String,
    pub expiry_height: u64,
    /// The canonical `NetworkId` text literal (`hash:<HEX>#<CHECKSUM>`).
    pub network_id: String,
}

/// An output's key material: the answer of `/aps/address`, and the recipient output inside a `/aps/leg` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputKey {
    pub authority: String,
    pub view_public: String,
    /// norito hex of `PrivateSettlementAuditViewKeyAuthorizationV1`.
    pub authorization: String,
}

/// The sponsor's output 2 inside a `/aps/leg` body; `active` only on the leg that pays the reimbursement (leg 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorOutput {
    pub authority: String,
    pub view_public: String,
    pub authorization: String,
    pub active: bool,
}

/// Body of `POST /aps/leg` (coordinator -> payer). The backend gets it after the intent was matched and consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegReq {
    pub intent: String,
    /// Legs are sorted by lane: leg 0 (the lowest lane) also pays the sponsor's reimbursement.
    pub ordinal: u8,
    /// The pool of this leg.
    pub lane: u32,
    /// "rd" or "dfabi".
    pub asset: String,
    /// norito hex of `AtomicPrivateSettlementV1`.
    pub manifest: String,
    pub authority_digest: String,
    pub salt: String,
    pub recipient: String,
    pub amount: String,
    pub recipient_output: OutputKey,
    pub sponsor_output: SponsorOutput,
}

/// The finalized bundles of both pools, as the coordinator records them (`GET /aps/bundles`): ids in ledger order, plus their heights.
/// A party driver rebuilds a pool's history from the chain by bundle id; the coordinator is the only one that records them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleLists {
    pub rd: Vec<String>,
    pub dfabi: Vec<String>,
    /// bundle id -> finalized height, for the wallet's rows; absent = unknown (0).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub heights: BTreeMap<String, u64>,
    /// bundle id -> its finalization carrier tx, where the coordinator recorded it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub carriers: BTreeMap<String, String>,
}

/// What `begin_bundle` fixed for the whole bundle (everything the parties need to sign and prove against).
#[derive(Debug, Clone)]
pub struct BundleCtx {
    pub bundle_id: String,
    /// norito hex of `AtomicPrivateSettlementV1`.
    pub manifest: String,
    pub salt: String,
    pub expiry_height: u64,
    pub network_id: String,
    pub legs: [LegCtx; 2],
}

#[derive(Debug, Clone)]
pub struct LegCtx {
    pub pool_id: String,
    pub route: String,
    pub authority_digest: String,
    pub lane: u32,
    pub asset: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub carrier_tx: String,
    pub height: u64,
}

/// Everything that touches keys, the chain or the prover. The real one calls the split-leg API of `aps_split` (T1); tests inject a fake.
pub trait ApsBackend: Send + Sync {
    /// The own account's public key (`ed0120...`), from the own seed.
    fn own_key(&self) -> Result<String>;
    /// Recipient side: sign the output-0 authorization with the own seed.
    fn address(&self, req: &AddressReq) -> Result<OutputKey>;
    /// Coordinator side: the sponsor's output 2 for this leg (`ctx` as for `address`).
    fn sponsor_output(&self, ctx: &AddressReq, active: bool) -> Result<SponsorOutput>;
    /// What the own party can spend from each pool of `asset`, by lane (`POST /aps/capacity`, and the coordinator's own).
    fn capacity(&self, asset: Asset) -> Result<Vec<(u32, Capacity)>>;
    /// Coordinator side: build the bundle manifest over the two planned pools (sorted by lane).
    fn begin_bundle(&self, keys: [PoolKey; 2]) -> Result<BundleCtx>;
    /// Payer side: scan the own notes, pick one, prove the leg; returns the prepared leg as `statement.proof.capsule` (each hex:
    /// `AtomicPrivateSettlementPreparedLegV1` has no norito codec upstream).
    /// The intent is already consumed; `req.intent` is empty for the coordinator's own BI -> BI companion leg.
    fn prove_leg(&self, req: &LegReq) -> Result<String>;
    /// Payer side, before the intent is spent: whether `req.lane`/`req.asset` name the pool the manifest has at `req.ordinal`.
    fn is_leg_pool(&self, req: &LegReq) -> Result<bool>;
    /// Coordinator side: audit quorum, prepare, commit. `None` = the bundle was aborted (nothing moved).
    fn settle(&self, bundle: &BundleCtx, prepared: &[String; 2]) -> Result<Option<Settled>>;
    /// Coordinator side: the finalized bundles of both pools (height > 0) from its pools file.
    fn bundles(&self) -> Result<BundleLists>;
    /// Party side: merge the coordinator's finalized bundles into the own pools file (no duplicates, own entries kept).
    fn merge_bundles(&self, lists: &BundleLists) -> Result<()>;
    /// The own `wallet_json`.
    fn wallet(&self) -> Result<serde_json::Value>;
    /// Coordinator start: carry every bundle a previous run left in flight to its end (`pools::resume_all`).
    fn resume_all(&self) -> Result<()>;
}

/// One HTTP call to another party's gateway; `target` is a base URL, the answer `(status, body)`.
pub trait Peer: Send + Sync {
    fn call(&self, target: &str, method: &str, path: &str, body: &str) -> Result<(u16, String)>;
}

/// Public terms a driver approved for one leg it pays. `to` is lower-cased, `asset` is "rd" or "dfabi".
#[derive(Debug, Clone, PartialEq, Eq)]
struct IntentTerms {
    asset: String,
    to: String,
    amount: u128,
}

enum Slot {
    /// The approved terms, the amount no leg has spent yet and the `(ordinal, lane)` of the legs taken. A split pay spends one intent
    /// over two legs: leg 0 and leg 1, each in its own lane, so the payer pays the sponsor's reimbursement (leg 0) at most once.
    Open(IntentTerms, u128, Vec<(u8, u32)>),
    Used,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Take {
    Taken,
    Missing,
    Mismatch,
}

/// In-memory one-shot intents. A used intent stays listed (as `Used`) until its TTL ends, so it cannot be registered again.
#[derive(Default)]
struct IntentStore {
    slots: Mutex<HashMap<String, (Slot, Instant)>>,
}

impl IntentStore {
    /// `false` = the intent is known with other terms, or already used.
    fn put(&self, now: Instant, intent: &str, terms: IntentTerms) -> bool {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.retain(|_, (_, expires)| *expires > now);
        let known = match slots.get(intent) {
            Some((Slot::Open(old, _, _), _)) => Some(*old == terms),
            Some((Slot::Used, _)) => Some(false),
            None => None,
        };
        match known {
            Some(same) => same,
            None => {
                let amount = terms.amount;
                slots.insert(intent.to_owned(), (Slot::Open(terms, amount, Vec::new()), now + INTENT_TTL));
                true
            }
        }
    }

    /// Spend `leg.amount` of the intent when asset and recipient match, that much is left, and no taken leg had this ordinal or
    /// this lane; spent in full, it is used. A refused leg spends nothing.
    fn take(&self, now: Instant, intent: &str, leg: &IntentTerms, ordinal: u8, lane: u32) -> Take {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.retain(|_, (_, expires)| *expires > now);
        let Some((slot, _)) = slots.get_mut(intent) else {
            return Take::Missing;
        };
        let Slot::Open(terms, left, taken) = slot else {
            return Take::Missing;
        };
        let reused = taken.iter().any(|&(o, l)| o == ordinal || l == lane);
        if terms.asset != leg.asset || terms.to != leg.to || leg.amount > *left || reused {
            return Take::Mismatch;
        }
        taken.push((ordinal, lane));
        *left -= leg.amount;
        if *left == 0 {
            *slot = Slot::Used;
        }
        Take::Taken
    }
}

/// Body of `POST /aps/intent`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentReq {
    intent: String,
    asset: String,
    to: String,
    amount: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    prepared: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayReq {
    #[serde(rename = "kind")]
    _kind: String,
    intent: String,
    asset: String,
    from: String,
    to: String,
    amount: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DvpReq {
    #[serde(rename = "kind")]
    _kind: String,
    intent_rd: String,
    intent_dfabi: String,
    buyer: String,
    seller: String,
    rd: String,
    dfabi: String,
}

/// Body of `POST /aps/capacity` (coordinator -> party).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityReq {
    asset: Asset,
}

/// One pool of a `/aps/capacity` answer; amounts are decimal strings.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityRow {
    lane: u32,
    two_notes: String,
    total: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapacityAnswer {
    pools: Vec<CapacityRow>,
}

/// `(HTTP status, JSON body)`.
type Reply = (u16, String);

fn reply(status: u16, value: serde_json::Value) -> Reply {
    (status, value.to_string())
}

fn error(status: u16, message: impl Into<String>) -> Reply {
    let message: String = message.into();
    reply(status, serde_json::json!({ "error": message }))
}

fn ok<T: Serialize>(value: &T) -> Reply {
    (200, serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned()))
}

/// A backend error for a response: never a key file name (a missing `<party>.seed` or `.note` error names its path).
fn safe(e: &eyre::Report) -> String {
    let text = format!("{e:#}");
    if [".seed", ".note", ".hybrid", "client.toml"].iter().any(|name| text.contains(*name)) {
        eprintln!("aps error (not sent to the caller): {text}");
        return "key material unavailable".to_owned();
    }
    text
}

fn fail(e: eyre::Report) -> Reply {
    error(502, safe(&e))
}

fn parse<T: DeserializeOwned>(body: &str) -> Result<T, Reply> {
    serde_json::from_str(body).map_err(|e| error(400, format!("bad request body: {e}")))
}

fn hex_n(text: &str, bytes: usize) -> bool {
    text.len() == 2 * bytes && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex_any(text: &str) -> bool {
    !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Public keys and ids are hex: compare them case-insensitively.
fn norm(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn check_key(authority: &str, view_public: &str, authorization: &str) -> Result<()> {
    ensure!(
        hex_n(authority, 32) && hex_n(view_public, 32) && hex_any(authorization),
        "authority and view_public are 64 hex characters, authorization is hex"
    );
    Ok(())
}

fn check_intent(req: &IntentReq) -> Result<(String, IntentTerms)> {
    ensure!(hex_n(&req.intent, 32), "intent must be 64 hex characters");
    ensure!(matches!(req.asset.as_str(), "rd" | "dfabi"), "asset must be rd or dfabi");
    dvp_native::parse_account(&req.to)?;
    let amount = dvp_native::parse_amount(&req.amount)?;
    Ok((norm(&req.intent), IntentTerms { asset: req.asset.clone(), to: norm(&req.to), amount }))
}

fn check_address(req: &AddressReq) -> Result<()> {
    ensure!(hex_n(&req.bundle_id, 32) && hex_n(&req.pool_id, 32), "bundle_id and pool_id must be 64 hex characters");
    ensure!(req.leg_ordinal < 2, "leg_ordinal must be 0 or 1");
    ensure!(hex_any(&req.route), "route must be hex");
    ensure!(!req.network_id.is_empty() && req.network_id.len() <= 200, "network_id must be the canonical text literal");
    Ok(())
}

/// Returns the amount.
fn check_leg(req: &LegReq) -> Result<u128> {
    ensure!(hex_n(&req.intent, 32), "intent must be 64 hex characters");
    ensure!(req.ordinal < 2, "ordinal must be 0 or 1");
    Asset::parse(&req.asset)?;
    ensure!(hex_any(&req.manifest), "manifest must be hex");
    ensure!(hex_n(&req.authority_digest, 32) && hex_n(&req.salt, 32), "authority_digest and salt must be 64 hex characters");
    dvp_native::parse_account(&req.recipient)?;
    let amount = dvp_native::parse_amount(&req.amount)?;
    check_key(&req.recipient_output.authority, &req.recipient_output.view_public, &req.recipient_output.authorization)?;
    check_key(&req.sponsor_output.authority, &req.sponsor_output.view_public, &req.sponsor_output.authorization)?;
    Ok(amount)
}

/// A submit body, checked; `plan` turns it into two legs.
fn parse_submit(body: &str) -> Result<Request> {
    let value: serde_json::Value = serde_json::from_str(body).wrap_err("bad request body")?;
    let kind = value.get("kind").and_then(|kind| kind.as_str()).map(str::to_owned);
    match kind.as_deref() {
        Some("pay") => {
            let req: PayReq = serde_json::from_value(value).wrap_err("bad pay body")?;
            ensure!(hex_n(&req.intent, 32), "intent must be 64 hex characters");
            let asset = Asset::parse(&req.asset).map_err(|_| eyre::eyre!("asset must be rd or dfabi"))?;
            dvp_native::parse_account(&req.from)?;
            dvp_native::parse_account(&req.to)?;
            ensure!(norm(&req.from) != norm(&req.to), "from and to must differ");
            let amount = dvp_native::parse_amount(&req.amount)?;
            Ok(Request::Pay { asset, from: req.from, to: req.to, amount, intent: norm(&req.intent) })
        }
        Some("dvp") => {
            let req: DvpReq = serde_json::from_value(value).wrap_err("bad dvp body")?;
            ensure!(hex_n(&req.intent_rd, 32) && hex_n(&req.intent_dfabi, 32), "intent_rd and intent_dfabi must be 64 hex characters");
            dvp_native::parse_account(&req.buyer)?;
            dvp_native::parse_account(&req.seller)?;
            ensure!(norm(&req.buyer) != norm(&req.seller), "buyer and seller must differ");
            let (rd, dfabi) = (dvp_native::parse_amount(&req.rd)?, dvp_native::parse_amount(&req.dfabi)?);
            Ok(Request::Dvp {
                buyer: req.buyer,
                seller: req.seller,
                rd,
                dfabi,
                intent_rd: norm(&req.intent_rd),
                intent_dfabi: norm(&req.intent_dfabi),
            })
        }
        _ => bail!("kind must be pay or dvp"),
    }
}

/// The text of a peer's `{"error": ...}` answer, short; empty when it has none.
fn peer_error(body: &str) -> String {
    let text = serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned));
    text.unwrap_or_default().chars().take(200).collect()
}

/// The `/aps/*` handlers of one driver.
pub struct Aps<'a> {
    backend: &'a dyn ApsBackend,
    peer: &'a dyn Peer,
    cfg: ApsConfig,
    intents: IntentStore,
    /// The coordinator's global mutex: the pool is serial (`old_root` must be the current root), so one bundle at a time.
    submit_lock: Mutex<()>,
    /// One own proof at a time, the coordinator's own legs and every `/aps/leg` alike (a split pay asks one payer for two legs):
    /// a proof peaks at about 1.1 GB, two would crowd the driver's memory limit.
    prove_lock: Mutex<()>,
}

impl<'a> Aps<'a> {
    pub fn new(backend: &'a dyn ApsBackend, peer: &'a dyn Peer, cfg: ApsConfig) -> Self {
        Self { backend, peer, cfg, intents: IntentStore::default(), submit_lock: Mutex::new(()), prove_lock: Mutex::new(()) }
    }

    /// Coordinator start: the bundles a previous run left in flight finish before any new submit (`submit_lock`). `locked` runs
    /// once the lock is held, so the caller starts serving only then (`/healthz` answers meanwhile).
    pub fn resume(&self, locked: impl FnOnce()) {
        let _one_bundle_at_a_time = self.submit_lock.lock().unwrap_or_else(|p| p.into_inner());
        locked();
        if let Err(e) = self.backend.resume_all() {
            eprintln!("resume failed: {}", safe(&e));
        }
    }

    /// Answer one `/aps/*` request: `(HTTP status, JSON body)`.
    pub fn route(&self, method: &str, path: &str, body: &str) -> Reply {
        self.route_at(Instant::now(), method, path, body)
    }

    /// `route` with the clock injected (intent TTL).
    pub fn route_at(&self, now: Instant, method: &str, path: &str, body: &str) -> Reply {
        match (method, path) {
            ("POST", "/aps/intent") => self.intent(now, body),
            ("POST", "/aps/address") => self.address(body),
            ("POST", "/aps/leg") => self.leg(now, body),
            ("POST", "/aps/capacity") => self.capacity(body),
            ("GET", "/aps/wallet") => self.wallet(),
            ("GET", "/aps/bundles") => self.bundles(),
            ("POST", "/aps/submit") => self.submit(now, body),
            (_, "/aps/intent" | "/aps/address" | "/aps/leg" | "/aps/capacity" | "/aps/wallet" | "/aps/bundles" | "/aps/submit") => {
                error(405, "method not allowed")
            }
            _ => error(404, "not found"),
        }
    }

    fn intent(&self, now: Instant, body: &str) -> Reply {
        let req: IntentReq = match parse(body) {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let (intent, terms) = match check_intent(&req) {
            Ok(checked) => checked,
            Err(e) => return error(400, format!("{e:#}")),
        };
        if self.intents.put(now, &intent, terms) {
            reply(200, serde_json::json!({ "intent": intent }))
        } else {
            error(409, "this intent is already registered with other terms, or already used")
        }
    }

    fn address(&self, body: &str) -> Reply {
        let req: AddressReq = match parse(body) {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        if let Err(e) = check_address(&req) {
            return error(400, format!("{e:#}"));
        }
        match self.backend.address(&req) {
            Ok(key) => ok(&key),
            Err(e) => fail(e),
        }
    }

    fn leg(&self, now: Instant, body: &str) -> Reply {
        let req: LegReq = match parse(body) {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        let amount = match check_leg(&req) {
            Ok(amount) => amount,
            Err(e) => return error(400, format!("{e:#}")),
        };
        match self.backend.is_leg_pool(&req) {
            Ok(true) => {}
            Ok(false) => return error(400, "lane and asset do not name the manifest's pool for this leg"),
            Err(e) => return fail(e),
        }
        if let Err(reply) = self.consume(now, &req, amount) {
            return reply;
        }
        if let Err(reply) = self.refresh() {
            return reply;
        }
        let _one_own_proof = self.prove_lock.lock().unwrap_or_else(|p| p.into_inner());
        match self.backend.prove_leg(&req) {
            Ok(prepared) => ok(&Prepared { prepared }),
            Err(e) => fail(e),
        }
    }

    /// Match the leg against the intent this driver registered and spend it, before any proving.
    fn consume(&self, now: Instant, req: &LegReq, amount: u128) -> Result<(), Reply> {
        let terms = IntentTerms { asset: req.asset.clone(), to: norm(&req.recipient), amount };
        match self.intents.take(now, &norm(&req.intent), &terms, req.ordinal, req.lane) {
            Take::Taken => Ok(()),
            Take::Missing => Err(error(403, "no open intent for this leg (unknown, already used or expired)")),
            Take::Mismatch => Err(error(403, "the intent's terms do not match this leg")),
        }
    }

    /// What the own party can spend per pool of an asset, on a fresh pool history (only the coordinator asks; gateway policy).
    fn capacity(&self, body: &str) -> Reply {
        let req: CapacityReq = match parse(body) {
            Ok(req) => req,
            Err(reply) => return reply,
        };
        if let Err(reply) = self.refresh() {
            return reply;
        }
        match self.backend.capacity(req.asset) {
            Ok(pools) => ok(&CapacityAnswer {
                pools: pools
                    .into_iter()
                    .map(|(lane, cap)| CapacityRow { lane, two_notes: cap.two_notes.to_string(), total: cap.total.to_string() })
                    .collect(),
            }),
            Err(e) => fail(e),
        }
    }

    fn wallet(&self) -> Reply {
        if let Err(reply) = self.refresh() {
            return reply;
        }
        match self.backend.wallet() {
            Ok(wallet) => reply(200, wallet),
            Err(e) => fail(e),
        }
    }

    /// Only the coordinator has the list (a party driver answers 404).
    fn bundles(&self) -> Reply {
        if !self.cfg.coordinator {
            return error(404, "not found");
        }
        match self.backend.bundles() {
            Ok(lists) => ok(&lists),
            Err(e) => fail(e),
        }
    }

    /// A party driver's pool history needs every finalized bundle of the pools, but only the coordinator records them: take its list
    /// (merged into the own pools file) before proving a leg or reading the wallet. Integrity stays on chain: `history()` trusts only
    /// bundles whose finalized receipt it reads from the chain. No fresh list = no proving on a stale history.
    fn refresh(&self) -> Result<(), Reply> {
        if self.cfg.coordinator {
            return Ok(());
        }
        let Some(url) = &self.cfg.coordinator_url else {
            return Err(error(503, "this driver has no [aps] coordinator_url to read the finalized bundles from"));
        };
        let (status, answer) = self.peer.call(url, "GET", "/aps/bundles", "").map_err(|e| error(502, format!("/aps/bundles: {}", safe(&e))))?;
        if status != 200 {
            return Err(error(502, format!("/aps/bundles refused by the coordinator ({status}): {}", peer_error(&answer))));
        }
        let lists: BundleLists = serde_json::from_str(&answer).map_err(|e| error(502, format!("/aps/bundles: bad answer: {e}")))?;
        if !lists.rd.iter().chain(&lists.dfabi).all(|id| hex_n(id, 32)) {
            return Err(error(502, "/aps/bundles: bad bundle id"));
        }
        self.backend.merge_bundles(&lists).map_err(fail)
    }

    fn submit(&self, now: Instant, body: &str) -> Reply {
        let req = match parse_submit(body) {
            Ok(req) => req,
            Err(e) => return error(400, format!("{e:#}")),
        };
        if !self.cfg.coordinator {
            return self.forward(body);
        }
        let _one_bundle_at_a_time = self.submit_lock.lock().unwrap_or_else(|p| p.into_inner());
        match self.coordinate(now, &req) {
            Ok(reply) | Err(reply) => reply,
        }
    }

    /// A non-coordinator hands the body, unchanged, to BI and returns BI's answer.
    fn forward(&self, body: &str) -> Reply {
        let Some(url) = &self.cfg.coordinator_url else {
            return error(503, "this driver is not the coordinator and has no [aps] coordinator_url");
        };
        match self.peer.call(url, "POST", "/aps/submit", body) {
            Ok(answer) => answer,
            Err(e) => fail(e),
        }
    }

    /// The gateway of the party holding `key`.
    fn gateway(&self, key: &str) -> Result<&str, Reply> {
        let known = self.cfg.peers.iter().find(|(peer, _)| norm(peer) == norm(key));
        known.map(|(_, url)| url.as_str()).ok_or_else(|| error(400, format!("no [aps.peers] gateway for account {key}")))
    }

    /// POST to a party's gateway and read its 200 answer; a refusal (403) is passed on as 403, anything else is 502.
    fn ask<T: DeserializeOwned, B: Serialize>(&self, key: &str, path: &str, body: &B) -> Result<T, Reply> {
        let target = self.gateway(key)?;
        let text = serde_json::to_string(body).map_err(|e| error(500, e.to_string()))?;
        let (status, answer) = self.peer.call(target, "POST", path, &text).map_err(|e| error(502, format!("{path}: {}", safe(&e))))?;
        if status != 200 {
            let code = if status == 403 { 403 } else { 502 };
            return Err(error(code, format!("{path} refused by the party ({status}): {}", peer_error(&answer))));
        }
        serde_json::from_str(&answer).map_err(|e| error(502, format!("{path}: bad answer: {e}")))
    }

    /// One leg's proof: the coordinator proves its own leg, any other payer proves it on its driver.
    fn prove(&self, local: bool, payer: &str, req: &LegReq) -> Result<String, Reply> {
        if local {
            let _one_own_proof = self.prove_lock.lock().unwrap_or_else(|p| p.into_inner());
            return self.backend.prove_leg(req).map_err(fail);
        }
        let answer: Prepared = self.ask(payer, "/aps/leg", req)?;
        if !answer.prepared.split('.').all(hex_any) {
            return Err(error(502, "/aps/leg: bad answer"));
        }
        Ok(answer.prepared)
    }

    /// What `who` (`None` = this coordinator) can spend from each pool of `asset`, by lane.
    fn capacity_of(&self, who: Option<&str>, asset: Asset) -> Result<Vec<(u32, Capacity)>, Reply> {
        let Some(key) = who else {
            return self.backend.capacity(asset).map_err(fail);
        };
        let answer: CapacityAnswer = self.ask(key, "/aps/capacity", &CapacityReq { asset })?;
        let row = |row: &CapacityRow| Ok::<_, std::num::ParseIntError>((row.lane, Capacity { two_notes: row.two_notes.parse()?, total: row.total.parse()? }));
        answer.pools.iter().map(row).collect::<Result<_, _>>().map_err(|e| error(502, format!("/aps/capacity: bad answer: {e}")))
    }

    /// One bundle: the payers' capacities and the plan, the manifest, then per leg the recipient's address, the sponsor's output
    /// and the payer's proof, then settle.
    fn coordinate(&self, now: Instant, req: &Request) -> Result<Reply, Reply> {
        let me = self.backend.own_key().map_err(fail)?;
        let is_me = |key: &str| norm(key) == norm(&me);
        let other = |key: &String| (!is_me(key)).then(|| key.clone());
        // The capacities `plan` reads: each payer's; for a pay also BI's (the companion) and, for an issuance, the recipient's.
        let (accounts, mut asked) = match req {
            Request::Pay { asset, from, to, .. } => {
                let mut asked = vec![(None, *asset), (other(from), *asset)];
                if other(from).is_none() {
                    asked.push((other(to), *asset));
                }
                ([from, to], asked)
            }
            Request::Dvp { buyer, seller, .. } => ([buyer, seller], vec![(other(buyer), Asset::Rd), (other(seller), Asset::Dfabi)]),
        };
        // Unknown parties are refused before anything is asked or prepared.
        for key in accounts {
            if !is_me(key) {
                self.gateway(key)?;
            }
        }
        asked.dedup();
        let mut caps = HashMap::new();
        let mut lanes = BTreeSet::new();
        for (who, asset) in asked {
            for (lane, cap) in self.capacity_of(who.as_deref(), asset)? {
                lanes.insert(lane);
                caps.insert((who.as_deref().map(norm), PoolKey { lane, asset }), cap);
            }
        }
        let lanes: [u32; 2] = Vec::from_iter(lanes).try_into().map_err(|_| error(502, "/aps/capacity: the pools are not in exactly two lanes"))?;
        let cap = |who: Option<&str>, key: PoolKey| caps.get(&(who.map(norm), key)).copied().unwrap_or_default();
        let legs = plan::plan(req, &me, lanes, &cap, &mut rand::rng()).map_err(|PlanError::Insufficient(message)| error(422, message))?;
        let party = |key: &Option<String>| key.clone().unwrap_or_else(|| me.clone());
        let bundle = self.backend.begin_bundle([legs[0].key, legs[1].key]).map_err(fail)?;
        // Per leg, in order: the recipient's address, the sponsor's output and, for a leg the coordinator pays, its intent.
        // Nothing is proved before both legs are ready, so a refused intent costs no proving.
        let mut jobs = Vec::new();
        for (index, spec) in legs.iter().enumerate() {
            let ordinal = index as u8;
            let ctx = AddressReq {
                bundle_id: bundle.bundle_id.clone(),
                pool_id: bundle.legs[index].pool_id.clone(),
                leg_ordinal: ordinal,
                route: bundle.legs[index].route.clone(),
                expiry_height: bundle.expiry_height,
                network_id: bundle.network_id.clone(),
            };
            let (payer, recipient) = (party(&spec.payer), party(&spec.recipient));
            let recipient_output = if is_me(&recipient) {
                self.backend.address(&ctx).map_err(fail)?
            } else {
                let key: OutputKey = self.ask(&recipient, "/aps/address", &ctx)?;
                check_key(&key.authority, &key.view_public, &key.authorization).map_err(|e| error(502, format!("/aps/address: bad answer: {e:#}")))?;
                key
            };
            let sponsor_output = self.backend.sponsor_output(&ctx, ordinal == 0).map_err(fail)?;
            let req = LegReq {
                intent: spec.intent.clone().unwrap_or_default(),
                ordinal,
                lane: bundle.legs[index].lane,
                asset: bundle.legs[index].asset.clone(),
                manifest: bundle.manifest.clone(),
                authority_digest: bundle.legs[index].authority_digest.clone(),
                salt: bundle.salt.clone(),
                recipient,
                amount: spec.amount.to_string(),
                recipient_output,
                sponsor_output,
            };
            let local = is_me(&payer);
            // A leg BI pays itself needs BI's own intent like any other payer's; only the companion has none.
            if local && spec.intent.is_some() {
                self.consume(now, &req, spec.amount)?;
            }
            jobs.push((local, payer, req));
        }
        // The two proofs are independent (two pools, each leg proved by its payer, which takes one own proof at a time): run them at
        // the same time. Both are joined; the first failing leg in leg order is the answer.
        let prepared = std::thread::scope(|scope| {
            let running: Vec<_> = jobs.iter().map(|(local, payer, req)| scope.spawn(move || self.prove(*local, payer, req))).collect();
            let done: Vec<_> = running.into_iter().map(|job| job.join().unwrap_or_else(|_| Err(error(500, "leg prover panicked")))).collect();
            done.into_iter().collect::<Result<Vec<_>, Reply>>()
        })?;
        let settled = self.backend.settle(&bundle, &[prepared[0].clone(), prepared[1].clone()]).map_err(fail)?;
        Ok(match settled {
            Some(done) => reply(200, serde_json::json!({ "outcome": "finalized", "bundle_id": bundle.bundle_id, "carrier_tx": done.carrier_tx, "height": done.height })),
            None => reply(200, serde_json::json!({ "outcome": "aborted", "bundle_id": bundle.bundle_id, "carrier_tx": null, "height": null })),
        })
    }
}

/// The real peer: `https://gateway...` over mutual TLS with the driver's leaf certificate (`tls_http`).
pub struct RealPeer {
    pub tls: Option<TlsConfig>,
}

impl Peer for RealPeer {
    fn call(&self, target: &str, method: &str, path: &str, body: &str) -> Result<(u16, String)> {
        // A bank waits for the whole bundle (about 100-200 s, route timeout 600 s), BI for a payer's proof.
        http::send(self.tls.as_ref(), target, method, path, body, None, Duration::from_secs(660))
    }
}

/// Fakes for the APS HTTP tests (this file's and `server.rs`'s): no chain, no proving, no network.
#[cfg(test)]
pub(crate) mod testkit {
    use std::{
        collections::BTreeMap,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::*;

    /// A distinct valid account public key per `n`.
    pub(crate) fn account(n: u8) -> String {
        crate::config::signing_key(&[n; 32]).public_key().to_string()
    }

    /// 32 bytes of `n`, as 64 lowercase hex characters.
    pub(crate) fn id(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    /// What the coordinator lists as finalized: two RD bundles, one of them also in the DFABI pool.
    pub(crate) fn lists() -> BundleLists {
        BundleLists { rd: vec![id(0xa1), id(0xa2)], dfabi: vec![id(0xa1)], heights: BTreeMap::from([(id(0xa1), 5), (id(0xa2), 9)]), ..Default::default() }
    }

    #[derive(Default)]
    pub(crate) struct FakeBackend {
        /// The own account key `own_key` answers.
        pub me: String,
        /// Every call that reached the backend, in order (`own_key` is not listed).
        pub calls: Mutex<Vec<&'static str>>,
        /// `Some(message)` = address, sponsor_output, begin_bundle, prove_leg, settle and wallet all fail with it.
        pub error: Option<String>,
        /// `settle` answers "aborted".
        pub aborts: bool,
        pub settle_delay: Duration,
        /// How long `prove_leg` takes.
        pub prove_delay: Duration,
        pub proving: AtomicUsize,
        pub max_proving: AtomicUsize,
        /// What `bundles` answers (coordinator).
        pub lists: BundleLists,
        /// Every list `merge_bundles` was given (party driver).
        pub merged: Mutex<Vec<BundleLists>>,
        pub active: AtomicUsize,
        pub max_active: AtomicUsize,
        /// What `capacity` answers for either asset; empty = 1000 in lanes 1 and 2.
        pub caps: Vec<(u32, Capacity)>,
        /// `is_leg_pool` answers false: the leg's lane/asset are not the manifest's pool.
        pub foreign_pool: AtomicBool,
        /// How long `resume_all` takes.
        pub resume_delay: Duration,
    }

    impl FakeBackend {
        fn note(&self, call: &'static str) -> Result<()> {
            self.calls.lock().unwrap().push(call);
            match &self.error {
                Some(message) => Err(eyre::eyre!("{message}")),
                None => Ok(()),
            }
        }
    }

    fn key() -> OutputKey {
        OutputKey { authority: id(0x11), view_public: id(0x22), authorization: "abcd".to_owned() }
    }

    impl ApsBackend for FakeBackend {
        fn own_key(&self) -> Result<String> {
            Ok(self.me.clone())
        }

        fn address(&self, _req: &AddressReq) -> Result<OutputKey> {
            self.note("address")?;
            Ok(key())
        }

        fn sponsor_output(&self, _ctx: &AddressReq, active: bool) -> Result<SponsorOutput> {
            self.note("sponsor_output")?;
            let key = key();
            Ok(SponsorOutput { authority: key.authority, view_public: key.view_public, authorization: key.authorization, active })
        }

        fn capacity(&self, _asset: Asset) -> Result<Vec<(u32, Capacity)>> {
            self.note("capacity")?;
            let plenty = Capacity { two_notes: 1000, total: 1000 };
            Ok(if self.caps.is_empty() { vec![(1, plenty), (2, plenty)] } else { self.caps.clone() })
        }

        fn begin_bundle(&self, keys: [PoolKey; 2]) -> Result<BundleCtx> {
            self.note("begin_bundle")?;
            let leg = |n: u8, key: PoolKey| LegCtx { pool_id: id(n), route: "0a".to_owned(), authority_digest: id(0xdd), lane: key.lane, asset: key.asset.name().to_owned() };
            let legs = [leg(1, keys[0]), leg(2, keys[1])];
            Ok(BundleCtx { bundle_id: id(0xbb), manifest: "abcd".to_owned(), salt: id(0xcc), expiry_height: 10, network_id: "ee".to_owned(), legs })
        }

        fn prove_leg(&self, _req: &LegReq) -> Result<String> {
            let now = self.proving.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_proving.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.prove_delay);
            self.proving.fetch_sub(1, Ordering::SeqCst);
            self.note("prove")?;
            Ok("beef".to_owned())
        }

        /// Not listed in `calls`: a check, not work.
        fn is_leg_pool(&self, _req: &LegReq) -> Result<bool> {
            Ok(!self.foreign_pool.load(Ordering::SeqCst))
        }

        fn settle(&self, _bundle: &BundleCtx, _prepared: &[String; 2]) -> Result<Option<Settled>> {
            let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(self.settle_delay);
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.note("settle")?;
            Ok(if self.aborts { None } else { Some(Settled { carrier_tx: "txh".to_owned(), height: 42 }) })
        }

        fn bundles(&self) -> Result<BundleLists> {
            self.note("bundles")?;
            Ok(self.lists.clone())
        }

        /// Never fails with `error`: a refresh is not what those tests are about.
        fn merge_bundles(&self, lists: &BundleLists) -> Result<()> {
            self.calls.lock().unwrap().push("merge_bundles");
            self.merged.lock().unwrap().push(lists.clone());
            Ok(())
        }

        fn wallet(&self) -> Result<serde_json::Value> {
            self.note("wallet")?;
            Ok(serde_json::json!({ "party": "fake", "balances": { "rd": "5", "dfabi": "6" }, "items": [] }))
        }

        /// Listed when it ends.
        fn resume_all(&self) -> Result<()> {
            std::thread::sleep(self.resume_delay);
            self.note("resume_all")
        }
    }

    type Answer = Box<dyn Fn(&str, &str, &str) -> Result<(u16, String)> + Send + Sync>;

    pub(crate) struct FakePeer {
        /// `(target, method, path, body)` of every call.
        pub calls: Mutex<Vec<(String, String, String, String)>>,
        answer: Answer,
    }

    impl FakePeer {
        /// `answer(target, path, body)`.
        pub(crate) fn with(answer: impl Fn(&str, &str, &str) -> Result<(u16, String)> + Send + Sync + 'static) -> Self {
            Self { calls: Mutex::default(), answer: Box::new(answer) }
        }

        /// A healthy party: signs addresses, proves legs, finalizes submits.
        pub(crate) fn standard() -> Self {
            Self::with(standard_answer)
        }
    }

    /// A `/aps/capacity` answer: `(lane, two_notes = total)` per pool.
    pub(crate) fn capacity_answer(pools: &[(u32, u128)]) -> String {
        let pools: Vec<_> = pools.iter().map(|(lane, v)| serde_json::json!({ "lane": lane, "two_notes": v.to_string(), "total": v.to_string() })).collect();
        serde_json::json!({ "pools": pools }).to_string()
    }

    /// What a healthy party answers. Its RD sits in lane 1 and its DFABI in lane 2, so a plan has one outcome: a pay's main leg in
    /// its asset's lane, a DvP's RD leg in lane 1.
    pub(crate) fn standard_answer(_target: &str, path: &str, body: &str) -> Result<(u16, String)> {
        match path {
            "/aps/address" => Ok((200, serde_json::json!({ "authority": id(0x33), "view_public": id(0x44), "authorization": "abcd" }).to_string())),
            "/aps/leg" => Ok((200, r#"{"prepared":"cafe"}"#.to_owned())),
            "/aps/submit" => Ok((200, r#"{"outcome":"finalized"}"#.to_owned())),
            "/aps/bundles" => Ok((200, serde_json::to_string(&lists()).unwrap())),
            "/aps/capacity" if body.contains(r#""rd""#) => Ok((200, capacity_answer(&[(1, 1000), (2, 0)]))),
            "/aps/capacity" => Ok((200, capacity_answer(&[(1, 0), (2, 1000)]))),
            _ => Ok((404, r#"{"error":"not found"}"#.to_owned())),
        }
    }

    impl Peer for FakePeer {
        fn call(&self, target: &str, method: &str, path: &str, body: &str) -> Result<(u16, String)> {
            self.calls.lock().unwrap().push((target.to_owned(), method.to_owned(), path.to_owned(), body.to_owned()));
            (self.answer)(target, path, body)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::atomic::Ordering, time::Duration};

    use super::{testkit::*, *};

    const BI: &str = "https://gateway.rd-iroha3-bi.svc.cluster.local:8443";
    const BANK_A: &str = "https://gateway.rd-iroha3-bank-a.svc.cluster.local:8443";
    const BANK_B: &str = "https://gateway.rd-iroha3-bank-b.svc.cluster.local:8443";

    /// The BI driver's account is `account(7)`, bank A's `account(8)`, bank B's `account(9)`.
    fn driver(me: u8) -> FakeBackend {
        FakeBackend { me: account(me), ..FakeBackend::default() }
    }

    fn coordinator() -> ApsConfig {
        ApsConfig { coordinator: true, peers: BTreeMap::from([(account(8), BANK_A.to_owned()), (account(9), BANK_B.to_owned())]), ..ApsConfig::default() }
    }

    fn bank() -> ApsConfig {
        ApsConfig { coordinator_url: Some(BI.to_owned()), ..ApsConfig::default() }
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    fn calls(backend: &FakeBackend) -> Vec<&'static str> {
        backend.calls.lock().unwrap().clone()
    }

    fn intent_body(intent: &str, asset: &str, to: &str, amount: &str) -> String {
        serde_json::json!({ "intent": intent, "asset": asset, "to": to, "amount": amount }).to_string()
    }

    /// Leg 0 in lane 1.
    fn leg_body(intent: &str, asset: &str, to: &str, amount: &str) -> String {
        let out = serde_json::json!({ "authority": id(0x11), "view_public": id(0x22), "authorization": "abcd" });
        let sponsor = serde_json::json!({ "authority": id(0x55), "view_public": id(0x66), "authorization": "abcd", "active": true });
        serde_json::json!({
            "intent": intent, "ordinal": 0, "lane": 1, "asset": asset, "manifest": "abcd", "authority_digest": id(0xdd), "salt": id(0xcc),
            "recipient": to, "amount": amount, "recipient_output": out, "sponsor_output": sponsor,
        })
        .to_string()
    }

    /// `leg_body` as leg `ordinal` in `lane`.
    fn leg_at(intent: &str, to: &str, amount: &str, ordinal: u8, lane: u32) -> String {
        leg_body(intent, "rd", to, amount).replace(r#""ordinal":0"#, &format!(r#""ordinal":{ordinal}"#)).replace(r#""lane":1"#, &format!(r#""lane":{lane}"#))
    }

    fn address_body() -> String {
        serde_json::json!({ "bundle_id": id(0xbb), "pool_id": id(1), "leg_ordinal": 0, "route": "0a", "expiry_height": 10, "network_id": "ee" }).to_string()
    }

    fn pay_body(intent: &str, asset: &str, from: &str, to: &str, amount: &str) -> String {
        serde_json::json!({ "kind": "pay", "intent": intent, "asset": asset, "from": from, "to": to, "amount": amount }).to_string()
    }

    fn dvp_body(buyer: &str, seller: &str, rd: &str, dfabi: &str) -> String {
        serde_json::json!({ "kind": "dvp", "intent_rd": id(1), "intent_dfabi": id(2), "buyer": buyer, "seller": seller, "rd": rd, "dfabi": dfabi }).to_string()
    }

    #[test]
    fn an_intent_is_one_shot() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let (status, response) = aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "intent": intent })));
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "prepared": "beef" })));
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 403, "the intent is spent");
        assert_eq!(calls(&backend), ["merge_bundles", "prove"]);
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 409, "a spent intent is not registered again");
    }

    #[test]
    fn the_same_intent_with_other_terms_is_409_and_keeps_the_stored_terms() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200, "same terms again is harmless");
        for other in [intent_body(&intent, "rd", &to, "6"), intent_body(&intent, "dfabi", &to, "5"), intent_body(&intent, "rd", &account(7), "5")] {
            let (status, response) = aps.route("POST", "/aps/intent", &other);
            assert_eq!(status, 409, "{other}");
            assert!(json(&response)["error"].is_string());
        }
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "6")).0, 403, "the rejected terms were not stored");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 200, "the first terms still hold");
    }

    #[test]
    fn an_intent_expires_after_fifteen_minutes() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let start = std::time::Instant::now();
        assert_eq!(aps.route_at(start, "POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let late = start + Duration::from_secs(15 * 60 + 1);
        assert_eq!(aps.route_at(late, "POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 403);
        assert!(calls(&backend).is_empty());
        let early = start + Duration::from_secs(14 * 60);
        assert_eq!(aps.route_at(early, "POST", "/aps/intent", &intent_body(&id(2), "rd", &to, "5")).0, 200);
        assert_eq!(aps.route_at(early, "POST", "/aps/leg", &leg_body(&id(2), "rd", &to, "5")).0, 200);
    }

    #[test]
    fn a_leg_without_a_matching_intent_is_403_and_never_proves() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5"));
        assert_eq!(status, 403);
        assert!(json(&response)["error"].is_string());
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        // another recipient, a larger amount, the other asset: none of them is what was approved
        for bad in [leg_body(&intent, "rd", &account(7), "5"), leg_body(&intent, "rd", &to, "6"), leg_body(&intent, "dfabi", &to, "5")] {
            assert_eq!(aps.route("POST", "/aps/leg", &bad).0, 403, "{bad}");
        }
        assert!(calls(&backend).is_empty(), "no proving without a matching intent");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 200, "a refused leg did not spend the intent");
        assert_eq!(calls(&backend), ["merge_bundles", "prove"]);
    }

    #[test]
    fn an_intent_is_spent_even_when_proving_fails() {
        let backend = FakeBackend { error: Some("read /keys/bank-a.note: denied".to_owned()), ..driver(8) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5"));
        assert_eq!(status, 502);
        assert!(!response.contains(".note") && !response.contains(".seed"), "{response}");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 403, "a retry needs a new intent");
        assert_eq!(calls(&backend), ["merge_bundles", "prove"]);
    }

    #[test]
    fn address_signs_for_the_own_account_and_needs_no_intent() {
        let (backend, peer) = (driver(9), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("POST", "/aps/address", &address_body());
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "authority": id(0x11), "view_public": id(0x22), "authorization": "abcd" })));
        assert_eq!(calls(&backend), ["address"]);
    }

    #[test]
    fn wallet_is_a_get_and_returns_what_the_backend_read() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("GET", "/aps/wallet", "");
        // the bare wallet_json object, nothing wrapped around it (the Lensa adapter reads exactly this)
        let wallet = serde_json::json!({ "party": "fake", "balances": { "rd": "5", "dfabi": "6" }, "items": [] });
        assert_eq!((status, json(&response)), (200, wallet));
        assert_eq!(aps.route("POST", "/aps/wallet", "{}").0, 405);
        assert_eq!(calls(&backend), ["merge_bundles", "wallet"]);
    }

    #[test]
    fn a_bank_driver_forwards_submit_verbatim_to_the_coordinator_url_and_returns_its_answer() {
        let backend = driver(8);
        let peer = FakePeer::with(|_, _, _| Ok((403, r#"{"error":"payer refused"}"#.to_owned())));
        let aps = Aps::new(&backend, &peer, bank());
        let body = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let (status, response) = aps.route("POST", "/aps/submit", &body);
        assert_eq!((status, json(&response)), (403, serde_json::json!({ "error": "payer refused" })));
        assert_eq!(*peer.calls.lock().unwrap(), vec![(BI.to_owned(), "POST".to_owned(), "/aps/submit".to_owned(), body)]);
        assert!(calls(&backend).is_empty(), "a bank does no coordinating");
    }

    #[test]
    fn a_dvp_submit_is_forwarded_too_and_a_bank_without_coordinator_url_answers_503() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let forwarding = Aps::new(&backend, &peer, bank());
        let body = dvp_body(&account(9), &account(8), "5", "7");
        assert_eq!(forwarding.route("POST", "/aps/submit", &body), (200, r#"{"outcome":"finalized"}"#.to_owned()));
        assert_eq!(peer.calls.lock().unwrap()[0].3, body);
        let lone_peer = FakePeer::standard();
        let alone = Aps::new(&backend, &lone_peer, ApsConfig::default());
        let (status, response) = alone.route("POST", "/aps/submit", &body);
        assert_eq!(status, 503);
        assert!(json(&response)["error"].is_string());
        assert!(lone_peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_peer_that_cannot_be_reached_is_502() {
        let (backend, peer) = (driver(8), FakePeer::with(|_, _, _| Err(eyre::eyre!("connection refused"))));
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!((status, json(&response)), (502, serde_json::json!({ "error": "connection refused" })));
    }

    #[test]
    fn the_coordinator_collects_the_address_and_the_leg_from_their_owners_then_settles() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let body = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let (status, response) = aps.route("POST", "/aps/submit", &body);
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "outcome": "finalized", "bundle_id": id(0xbb), "carrier_tx": "txh", "height": 42 })));
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        assert_eq!(
            route,
            [(BANK_A, "/aps/capacity"), (BANK_B, "/aps/address"), (BANK_A, "/aps/leg")],
            "capacity from the payer, address from the recipient, leg from the payer"
        );
        assert_eq!(json(&sent[0].3), serde_json::json!({ "asset": "rd" }));
        let leg = json(&sent[2].3);
        assert_eq!(
            (leg["intent"].as_str(), leg["ordinal"].as_u64(), leg["recipient"].as_str(), leg["amount"].as_str(), leg["manifest"].as_str()),
            (Some(id(1).as_str()), Some(0), Some(account(9).as_str()), Some("5"), Some("abcd"))
        );
        assert_eq!((leg["lane"].as_u64(), leg["asset"].as_str()), (Some(1), Some("rd")), "the payer's RD is in lane 1");
        assert_eq!(leg["recipient_output"]["authority"], id(0x33), "the recipient's own answer");
        assert_eq!(leg["sponsor_output"]["active"], true, "leg 0 pays the sponsor");
        // BI's own side: its capacity (companion), manifest, its sponsor output per leg, the BI -> BI companion leg without HTTP, then settle
        assert_eq!(calls(&backend), ["capacity", "begin_bundle", "sponsor_output", "address", "sponsor_output", "prove", "settle"]);
    }

    #[test]
    fn the_two_legs_are_proved_at_the_same_time() {
        // Leg 0 is proved by bank A over HTTP, leg 1 (the BI -> BI companion) by the coordinator: 400 ms each.
        let backend = FakeBackend { prove_delay: Duration::from_millis(400), ..driver(7) };
        let peer = FakePeer::with(|target, path, body| match path {
            "/aps/leg" => {
                std::thread::sleep(Duration::from_millis(400));
                Ok((200, r#"{"prepared":"cafe"}"#.to_owned()))
            }
            _ => standard_answer(target, path, body),
        });
        let aps = Aps::new(&backend, &peer, coordinator());
        let started = std::time::Instant::now();
        assert_eq!(aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5")).0, 200);
        let took = started.elapsed();
        assert!(took < Duration::from_millis(700), "the legs were proved one after the other: {took:?}");
    }

    #[test]
    fn the_coordinator_proves_its_own_two_legs_one_after_the_other() {
        // BI's issuance leg and its companion are both BI's own proofs: one at a time (memory).
        let backend = FakeBackend { prove_delay: Duration::from_millis(100), ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(1), "rd", &account(9), "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(7), &account(9), "5")).0, 200);
        assert_eq!(calls(&backend).iter().filter(|call| **call == "prove").count(), 2);
        assert_eq!(backend.max_proving.load(Ordering::SeqCst), 1);
        // the recipient's capacity decides the lane: it holds its RD in lane 1, so the issuance goes to lane 2 (leg 1)
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        assert_eq!(route, [(BANK_B, "/aps/capacity"), (BANK_B, "/aps/address")]);
        assert_eq!(json(&sent[1].3)["leg_ordinal"], 1);
    }

    #[test]
    fn a_dvp_asks_the_buyer_for_the_rd_leg_and_the_seller_for_the_dfabi_leg() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, _) = aps.route("POST", "/aps/submit", &dvp_body(&account(8), &account(9), "5", "7"));
        assert_eq!(status, 200);
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        // The buyer's RD and the seller's DFABI capacity, both addresses in leg order; then the two legs, proved at the same time
        // (either may be asked first).
        assert_eq!(route[..4], [(BANK_A, "/aps/capacity"), (BANK_B, "/aps/capacity"), (BANK_B, "/aps/address"), (BANK_A, "/aps/address")]);
        let leg_of = |bank: &str| sent.iter().find(|call| call.0 == bank && call.2 == "/aps/leg").map(|call| json(&call.3)).unwrap();
        assert_eq!(route.len(), 6);
        let (rd, dfabi) = (leg_of(BANK_A), leg_of(BANK_B));
        assert_eq!((rd["intent"].as_str(), rd["amount"].as_str(), rd["recipient"].as_str()), (Some(id(1).as_str()), Some("5"), Some(account(9).as_str())));
        assert_eq!((dfabi["intent"].as_str(), dfabi["amount"].as_str(), dfabi["recipient"].as_str()), (Some(id(2).as_str()), Some("7"), Some(account(8).as_str())));
        assert_eq!((dfabi["ordinal"].as_u64(), dfabi["sponsor_output"]["active"].as_bool()), (Some(1), Some(false)));
        assert_eq!((rd["lane"].as_u64(), rd["asset"].as_str(), dfabi["lane"].as_u64(), dfabi["asset"].as_str()), (Some(1), Some("rd"), Some(2), Some("dfabi")));
    }

    #[test]
    fn a_payer_that_refuses_its_leg_stops_the_submit_before_settle() {
        let backend = driver(7);
        let peer = FakePeer::with(|target, path, body| match path {
            "/aps/leg" => Ok((403, r#"{"error":"no matching intent"}"#.to_owned())),
            _ => standard_answer(target, path, body),
        });
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!(status, 403);
        assert!(json(&response)["error"].as_str().unwrap().contains("no matching intent"), "{response}");
        assert!(!calls(&backend).contains(&"settle"));
    }

    #[test]
    fn a_leg_paid_by_the_coordinator_still_needs_its_own_intent_but_the_companion_does_not() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let body = pay_body(&id(1), "rd", &account(7), &account(9), "5");
        assert_eq!(aps.route("POST", "/aps/submit", &body).0, 403, "BI's issuance leg without a registered intent");
        assert!(!calls(&backend).contains(&"prove") && !calls(&backend).contains(&"settle"));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(1), "rd", &account(9), "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/submit", &body).0, 200);
        assert_eq!(calls(&backend).iter().filter(|call| **call == "prove").count(), 2, "the issuance leg and the companion");
    }

    #[test]
    fn a_party_without_a_configured_gateway_is_400_before_anything_is_prepared() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, ApsConfig { coordinator: true, ..ApsConfig::default() });
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!(status, 400);
        assert!(json(&response)["error"].is_string());
        assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn an_aborted_bundle_is_a_200_with_outcome_aborted() {
        let backend = FakeBackend { aborts: true, ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, response) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "outcome": "aborted", "bundle_id": id(0xbb), "carrier_tx": null, "height": null })));
    }

    /// A restarted coordinator finishes the bundle it left in flight before it starts a new one.
    #[test]
    fn submit_waits_for_resumed_bundle() {
        let backend = FakeBackend { resume_delay: Duration::from_millis(300), ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let started = std::time::Instant::now();
        let aps = &aps;
        std::thread::scope(|scope| {
            let (locked, held) = std::sync::mpsc::channel();
            scope.spawn(move || aps.resume(move || locked.send(()).unwrap()));
            held.recv().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let (status, _) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5"));
            assert_eq!(status, 200);
            assert!(started.elapsed() >= Duration::from_millis(300), "the submit ran during the resume: {:?}", started.elapsed());
        });
        assert_eq!(calls(&backend).first().copied(), Some("resume_all"), "{:?}", calls(&backend));
    }

    #[test]
    fn two_concurrent_submits_on_the_coordinator_run_one_after_the_other() {
        let backend = FakeBackend { settle_delay: Duration::from_millis(150), ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let to = account(9);
        let bodies: Vec<String> = [1u8, 2]
            .iter()
            .map(|n| {
                assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(*n), "rd", &to, "5")).0, 200);
                pay_body(&id(*n), "rd", &account(7), &to, "5")
            })
            .collect();
        std::thread::scope(|scope| {
            let first = scope.spawn(|| aps.route("POST", "/aps/submit", &bodies[0]));
            let second = scope.spawn(|| aps.route("POST", "/aps/submit", &bodies[1]));
            assert_eq!(first.join().unwrap().0, 200);
            assert_eq!(second.join().unwrap().0, 200);
        });
        assert_eq!(backend.max_active.load(Ordering::SeqCst), 1, "two bundles were in settle at once");
        assert_eq!(calls(&backend).iter().filter(|call| **call == "settle").count(), 2);
    }

    #[test]
    fn a_driver_keeps_answering_address_and_leg_while_its_own_submit_waits_on_the_coordinator() {
        // a bank forwards `/aps/submit` to BI while BI asks the same bank for `/aps/leg`
        let backend = driver(8);
        let peer = FakePeer::with(|_, _, _| {
            std::thread::sleep(Duration::from_millis(200));
            Ok((200, r#"{"outcome":"finalized"}"#.to_owned()))
        });
        let aps = Aps::new(&backend, &peer, bank());
        std::thread::scope(|scope| {
            let waiting = scope.spawn(|| aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "5")));
            std::thread::sleep(Duration::from_millis(50));
            let started = std::time::Instant::now();
            assert_eq!(aps.route("POST", "/aps/address", &address_body()).0, 200);
            assert!(started.elapsed() < Duration::from_millis(150), "address waited for the forwarded submit");
            assert_eq!(waiting.join().unwrap().0, 200);
        });
    }

    #[test]
    fn malformed_submit_bodies_are_400_and_touch_neither_backend_nor_peer() {
        let ok = pay_body(&id(1), "rd", &account(8), &account(9), "5");
        let dvp = dvp_body(&account(8), &account(9), "5", "7");
        let cases = [
            String::new(),
            "not json".to_owned(),
            "{}".to_owned(),
            r#"{"kind":"mint"}"#.to_owned(),
            r#"{"kind":"pay"}"#.to_owned(),
            r#"{"kind":"dvp"}"#.to_owned(),
            ok.replace('}', r#","extra":1}"#),
            pay_body("abcd", "rd", &account(8), &account(9), "5"),
            pay_body(&id(1), "gold", &account(8), &account(9), "5"),
            pay_body(&id(1), "rd", "not-a-key", &account(9), "5"),
            pay_body(&id(1), "rd", &account(8), "not-a-key", "5"),
            pay_body(&id(1), "rd", &account(8), &account(9), "0"),
            pay_body(&id(1), "rd", &account(8), &account(9), "-1"),
            pay_body(&id(1), "rd", &account(8), &account(8), "5"),
            dvp.replace('}', r#","extra":1}"#),
            dvp_body(&account(8), &account(9), "0", "7"),
            dvp_body(&account(8), &account(9), "5", "x"),
            dvp_body(&account(8), &account(8), "5", "7"),
            dvp.replace(&id(1), "abcd"),
        ];
        for config in [coordinator(), bank()] {
            let (backend, peer) = (driver(7), FakePeer::standard());
            let aps = Aps::new(&backend, &peer, config);
            for bad in &cases {
                let (status, response) = aps.route("POST", "/aps/submit", bad);
                assert_eq!(status, 400, "{bad:?}");
                assert!(json(&response)["error"].is_string());
            }
            assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn malformed_intent_address_and_leg_bodies_are_400_and_touch_nothing() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let to = account(9);
        let intent = intent_body(&id(1), "rd", &to, "5");
        let leg = leg_body(&id(1), "rd", &to, "5");
        let address = address_body();
        let cases: Vec<(&str, String)> = vec![
            ("/aps/intent", String::new()),
            ("/aps/intent", "x".to_owned()),
            ("/aps/intent", "{}".to_owned()),
            ("/aps/intent", intent.replace('}', r#","extra":1}"#)),
            ("/aps/intent", intent_body("abcd", "rd", &to, "5")),
            ("/aps/intent", intent_body(&id(1), "gold", &to, "5")),
            ("/aps/intent", intent_body(&id(1), "rd", "not-a-key", "5")),
            ("/aps/intent", intent_body(&id(1), "rd", &to, "0")),
            ("/aps/intent", intent_body(&id(1), "rd", &to, "1.5")),
            ("/aps/leg", String::new()),
            ("/aps/leg", "{}".to_owned()),
            ("/aps/leg", leg.replace('}', r#","extra":1}"#)),
            ("/aps/leg", leg.replace(r#""ordinal":0"#, r#""ordinal":2"#)),
            ("/aps/leg", leg_body(&id(1), "gold", &to, "5")),
            ("/aps/leg", leg.replace(r#","lane":1"#, "")),
            ("/aps/leg", leg_body("abcd", "rd", &to, "5")),
            ("/aps/leg", leg_body(&id(1), "rd", "not-a-key", "5")),
            ("/aps/leg", leg_body(&id(1), "rd", &to, "0")),
            ("/aps/leg", leg.replace(r#""manifest":"abcd""#, r#""manifest":"xyz""#)),
            ("/aps/address", String::new()),
            ("/aps/address", "{}".to_owned()),
            ("/aps/address", address.replace('}', r#","extra":1}"#)),
            ("/aps/address", address.replace(&id(0xbb), "abcd")),
            ("/aps/address", address.replace(r#""leg_ordinal":0"#, r#""leg_ordinal":2"#)),
            ("/aps/address", address.replace(r#""route":"0a""#, r#""route":"zz""#)),
        ];
        for (path, bad) in &cases {
            let (status, response) = aps.route("POST", path, bad);
            assert_eq!(status, 400, "{path} {bad:?}");
            assert!(json(&response)["error"].is_string());
        }
        assert!(calls(&backend).is_empty());
    }

    #[test]
    fn unknown_aps_routes_are_404_and_known_ones_with_the_wrong_method_are_405() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        for path in ["/aps", "/aps/", "/aps/keys", "/aps/submit/x", "/aps/wallet?x=1", "/aps/Intent"] {
            assert_eq!(aps.route("GET", path, "").0, 404, "GET {path}");
            assert_eq!(aps.route("POST", path, "{}").0, 404, "POST {path}");
        }
        for (method, path) in [
            ("GET", "/aps/intent"),
            ("GET", "/aps/address"),
            ("GET", "/aps/leg"),
            ("GET", "/aps/capacity"),
            ("GET", "/aps/submit"),
            ("POST", "/aps/wallet"),
            ("DELETE", "/aps/leg"),
            ("POST", "/aps/bundles"),
        ] {
            assert_eq!(aps.route(method, path, "{}").0, 405, "{method} {path}");
        }
        assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn no_response_names_a_key_file_or_carries_secret_material() {
        let failing = FakeBackend { error: Some("read /keys/bank-a.seed: denied; /keys/bank-a.note; /keys/bi-auditor.hybrid; /etc/client.toml".to_owned()), ..driver(7) };
        let healthy = driver(7);
        let (peer, to) = (FakePeer::standard(), account(9));
        let mut all = Vec::new();
        for backend in [&failing, &healthy] {
            let aps = Aps::new(backend, &peer, coordinator());
            all.push(aps.route("POST", "/aps/intent", &intent_body(&id(1), "rd", &to, "5")).1);
            all.push(aps.route("POST", "/aps/leg", &leg_body(&id(1), "rd", &to, "5")).1);
            all.push(aps.route("POST", "/aps/address", &address_body()).1);
            all.push(aps.route("GET", "/aps/wallet", "").1);
            all.push(aps.route("GET", "/aps/bundles", "").1);
            all.push(aps.route("POST", "/aps/submit", &pay_body(&id(2), "rd", &account(8), &to, "5")).1);
            all.push(aps.route("POST", "/aps/submit", "garbage").1);
            all.push(aps.route("GET", "/aps/nope", "").1);
        }
        assert!(all.iter().any(|response| response.contains("error")));
        for response in all {
            for secret in [".seed", ".note", ".hybrid", "client.toml"] {
                assert!(!response.contains(secret), "{secret} in {response}");
            }
        }
    }

    #[test]
    fn a_party_driver_refreshes_the_finalized_bundles_from_the_coordinator_before_proving_and_before_the_wallet() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 200);
        assert_eq!(aps.route("GET", "/aps/wallet", "").0, 200);
        let sent: Vec<_> = peer.calls.lock().unwrap().iter().map(|call| (call.0.clone(), call.1.clone(), call.2.clone(), call.3.clone())).collect();
        let ask = (BI.to_owned(), "GET".to_owned(), "/aps/bundles".to_owned(), String::new());
        assert_eq!(sent, [ask.clone(), ask], "one refresh per leg and per wallet read");
        assert_eq!(*backend.merged.lock().unwrap(), [lists(), lists()]);
        assert_eq!(calls(&backend), ["merge_bundles", "prove", "merge_bundles", "wallet"], "merged before it was used");
    }

    #[test]
    fn a_failed_refresh_is_502_and_nothing_is_proved_or_read() {
        let (to, intent) = (account(9), id(1));
        let answers: Vec<Result<(u16, String)>> = vec![
            Err(eyre::eyre!("connection refused")),
            Ok((500, r#"{"error":"boom"}"#.to_owned())),
            Ok((200, "not json".to_owned())),
            Ok((200, r#"{"rd":["zz"],"dfabi":[]}"#.to_owned())),
        ];
        for answer in answers {
            let backend = driver(8);
            let answer = std::sync::Mutex::new(Some(answer));
            let peer = FakePeer::with(move |_, _, _| answer.lock().unwrap().take().unwrap_or_else(|| Err(eyre::eyre!("again"))));
            let aps = Aps::new(&backend, &peer, bank());
            assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
            let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5"));
            assert_eq!(status, 502, "{response}");
            assert!(json(&response)["error"].is_string());
            assert!(calls(&backend).is_empty(), "no proving on a stale pool history: {:?}", calls(&backend));
            assert_eq!(aps.route("GET", "/aps/wallet", "").0, 502, "the wallet is not read from a stale history either");
            assert!(calls(&backend).is_empty());
        }
    }

    #[test]
    fn a_party_driver_without_coordinator_url_cannot_refresh_so_it_does_not_prove() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, ApsConfig::default());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 503);
        assert_eq!(aps.route("GET", "/aps/wallet", "").0, 503);
        assert!(calls(&backend).is_empty() && peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn the_coordinator_serves_its_finalized_bundles_and_never_refreshes_from_anyone() {
        let backend = FakeBackend { lists: lists(), ..driver(7) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, response) = aps.route("GET", "/aps/bundles", "");
        assert_eq!(status, 200);
        let answer = json(&response);
        assert_eq!((answer["rd"].clone(), answer["dfabi"].clone()), (serde_json::json!([id(0xa1), id(0xa2)]), serde_json::json!([id(0xa1)])));
        assert_eq!(answer["heights"][id(0xa2)], 9);
        assert_eq!(aps.route("GET", "/aps/wallet", "").0, 200);
        assert_eq!(calls(&backend), ["bundles", "wallet"]);
        assert!(peer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_party_driver_does_not_serve_bundles() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        assert_eq!(aps.route("GET", "/aps/bundles", "").0, 404);
        assert!(calls(&backend).is_empty());
    }

    #[test]
    fn a_prepared_answer_may_have_dot_separated_hex_parts_and_nothing_else() {
        let (to, from) = (account(9), account(8));
        for (prepared, status) in [("aa.bb.cc", 200), ("cafe", 200), ("zz", 502), ("aa..cc", 502), ("", 502), ("aa.", 502)] {
            let (backend, answer) = (driver(7), format!(r#"{{"prepared":"{prepared}"}}"#));
            let peer = FakePeer::with(move |target, path, body| match path {
                "/aps/leg" => Ok((200, answer.clone())),
                _ => standard_answer(target, path, body),
            });
            let aps = Aps::new(&backend, &peer, coordinator());
            let (got, _) = aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &from, &to, "5"));
            assert_eq!(got, status, "{prepared:?}");
            assert_eq!(calls(&backend).contains(&"settle"), status == 200, "{prepared:?}");
        }
    }

    #[test]
    fn the_network_id_is_the_canonical_text_literal_not_hex() {
        let (backend, peer) = (driver(9), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let literal = address_body().replace(r#""network_id":"ee""#, r#""network_id":"hash:AB12#34""#);
        assert_eq!(aps.route("POST", "/aps/address", &literal).0, 200);
        let empty = address_body().replace(r#""network_id":"ee""#, r#""network_id":"""#);
        assert_eq!(aps.route("POST", "/aps/address", &empty).0, 400);
    }

    #[test]
    fn capacity_answers_per_pool() {
        let backend = FakeBackend { caps: vec![(1, Capacity { two_notes: 13, total: 17 }), (2, Capacity::default())], ..driver(8) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, bank());
        let (status, response) = aps.route("POST", "/aps/capacity", r#"{"asset":"dfabi"}"#);
        let pools = serde_json::json!({ "pools": [{ "lane": 1, "two_notes": "13", "total": "17" }, { "lane": 2, "two_notes": "0", "total": "0" }] });
        assert_eq!((status, json(&response)), (200, pools));
        assert_eq!(calls(&backend), ["merge_bundles", "capacity"], "read on a fresh pool history");
        for bad in ["", "{}", r#"{"asset":"gold"}"#, r#"{"asset":"rd","x":1}"#] {
            assert_eq!(aps.route("POST", "/aps/capacity", bad).0, 400, "{bad}");
        }
        assert_eq!(calls(&backend).len(), 2);
    }

    #[test]
    fn split_intent_covers_two_legs() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "9")).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "5", 0, 1)).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "4", 0, 2)).0, 403, "leg 0 (it pays the reimbursement) again");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "4", 1, 1)).0, 403, "lane 1 again");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "5", 1, 2)).0, 403, "more than is left of the intent");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "4", 1, 2)).0, 200, "the refused legs spent nothing");
        for (ordinal, lane) in [(0, 1), (1, 2), (0, 2), (1, 1)] {
            assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "1", ordinal, lane)).0, 403, "the intent is spent");
        }
        assert_eq!(calls(&backend).iter().filter(|call| **call == "prove").count(), 2);
    }

    /// A leg smaller than the intent is the first half of a split: the rest stays open for the TTL, but only for the other ordinal in
    /// the other lane. So one intent is at most two legs, at most once leg 0 (one reimbursement), and never more than its amount.
    #[test]
    fn a_partial_intent_takes_one_more_leg_at_most() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "9")).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "3", 0, 1)).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "3", 1, 2)).0, 200);
        // 3 of 9 are left, and no third leg can take them: both ordinals and both lanes are used
        for (ordinal, lane) in [(0, 1), (1, 2), (0, 2), (1, 1), (0, 3), (1, 3)] {
            let (status, response) = aps.route("POST", "/aps/leg", &leg_at(&intent, &to, "3", ordinal, lane));
            assert_eq!(status, 403, "ordinal {ordinal} lane {lane}: {response}");
        }
        assert_eq!(calls(&backend).iter().filter(|call| **call == "prove").count(), 2, "6 of 9 proved, never more");
        // a single leg 0 above the intent is refused outright
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&id(2), "rd", &to, "9")).0, 200);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&id(2), &to, "10", 0, 1)).0, 403);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&id(2), &to, "9", 0, 1)).0, 200, "the refusal spent nothing");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_at(&id(2), &to, "1", 1, 2)).0, 403, "the intent is spent");
    }

    /// The coordinator names the leg's pool twice: `lane`/`asset`, and the manifest's pool at `ordinal`. A leg where the two disagree
    /// is refused before the intent is spent or anything is refreshed or proved.
    #[test]
    fn a_leg_outside_the_manifests_pool_is_400_and_spends_nothing() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        backend.foreign_pool.store(true, Ordering::SeqCst);
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5"));
        assert_eq!(status, 400, "{response}");
        assert!(calls(&backend).is_empty(), "nothing refreshed or proved");
        backend.foreign_pool.store(false, Ordering::SeqCst);
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, "rd", &to, "5")).0, 200, "the refused leg spent nothing");
    }

    #[test]
    fn a_party_proves_two_legs_one_after_the_other() {
        // A split pay asks one payer for both legs at once: one proof at a time (memory), as for the coordinator's own legs.
        let backend = FakeBackend { prove_delay: Duration::from_millis(100), ..driver(8) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "9")).0, 200);
        let (first, second) = (leg_at(&intent, &to, "5", 0, 1), leg_at(&intent, &to, "4", 1, 2));
        std::thread::scope(|scope| {
            let one = scope.spawn(|| aps.route("POST", "/aps/leg", &first).0);
            let two = scope.spawn(|| aps.route("POST", "/aps/leg", &second).0);
            assert_eq!((one.join().unwrap(), two.join().unwrap()), (200, 200));
        });
        assert_eq!(backend.max_proving.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_payment_no_single_pool_covers_is_split_into_two_legs_of_the_payer() {
        let backend = driver(7);
        let peer = FakePeer::with(|target, path, body| match path {
            "/aps/capacity" => Ok((200, capacity_answer(&[(1, 6), (2, 5)]))),
            _ => standard_answer(target, path, body),
        });
        let aps = Aps::new(&backend, &peer, coordinator());
        assert_eq!(aps.route("POST", "/aps/submit", &pay_body(&id(1), "rd", &account(8), &account(9), "9")).0, 200);
        let sent = peer.calls.lock().unwrap().clone();
        let mut legs: Vec<_> = sent.iter().filter(|call| call.2 == "/aps/leg").map(|call| (call.0.clone(), json(&call.3))).collect();
        legs.sort_by_key(|(_, leg)| leg["ordinal"].as_u64());
        let intent = id(1);
        let summary: Vec<_> = legs
            .iter()
            .map(|(bank, leg)| (bank.as_str(), leg["ordinal"].as_u64(), leg["lane"].as_u64(), leg["asset"].as_str(), leg["amount"].as_str(), leg["intent"].as_str()))
            .collect();
        let expected = [
            (BANK_A, Some(0), Some(1), Some("rd"), Some("5"), Some(intent.as_str())),
            (BANK_A, Some(1), Some(2), Some("rd"), Some("4"), Some(intent.as_str())),
        ];
        assert_eq!(summary, expected);
        assert!(!calls(&backend).contains(&"prove"), "no companion: BI proves nothing");
    }

    #[test]
    fn a_payment_no_pool_arrangement_covers_is_422_before_anything_is_prepared() {
        for (body, own) in [(pay_body(&id(1), "rd", &account(8), &account(9), "9"), vec!["capacity"]), (dvp_body(&account(8), &account(9), "5", "7"), vec![])] {
            let backend = driver(7);
            let peer = FakePeer::with(|target, path, body| match path {
                "/aps/capacity" => Ok((200, capacity_answer(&[(1, 3), (2, 3)]))),
                _ => standard_answer(target, path, body),
            });
            let aps = Aps::new(&backend, &peer, coordinator());
            let (status, response) = aps.route("POST", "/aps/submit", &body);
            assert_eq!((status, json(&response)), (422, serde_json::json!({ "error": "no pool arrangement covers the payment" })), "{body}");
            assert_eq!(calls(&backend), own, "nothing prepared or proved");
            assert!(peer.calls.lock().unwrap().iter().all(|call| call.2 == "/aps/capacity"));
        }
    }
}
