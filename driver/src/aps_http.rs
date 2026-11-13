//! APS HTTP side of a per-org driver (plan 2026-11-13-04, task T2).
//!
//! `POST /aps/intent`, `POST /aps/address`, `POST /aps/leg`, `GET /aps/wallet` and `POST /aps/submit`. A leg is split per key holder: the
//! recipient signs its own output authorization (`/aps/address`), the payer proves its own leg (`/aps/leg`, only after the one-shot
//! intent that its Lensa registered with `/aps/intent`), and BI (`[aps] coordinator`) walks the parties through one bundle at a time
//! (`/aps/submit`). Every other driver forwards its `/aps/submit` to BI over the mTLS client. Nothing secret is read from a request or
//! written to a response: all chain, proving and key work sits behind `ApsBackend`, all calls to another party behind `Peer`.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    config::{ApsConfig, Config, TlsConfig, signing_key},
    dvp_native, http, pools,
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
    /// norito hex (`aps::enc`).
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
    /// 0 = the RD leg, 1 = the DFABI leg (bundles are always [rd, dfabi]).
    pub ordinal: u8,
    /// norito hex of `AtomicPrivateSettlementV1`.
    pub manifest: String,
    pub authority_digest: String,
    pub salt: String,
    pub recipient: String,
    pub amount: String,
    pub recipient_output: OutputKey,
    pub sponsor_output: SponsorOutput,
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
    /// Coordinator side: build the bundle manifest over the two pools.
    fn begin_bundle(&self) -> Result<BundleCtx>;
    /// Payer side: scan the own notes, pick one, prove the leg; returns norito hex of `AtomicPrivateSettlementPreparedLegV1`.
    /// The intent is already consumed; `req.intent` is empty for the coordinator's own BI -> BI companion leg.
    fn prove_leg(&self, req: &LegReq) -> Result<String>;
    /// Coordinator side: audit quorum, prepare, commit. `None` = the bundle was aborted (nothing moved).
    fn settle(&self, bundle: &BundleCtx, prepared: &[String; 2]) -> Result<Option<Settled>>;
    /// The own `wallet_json`.
    fn wallet(&self) -> Result<serde_json::Value>;
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
    Open(IntentTerms),
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
            Some((Slot::Open(old), _)) => Some(*old == terms),
            Some((Slot::Used, _)) => Some(false),
            None => None,
        };
        match known {
            Some(same) => same,
            None => {
                slots.insert(intent.to_owned(), (Slot::Open(terms), now + INTENT_TTL));
                true
            }
        }
    }

    /// Spend the intent when its terms are exactly `expected`; a refused leg does not spend it.
    fn take(&self, now: Instant, intent: &str, expected: &IntentTerms) -> Take {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        slots.retain(|_, (_, expires)| *expires > now);
        let outcome = match slots.get(intent) {
            Some((Slot::Open(terms), _)) if terms == expected => Take::Taken,
            Some((Slot::Open(_), _)) => Take::Mismatch,
            _ => Take::Missing,
        };
        if outcome == Take::Taken {
            if let Some(entry) = slots.get_mut(intent) {
                entry.0 = Slot::Used;
            }
        }
        outcome
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

/// One leg of a submit. `None` payer/recipient = the coordinator's own account (the BI -> BI companion leg of a `pay`).
struct LegSpec {
    payer: Option<String>,
    recipient: Option<String>,
    amount: u128,
    /// `None` only for the companion leg, which the coordinator pays itself.
    intent: Option<String>,
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

/// Bundles are always [rd, dfabi] (`pools::run_bundle`).
fn asset_of(ordinal: u8) -> &'static str {
    if ordinal == 0 { "rd" } else { "dfabi" }
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
    ensure!(hex_any(&req.route) && hex_any(&req.network_id), "route and network_id must be hex");
    Ok(())
}

/// Returns the amount.
fn check_leg(req: &LegReq) -> Result<u128> {
    ensure!(hex_n(&req.intent, 32), "intent must be 64 hex characters");
    ensure!(req.ordinal < 2, "ordinal must be 0 or 1");
    ensure!(hex_any(&req.manifest), "manifest must be hex");
    ensure!(hex_n(&req.authority_digest, 32) && hex_n(&req.salt, 32), "authority_digest and salt must be 64 hex characters");
    dvp_native::parse_account(&req.recipient)?;
    let amount = dvp_native::parse_amount(&req.amount)?;
    check_key(&req.recipient_output.authority, &req.recipient_output.view_public, &req.recipient_output.authorization)?;
    check_key(&req.sponsor_output.authority, &req.sponsor_output.view_public, &req.sponsor_output.authorization)?;
    Ok(amount)
}

/// The two legs of a submit body, [rd, dfabi]. A `pay` pairs its leg with BI -> BI 1 in the other pool (APS needs two dataspaces).
fn parse_submit(body: &str) -> Result<[LegSpec; 2]> {
    let value: serde_json::Value = serde_json::from_str(body).wrap_err("bad request body")?;
    let kind = value.get("kind").and_then(|kind| kind.as_str()).map(str::to_owned);
    match kind.as_deref() {
        Some("pay") => {
            let req: PayReq = serde_json::from_value(value).wrap_err("bad pay body")?;
            ensure!(hex_n(&req.intent, 32), "intent must be 64 hex characters");
            ensure!(matches!(req.asset.as_str(), "rd" | "dfabi"), "asset must be rd or dfabi");
            dvp_native::parse_account(&req.from)?;
            dvp_native::parse_account(&req.to)?;
            ensure!(norm(&req.from) != norm(&req.to), "from and to must differ");
            let amount = dvp_native::parse_amount(&req.amount)?;
            let main = LegSpec { payer: Some(req.from), recipient: Some(req.to), amount, intent: Some(norm(&req.intent)) };
            let companion = LegSpec { payer: None, recipient: None, amount: 1, intent: None };
            Ok(if req.asset == "rd" { [main, companion] } else { [companion, main] })
        }
        Some("dvp") => {
            let req: DvpReq = serde_json::from_value(value).wrap_err("bad dvp body")?;
            ensure!(hex_n(&req.intent_rd, 32) && hex_n(&req.intent_dfabi, 32), "intent_rd and intent_dfabi must be 64 hex characters");
            dvp_native::parse_account(&req.buyer)?;
            dvp_native::parse_account(&req.seller)?;
            ensure!(norm(&req.buyer) != norm(&req.seller), "buyer and seller must differ");
            let (rd, dfabi) = (dvp_native::parse_amount(&req.rd)?, dvp_native::parse_amount(&req.dfabi)?);
            Ok([
                LegSpec { payer: Some(req.buyer.clone()), recipient: Some(req.seller.clone()), amount: rd, intent: Some(norm(&req.intent_rd)) },
                LegSpec { payer: Some(req.seller), recipient: Some(req.buyer), amount: dfabi, intent: Some(norm(&req.intent_dfabi)) },
            ])
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
}

impl<'a> Aps<'a> {
    pub fn new(backend: &'a dyn ApsBackend, peer: &'a dyn Peer, cfg: ApsConfig) -> Self {
        Self { backend, peer, cfg, intents: IntentStore::default(), submit_lock: Mutex::new(()) }
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
            ("GET", "/aps/wallet") => self.wallet(),
            ("POST", "/aps/submit") => self.submit(now, body),
            (_, "/aps/intent" | "/aps/address" | "/aps/leg" | "/aps/wallet" | "/aps/submit") => error(405, "method not allowed"),
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
        if let Err(reply) = self.consume(now, &req, amount) {
            return reply;
        }
        match self.backend.prove_leg(&req) {
            Ok(prepared) => ok(&Prepared { prepared }),
            Err(e) => fail(e),
        }
    }

    /// Match the leg against the intent this driver registered and spend it, before any proving.
    fn consume(&self, now: Instant, req: &LegReq, amount: u128) -> Result<(), Reply> {
        let terms = IntentTerms { asset: asset_of(req.ordinal).to_owned(), to: norm(&req.recipient), amount };
        match self.intents.take(now, &norm(&req.intent), &terms) {
            Take::Taken => Ok(()),
            Take::Missing => Err(error(403, "no open intent for this leg (unknown, already used or expired)")),
            Take::Mismatch => Err(error(403, "the intent's terms do not match this leg")),
        }
    }

    fn wallet(&self) -> Reply {
        match self.backend.wallet() {
            Ok(wallet) => reply(200, wallet),
            Err(e) => fail(e),
        }
    }

    fn submit(&self, now: Instant, body: &str) -> Reply {
        let legs = match parse_submit(body) {
            Ok(legs) => legs,
            Err(e) => return error(400, format!("{e:#}")),
        };
        if !self.cfg.coordinator {
            return self.forward(body);
        }
        let _one_bundle_at_a_time = self.submit_lock.lock().unwrap_or_else(|p| p.into_inner());
        match self.coordinate(now, &legs) {
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

    /// One bundle: manifest, then per leg the recipient's address, the sponsor's output and the payer's proof, then settle.
    fn coordinate(&self, now: Instant, legs: &[LegSpec; 2]) -> Result<Reply, Reply> {
        let me = self.backend.own_key().map_err(fail)?;
        let is_me = |key: &str| norm(key) == norm(&me);
        let party = |key: &Option<String>| key.clone().unwrap_or_else(|| me.clone());
        // Unknown parties are refused before anything is prepared.
        for spec in legs {
            for key in [party(&spec.payer), party(&spec.recipient)] {
                if !is_me(&key) {
                    self.gateway(&key)?;
                }
            }
        }
        let bundle = self.backend.begin_bundle().map_err(fail)?;
        let mut prepared = Vec::new();
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
                manifest: bundle.manifest.clone(),
                authority_digest: bundle.legs[index].authority_digest.clone(),
                salt: bundle.salt.clone(),
                recipient,
                amount: spec.amount.to_string(),
                recipient_output,
                sponsor_output,
            };
            let leg = if is_me(&payer) {
                // A leg BI pays itself needs BI's own intent like any other payer's; only the companion has none.
                if spec.intent.is_some() {
                    self.consume(now, &req, spec.amount)?;
                }
                self.backend.prove_leg(&req).map_err(fail)?
            } else {
                let answer: Prepared = self.ask(&payer, "/aps/leg", &req)?;
                if !hex_any(&answer.prepared) {
                    return Err(error(502, "/aps/leg: bad answer"));
                }
                answer.prepared
            };
            prepared.push(leg);
        }
        let settled = self.backend.settle(&bundle, &[prepared[0].clone(), prepared[1].clone()]).map_err(fail)?;
        Ok(match settled {
            Some(done) => reply(200, serde_json::json!({ "outcome": "finalized", "bundle_id": bundle.bundle_id, "carrier_tx": done.carrier_tx, "height": done.height })),
            None => reply(200, serde_json::json!({ "outcome": "aborted", "bundle_id": bundle.bundle_id, "carrier_tx": null, "height": null })),
        })
    }
}

/// The real backend, on the driver's own config. The calls that need the split-leg API (T1, `aps_split`) are not wired yet.
pub struct RealBackend<'a> {
    cfg: &'a Mutex<Config>,
}

impl<'a> RealBackend<'a> {
    pub fn new(cfg: &'a Mutex<Config>) -> Self {
        Self { cfg }
    }
}

fn not_wired() -> eyre::Report {
    eyre::eyre!("split leg not wired")
}

impl ApsBackend for RealBackend<'_> {
    fn own_key(&self) -> Result<String> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        Ok(signing_key(&cfg.seed(&cfg.party)?).public_key().to_string())
    }

    fn address(&self, _req: &AddressReq) -> Result<OutputKey> {
        Err(not_wired())
    }

    fn sponsor_output(&self, _ctx: &AddressReq, _active: bool) -> Result<SponsorOutput> {
        Err(not_wired())
    }

    fn begin_bundle(&self) -> Result<BundleCtx> {
        Err(not_wired())
    }

    fn prove_leg(&self, _req: &LegReq) -> Result<String> {
        Err(not_wired())
    }

    fn settle(&self, _bundle: &BundleCtx, _prepared: &[String; 2]) -> Result<Option<Settled>> {
        Err(not_wired())
    }

    fn wallet(&self) -> Result<serde_json::Value> {
        let cfg = self.cfg.lock().unwrap_or_else(|p| p.into_inner());
        pools::wallet_json(&cfg, &cfg.party)
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
            atomic::{AtomicUsize, Ordering},
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
        BundleLists { rd: vec![id(0xa1), id(0xa2)], dfabi: vec![id(0xa1)], heights: BTreeMap::from([(id(0xa1), 5), (id(0xa2), 9)]) }
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
        /// What `bundles` answers (coordinator).
        pub lists: BundleLists,
        /// Every list `merge_bundles` was given (party driver).
        pub merged: Mutex<Vec<BundleLists>>,
        pub active: AtomicUsize,
        pub max_active: AtomicUsize,
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

        fn begin_bundle(&self) -> Result<BundleCtx> {
            self.note("begin_bundle")?;
            let leg = |n: u8| LegCtx { pool_id: id(n), route: "0a".to_owned(), authority_digest: id(0xdd) };
            Ok(BundleCtx { bundle_id: id(0xbb), manifest: "abcd".to_owned(), salt: id(0xcc), expiry_height: 10, network_id: "ee".to_owned(), legs: [leg(1), leg(2)] })
        }

        fn prove_leg(&self, _req: &LegReq) -> Result<String> {
            self.note("prove")?;
            Ok("beef".to_owned())
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
            Self::with(|_, path, _| match path {
                "/aps/address" => Ok((200, serde_json::json!({ "authority": id(0x33), "view_public": id(0x44), "authorization": "abcd" }).to_string())),
                "/aps/leg" => Ok((200, r#"{"prepared":"cafe"}"#.to_owned())),
                "/aps/submit" => Ok((200, r#"{"outcome":"finalized"}"#.to_owned())),
                "/aps/bundles" => Ok((200, serde_json::to_string(&lists()).unwrap())),
                _ => Ok((404, r#"{"error":"not found"}"#.to_owned())),
            })
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

    fn leg_body(intent: &str, ordinal: u8, to: &str, amount: &str) -> String {
        let out = serde_json::json!({ "authority": id(0x11), "view_public": id(0x22), "authorization": "abcd" });
        let sponsor = serde_json::json!({ "authority": id(0x55), "view_public": id(0x66), "authorization": "abcd", "active": ordinal == 0 });
        serde_json::json!({
            "intent": intent, "ordinal": ordinal, "manifest": "abcd", "authority_digest": id(0xdd), "salt": id(0xcc),
            "recipient": to, "amount": amount, "recipient_output": out, "sponsor_output": sponsor,
        })
        .to_string()
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
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!((status, json(&response)), (200, serde_json::json!({ "prepared": "beef" })));
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403, "the intent is spent");
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
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "6")).0, 403, "the rejected terms were not stored");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 200, "the first terms still hold");
    }

    #[test]
    fn an_intent_expires_after_fifteen_minutes() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let start = std::time::Instant::now();
        assert_eq!(aps.route_at(start, "POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let late = start + Duration::from_secs(15 * 60 + 1);
        assert_eq!(aps.route_at(late, "POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403);
        assert!(calls(&backend).is_empty());
        let early = start + Duration::from_secs(14 * 60);
        assert_eq!(aps.route_at(early, "POST", "/aps/intent", &intent_body(&id(2), "rd", &to, "5")).0, 200);
        assert_eq!(aps.route_at(early, "POST", "/aps/leg", &leg_body(&id(2), 0, &to, "5")).0, 200);
    }

    #[test]
    fn a_leg_without_a_matching_intent_is_403_and_never_proves() {
        let (backend, peer) = (driver(8), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!(status, 403);
        assert!(json(&response)["error"].is_string());
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        // another recipient, another amount, the other pool (ordinal 1 = dfabi): none of them is what was approved
        for bad in [leg_body(&intent, 0, &account(7), "5"), leg_body(&intent, 0, &to, "6"), leg_body(&intent, 1, &to, "5")] {
            assert_eq!(aps.route("POST", "/aps/leg", &bad).0, 403, "{bad}");
        }
        assert!(calls(&backend).is_empty(), "no proving without a matching intent");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 200, "a refused leg did not spend the intent");
        assert_eq!(calls(&backend), ["merge_bundles", "prove"]);
    }

    #[test]
    fn an_intent_is_spent_even_when_proving_fails() {
        let backend = FakeBackend { error: Some("read /keys/bank-a.note: denied".to_owned()), ..driver(8) };
        let peer = FakePeer::standard();
        let aps = Aps::new(&backend, &peer, bank());
        let (to, intent) = (account(9), id(1));
        assert_eq!(aps.route("POST", "/aps/intent", &intent_body(&intent, "rd", &to, "5")).0, 200);
        let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
        assert_eq!(status, 502);
        assert!(!response.contains(".note") && !response.contains(".seed"), "{response}");
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 403, "a retry needs a new intent");
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
        assert_eq!(route, [(BANK_B, "/aps/address"), (BANK_A, "/aps/leg")], "address from the recipient, leg from the payer");
        let leg = json(&sent[1].3);
        assert_eq!(
            (leg["intent"].as_str(), leg["ordinal"].as_u64(), leg["recipient"].as_str(), leg["amount"].as_str(), leg["manifest"].as_str()),
            (Some(id(1).as_str()), Some(0), Some(account(9).as_str()), Some("5"), Some("abcd"))
        );
        assert_eq!(leg["recipient_output"]["authority"], id(0x33), "the recipient's own answer");
        assert_eq!(leg["sponsor_output"]["active"], true, "leg 0 pays the sponsor");
        // BI's own side: manifest, its sponsor output per leg, the BI -> BI companion leg without HTTP, then settle
        assert_eq!(calls(&backend), ["begin_bundle", "sponsor_output", "address", "sponsor_output", "prove", "settle"]);
    }

    #[test]
    fn a_dvp_asks_the_buyer_for_the_rd_leg_and_the_seller_for_the_dfabi_leg() {
        let (backend, peer) = (driver(7), FakePeer::standard());
        let aps = Aps::new(&backend, &peer, coordinator());
        let (status, _) = aps.route("POST", "/aps/submit", &dvp_body(&account(8), &account(9), "5", "7"));
        assert_eq!(status, 200);
        let sent = peer.calls.lock().unwrap().clone();
        let route: Vec<_> = sent.iter().map(|call| (call.0.as_str(), call.2.as_str())).collect();
        assert_eq!(route, [(BANK_B, "/aps/address"), (BANK_A, "/aps/leg"), (BANK_A, "/aps/address"), (BANK_B, "/aps/leg")]);
        let (rd, dfabi) = (json(&sent[1].3), json(&sent[3].3));
        assert_eq!((rd["intent"].as_str(), rd["amount"].as_str(), rd["recipient"].as_str()), (Some(id(1).as_str()), Some("5"), Some(account(9).as_str())));
        assert_eq!((dfabi["intent"].as_str(), dfabi["amount"].as_str(), dfabi["recipient"].as_str()), (Some(id(2).as_str()), Some("7"), Some(account(8).as_str())));
        assert_eq!((dfabi["ordinal"].as_u64(), dfabi["sponsor_output"]["active"].as_bool()), (Some(1), Some(false)));
    }

    #[test]
    fn a_payer_that_refuses_its_leg_stops_the_submit_before_settle() {
        let backend = driver(7);
        let peer = FakePeer::with(|_, path, _| match path {
            "/aps/leg" => Ok((403, r#"{"error":"no matching intent"}"#.to_owned())),
            _ => Ok((200, serde_json::json!({ "authority": id(0x33), "view_public": id(0x44), "authorization": "abcd" }).to_string())),
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
        let leg = leg_body(&id(1), 0, &to, "5");
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
            ("/aps/leg", leg_body(&id(1), 2, &to, "5")),
            ("/aps/leg", leg_body("abcd", 0, &to, "5")),
            ("/aps/leg", leg_body(&id(1), 0, "not-a-key", "5")),
            ("/aps/leg", leg_body(&id(1), 0, &to, "0")),
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
        for (method, path) in [("GET", "/aps/intent"), ("GET", "/aps/address"), ("GET", "/aps/leg"), ("GET", "/aps/submit"), ("POST", "/aps/wallet"), ("DELETE", "/aps/leg"), ("POST", "/aps/bundles")] {
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
            all.push(aps.route("POST", "/aps/leg", &leg_body(&id(1), 0, &to, "5")).1);
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
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 200);
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
            let (status, response) = aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5"));
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
        assert_eq!(aps.route("POST", "/aps/leg", &leg_body(&intent, 0, &to, "5")).0, 503);
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
}
