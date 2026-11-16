//! Coordinator: one private DvP (leg 0 RD in ds-rd, leg 1 DFABI in ds-dfabi) as one
//! `AtomicPrivateSettlementV1` bundle against the live network.
//!
//! Follows upstream `integration_tests/tests/nexus/atomic_private_settlement_localnet.rs`
//! @ 071e281e (`governed_legs_with_asset_definitions`, `private_settlement_funding`,
//! `proof_manifest`, `prepare_leg_with_private_data_and_rngs` and the positive smoke
//! workflow), with fresh random secrets instead of fixture seeds.
//!
//! Upstream limit (wallet.rs:750-760): Merkle paths exist only for a freshly activated pool
//! holding exactly its 2 origin notes. So every leg activates its own pool just before it
//! is proved; the origin note is the issuance to the payer, and received notes are not
//! respendable. Public RD/DFABI balances never move.

use std::{
    cell::{Cell, RefCell},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, ensure, eyre};
use iroha::{
    client::{
        AccountTransactionDraft, PrivateSettlementBundleReceiptResponseV1, PrivateSettlementBundleSubmitRequestV1,
        PrivateSettlementLifecycleDtoV1, TransactionWaitOptions, TxConfirmationStatus,
    },
    data_model::{
        NetworkId,
        account::AccountId,
        asset::AssetDefinitionId,
        isi::private_settlement::ActivatePrivateSettlementPoolV1,
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1,
            PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1, PrivateSettlementAbortReasonV1,
            PrivateSettlementAuditNoteOpeningV1, PrivateSettlementAuditOutputRoleV1,
            PrivateSettlementAuditPayerAuthorizationBodyV1,
            PrivateSettlementAuditPayerAuthorizationV1, PrivateSettlementAuditPayerInputV1,
            PrivateSettlementAuditPayerSignatureV1, PrivateSettlementAuditPlaintextV1,
            PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditPolicyV1,
            PrivateSettlementAuditorV1, PrivateSettlementCommitteeAuthorityV1,
            PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementLegCommitmentV1, PrivateSettlementPoolGovernanceLifecycleV1,
            PrivateSettlementPhaseCertificateV1, PrivateSettlementPoolGovernanceV1,
            PrivateSettlementPrepareBarrierV1, PrivateSettlementProvisionalLegMaterialV1,
            PrivateSettlementReceiptV1, PrivateSettlementRouteV1,
        },
        privacy::{
            PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
            PrivacyEncryptedOutputV1, PrivacyEncryptionKeyV1, PrivacyNullifierV1, PrivacyPoolIdV1,
            PrivacyProtocolIdV1, PrivacyRecipientIdV1,
        },
        transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
    },
};
use iroha_core::privacy_engines::{
    atomic_private_settlement::{
        AtomicPrivateSettlementPreparedLegV1,
        AtomicPrivateSettlementProvisionalLegInputV1,
        finalize_atomic_private_settlement_provisional_bundle_v1,
        verify_atomic_private_settlement_v1,
        prepare_atomic_private_settlement_funding_note_v1,
    },
    ivm_private_note::derive_note_authority_v1,
};
use iroha_crypto::{Hash, HashOf, KeyPair, PublicKey, SignatureOf};
use iroha_model_base::{
    metadata::Metadata,
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::numeric::Quantity;
use serde::Deserialize;
use url::Url;

use crate::{
    auditor::{ApproveRequest, ApproveResponse, Keys},
    config::Config,
    inflight::Phase,
    tree::PoolTree,
    wallet::{NoteKeys, open_output},
};

/// Bundles expire this many blocks after the authority context (max_expiry_blocks = 7200).
pub(crate) const EXPIRY_BLOCKS: u64 = 1_000;
/// Must be >= the peers' `nexus.atomic_private_settlement.sidecar_retention_blocks`: Torii
/// rejects an availability share whose retention ends before `stored_at + that value`
/// (torii private_settlement.rs validate_availability_share_policy). Our network keeps the
/// upstream default 1_000_000 (network/nexus.toml does not override it; the upstream localnet
/// test sets 4096, which made every committee member answer 400).
const SIDECAR_RETENTION_BLOCKS: u64 = 1_000_000;
/// Fee ceiling signed into the manifest; each carrier costs per_instruction_fee = 0.001.
const FEE_SIGNED_MAXIMUM: u64 = 1;
/// Private note the sponsor gets back on leg 0 (reimbursement leg). Same value goes into
/// the reimbursement terms commitment and into the leg plaintext.
pub(crate) const SPONSOR_REIMBURSEMENT: u128 = 1;
/// The prover recurses deeply; upstream runs it on 64 MiB stacks.
const PROVER_STACK_BYTES: usize = 64 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const FINALITY_TIMEOUT: Duration = Duration::from_secs(300);
/// Per committee node: the Prepare block reaches every node within seconds once the sponsor's node applied it.
const PREPARE_APPLIED_TIMEOUT: Duration = Duration::from_secs(20);

/// One payment inside the bundle.
pub struct Leg {
    pub lane: u32,
    pub asset: AssetDefinitionId,
    pub payer: KeyPair,
    pub recipient: KeyPair,
    /// Origin note issued to the payer when this leg's pool is activated.
    pub funding: u128,
    pub amount: u128,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    Finalized,
    Aborted,
    /// Either outcome is a result (the HTTP coordinator answers "aborted" for an audit-rejected bundle).
    Either,
}

pub struct Options {
    pub expect: Expect,
    /// After finalization, resubmit the same carrier (S3a) and require a rejection.
    pub replay: bool,
}

#[derive(Clone)]
pub(crate) struct Governed {
    pub route: PrivateSettlementRouteV1,
    pub policy: PrivateSettlementAuditPolicyV1,
    pub governance: PrivateSettlementPoolGovernanceV1,
}

pub struct Funding {
    pub opening: PrivateSettlementAuditNoteOpeningV1,
    pub(crate) spending_secret: [u8; 32],
    /// Positive input in slot 0, unspent reserve (value 1) in slot 1.
    pub input_commitments: [PrivacyCommitmentV1; 2],
}

impl Funding {
    pub fn activation_commitments(&self) -> [PrivacyCommitmentV1; 2] {
        let mut commitments = self.input_commitments;
        commitments.sort_unstable();
        commitments
    }
}

/// Where a leg's positive input note comes from.
pub enum Spend {
    /// Origin note of a pool activated for this bundle (fresh two-note tree).
    Bootstrap(Funding),
    /// A note already in a live pool: `tree` holds every commitment in ledger order, the pool
    /// is at `epoch`, and `secret` is the spend secret behind `opening.spending_authority`. `extra`: a second unspent
    /// note of the same owner (same `secret`) spent in input slot 1 when no single note covers the leg.
    Continue {
        opening: PrivateSettlementAuditNoteOpeningV1,
        secret: [u8; 32],
        tree: PoolTree,
        epoch: u64,
        extra: Option<PrivateSettlementAuditNoteOpeningV1>,
    },
}

impl Spend {
    pub(crate) fn value(&self) -> u128 {
        match self {
            Self::Bootstrap(funding) => funding.opening.value,
            Self::Continue { opening, extra, .. } => opening.value + extra.as_ref().map_or(0, |note| note.value),
        }
    }
}

/// Note keys the leg's settlement output, change output and sponsor reimbursement output are addressed to.
pub struct LegNotes {
    pub recipient: NoteKeys,
    pub change: NoteKeys,
    /// `Config::reimbursement_keys`.
    pub sponsor: NoteKeys,
}

impl LegNotes {
    /// Throwaway keys (DvP on fresh pools: nobody spends these notes again).
    pub fn random() -> Self {
        Self { recipient: NoteKeys::random(), change: NoteKeys::random(), sponsor: NoteKeys::random() }
    }
}

pub(crate) struct Committee {
    pub authority: PrivateSettlementCommitteeAuthorityV1,
    pub endpoints: Vec<Url>,
}

pub fn run_dvp(cfg: &Config, legs: Vec<Leg>, options: &Options) -> Result<()> {
    for (ordinal, leg) in legs.iter().enumerate() {
        let reimbursement = if ordinal == 0 { SPONSOR_REIMBURSEMENT } else { 0 };
        // S2a: refuse before any proving or on-chain write. No amounts in the message:
        // Job logs must not carry transaction plaintext.
        ensure!(
            leg.funding >= leg.amount + reimbursement,
            "leg {ordinal}: insufficient payer note (rejected before proving)"
        );
        // A zero-value change note makes the audit capsule seal fail after the pools are already
        // activated ("private-settlement audit canonical encoding failed", measured 2026-11-10).
        ensure!(
            leg.funding > leg.amount + reimbursement,
            "leg {ordinal}: payer note leaves no change; fund at least 1 more (rejected before proving)"
        );
    }
    let (sponsor, sponsor_key) = cfg.acting_sponsor()?;
    let sponsor_id = AccountId::new(sponsor_key.public_key().clone());
    let network_id = *sponsor.client().network_id();
    let fee = bounded_fee(cfg)?;

    let caps = sponsor.client().get_privacy_capabilities()?;
    ensure!(
        caps.protocols.iter().any(|row| row.protocol_id
            == PrivacyProtocolIdV1::IrohaIvmPrivateNoteStarkV1
            && row.activation.is_some()),
        "IVM private-note capability is not activated"
    );
    let status = sponsor.client().get_lane_lifecycle_status()?;
    status.validate().wrap_err("lane lifecycle status")?;
    let routes = legs
        .iter()
        .map(|leg| {
            let lane_id = LaneId::new(leg.lane);
            let incarnation = status
                .incarnations
                .iter()
                .find(|entry| entry.lane_id == lane_id)
                .ok_or_else(|| eyre!("lane {} has no active incarnation", leg.lane))?
                .incarnation;
            Ok(PrivateSettlementRouteV1 {
                dataspace_id: DataSpaceId::new(u64::from(leg.lane)),
                lane_id,
                lane_incarnation: incarnation,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let committees = routes
        .iter()
        .map(|route| {
            let (authority, endpoints) = committee(cfg, *route)?;
            Ok(Committee { authority, endpoints })
        })
        .collect::<Result<Vec<_>>>()?;

    let (auditors, min_approvals) = auditors_from_config(cfg)?;

    // Pools: policy and governance are active from the height observed now; activation
    // itself commits a few blocks later and becomes the authority context.
    let height = caps.committed_height;
    let expiry_height = height + EXPIRY_BLOCKS;
    let governed = routes
        .iter()
        .zip(&legs)
        .map(|(route, leg)| {
            govern_with(*route, leg.asset.clone(), height, Some(expiry_height + 1), &auditors, min_approvals)
        })
        .collect::<Result<Vec<_>>>()?;
    let fundings = legs
        .iter()
        .map(|leg| funding(leg.funding))
        .collect::<Result<Vec<_>>>()?;
    let activations = governed
        .iter()
        .zip(&fundings)
        .map(|(governed, funding)| {
            Ok(ActivatePrivateSettlementPoolV1::from_restricted(
                &governed.governance,
                funding.activation_commitments().to_vec(),
            )?)
        })
        .collect::<Result<Vec<_>>>()?;
    // One transaction per pool: each activation routes to its own dataspace
    // (queue/router.rs ActivatePrivateSettlementPoolV1 => route.dataspace_id). Both in one
    // transaction (as upstream localnet does) becomes a cross-dataspace NativeAmx plan that
    // never got a lane payload on this cluster: queued forever, no block, 300 s timeout.
    let account = sponsor.account_client();
    for (governed, activation) in governed.iter().zip(activations) {
        let activation = account
            .prepare_transaction(AccountTransactionDraft::new(
                vec![activation],
                fee.clone(),
                Metadata::default(),
            ))
            .and_then(|payload| account.sign_transaction(payload))
            .wrap_err("build pool activation")?;
        let activation_hash = sponsor
            .submit_transaction_and_wait(&activation)
            .wrap_err_with(|| format!("activate pool lane {}", governed.route.lane_id))?;
        println!(
            "pool_activation_tx={activation_hash} lane={} pool_id={}",
            governed.route.lane_id,
            hex::encode(governed.governance.body.pool_id.as_ref())
        );
    }
    let authority_context_height = sponsor.client().get_privacy_capabilities()?.committed_height;
    ensure!(authority_context_height < expiry_height, "pools activated after expiry");

    let reimbursement_salt = rnd();
    let manifest = proof_manifest(
        network_id,
        authority_context_height,
        expiry_height,
        sponsor_id,
        fee,
        &governed,
        reimbursement_salt,
    )?;
    println!("bundle_id={}", hex::encode(manifest.bundle_id.as_ref()));

    let started = Instant::now();
    let mut prepared = Vec::new();
    for (ordinal, ((leg, governed), funding)) in legs.iter().zip(&governed).zip(fundings).enumerate() {
        let authority_digest = committees[ordinal].authority.digest()?;
        prepared.push(on_big_stack(|| {
            prepare_leg(
                ordinal,
                leg,
                governed,
                Spend::Bootstrap(funding),
                &LegNotes::random(),
                &manifest,
                authority_digest,
                &sponsor_key,
                reimbursement_salt,
            )
        })?);
        println!("leg {ordinal} proved after {:?} {}", started.elapsed(), peak_rss());
    }

    settle(cfg, manifest, &prepared, &governed, &committees, started, options, &Cell::new(false), &mut |_, _| Ok(()))?;
    Ok(())
}

/// Upload, audit, prepare, commit and finalize proved legs; prints `result_json=`.
/// Returns the carrier tx and height when the bundle finalized (an audit rejection aborts it). `aborted` is set when a failed
/// stage after Prepare was aborted successfully, so the caller knows nothing moved and nothing stays reserved. `save` gets every
/// phase the nodes made durable, with the manifest to continue from (the final one from `Uploaded` on).
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle(
    cfg: &Config,
    manifest: AtomicPrivateSettlementV1,
    prepared: &[AtomicPrivateSettlementPreparedLegV1],
    governed: &[Governed],
    committees: &[Committee],
    started: Instant,
    options: &Options,
    aborted: &Cell<bool>,
    save: &mut dyn FnMut(Phase, &AtomicPrivateSettlementV1) -> Result<()>,
) -> Result<Option<(String, u64)>> {
    let nodes = RealNodes::new(cfg, &manifest, prepared, governed, committees)?;
    let done = drive(&nodes, manifest, Phase::Proved, aborted, save)?;
    println!("settled after {:?}", started.elapsed());
    print_result(&done.manifest, governed, &done.carrier_tx, done.outcome, done.height);
    check_outcome(done.outcome, options.expect)?;
    if options.replay && done.outcome == "finalized" {
        nodes.replay(&done.manifest)?;
    }
    // The carrier tx, not the bundle id: the chain knows a bundle only by this tx (POST /aps/submit replies it as `carrier_tx`).
    Ok((done.outcome == "finalized").then_some((done.carrier_tx, done.height)))
}

/// Coordinator restart: continue a bundle a previous run left at `phase` (`pools::resume`). `None` = it never reached Prepare.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resume_bundle(
    cfg: &Config,
    manifest: AtomicPrivateSettlementV1,
    prepared: &[AtomicPrivateSettlementPreparedLegV1],
    governed: &[Governed],
    committees: &[Committee],
    phase: Phase,
    aborted: &Cell<bool>,
    save: &mut dyn FnMut(Phase, &AtomicPrivateSettlementV1) -> Result<()>,
) -> Result<Option<Settlement>> {
    let nodes = RealNodes::new(cfg, &manifest, prepared, governed, committees)?;
    continue_bundle(&nodes, manifest, phase, aborted, save)
}

/// How a bundle ended: finalized, or aborted after an audit rejection (`carrier_tx` is then the abort carrier).
pub(crate) struct Settlement {
    pub manifest: AtomicPrivateSettlementV1,
    pub carrier_tx: String,
    pub outcome: &'static str,
    pub height: u64,
}

/// The committee nodes, the auditors and the chain as the coordinator uses them after proving, in the order of the official
/// sequence (docs "Settlement workflow"). `RealNodes` calls them; a test fake counts the carriers.
pub(crate) trait Nodes {
    type Barrier;
    type Commits;
    /// The bundle's public lifecycle on the coordinator's node, `None` when that node cannot say. `Aborted` covers both global abort
    /// markers (an applied `Expired` marker too); `Expired` means past its expiry with no global marker yet: its pools stay
    /// reserved until one is applied.
    fn status(&self, manifest: &AtomicPrivateSettlementV1) -> Option<PrivateSettlementLifecycleDtoV1>;
    /// Certify availability and upload every leg; returns the final manifest.
    fn upload(&self, provisional: &AtomicPrivateSettlementV1) -> Result<AtomicPrivateSettlementV1>;
    /// The audit quorum of every leg; `false` = a leg was rejected.
    fn audited(&self, manifest: &AtomicPrivateSettlementV1) -> Result<bool>;
    /// The Prepare barrier, from the Prepare certificates the nodes hold or else from fresh votes.
    fn prepare(&self, manifest: &AtomicPrivateSettlementV1) -> Result<Self::Barrier>;
    /// Carrier: the Prepare registration, applied on a vote quorum of the committee.
    fn register(&self, barrier: &Self::Barrier) -> Result<()>;
    /// The Commit certificates the nodes hold, or else fresh ones.
    fn commit(&self, barrier: &Self::Barrier) -> Result<Self::Commits>;
    /// Carrier: the finalization; returns its tx hash.
    fn finalize(&self, barrier: &Self::Barrier, commits: &Self::Commits) -> Result<String>;
    /// Carrier: the abort marker; returns its tx hash.
    fn abort(&self, manifest: &AtomicPrivateSettlementV1, reason: PrivateSettlementAbortReasonV1) -> Result<String>;
    /// The terminal receipt all four nodes agree on.
    fn receipt(&self, manifest: &AtomicPrivateSettlementV1) -> Result<(&'static str, u64)>;
}

/// A bundle a previous run left at `phase`: its end when the nodes report one; past its expiry with no marker, the `Expired` marker;
/// `None` when it never reached Prepare (nothing is reserved; it is dropped and its sidecars expire); else the phases after `phase`.
pub(crate) fn continue_bundle<N: Nodes>(
    nodes: &N,
    manifest: AtomicPrivateSettlementV1,
    phase: Phase,
    aborted: &Cell<bool>,
    save: &mut dyn FnMut(Phase, &AtomicPrivateSettlementV1) -> Result<()>,
) -> Result<Option<Settlement>> {
    use PrivateSettlementLifecycleDtoV1::{Aborted, Expired, Finalized};
    match nodes.status(&manifest) {
        Some(Finalized | Aborted) => {
            // The carrier tx of an earlier run is not known here.
            let (outcome, height) = nodes.receipt(&manifest)?;
            return Ok(Some(Settlement { manifest, carrier_tx: String::new(), outcome, height }));
        }
        // The receipt stays pending until a marker is applied: submit it, or the pools stay reserved.
        Some(Expired) => {
            let (carrier_tx, height) = abort_and_wait(nodes, &manifest)?;
            aborted.set(true);
            return Ok(Some(Settlement { manifest, carrier_tx, outcome: "aborted", height }));
        }
        _ => {}
    }
    if phase == Phase::Proved {
        return Ok(None);
    }
    drive(nodes, manifest, phase, aborted, save).map(Some)
}

/// Run the phases after `from` (a fresh bundle: `Proved`) and `save` each one the nodes made durable. Prepare and Commit
/// certificates always come from the nodes (`recover_or_*`). Any failure once Prepare may have reserved the pools aborts the bundle.
fn drive<N: Nodes>(
    nodes: &N,
    manifest: AtomicPrivateSettlementV1,
    from: Phase,
    aborted: &Cell<bool>,
    save: &mut dyn FnMut(Phase, &AtomicPrivateSettlementV1) -> Result<()>,
) -> Result<Settlement> {
    let manifest = if from == Phase::Proved {
        let uploaded = nodes.upload(&manifest)?;
        save(Phase::Uploaded, &uploaded)?;
        println!("legs uploaded");
        uploaded
    } else {
        manifest
    };
    if from <= Phase::Uploaded && !nodes.audited(&manifest)? {
        let carrier_tx = nodes.abort(&manifest, PrivateSettlementAbortReasonV1::AuditUnavailable)?;
        let (outcome, height) = nodes.receipt(&manifest)?;
        return Ok(Settlement { manifest, carrier_tx, outcome, height });
    }
    // Prepare votes stage each leg and reserve its pool head (iroha_core sidecar_store.rs ensure_reservations_available_v1): a
    // bundle that stops here would lock both pools until expiry. Abort it so the global terminal record releases the reservations.
    let abort = || -> Result<()> {
        abort_and_wait(nodes, &manifest)?;
        aborted.set(true);
        Ok(())
    };
    let prepared = (|| -> Result<_> {
        let barrier = nodes.prepare(&manifest)?;
        if from <= Phase::Uploaded {
            nodes.register(&barrier)?;
            save(Phase::Registered, &manifest)?;
            println!("prepare registered");
        }
        Ok(barrier)
    })();
    let barrier = abort_on_error(prepared, "prepare", &abort)?;
    // Past this point the pools are reserved too: any failure before a terminal receipt aborts the bundle.
    let finalization = (|| -> Result<_> {
        let commits = nodes.commit(&barrier)?;
        if from < Phase::Committed {
            save(Phase::Committed, &manifest)?;
        }
        let carrier_tx = match nodes.finalize(&barrier, &commits) {
            Ok(carrier_tx) => carrier_tx,
            // An earlier run's finalization may already be queued: its receipt wins over an abort.
            Err(error) if from == Phase::Committed => {
                return match nodes.receipt(&manifest) {
                    Ok((outcome, height)) => Ok((String::new(), outcome, height)),
                    Err(seen) if seen.downcast_ref::<FinalizedSeen>().is_some() => Err(seen),
                    Err(_) => Err(error),
                };
            }
            Err(error) => return Err(error),
        };
        let (outcome, height) = nodes.receipt(&manifest)?;
        Ok((carrier_tx, outcome, height))
    })();
    let (carrier_tx, outcome, height) = abort_on_error(finalization, "finalization", &abort)?;
    Ok(Settlement { manifest, carrier_tx, outcome, height })
}

/// Abort a bundle that has not finalized and wait until all four validators report it aborted; this releases its
/// pool/nullifier/output reservations.
/// Returns the abort carrier tx and the aborted height.
fn abort_and_wait<N: Nodes>(nodes: &N, manifest: &AtomicPrivateSettlementV1) -> Result<(String, u64)> {
    // Past its expiry only the `Expired` marker is admissible (Torii's authoritative-height rule): a bundle resumed late still ends.
    let carrier_tx = nodes
        .abort(manifest, PrivateSettlementAbortReasonV1::ParticipantRejected)
        .or_else(|first| nodes.abort(manifest, PrivateSettlementAbortReasonV1::Expired).map_err(|_| first))?;
    let (outcome, height) = nodes.receipt(manifest)?;
    if outcome == "finalized" {
        return Err(eyre::Report::new(FinalizedSeen("abort ended as finalized".into())));
    }
    ensure!(outcome == "aborted", "abort ended as {outcome}");
    Ok((carrier_tx, height))
}

/// `abort-bundle`: abort with the key that is `manifest.sponsor` (`Config::signer_for`).
pub(crate) fn abort_bundle(cfg: &Config, manifest: &AtomicPrivateSettlementV1) -> Result<()> {
    abort_and_wait(&RealNodes::new(cfg, manifest, &[], &[], &[])?, manifest).map(|_| ())
}

/// Torii of the committee nodes and the auditors for one bundle; every carrier is signed by the key that is `manifest.sponsor`
/// and measured against the governed carrier limit.
struct RealNodes<'a> {
    cfg: &'a Config,
    sponsor: iroha::blocking::Client,
    prepared: &'a [AtomicPrivateSettlementPreparedLegV1],
    governed: &'a [Governed],
    committees: &'a [Committee],
    endpoints: Vec<Vec<Url>>,
    max_carrier_bytes: u64,
    /// The finalization carrier, for `Options::replay`.
    finalization: RefCell<Option<PrivateSettlementBundleSubmitRequestV1>>,
}

impl<'a> RealNodes<'a> {
    fn new(
        cfg: &'a Config,
        manifest: &AtomicPrivateSettlementV1,
        prepared: &'a [AtomicPrivateSettlementPreparedLegV1],
        governed: &'a [Governed],
        committees: &'a [Committee],
    ) -> Result<Self> {
        let max_carrier_bytes = cfg.max_carrier_bytes()?;
        let (sponsor, _) = cfg.signer_for(&manifest.sponsor)?;
        let endpoints = committees.iter().map(|c| c.endpoints.clone()).collect();
        Ok(Self { cfg, sponsor, prepared, governed, committees, endpoints, max_carrier_bytes, finalization: RefCell::new(None) })
    }

    /// S3a: resubmit the finalization carrier and require that the receipt stays finalized once.
    fn replay(&self, manifest: &AtomicPrivateSettlementV1) -> Result<()> {
        let finalization = self.finalization.borrow();
        let request = finalization.as_ref().ok_or_else(|| eyre!("no finalization carrier to replay"))?;
        match self.sponsor.client().submit_private_settlement_bundle_v1(request) {
            Err(error) => println!("replay rejected: {error:#}"),
            Ok(_) => {
                thread::sleep(Duration::from_secs(10));
                let (again, _) = wait_receipt(self.cfg, manifest)?;
                ensure!(again == "finalized", "replay changed the receipt to {again}");
                println!("replay accepted by Torii but receipt unchanged (finalized once)");
            }
        }
        Ok(())
    }
}

impl Nodes for RealNodes<'_> {
    type Barrier = PrivateSettlementPrepareBarrierV1;
    type Commits = Vec<PrivateSettlementPhaseCertificateV1>;

    fn status(&self, manifest: &AtomicPrivateSettlementV1) -> Option<PrivateSettlementLifecycleDtoV1> {
        let client = self.sponsor.client();
        match client.private_settlement_bundle_status_v1(manifest.bundle_id) {
            // A global marker has a finalized height; an applied `Expired` marker ends the bundle like an abort.
            Ok(status) if status.finalized_height.is_some() && status.lifecycle == PrivateSettlementLifecycleDtoV1::Expired => {
                Some(PrivateSettlementLifecycleDtoV1::Aborted)
            }
            Ok(status) => Some(status.lifecycle),
            // Past expiry with no marker Torii answers `Expired` without a finalized height, which the upstream client refuses as
            // malformed: read the height instead.
            Err(_) => client
                .get_privacy_capabilities()
                .ok()
                .filter(|caps| caps.committed_height > manifest.expiry_height)
                .map(|_| PrivateSettlementLifecycleDtoV1::Expired),
        }
    }

    /// Upstream certifies availability (exactly 3 of 4 shares) and promotes every leg on all four nodes; only a certificate signer
    /// that refuses the upload fails it. It returns no manifest, so the final one is read back from a committee node and must be
    /// the provisional one with every availability certificate digest filled in and nothing else changed.
    fn upload(&self, provisional: &AtomicPrivateSettlementV1) -> Result<AtomicPrivateSettlementV1> {
        let materials = provisional_materials(provisional.clone(), self.prepared, self.governed, self.committees)?;
        self.sponsor
            .client()
            .certify_and_upload_private_settlement_legs_v1(&materials, &self.endpoints)
            .wrap_err("upload legs")?;
        let sent = &materials[0].manifest;
        for endpoint in &self.endpoints[0] {
            let (node, _) = self.cfg.sponsor_at(endpoint)?;
            let retained = node.client().private_settlement_bundle_status_v1(sent.bundle_id).ok().and_then(|status| status.manifest);
            if let Some(manifest) = retained.filter(|manifest| is_final_of(manifest, sent)) {
                return Ok(manifest);
            }
        }
        Err(eyre!("no committee node returned the uploaded manifest"))
    }

    fn audited(&self, manifest: &AtomicPrivateSettlementV1) -> Result<bool> {
        for (ordinal, leg) in self.governed.iter().enumerate() {
            let response: ApproveResponse = approve_k_of_n(
                self.cfg,
                &serde_json::to_string(&ApproveRequest {
                    governance: enc(&leg.governance)?,
                    policy: enc(&leg.policy)?,
                    payload_digest: enc(&manifest.legs[ordinal].payload_digest)?,
                })?,
            )?;
            if !response.approved {
                println!("leg {ordinal} audit rejected: {}", response.reason);
                return Ok(false);
            }
            println!("leg {ordinal} audited");
        }
        Ok(true)
    }

    fn prepare(&self, manifest: &AtomicPrivateSettlementV1) -> Result<Self::Barrier> {
        let authorities = self.committees.iter().map(|c| c.authority.clone()).collect::<Vec<_>>();
        let deltas = self.prepared.iter().map(|leg| leg.delta.clone()).collect::<Vec<_>>();
        self.sponsor
            .client()
            .recover_or_prepare_private_settlement_bundle_v1(&self.endpoints, manifest, &authorities, &deltas)
            .wrap_err("prepare votes")
    }

    fn register(&self, barrier: &Self::Barrier) -> Result<()> {
        let client = self.sponsor.client();
        let request = client
            .build_private_settlement_prepare_registration_request_v1(barrier, self.max_carrier_bytes)
            .wrap_err("register prepare")?;
        let hash = request.transaction.hash();
        register_with_recheck(
            || {
                client.submit_private_settlement_bundle_v1(&request).wrap_err("register prepare")?;
                client
                    .wait_for_transaction_applied(
                        hash,
                        TransactionWaitOptions { timeout: FINALITY_TIMEOUT, poll_interval: POLL_INTERVAL },
                    )
                    .wrap_err("register prepare")?;
                Ok(())
            },
            // One idempotent GET of the same tx on a fresh client (a new connection pool).
            || {
                let (fresh, _) = self.cfg.acting_sponsor()?;
                Ok(matches!(fresh.client().get_transaction_status(hash)?, Some(TxConfirmationStatus::Applied)))
            },
        )?;
        // Every leg's committee is the same four validators (committee()), in authority order.
        applied_on_quorum(self.endpoints[0].len(), |node| {
            let (peer, _) = self.cfg.sponsor_at(&self.endpoints[0][node])?;
            peer.client().wait_for_transaction_applied(
                hash,
                TransactionWaitOptions { timeout: PREPARE_APPLIED_TIMEOUT, poll_interval: POLL_INTERVAL },
            )?;
            Ok(())
        })
        .wrap_err("commit votes")
    }

    fn commit(&self, barrier: &Self::Barrier) -> Result<Self::Commits> {
        self.sponsor
            .client()
            .recover_or_commit_private_settlement_bundle_v1(&self.endpoints, barrier)
            .wrap_err("commit votes")
    }

    fn finalize(&self, barrier: &Self::Barrier, commits: &Self::Commits) -> Result<String> {
        let client = self.sponsor.client();
        let request = client.build_private_settlement_finalization_request_v1(barrier, commits, self.max_carrier_bytes)?;
        client.submit_private_settlement_bundle_v1(&request).wrap_err("submit finalization")?;
        let carrier_tx = request.transaction.hash().to_string();
        *self.finalization.borrow_mut() = Some(request);
        Ok(carrier_tx)
    }

    fn abort(&self, manifest: &AtomicPrivateSettlementV1, reason: PrivateSettlementAbortReasonV1) -> Result<String> {
        let client = self.sponsor.client();
        let request = client.build_private_settlement_abort_request_v1(manifest, reason, self.max_carrier_bytes)?;
        client.submit_private_settlement_bundle_v1(&request).wrap_err("submit abort")?;
        Ok(request.transaction.hash().to_string())
    }

    fn receipt(&self, manifest: &AtomicPrivateSettlementV1) -> Result<(&'static str, u64)> {
        wait_receipt(self.cfg, manifest)
    }
}

/// `manifest` is `provisional` with every availability certificate digest filled in, and nothing else changed.
fn is_final_of(manifest: &AtomicPrivateSettlementV1, provisional: &AtomicPrivateSettlementV1) -> bool {
    let mut unfilled = manifest.clone();
    for (leg, sent) in unfilled.legs.iter_mut().zip(&provisional.legs) {
        if leg.availability_certificate_digest == sent.availability_certificate_digest {
            return false;
        }
        leg.availability_certificate_digest = sent.availability_certificate_digest;
    }
    unfilled == *provisional
}

/// A receipt poll failed after some node had already finalized the bundle: it can no longer be aborted.
#[derive(Debug)]
struct FinalizedSeen(String);

impl std::fmt::Display for FinalizedSeen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for FinalizedSeen {}

/// Why a receipt poll has no single terminal answer (yet), or Ok while it should keep polling.
fn receipt_error(kinds: &[&str], expired: bool) -> Result<()> {
    let finalized = kinds.contains(&"finalized");
    if finalized && kinds.contains(&"aborted") {
        return Err(eyre::Report::new(FinalizedSeen(format!("nodes disagree: {kinds:?}"))));
    }
    if expired {
        let message = format!("no terminal receipt on all nodes: {kinds:?}");
        return Err(if finalized { eyre::Report::new(FinalizedSeen(message)) } else { eyre!(message) });
    }
    Ok(())
}

/// Runs the Prepare registration. When it fails (for example one dropped status GET while waiting), asks `applied`
/// once, on a fresh connection, whether the registration transaction was applied anyway: then the bundle is
/// prepared and the flow goes on. Otherwise the original error is returned and the caller aborts.
fn register_with_recheck(register: impl FnOnce() -> Result<()>, applied: impl FnOnce() -> Result<bool>) -> Result<()> {
    match register() {
        Ok(()) => Ok(()),
        Err(error) => match applied() {
            Ok(true) => {
                eprintln!("prepare registration wait failed but the transaction is Applied, continuing: {error:#}");
                Ok(())
            }
            Ok(false) => Err(error),
            Err(check) => {
                eprintln!("prepare re-check failed: {check:#}");
                Err(error)
            }
        },
    }
}

/// Waits, peer by peer, until `wait_one(i)` reports the Prepare registration applied on a vote quorum of the
/// `peers` committee nodes. A node signs a Commit vote only once its own state holds the staged Prepare lock
/// (iroha_core phase.rs commit_vote), so asking for votes as soon as the sponsor's node applied it races the others.
fn applied_on_quorum(peers: usize, mut wait_one: impl FnMut(usize) -> Result<()>) -> Result<()> {
    let quorum = usize::from(PRIVATE_SETTLEMENT_COMMITTEE_QUORUM_V1);
    let mut applied = 0;
    for node in 0..peers {
        match wait_one(node) {
            Ok(()) => applied += 1,
            Err(error) => eprintln!("prepare registration not applied on committee node {node}: {error:#}"),
        }
        if applied >= quorum {
            return Ok(());
        }
    }
    Err(eyre!("prepare registration applied on {applied} of {peers} committee nodes, {quorum} needed for Commit votes"))
}

/// Runs `abort` when `result` failed, so a failed stage never leaves pool reservations held until expiry.
/// The stage's own error is returned; a failed abort is only reported.
fn abort_on_error<T>(result: Result<T>, stage: &str, abort: impl FnOnce() -> Result<()>) -> Result<T> {
    if let Err(error) = &result {
        if error.downcast_ref::<FinalizedSeen>().is_some() {
            eprintln!("{stage} failed after a node finalized the bundle, not aborting: {error:#}");
        } else {
            eprintln!("{stage} failed, aborting the bundle to release pool reservations: {error:#}");
            match abort() {
                Ok(()) => eprintln!("bundle aborted"), // stderr: Lensa logs only stderr, stdout is parsed
                Err(abort) if abort.downcast_ref::<FinalizedSeen>().is_some() => {
                    eprintln!("the bundle had finalized, nothing to release: {abort:#}");
                }
                Err(abort) => eprintln!("abort failed (pools stay reserved until the bundle expires; `abort-bundle <bundle_id printed above>` retries): {abort:#}"),
            }
        }
    }
    result
}

/// One machine-readable line for callers (Lensa): public identifiers only, no amounts or
/// parties (those stay in the payers' wallets and in BI's audit store).
fn print_result(manifest: &AtomicPrivateSettlementV1, governed: &[Governed], carrier_tx: &str, outcome: &str, height: u64) {
    let legs = governed
        .iter()
        .map(|leg| {
            serde_json::json!({
                "lane": leg.route.lane_id.as_u32(),
                "pool_id": hex::encode(leg.governance.body.pool_id.as_ref()),
            })
        })
        .collect::<Vec<_>>();
    println!(
        "result_json={}",
        serde_json::json!({
            "bundle_id": hex::encode(manifest.bundle_id.as_ref()),
            "carrier_tx": carrier_tx,
            "outcome": outcome,
            "height": height,
            "legs": legs,
        })
    );
}

pub(crate) fn check_outcome(outcome: &'static str, expect: Expect) -> Result<()> {
    println!("outcome={outcome}");
    let want = match expect {
        Expect::Finalized => "finalized",
        Expect::Aborted => "aborted",
        Expect::Either => return Ok(()),
    };
    ensure!(outcome == want, "expected {want}, got {outcome}");
    Ok(())
}

pub(crate) fn bounded_fee(cfg: &Config) -> Result<FeePaymentIntent> {
    bounded_fee_for(&cfg.fee_asset)
}

pub(crate) fn bounded_fee_for(fee_asset: &str) -> Result<FeePaymentIntent> {
    Ok(FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset.parse()?,
            Quantity::from(FEE_SIGNED_MAXIMUM),
        )],
        None,
    ))
}

/// Wait until every node reports the same terminal receipt kind. A finalized receipt must carry exactly `manifest`.
pub(crate) fn wait_receipt(cfg: &Config, manifest: &AtomicPrivateSettlementV1) -> Result<(&'static str, u64)> {
    let clients = cfg
        .torii
        .keys()
        .map(|party| Ok((party.clone(), cfg.sponsor(party)?.0)))
        .collect::<Result<Vec<_>>>()?;
    let deadline = Instant::now() + FINALITY_TIMEOUT;
    loop {
        let mut kinds = Vec::new();
        let mut height = 0;
        for (party, client) in &clients {
            let kind = match client.client().private_settlement_bundle_receipt_v1(manifest.bundle_id) {
                Ok(PrivateSettlementBundleReceiptResponseV1::Pending { .. }) => "pending",
                Ok(PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)) => {
                    height = finalized_height(party, &receipt, manifest)?;
                    "finalized"
                }
                Ok(PrivateSettlementBundleReceiptResponseV1::Aborted(_)) => "aborted",
                Err(error) => {
                    eprintln!("{party}: receipt query failed: {error:#}");
                    "pending"
                }
            };
            kinds.push(kind);
        }
        if kinds.iter().all(|kind| *kind != "pending" && *kind == kinds[0]) {
            return Ok((kinds[0], height));
        }
        receipt_error(&kinds, Instant::now() >= deadline)?;
        thread::sleep(POLL_INTERVAL);
    }
}

/// The height of one node's finalized receipt, which must be this bundle's exact manifest and name its legs.
fn finalized_height(party: &str, receipt: &PrivateSettlementReceiptV1, manifest: &AtomicPrivateSettlementV1) -> Result<u64> {
    ensure!(receipt.manifest == *manifest, "{party}: receipt manifest differs");
    if receipt.legs.is_empty() {
        return Err(eyre::Report::new(FinalizedSeen(format!("{party}: empty finalized receipt"))));
    }
    Ok(receipt.finalized_height)
}

pub(crate) fn auditor_call<T: for<'de> Deserialize<'de>>(cfg: &Config, method: &str, path: &str, body: &str) -> Result<T> {
    auditor_call_at(cfg.tls.as_ref(), &cfg.auditor_url, method, path, body)
}

pub(crate) fn auditor_call_at<T: for<'de> Deserialize<'de>>(tls: Option<&crate::config::TlsConfig>, url: &str, method: &str, path: &str, body: &str) -> Result<T> {
    let (status, response) = crate::http::send(tls, url, method, path, body, None, Duration::from_secs(600)).wrap_err_with(|| format!("call auditor {url}"))?;
    ensure!(status == 200, "auditor {url} {path} returned {status}: {response}");
    Ok(serde_json::from_str(&response)?)
}

/// The policy's auditors (signing + encryption key, in the config's order) and `min_approvals`, from `[audit]` or the single
/// `auditor_url` (iroha3 PLAN S11). Every auditor must answer `/keys`: a policy cannot name an auditor whose key is unknown.
pub(crate) fn auditors_from_config(cfg: &Config) -> Result<(Vec<(PublicKey, PrivateSettlementHybridPublicKeyV1)>, usize)> {
    let policy = cfg.audit_policy()?;
    let auditors = policy
        .auditor_urls
        .iter()
        .map(|url| {
            let keys: Keys = auditor_call_at(cfg.tls.as_ref(), url, "GET", "/keys", "")?;
            Ok((keys.signing.parse::<PublicKey>()?, dec::<PrivateSettlementHybridPublicKeyV1>(&keys.encryption)?))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((auditors, policy.min_approvals))
}

/// Product timeouts of the audit decision (ANALYST Q-D): connect 3 s and response 60 s per auditor, 90 s overall.
const AUDITOR_CONNECT: Duration = Duration::from_secs(3);
const AUDITOR_RESPONSE: Duration = Duration::from_secs(60);
const AUDIT_DECISION: Duration = Duration::from_secs(90);

/// Ask ALL auditors in parallel to approve one leg, then decide (b2, client policy): any explicit Reject aborts, else k
/// approvals proceed, else abort "insufficient approvals". An unreachable or slow auditor is no approval and never blocks.
fn approve_k_of_n(cfg: &Config, request: &str) -> Result<ApproveResponse> {
    use crate::approval::{Answer, Verdict, gather, reason};
    let policy = cfg.audit_policy()?;
    let urls = Arc::new(policy.auditor_urls.clone());
    let body = Arc::new(request.to_owned());
    let tls = Arc::new(cfg.tls.clone());
    let ask: Arc<dyn Fn(usize) -> Answer + Send + Sync> = {
        let urls = urls.clone();
        Arc::new(move |index| {
            let url = &urls[index];
            let result = crate::http::send(tls.as_ref().as_ref(), url, "POST", "/approve", &body, Some(AUDITOR_CONNECT), AUDITOR_RESPONSE).and_then(|(status, response)| {
                ensure!(status == 200, "auditor {url} /approve returned {status}: {response}");
                Ok(serde_json::from_str::<ApproveResponse>(&response)?)
            });
            match result {
                Ok(response) if response.approved => Answer::Approved,
                Ok(response) => {
                    eprintln!("auditor {url} REJECTED: {}", response.reason);
                    Answer::Rejected
                }
                Err(error) => {
                    eprintln!("auditor {url} unavailable: {error:#}");
                    Answer::Unavailable
                }
            }
        })
    };
    let (verdict, answers) = gather(policy.min_approvals, urls.len(), AUDIT_DECISION, ask);
    eprintln!("audit decision {verdict:?} (k = {}): {} = {answers:?}", policy.min_approvals, urls.join(","));
    Ok(match verdict {
        Verdict::Approved => ApproveResponse { approved: true, reason: String::new() },
        other => ApproveResponse { approved: false, reason: reason(other).to_owned() },
    })
}

/// Committee for a route: all four validators sorted by PeerId, with their Torii URLs in
/// the same order. Our validators serve every lane (network/nexus.toml).
pub fn committee(
    cfg: &Config,
    route: PrivateSettlementRouteV1,
) -> Result<(PrivateSettlementCommitteeAuthorityV1, Vec<Url>)> {
    let (authority, parties) = committee_authority(&cfg.peers_json, route)?;
    let endpoints = parties
        .iter()
        .map(|party| Ok(cfg.torii(party)?.clone()))
        .collect::<Result<_>>()?;
    Ok((authority, endpoints))
}

/// Authority from network/public/peers.json, plus the party names in authority order.
pub(crate) fn committee_authority(
    peers_json: &Path,
    route: PrivateSettlementRouteV1,
) -> Result<(PrivateSettlementCommitteeAuthorityV1, Vec<String>)> {
    #[derive(Deserialize)]
    struct Peer {
        party: String,
        public_key: String,
        pop_hex: String,
    }
    let text = std::fs::read_to_string(peers_json)
        .wrap_err_with(|| format!("read {}", peers_json.display()))?;
    let peers: Vec<Peer> = serde_json::from_str(&text)?;
    let mut rows = peers
        .into_iter()
        .map(|peer| {
            Ok((
                PeerId::from(peer.public_key.parse::<PublicKey>()?),
                hex::decode(peer.pop_hex.trim_start_matches("0x"))?,
                peer.party,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let validators = rows.iter().map(|row| row.0.clone()).collect::<Vec<_>>();
    let authority = PrivateSettlementCommitteeAuthorityV1 {
        route,
        validator_set_hash: HashOf::new(&validators),
        validators,
        validator_pops: rows.iter().map(|row| row.1.clone()).collect(),
    };
    authority.validate().wrap_err("committee authority")?;
    Ok((authority, rows.into_iter().map(|row| row.2).collect()))
}

/// Offline: build and prove one RD leg against a synthetic route, then print wall time
/// and peak RSS. No network access. Sizes the Job memory limit and smoke-tests the image.
pub fn prove_selftest(peers_json: &Path) -> Result<()> {
    // A bundle needs 2..=255 legs: govern both routes, prove leg 0 only.
    let route = |lane: u32| PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(u64::from(lane)),
        lane_id: LaneId::new(lane),
        lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
    };
    let (authority, _) = committee_authority(peers_json, route(1))?;
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"rd-dfabi-selftest-network",
    )));
    let auditor_key = fixture_key(0x30);
    let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
    let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng)?;
    let encryption = PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public());
    let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
        .into_iter()
        .map(|(lane, asset)| {
            govern(route(lane), asset.parse()?, 100, 100 + EXPIRY_BLOCKS, auditor_key.public_key(), &encryption)
        })
        .collect::<Result<Vec<_>>>()?;
    let sponsor_key = fixture_key(0x31);
    let leg = Leg {
        lane: 1,
        asset: governed[0].governance.body.asset_definition_id.clone(),
        payer: fixture_key(0x32),
        recipient: fixture_key(0x33),
        funding: 1_000,
        amount: 100,
    };
    let salt = rnd();
    let manifest = proof_manifest(
        network_id,
        101,
        100 + EXPIRY_BLOCKS,
        AccountId::new(sponsor_key.public_key().clone()),
        bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw")?,
        &governed,
        salt,
    )?;
    let started = Instant::now();
    let funding = funding(leg.funding)?;
    let authority_digest = authority.digest()?;
    on_big_stack(|| {
        prepare_leg(0, &leg, &governed[0], Spend::Bootstrap(funding), &LegNotes::random(), &manifest, authority_digest, &sponsor_key, salt)
    })?;
    println!(
        "prove-selftest ok elapsed_ms={} {}",
        started.elapsed().as_millis(),
        peak_rss()
    );
    Ok(())
}

/// Gate G1a (offline): settlement 2 spends the note settlement 1 paid out, in the same pool.
/// Input 0 is the received output (path from the client-side tree), input 1 a virtual dummy.
/// Both proofs must verify. Prints no amounts.
pub fn prove_continuation_selftest(peers_json: &Path) -> Result<()> {
    let route = |lane: u32| PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(u64::from(lane)),
        lane_id: LaneId::new(lane),
        lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
    };
    let (authority, _) = committee_authority(peers_json, route(1))?;
    let authority_digest = authority.digest()?;
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
        b"rd-dfabi-selftest-network",
    )));
    let auditor_key = fixture_key(0x30);
    let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
    let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng)?;
    let encryption = PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public());
    let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
        .into_iter()
        .map(|(lane, asset)| {
            govern(route(lane), asset.parse()?, 100, 100 + EXPIRY_BLOCKS, auditor_key.public_key(), &encryption)
        })
        .collect::<Result<Vec<_>>>()?;
    let pool_id = governed[0].governance.body.pool_id;
    let sponsor_key = fixture_key(0x31);
    let fee = bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw")?;
    let genesis = *network_id.as_genesis_hash().as_ref();
    let (alice, bob, carol) = (NoteKeys::random(), NoteKeys::random(), NoteKeys::random());
    let asset = governed[0].governance.body.asset_definition_id.clone();
    let started = Instant::now();

    // Settlement 1: alice's origin note pays bob 100 (bootstrap, as every DvP does today).
    let funding1 = funding(1_000)?;
    let mut tree = PoolTree::new(pool_id)?;
    tree.append(&funding1.activation_commitments())?;
    let salt1 = rnd();
    let manifest1 = proof_manifest(network_id, 101, 100 + EXPIRY_BLOCKS, AccountId::new(sponsor_key.public_key().clone()), fee.clone(), &governed, salt1)?;
    let leg1 = Leg { lane: 1, asset: asset.clone(), payer: fixture_key(0x32), recipient: fixture_key(0x33), funding: 1_000, amount: 100 };
    let notes1 = LegNotes { recipient: bob.clone(), change: alice, sponsor: NoteKeys::random() };
    let first = on_big_stack(|| {
        prepare_leg(0, &leg1, &governed[0], Spend::Bootstrap(funding1), &notes1, &manifest1, authority_digest, &sponsor_key, salt1)
    })?;
    verify_atomic_private_settlement_v1(&manifest1, &first.statement, genesis, 101, &first.proof)
        .map_err(|e| eyre!("settlement 1 proof rejected: {e:?}"))?;
    tree.append(&first.statement.output_commitments)?;
    ensure!(tree.root() == first.statement.new_root, "client tree root differs from settlement 1 successor root");

    // bob finds his note among the public outputs with his view key alone.
    let mut received = None;
    for (commitment, encrypted) in first.statement.output_commitments.iter().zip(&first.statement.encrypted_outputs) {
        if let Some(opening) = open_output(pool_id, *commitment, encrypted, &bob)? {
            received = Some(opening);
        }
    }
    let received = received.ok_or_else(|| eyre!("bob found no note addressed to him"))?;

    // Settlement 2: bob spends the received note, paying carol 40 (change 59, reimbursement 1).
    let salt2 = rnd();
    let manifest2 = proof_manifest(network_id, 102, 100 + EXPIRY_BLOCKS, AccountId::new(sponsor_key.public_key().clone()), fee, &governed, salt2)?;
    let leg2 = Leg { lane: 1, asset, payer: fixture_key(0x33), recipient: fixture_key(0x34), funding: received.value, amount: 40 };
    let notes2 = LegNotes { recipient: carol, change: bob.one_time(manifest2.bundle_id.as_ref(), pool_id.as_ref(), 1), sponsor: NoteKeys::random() };
    let expected_nullifier = crate::wallet::note_nullifier(pool_id, &bob.spend, &received)?;
    let spend = Spend::Continue { opening: received, secret: bob.spend, tree, epoch: 2, extra: None };
    let second = on_big_stack(|| {
        prepare_leg(0, &leg2, &governed[0], spend, &notes2, &manifest2, authority_digest, &sponsor_key, salt2)
    })?;
    verify_atomic_private_settlement_v1(&manifest2, &second.statement, genesis, 102, &second.proof)
        .map_err(|e| eyre!("continuation proof rejected: {e:?}"))?;
    ensure!(second.statement.old_epoch == 2 && second.statement.new_epoch == 3, "continuation epochs");
    ensure!(second.statement.nullifiers[0] == expected_nullifier, "wallet nullifier differs from the proved one");
    println!("continuation_verified=true elapsed_ms={} {}", started.elapsed().as_millis(), peak_rss());
    Ok(())
}

pub(crate) fn peak_rss() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .map(|line| format!("peak_rss_kb={}", line.split_whitespace().nth(1).unwrap_or("?")))
        })
        .unwrap_or_else(|| "peak_rss_kb=?".into())
}

/// Canonical Norito, hex: how typed values cross the coordinator <-> auditor hop.
pub fn enc<T: norito::NoritoSerialize>(value: &T) -> Result<String> {
    Ok(hex::encode(norito::encode_canonical(value)?))
}

pub fn dec<T>(text: &str) -> Result<T>
where
    T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>,
{
    Ok(norito::decode_canonical(&hex::decode(text)?)?)
}

pub(crate) fn rnd() -> [u8; 32] {
    rand::random()
}

pub(crate) fn on_big_stack<T: Send>(work: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    thread::scope(|scope| {
        thread::Builder::new()
            .name("aps-prover".into())
            .stack_size(PROVER_STACK_BYTES)
            .spawn_scoped(scope, work)?
            .join()
            .map_err(|_| eyre!("prover thread panicked"))?
    })
}

pub(crate) fn govern(
    route: PrivateSettlementRouteV1,
    asset: AssetDefinitionId,
    height: u64,
    expiry_height: u64,
    auditor_key: &PublicKey,
    auditor_encryption: &PrivateSettlementHybridPublicKeyV1,
) -> Result<Governed> {
    govern_until(route, asset, height, Some(expiry_height + 1), auditor_key, auditor_encryption)
}

/// `retirement: None` keeps the policy and pool mapping valid indefinitely (long-lived pools).
pub(crate) fn govern_until(
    route: PrivateSettlementRouteV1,
    asset: AssetDefinitionId,
    height: u64,
    retirement: Option<u64>,
    auditor_key: &PublicKey,
    auditor_encryption: &PrivateSettlementHybridPublicKeyV1,
) -> Result<Governed> {
    govern_with(route, asset, height, retirement, &[(auditor_key.clone(), auditor_encryption.clone())], 1)
}

/// k-of-n policy: `auditors` in order, `min_approvals` of them must approve (1 <= k <= n).
pub(crate) fn govern_with(
    route: PrivateSettlementRouteV1,
    asset: AssetDefinitionId,
    height: u64,
    retirement: Option<u64>,
    auditors: &[(PublicKey, PrivateSettlementHybridPublicKeyV1)],
    min_approvals: usize,
) -> Result<Governed> {
    ensure!(!auditors.is_empty(), "an audit policy needs at least one auditor");
    ensure!((1..=auditors.len()).contains(&min_approvals), "min_approvals {min_approvals} must be between 1 and the {} auditors", auditors.len());
    // Core wants the roster strictly ascending by auditor_id (iroha@071e281e nexus/private_settlement.rs:2228-2237); configs list URLs.
    let mut auditors = auditors.to_vec();
    auditors.sort_by_key(|(key, _)| AccountId::new(key.clone()));
    let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        dataspace_id: route.dataspace_id,
        policy_id: Hash::new(rnd()),
        revision: 1,
        key_epoch: 1,
        activation_height: height,
        retirement_height: retirement,
        min_approvals: u8::try_from(min_approvals).wrap_err("min_approvals")?,
        auditors: auditors
            .iter()
            .map(|(key, encryption)| PrivateSettlementAuditorV1 {
                auditor_id: AccountId::new(key.clone()),
                signing_key: key.clone(),
                encryption_key: encryption.clone(),
            })
            .collect(),
    })?;
    let governance = PrivateSettlementPoolGovernanceV1::from_restricted_mapping(
        route,
        PrivacyPoolIdV1::new(rnd()),
        asset,
        rnd(),
        &policy,
        PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: height,
            retirement_height: retirement,
        },
    )?;
    Ok(Governed { route, policy, governance })
}

pub(crate) fn funding(value: u128) -> Result<Funding> {
    funding_with_secret(value, rnd())
}

/// Origin funding whose positive note is spendable with `secret` (a party's note spend key).
pub(crate) fn funding_with_secret(value: u128, owner_secret: [u8; 32]) -> Result<Funding> {
    let mut notes = Vec::with_capacity(2);
    for (value, secret) in [(value, owner_secret), (1, rnd())] {
        let mut opening = PrivateSettlementAuditNoteOpeningV1 {
            active: true,
            commitment: PrivacyCommitmentV1::new([0; 32]),
            value,
            spending_authority: derive_note_authority_v1(&secret)?,
            rho: rnd(),
            blinding: rnd(),
            memo_digest: rnd(),
            dummy_domain: None,
        };
        prepare_atomic_private_settlement_funding_note_v1(&mut opening)?;
        notes.push((opening, secret));
    }
    let (reserve, _) = notes.pop().expect("two notes");
    let (opening, spending_secret) = notes.pop().expect("two notes");
    let input_commitments = [opening.commitment, reserve.commitment];
    ensure!(input_commitments[0] != input_commitments[1], "funding note collision");
    Ok(Funding { opening, spending_secret, input_commitments })
}

pub(crate) fn hash(seed: u8) -> Hash {
    Hash::prehashed([seed.max(1); Hash::LENGTH])
}

pub(crate) fn bytes(seed: u8) -> [u8; 32] {
    [seed.max(1); 32]
}

pub(crate) fn fixture_key(seed: u8) -> KeyPair {
    crate::config::signing_key(&[seed; 32])
}

pub(crate) fn proof_manifest(
    network_id: NetworkId,
    authority_context_height: u64,
    expiry_height: u64,
    sponsor: AccountId,
    fee: FeePaymentIntent,
    governed: &[Governed],
    reimbursement_salt: [u8; 32],
) -> Result<AtomicPrivateSettlementV1> {
    let mut manifest = AtomicPrivateSettlementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id,
        bundle_id: hash(0xA0),
        authority_context_height,
        expiry_height,
        sponsor,
        public_fee_intent: fee,
        fee_intent_digest: hash(0xA1),
        reimbursement_terms_commitment: hash(0xA2),
        reimbursement_leg_ordinal: 0,
        legs: governed
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| PrivateSettlementLegCommitmentV1 {
                ordinal: u8::try_from(ordinal).expect("ordinal fits u8"),
                route: leg.route,
                pool_id: leg.governance.body.pool_id,
                asset_binding_commitment: leg.governance.body.asset_binding_commitment,
                audit_policy_digest: leg.policy.policy_digest,
                payload_digest: hash(0xB0 + ordinal as u8),
                availability_certificate_digest: hash(0xC0 + ordinal as u8),
                delta_digest: hash(0xD0 + ordinal as u8),
            })
            .collect(),
    };
    manifest.fee_intent_digest = manifest.computed_fee_intent_digest()?;
    manifest.reimbursement_terms_commitment =
        reimbursement_commitment(&manifest, &governed[0], reimbursement_salt)?;
    manifest.bundle_id = manifest.computed_bundle_id()?;
    manifest.validate()?;
    Ok(manifest)
}

/// Upstream `reimbursement_commitment`: the commitment covers the reimbursement terms
/// only, so a probe plaintext with placeholder parties yields the leg-0 value.
fn reimbursement_commitment(
    manifest: &AtomicPrivateSettlementV1,
    governed: &Governed,
    salt: [u8; 32],
) -> Result<Hash> {
    let payer = fixture_key(0x91);
    let probe = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: hash(0x92),
        leg_ordinal: 0,
        route: governed.route,
        pool_id: governed.governance.body.pool_id,
        payer: AccountId::new(payer.public_key().clone()),
        payer_authorization: placeholder_payer_authorization(
            manifest.network_id,
            governed.route,
            &payer,
            manifest.expiry_height,
        ),
        recipient: AccountId::new(fixture_key(0x93).public_key().clone()),
        sponsor: manifest.sponsor.clone(),
        asset_definition_id: governed.governance.body.asset_definition_id.clone(),
        asset_binding_salt: governed.governance.body.asset_binding_salt,
        amount: 1,
        sponsor_reimbursement_amount: SPONSOR_REIMBURSEMENT,
        fee_intent_digest: manifest.fee_intent_digest,
        settlement_expiry_height: manifest.expiry_height,
        reimbursement_terms_salt: salt,
        memo: Vec::new(),
        policy_references: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    Ok(probe.reimbursement_terms_commitment()?)
}

pub(crate) fn placeholder_payer_authorization(
    network_id: NetworkId,
    route: PrivateSettlementRouteV1,
    payer: &KeyPair,
    expiry_height: u64,
) -> PrivateSettlementAuditPayerAuthorizationV1 {
    let body = PrivateSettlementAuditPayerAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: hash(0x81),
        network_id,
        bundle_id: hash(0x82),
        leg_ordinal: 0,
        route,
        payer: AccountId::new(payer.public_key().clone()),
        expiry_height,
        inputs: vec![
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 0,
                active: true,
                commitment: PrivacyCommitmentV1::new(bytes(0x83)),
                nullifier: PrivacyNullifierV1::new(bytes(0x84)),
                note_spending_authority: bytes(0x85),
                dummy_domain: None,
            },
            PrivateSettlementAuditPayerInputV1 {
                input_ordinal: 1,
                active: false,
                commitment: PrivacyCommitmentV1::new(bytes(0x86)),
                nullifier: PrivacyNullifierV1::new(bytes(0x87)),
                note_spending_authority: bytes(0x88),
                dummy_domain: Some(hash(0x89)),
            },
        ],
    };
    PrivateSettlementAuditPayerAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            payer.public_key().clone(),
            SignatureOf::try_new(payer.private_key(), &body).expect("placeholder signature"),
        )],
    )
}

pub(crate) fn placeholder_encrypted_output(seed: u8) -> PrivacyEncryptedOutputV1 {
    let mut ciphertext = vec![seed.max(1); PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1];
    ciphertext[..4].copy_from_slice(b"IPNE");
    PrivacyEncryptedOutputV1 {
        recipient: PrivacyRecipientIdV1::new(bytes(seed.wrapping_add(1))),
        ephemeral_public_key: PrivacyEncryptionKeyV1::new(bytes(seed.wrapping_add(2))),
        commitment: PrivacyCommitmentV1::new(bytes(seed.wrapping_add(3))),
        ciphertext,
    }
}

/// Random note opening; commitment and spending authority are recomputed by the callers.
pub(crate) fn note_opening(active: bool, value: u128) -> PrivateSettlementAuditNoteOpeningV1 {
    PrivateSettlementAuditNoteOpeningV1 {
        active,
        commitment: PrivacyCommitmentV1::new(rnd()),
        value,
        spending_authority: rnd(),
        rho: rnd(),
        blinding: rnd(),
        memo_digest: rnd(),
        dummy_domain: (!active).then(|| Hash::prehashed(rnd())),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_leg(
    ordinal: usize,
    leg: &Leg,
    governed: &Governed,
    spend: Spend,
    notes: &LegNotes,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
    sponsor_key: &KeyPair,
    reimbursement_salt: [u8; 32],
) -> Result<AtomicPrivateSettlementPreparedLegV1> {
    prepare_leg_to(ordinal, leg, governed, spend, notes, None, manifest, authority_digest, sponsor_key, reimbursement_salt)
}

/// `prepare_leg` with the recipient's output optionally given as public values only: (spending authority,
/// x25519 view public key). The payer then needs none of the recipient's secrets (`notes.recipient` is ignored).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_leg_to(
    ordinal: usize,
    leg: &Leg,
    governed: &Governed,
    spend: Spend,
    notes: &LegNotes,
    recipient_public: Option<([u8; 32], [u8; 32])>,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
    sponsor_key: &KeyPair,
    reimbursement_salt: [u8; 32],
) -> Result<AtomicPrivateSettlementPreparedLegV1> {
    let leg_ordinal = u8::try_from(ordinal)?;
    let ctx = crate::aps_split::OutputCtx {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal,
        route: governed.route,
        expiry_height: manifest.expiry_height,
    };
    // Single process: all three owners' keys are at hand, so sign their outputs here and hand the leg to the
    // payer-only path. The sponsor output goes to `notes.sponsor` (`Config::reimbursement_keys`).
    let recipient_role = PrivateSettlementAuditOutputRoleV1::SettlementRecipient;
    let recipient_output = match recipient_public {
        Some((authority, view_public)) => {
            crate::aps_split::sign_output_public(&leg.recipient, &ctx, 0, recipient_role, authority, view_public, true)?
        }
        None => crate::aps_split::sign_output_key(&leg.recipient, &ctx, 0, recipient_role, &notes.recipient, true)?,
    };
    let sponsor_output = crate::aps_split::sign_output_key(
        sponsor_key,
        &ctx,
        2,
        PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
        &notes.sponsor,
        ordinal == 0,
    )?;
    let payer = crate::aps_split::LegPayer {
        lane: leg.lane,
        asset: leg.asset.clone(),
        payer: leg.payer.clone(),
        recipient: leg.recipient.public_key().clone(),
        amount: leg.amount,
    };
    crate::aps_split::prepare_leg_split(
        ordinal,
        &payer,
        governed,
        spend,
        &notes.change,
        &recipient_output,
        &sponsor_output,
        sponsor_key.public_key(),
        manifest,
        authority_digest,
        reimbursement_salt,
    )
}

fn provisional_materials(
    manifest: AtomicPrivateSettlementV1,
    prepared: &[AtomicPrivateSettlementPreparedLegV1],
    governed: &[Governed],
    committees: &[Committee],
) -> Result<Vec<PrivateSettlementProvisionalLegMaterialV1>> {
    let retention_until_height = manifest.authority_context_height + SIDECAR_RETENTION_BLOCKS + 512;
    let inputs = prepared
        .iter()
        .zip(governed)
        .zip(committees)
        .map(|((leg, governed), committee)| {
            AtomicPrivateSettlementProvisionalLegInputV1::new(
                leg.clone(),
                governed.policy.clone(),
                committee.authority.clone(),
                retention_until_height,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(finalize_atomic_private_settlement_provisional_bundle_v1(manifest, inputs)?.materials)
}

#[cfg(test)]
mod continuation_tests {
    use std::path::Path;

    #[test]
    fn continuation_leg_proves_and_verifies() {
        super::prove_continuation_selftest(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/peers.json")))
            .expect("gate G1a: a received note is spendable in the same pool");
    }
}

#[cfg(test)]
mod abort_tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn a_failed_stage_aborts_once_and_keeps_its_error() {
        let aborts = Cell::new(0);
        let result: Result<()> = abort_on_error(Err(eyre!("commit votes")), "commit", || {
            aborts.set(aborts.get() + 1);
            Ok(())
        });
        assert_eq!(aborts.get(), 1);
        assert_eq!(result.unwrap_err().to_string(), "commit votes");
    }

    #[test]
    fn a_failed_abort_does_not_hide_the_stage_error() {
        let aborts = Cell::new(0);
        let result: Result<()> = abort_on_error(Err(eyre!("submit finalization")), "finalize", || {
            aborts.set(aborts.get() + 1);
            Err(eyre!("abort ended as finalized"))
        });
        assert_eq!(aborts.get(), 1);
        assert_eq!(result.unwrap_err().to_string(), "submit finalization");
    }

    #[test]
    fn a_good_stage_does_not_abort() {
        let aborts = Cell::new(0);
        let result = abort_on_error(Ok(7), "commit", || {
            aborts.set(aborts.get() + 1);
            Ok(())
        });
        assert_eq!(aborts.get(), 0);
        assert_eq!(result.unwrap(), 7);
    }

    #[test]
    fn a_finalized_bundle_is_not_aborted() {
        let aborts = Cell::new(0);
        let result: Result<()> = abort_on_error(Err(eyre::Report::new(FinalizedSeen("nodes disagree".into()))), "finalization", || {
            aborts.set(aborts.get() + 1);
            Ok(())
        });
        assert_eq!(aborts.get(), 0);
        assert_eq!(result.unwrap_err().to_string(), "nodes disagree");
    }

    #[test]
    fn receipt_errors_say_whether_a_node_finalized() {
        let seen = |kinds: &[&str], expired| receipt_error(kinds, expired).unwrap_err().downcast_ref::<FinalizedSeen>().is_some();
        assert!(seen(&["finalized", "aborted"], false), "disagree");
        assert!(seen(&["finalized", "pending"], true), "timeout with a finalized node");
        assert!(!seen(&["pending", "pending"], true), "timeout, nothing finalized");
        assert!(receipt_error(&["finalized", "pending"], false).is_ok(), "keep polling");
    }
}

#[cfg(test)]
mod output_authority_tests {
    use std::path::Path;

    use super::*;

    /// A payer builds a leg for a recipient it holds no secret of: only the recipient's spending authority and
    /// x25519 view public key. The proof verifies and the real recipient, with its own keys, opens the note.
    #[test]
    fn leg_proves_with_the_recipient_output_given_as_public_values() {
        let route = |lane: u32| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(lane)),
            lane_id: LaneId::new(lane),
            lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
        };
        let peers = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/peers.json"));
        let (authority, _) = committee_authority(peers, route(1)).unwrap();
        let authority_digest = authority.digest().unwrap();
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"rd-dfabi-selftest-network")));
        let auditor_key = fixture_key(0x30);
        let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
        let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng).unwrap();
        let encryption = PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public());
        let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
            .into_iter()
            .map(|(lane, asset)| govern(route(lane), asset.parse().unwrap(), 100, 100 + EXPIRY_BLOCKS, auditor_key.public_key(), &encryption))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let pool_id = governed[0].governance.body.pool_id;
        let sponsor_key = fixture_key(0x31);
        let fee = bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw").unwrap();
        let genesis = *network_id.as_genesis_hash().as_ref();
        let funding = funding(1_000).unwrap();
        let salt = rnd();
        let manifest = proof_manifest(network_id, 101, 100 + EXPIRY_BLOCKS, AccountId::new(sponsor_key.public_key().clone()), fee, &governed, salt).unwrap();
        let leg = Leg {
            lane: 1,
            asset: governed[0].governance.body.asset_definition_id.clone(),
            payer: fixture_key(0x32),
            recipient: fixture_key(0x33),
            funding: 1_000,
            amount: 100,
        };
        // The recipient keeps its secrets; the payer is given the public values and a placeholder it never uses.
        let recipient = NoteKeys::random();
        let public = (recipient.authority().unwrap(), recipient.view_public().unwrap());
        let notes = LegNotes::random();
        let prepared = on_big_stack(|| {
            prepare_leg_to(0, &leg, &governed[0], Spend::Bootstrap(funding), &notes, Some(public), &manifest, authority_digest, &sponsor_key, salt)
        })
        .unwrap();
        verify_atomic_private_settlement_v1(&manifest, &prepared.statement, genesis, 101, &prepared.proof)
            .unwrap_or_else(|e| panic!("proof rejected: {e:?}"));
        let opened = prepared
            .statement
            .output_commitments
            .iter()
            .zip(&prepared.statement.encrypted_outputs)
            .find_map(|(commitment, encrypted)| open_output(pool_id, *commitment, encrypted, &recipient).unwrap())
            .expect("the real recipient found no note addressed to its public values");
        assert_eq!(opened.value, 100);
    }
}

#[cfg(test)]
mod recheck_tests {
    use std::cell::Cell;

    use super::*;

    /// register -> recheck -> abort, as settle wires them; returns (result, aborts, rechecks).
    fn run(register: Result<()>, applied: Option<Result<bool>>) -> (Result<()>, u32, u32) {
        let (aborts, rechecks) = (Cell::new(0), Cell::new(0));
        let result = abort_on_error(
            register_with_recheck(
                || register,
                || {
                    rechecks.set(rechecks.get() + 1);
                    applied.expect("recheck was not expected")
                },
            ),
            "prepare",
            || {
                aborts.set(aborts.get() + 1);
                Ok(())
            },
        );
        (result, aborts.get(), rechecks.get())
    }

    #[test]
    fn a_failed_wait_with_an_applied_registration_continues_without_abort() {
        let (result, aborts, rechecks) = run(Err(eyre!("connection closed before message completed")), Some(Ok(true)));
        assert!(result.is_ok(), "{result:?}");
        assert_eq!((aborts, rechecks), (0, 1));
    }

    #[test]
    fn a_failed_wait_with_no_registration_aborts_as_before() {
        let (result, aborts, rechecks) = run(Err(eyre!("register prepare")), Some(Ok(false)));
        assert_eq!(result.unwrap_err().to_string(), "register prepare");
        assert_eq!((aborts, rechecks), (1, 1));
    }

    #[test]
    fn a_failing_recheck_keeps_the_original_error_and_aborts() {
        let (result, aborts, _) = run(Err(eyre!("register prepare")), Some(Err(eyre!("status unreachable"))));
        assert_eq!(result.unwrap_err().to_string(), "register prepare");
        assert_eq!(aborts, 1);
    }

    #[test]
    fn a_good_wait_asks_for_no_recheck() {
        let (result, aborts, rechecks) = run(Ok(()), None);
        assert!(result.is_ok());
        assert_eq!((aborts, rechecks), (0, 0));
    }
}

#[cfg(test)]
mod prepare_quorum_tests {
    use super::*;

    /// Runs applied_on_quorum over 4 nodes where the nodes in `lagging` never apply; returns (result, nodes asked).
    fn run(lagging: &[usize]) -> (Result<()>, Vec<usize>) {
        let mut asked = Vec::new();
        let result = applied_on_quorum(4, |i| {
            asked.push(i);
            if lagging.contains(&i) { Err(eyre!("node {i} not applied")) } else { Ok(()) }
        });
        (result, asked)
    }

    #[test]
    fn stops_once_three_nodes_applied() {
        let (result, asked) = run(&[]);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(asked, [0, 1, 2]);
    }

    #[test]
    fn one_lagging_node_still_reaches_the_vote_quorum() {
        let (result, asked) = run(&[0]);
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(asked, [0, 1, 2, 3]);
    }

    #[test]
    fn two_lagging_nodes_fail_before_any_commit_vote() {
        let (result, asked) = run(&[1, 3]);
        assert_eq!(asked, [0, 1, 2, 3]);
        let error = result.expect_err("2 of 4 cannot give 3 Commit votes");
        assert!(error.to_string().contains("applied on 2 of 4"), "{error:#}");
    }
}

#[cfg(test)]
mod govern_policy_tests {
    use super::*;

    fn hybrid() -> PrivateSettlementHybridPublicKeyV1 {
        let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
        PrivateSettlementHybridPublicKeyV1::from_hybrid(iroha_crypto::HybridKeyPair::generate(&mut rng).unwrap().public())
    }

    fn route() -> PrivateSettlementRouteV1 {
        PrivateSettlementRouteV1 { dataspace_id: DataSpaceId::new(1), lane_id: LaneId::new(1), lane_incarnation: Hash::new(b"policy-test") }
    }

    fn auditors(n: u8) -> Vec<(PublicKey, PrivateSettlementHybridPublicKeyV1)> {
        (0..n).map(|i| (fixture_key(0x30 + i).public_key().clone(), hybrid())).collect()
    }

    const RD: &str = "7onbjg2gRXveoAAUFsohCZyGW98t";

    #[test]
    fn a_two_of_three_policy_carries_all_three_auditors_and_k_two() {
        let governed = govern_with(route(), RD.parse().unwrap(), 100, Some(200), &auditors(3), 2).unwrap();
        assert_eq!(governed.policy.body.min_approvals, 2);
        assert_eq!(governed.policy.body.auditors.len(), 3);
    }

    /// Live pool-init 2026-11-12T18:24Z stopped before any tx with "private settlement auditors must be strictly ordered and
    /// unique": core wants the policy roster ascending by auditor_id (iroha@071e281e data_model nexus/private_settlement.rs:2228-2237),
    /// the config lists the auditors in URL order (bi, bank-a, bank-b). Any input order must give the canonical roster.
    #[test]
    fn the_policy_roster_is_canonical_whatever_the_config_order() {
        let mut list = auditors(3);
        list.sort_by_key(|(key, _)| std::cmp::Reverse(AccountId::new(key.clone())));
        let governed = govern_with(route(), RD.parse().unwrap(), 100, Some(200), &list, 2).unwrap();
        let ids: Vec<_> = governed.policy.body.auditors.iter().map(|a| a.auditor_id.clone()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn k_zero_k_above_n_and_no_auditor_are_refused() {
        assert!(govern_with(route(), RD.parse().unwrap(), 100, Some(200), &auditors(3), 0).is_err());
        assert!(govern_with(route(), RD.parse().unwrap(), 100, Some(200), &auditors(3), 4).is_err());
        assert!(govern_with(route(), RD.parse().unwrap(), 100, Some(200), &[], 1).is_err());
    }

    #[test]
    fn the_single_auditor_entry_point_keeps_the_one_of_one_policy() {
        let (key, encryption) = auditors(1).remove(0);
        let governed = govern_until(route(), RD.parse().unwrap(), 100, None, &key, &encryption).unwrap();
        assert_eq!((governed.policy.body.min_approvals, governed.policy.body.auditors.len()), (1, 1));
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    /// The HTTP coordinator reports an audit-rejected (aborted) bundle as an outcome, not as an error.
    #[test]
    fn either_accepts_both_outcomes_and_the_fixed_expectations_stay_strict() {
        assert!(check_outcome("finalized", Expect::Either).is_ok());
        assert!(check_outcome("aborted", Expect::Either).is_ok());
        assert!(check_outcome("aborted", Expect::Finalized).is_err());
        assert!(check_outcome("finalized", Expect::Aborted).is_err());
    }
}

/// A valid manifest over two governed pools (lanes 1 and 2), different on every call; no proving, no network.
#[cfg(test)]
pub(crate) fn test_manifest() -> AtomicPrivateSettlementV1 {
    let route = |lane: u32| PrivateSettlementRouteV1 {
        dataspace_id: DataSpaceId::new(u64::from(lane)),
        lane_id: LaneId::new(lane),
        lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
    };
    let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
    let encryption = PrivateSettlementHybridPublicKeyV1::from_hybrid(iroha_crypto::HybridKeyPair::generate(&mut rng).unwrap().public());
    let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
        .into_iter()
        .map(|(lane, asset)| govern(route(lane), asset.parse().unwrap(), 100, 100 + EXPIRY_BLOCKS, fixture_key(0x30).public_key(), &encryption).unwrap())
        .collect::<Vec<_>>();
    let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"rd-dfabi-selftest-network")));
    let sponsor = AccountId::new(fixture_key(0x31).public_key().clone());
    proof_manifest(network_id, 101, 100 + EXPIRY_BLOCKS, sponsor, bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw").unwrap(), &governed, rnd()).unwrap()
}

#[cfg(test)]
mod receipt_tests {
    use iroha::data_model::nexus::PrivateSettlementAuthorityCatalogV1;

    use super::*;

    fn receipt(manifest: &AtomicPrivateSettlementV1) -> PrivateSettlementReceiptV1 {
        PrivateSettlementReceiptV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            manifest: manifest.clone(),
            authority_catalog: PrivateSettlementAuthorityCatalogV1 { rosters: Vec::new(), leg_roster_indices: Vec::new() },
            legs: Vec::new(),
            finalized_height: 9,
        }
    }

    /// A node's finalized receipt for this bundle id must carry the very manifest the coordinator settled.
    #[test]
    fn receipt_with_other_manifest_is_rejected() {
        let (ours, other) = (test_manifest(), test_manifest());
        let error = finalized_height("bi", &receipt(&other), &ours).unwrap_err();
        assert!(error.to_string().contains("receipt manifest differs"), "{error:#}");
        // The same manifest passes that check (and then must name its legs).
        let error = finalized_height("bi", &receipt(&ours), &ours).unwrap_err();
        assert!(error.downcast_ref::<FinalizedSeen>().is_some(), "{error:#}");
    }

    /// The manifest read back after the upload is taken only as the provisional one with its certificate digests filled in.
    #[test]
    fn only_the_filled_in_provisional_manifest_is_final() {
        let provisional = test_manifest();
        let mut certified = provisional.clone();
        for leg in &mut certified.legs {
            leg.availability_certificate_digest = Hash::new(rnd());
        }
        assert!(is_final_of(&certified, &provisional));
        assert!(!is_final_of(&provisional, &provisional), "a node that holds only the provisional manifest");
        let mut half = provisional.clone();
        half.legs[0].availability_certificate_digest = certified.legs[0].availability_certificate_digest;
        assert!(!is_final_of(&half, &provisional));
        let mut changed = certified.clone();
        changed.legs[1].payload_digest = Hash::new(rnd());
        assert!(!is_final_of(&changed, &provisional), "a substituted leg");
        assert!(!is_final_of(&test_manifest(), &provisional), "another bundle");
    }
}
