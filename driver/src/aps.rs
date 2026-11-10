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
    path::Path,
    thread,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr, ensure, eyre};
use iroha::{
    client::{
        AccountTransactionDraft, PrivateSettlementBundleReceiptResponseV1,
        PrivateSettlementLegUploadRequestV1, TransactionWaitOptions,
    },
    data_model::{
        NetworkId,
        account::AccountId,
        asset::AssetDefinitionId,
        isi::private_settlement::ActivatePrivateSettlementPoolV1,
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1,
            PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1, PrivateSettlementAbortReasonV1,
            PrivateSettlementAuditAadV1, PrivateSettlementAuditEncryptionOpeningV1,
            PrivateSettlementAuditNoteOpeningV1, PrivateSettlementAuditOutputRoleV1,
            PrivateSettlementAuditOutputV1, PrivateSettlementAuditPayerAuthorizationBodyV1,
            PrivateSettlementAuditPayerAuthorizationV1, PrivateSettlementAuditPayerInputV1,
            PrivateSettlementAuditPayerSignatureV1, PrivateSettlementAuditPlaintextV1,
            PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditPolicyV1,
            PrivateSettlementAuditViewKeyAuthorizationBodyV1,
            PrivateSettlementAuditViewKeyAuthorizationV1, PrivateSettlementAuditViewKeySignatureV1,
            PrivateSettlementAuditorV1, PrivateSettlementCapsulePaddingV1,
            PrivateSettlementCommitteeAuthorityV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementLegCommitmentV1, PrivateSettlementPoolGovernanceLifecycleV1,
            PrivateSettlementPoolGovernanceV1, PrivateSettlementProofProfileV1,
            PrivateSettlementProofStatementV1, PrivateSettlementProvisionalLegMaterialV1,
            PrivateSettlementRouteV1,
        },
        privacy::{
            PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PrivacyCommitmentV1,
            PrivacyEncryptedOutputV1, PrivacyEncryptionKeyV1, PrivacyNullifierV1, PrivacyPoolIdV1,
            PrivacyProtocolIdV1, PrivacyRecipientIdV1, PrivacyRootV1,
        },
        transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent},
    },
};
use iroha_core::privacy_engines::{
    atomic_private_settlement::{
        AtomicPrivateSettlementInputSecretV1, AtomicPrivateSettlementPreparedLegV1,
        AtomicPrivateSettlementProvisionalLegInputV1,
        atomic_private_settlement_audit_input_commitment_v1,
        complete_atomic_private_settlement_prepared_leg_v1,
        consume_atomic_private_settlement_wallet_bundle_v1,
        derive_atomic_private_settlement_input_nullifiers_v1,
        encode_atomic_private_settlement_wallet_bundle_v1,
        finalize_atomic_private_settlement_provisional_bundle_v1,
        verify_atomic_private_settlement_v1,
        plan_atomic_private_settlement_bootstrap_v1,
        prepare_atomic_private_settlement_funding_note_v1,
        prepare_atomic_private_settlement_input_openings_v1,
        prepare_atomic_private_settlement_outputs_v1,
    },
    ivm_private_note::{derive_note_authority_v1, ivm_private_recipient_public_key_v1},
};
use iroha_core::private_settlement::seal_private_settlement_audit_capsule_v1_with_rng;
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
}

pub struct Options {
    pub expect: Expect,
    /// After finalization, resubmit the same carrier (S3a) and require a rejection.
    pub replay: bool,
}

pub(crate) struct Governed {
    pub route: PrivateSettlementRouteV1,
    pub policy: PrivateSettlementAuditPolicyV1,
    pub governance: PrivateSettlementPoolGovernanceV1,
}

pub struct Funding {
    pub opening: PrivateSettlementAuditNoteOpeningV1,
    spending_secret: [u8; 32],
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
    /// is at `epoch`, and `secret` is the spend secret behind `opening.spending_authority`.
    Continue { opening: PrivateSettlementAuditNoteOpeningV1, secret: [u8; 32], tree: PoolTree, epoch: u64 },
}

impl Spend {
    fn value(&self) -> u128 {
        match self {
            Self::Bootstrap(funding) => funding.opening.value,
            Self::Continue { opening, .. } => opening.value,
        }
    }
}

/// Note keys the leg's settlement output and change output are addressed to.
pub struct LegNotes {
    pub recipient: NoteKeys,
    pub change: NoteKeys,
}

impl LegNotes {
    /// Throwaway keys (DvP on fresh pools: nobody spends these notes again).
    pub fn random() -> Self {
        Self { recipient: NoteKeys::random(), change: NoteKeys::random() }
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
    let (sponsor, sponsor_key) = cfg.sponsor("bi")?;
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

    let keys: Keys = auditor_call(cfg, "GET", "/keys", "")?;
    let auditor_key: PublicKey = keys.signing.parse()?;
    let auditor_encryption: PrivateSettlementHybridPublicKeyV1 = dec(&keys.encryption)?;

    // Pools: policy and governance are active from the height observed now; activation
    // itself commits a few blocks later and becomes the authority context.
    let height = caps.committed_height;
    let expiry_height = height + EXPIRY_BLOCKS;
    let governed = routes
        .iter()
        .zip(&legs)
        .map(|(route, leg)| {
            govern(*route, leg.asset.clone(), height, expiry_height, &auditor_key, &auditor_encryption)
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

    settle(cfg, &sponsor, manifest, &prepared, &governed, &committees, started, options)?;
    Ok(())
}

/// Upload, audit, prepare, commit and finalize proved legs; prints `result_json=`.
/// Returns whether the bundle finalized (an audit rejection aborts it).
#[allow(clippy::too_many_arguments)]
pub(crate) fn settle(
    cfg: &Config,
    sponsor: &iroha::blocking::Client,
    manifest: AtomicPrivateSettlementV1,
    prepared: &[AtomicPrivateSettlementPreparedLegV1],
    governed: &[Governed],
    committees: &[Committee],
    started: Instant,
    options: &Options,
) -> Result<Option<(String, u64)>> {
    let materials = provisional_materials(manifest, prepared, governed, committees)?;
    let client = sponsor.client();
    let certificates = materials
        .iter()
        .zip(committees)
        .map(|(material, committee)| {
            client.certify_private_settlement_leg_availability_v1(&committee.endpoints, material)
        })
        .collect::<Result<Vec<_>, _>>()
        .wrap_err("certify availability")?;
    let mut final_manifest = materials[0].manifest.clone();
    for (ordinal, certificate) in certificates.iter().enumerate() {
        final_manifest.legs[ordinal].availability_certificate_digest = certificate.digest()?;
    }
    final_manifest.validate()?;
    for (ordinal, ((material, certificate), committee)) in
        materials.iter().zip(&certificates).zip(committees).enumerate()
    {
        let request = PrivateSettlementLegUploadRequestV1 {
            manifest: final_manifest.clone(),
            audit_policy: material.audit_policy.clone(),
            committee_authority: material.committee_authority.clone(),
            payload: material.payload_with_certificate(certificate.clone()),
        };
        for endpoint in &committee.endpoints {
            let response = client
                .upload_private_settlement_leg_to_v1(endpoint, &request)
                .wrap_err_with(|| format!("upload leg {ordinal} to {endpoint}"))?;
            ensure!(usize::from(response.leg_ordinal) == ordinal, "upload ordinal substitution");
        }
    }
    println!("legs uploaded");

    for (ordinal, leg) in governed.iter().enumerate() {
        let response: ApproveResponse = auditor_call(
            cfg,
            "POST",
            "/approve",
            &serde_json::to_string(&ApproveRequest {
                governance: enc(&leg.governance)?,
                policy: enc(&leg.policy)?,
                payload_digest: enc(&final_manifest.legs[ordinal].payload_digest)?,
            })?,
        )?;
        if !response.approved {
            println!("leg {ordinal} audit rejected: {}", response.reason);
            let request = client.build_private_settlement_abort_request_v1(
                &final_manifest,
                PrivateSettlementAbortReasonV1::AuditUnavailable,
                max_carrier_bytes(),
            )?;
            client
                .submit_private_settlement_bundle_v1(&request)
                .wrap_err("submit abort")?;
            let (outcome, height) = wait_receipt(cfg, final_manifest.bundle_id)?;
            print_result(&final_manifest, governed, &request.transaction.hash().to_string(), outcome, height);
            check_outcome(outcome, options.expect)?;
            return Ok(None);
        }
        println!("leg {ordinal} audited");
    }

    let endpoints = committees.iter().map(|c| c.endpoints.clone()).collect::<Vec<_>>();
    let authorities = committees.iter().map(|c| c.authority.clone()).collect::<Vec<_>>();
    let deltas = prepared.iter().map(|leg| leg.delta.clone()).collect::<Vec<_>>();
    let barrier = client
        .prepare_private_settlement_bundle_v1(&endpoints, &final_manifest, &authorities, &deltas)
        .wrap_err("prepare votes")?;
    client
        .register_private_settlement_prepare_and_wait_v1(
            &barrier,
            max_carrier_bytes(),
            TransactionWaitOptions {
                timeout: FINALITY_TIMEOUT,
                poll_interval: POLL_INTERVAL,
            },
        )
        .wrap_err("register prepare")?;
    println!("prepare registered");
    let commits = client
        .recover_or_commit_private_settlement_bundle_v1(&endpoints, &barrier)
        .wrap_err("commit votes")?;
    let request = client.build_private_settlement_finalization_request_v1(
        &barrier,
        &commits,
        max_carrier_bytes(),
    )?;
    client
        .submit_private_settlement_bundle_v1(&request)
        .wrap_err("submit finalization")?;
    let (outcome, height) = wait_receipt(cfg, final_manifest.bundle_id)?;
    println!("settled after {:?}", started.elapsed());
    print_result(&final_manifest, governed, &request.transaction.hash().to_string(), outcome, height);
    check_outcome(outcome, options.expect)?;

    if options.replay {
        match client.submit_private_settlement_bundle_v1(&request) {
            Err(error) => println!("replay rejected: {error:#}"),
            Ok(_) => {
                thread::sleep(Duration::from_secs(10));
                let (again, _) = wait_receipt(cfg, final_manifest.bundle_id)?;
                ensure!(again == "finalized", "replay changed the receipt to {again}");
                println!("replay accepted by Torii but receipt unchanged (finalized once)");
            }
        }
    }
    Ok((outcome == "finalized").then(|| (hex::encode(final_manifest.bundle_id.as_ref()), height)))
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
    };
    ensure!(outcome == want, "expected {want}, got {outcome}");
    Ok(())
}

fn max_carrier_bytes() -> u64 {
    u64::try_from(PRIVATE_SETTLEMENT_MAX_RECEIPT_BYTES_V1).expect("V1 carrier ceiling fits u64")
}

pub(crate) fn bounded_fee(cfg: &Config) -> Result<FeePaymentIntent> {
    bounded_fee_for(&cfg.fee_asset)
}

fn bounded_fee_for(fee_asset: &str) -> Result<FeePaymentIntent> {
    Ok(FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset.parse()?,
            Quantity::from(FEE_SIGNED_MAXIMUM),
        )],
        None,
    ))
}

/// Wait until every node reports the same terminal receipt kind.
fn wait_receipt(cfg: &Config, bundle_id: Hash) -> Result<(&'static str, u64)> {
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
            let kind = match client.client().private_settlement_bundle_receipt_v1(bundle_id) {
                Ok(PrivateSettlementBundleReceiptResponseV1::Pending { .. }) => "pending",
                Ok(PrivateSettlementBundleReceiptResponseV1::Finalized(receipt)) => {
                    ensure!(!receipt.legs.is_empty(), "{party}: empty finalized receipt");
                    height = receipt.finalized_height;
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
        ensure!(
            !kinds.contains(&"finalized") || !kinds.contains(&"aborted"),
            "nodes disagree: {kinds:?}"
        );
        ensure!(Instant::now() < deadline, "no terminal receipt on all nodes: {kinds:?}");
        thread::sleep(POLL_INTERVAL);
    }
}

pub(crate) fn auditor_call<T: for<'de> Deserialize<'de>>(cfg: &Config, method: &str, path: &str, body: &str) -> Result<T> {
    let (status, response) = crate::http::request(&cfg.auditor_url, method, path, body)
        .wrap_err("call bi-auditor")?;
    ensure!(status == 200, "bi-auditor {path} returned {status}: {response}");
    Ok(serde_json::from_str(&response)?)
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
fn committee_authority(
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
    let notes1 = LegNotes { recipient: bob.clone(), change: alice };
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
    let notes2 = LegNotes { recipient: carol, change: bob.one_time(manifest2.bundle_id.as_ref(), pool_id.as_ref(), 1) };
    let expected_nullifier = crate::wallet::note_nullifier(pool_id, &bob.spend, &received)?;
    let spend = Spend::Continue { opening: received, secret: bob.spend, tree, epoch: 2 };
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
    let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        dataspace_id: route.dataspace_id,
        policy_id: Hash::new(rnd()),
        revision: 1,
        key_epoch: 1,
        activation_height: height,
        retirement_height: retirement,
        min_approvals: 1,
        auditors: vec![PrivateSettlementAuditorV1 {
            auditor_id: AccountId::new(auditor_key.clone()),
            signing_key: auditor_key.clone(),
            encryption_key: auditor_encryption.clone(),
        }],
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

fn hash(seed: u8) -> Hash {
    Hash::prehashed([seed.max(1); Hash::LENGTH])
}

fn bytes(seed: u8) -> [u8; 32] {
    [seed.max(1); 32]
}

fn fixture_key(seed: u8) -> KeyPair {
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

fn placeholder_payer_authorization(
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

fn placeholder_view_authorization(
    network_id: NetworkId,
    route: PrivateSettlementRouteV1,
    signer: &KeyPair,
    expiry_height: u64,
) -> PrivateSettlementAuditViewKeyAuthorizationV1 {
    let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: hash(0x8A),
        network_id,
        bundle_id: hash(0x8B),
        leg_ordinal: 0,
        route,
        output_ordinal: 0,
        role: PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
        authorized_account: AccountId::new(signer.public_key().clone()),
        recipient_view_key: bytes(0x8C),
        output_active: true,
        note_spending_authority: bytes(0x8D),
        expiry_height,
    };
    PrivateSettlementAuditViewKeyAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditViewKeySignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), &body).expect("placeholder signature"),
        )],
    )
}

fn placeholder_encrypted_output(seed: u8) -> PrivacyEncryptedOutputV1 {
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
fn note_opening(active: bool, value: u128) -> PrivateSettlementAuditNoteOpeningV1 {
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
    let mut output_rng = iroha_crypto::rng_from_seed_slice(&rnd());
    let mut capsule_rng = iroha_crypto::rng_from_seed_slice(&rnd());
    let leg_ordinal = u8::try_from(ordinal)?;
    let profile = PrivateSettlementProofProfileV1::IvmPrivateNoteFixed2In3Out;
    let placeholders = [
        placeholder_encrypted_output(0x11 + leg_ordinal * 6),
        placeholder_encrypted_output(0x13 + leg_ordinal * 6),
        placeholder_encrypted_output(0x15 + leg_ordinal * 6),
    ];
    let mut statement = PrivateSettlementProofStatementV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        profile,
        proof_profile_digest: profile.digest(),
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal,
        route: governed.route,
        authority_context_height: manifest.authority_context_height,
        pool_id: governed.governance.body.pool_id,
        asset_binding_commitment: governed.governance.body.asset_binding_commitment,
        old_root: PrivacyRootV1::new(bytes(0x20 + leg_ordinal)),
        new_root: PrivacyRootV1::new(bytes(0x24 + leg_ordinal)),
        old_epoch: 1,
        new_epoch: 2,
        nullifiers: vec![
            PrivacyNullifierV1::new(bytes(0x30 + leg_ordinal * 2)),
            PrivacyNullifierV1::new(bytes(0x31 + leg_ordinal * 2)),
        ],
        output_commitments: placeholders.iter().map(|output| output.commitment).collect(),
        encrypted_outputs: placeholders.to_vec(),
        audit_plaintext_commitment: hash(0x40 + leg_ordinal),
        audit_input_commitment: [0x48 + leg_ordinal; 32],
        audit_capsule_digest: hash(0x50 + leg_ordinal),
        audit_policy_digest: governed.policy.policy_digest,
        audit_key_epoch: governed.policy.body.key_epoch,
        fee_intent_digest: manifest.fee_intent_digest,
        reimbursement_terms_commitment: manifest.reimbursement_terms_commitment,
        reimbursement_leg_ordinal: manifest.reimbursement_leg_ordinal,
        expiry_height: manifest.expiry_height,
    };
    statement.validate()?;

    let payer = &leg.payer;
    let recipient = &leg.recipient;
    let (positive_input, positive_secret) = match &spend {
        Spend::Bootstrap(funding) => (funding.opening.clone(), funding.spending_secret),
        Spend::Continue { opening, secret, .. } => (opening.clone(), *secret),
    };
    let input_secrets = [positive_secret, rnd()];
    let output_secrets = [notes.recipient.spend, notes.change.spend, rnd()];
    let view_secrets = [notes.recipient.view, notes.change.view, rnd()];
    let ephemeral_secrets = [rnd(), rnd(), rnd()];
    let reimbursement = if ordinal == 0 { SPONSOR_REIMBURSEMENT } else { 0 };
    let change = spend
        .value()
        .checked_sub(leg.amount + reimbursement)
        .ok_or_else(|| eyre!("leg {ordinal}: insufficient payer note"))?;
    let output = |role, signer: &KeyPair, view_secret, ephemeral_secret, active, value| {
        Ok::<_, eyre::Report>(PrivateSettlementAuditOutputV1 {
            role,
            recipient_view_key: ivm_private_recipient_public_key_v1(view_secret)?,
            view_key_authorization: placeholder_view_authorization(
                manifest.network_id,
                governed.route,
                signer,
                manifest.expiry_height,
            ),
            encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 { ephemeral_secret },
            note: note_opening(active, value),
        })
    };
    let mut plaintext = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal,
        route: governed.route,
        pool_id: governed.governance.body.pool_id,
        payer: AccountId::new(payer.public_key().clone()),
        payer_authorization: placeholder_payer_authorization(
            manifest.network_id,
            governed.route,
            payer,
            manifest.expiry_height,
        ),
        recipient: AccountId::new(recipient.public_key().clone()),
        sponsor: manifest.sponsor.clone(),
        asset_definition_id: governed.governance.body.asset_definition_id.clone(),
        asset_binding_salt: governed.governance.body.asset_binding_salt,
        amount: leg.amount,
        sponsor_reimbursement_amount: reimbursement,
        fee_intent_digest: manifest.fee_intent_digest,
        settlement_expiry_height: manifest.expiry_height,
        reimbursement_terms_salt: reimbursement_salt,
        memo: format!("rd-dfabi-leg-{ordinal}").into_bytes(),
        policy_references: vec![governed.governance.governance_digest],
        inputs: vec![positive_input.clone(), note_opening(false, 0)],
        outputs: vec![
            output(
                PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
                recipient,
                &view_secrets[0],
                ephemeral_secrets[0],
                true,
                leg.amount,
            )?,
            output(
                PrivateSettlementAuditOutputRoleV1::PayerChange,
                payer,
                &view_secrets[1],
                ephemeral_secrets[1],
                true,
                change,
            )?,
            output(
                PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
                sponsor_key,
                &view_secrets[2],
                ephemeral_secrets[2],
                ordinal == 0,
                reimbursement,
            )?,
        ],
    };
    for (opening, secret) in plaintext.inputs.iter_mut().zip(input_secrets) {
        opening.spending_authority = derive_note_authority_v1(&secret)?;
    }
    for (output, secret) in plaintext.outputs.iter_mut().zip(output_secrets) {
        output.note.spending_authority = derive_note_authority_v1(&secret)?;
    }
    prepare_atomic_private_settlement_input_openings_v1(manifest, &statement, &mut plaintext.inputs)?;
    ensure!(
        plaintext.inputs[0].commitment == positive_input.commitment,
        "settlement changed its already-funded positive input"
    );
    statement.nullifiers = derive_atomic_private_settlement_input_nullifiers_v1(
        manifest,
        &statement,
        &plaintext.inputs,
        &input_secrets,
    )?
    .to_vec();
    let payer_body = plaintext.payer_authorization_body(&statement.nullifiers)?;
    plaintext.payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
        payer_body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            payer.public_key().clone(),
            SignatureOf::try_new(payer.private_key(), &payer_body)?,
        )],
    );
    for (index, signer) in [recipient, payer, sponsor_key].into_iter().enumerate() {
        let body = plaintext.output_view_key_authorization_body(index)?;
        plaintext.outputs[index].view_key_authorization =
            PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![PrivateSettlementAuditViewKeySignatureV1::new(
                    signer.public_key().clone(),
                    SignatureOf::try_new(signer.private_key(), &body)?,
                )],
            );
    }
    statement.audit_plaintext_commitment = plaintext.commitment()?;
    statement.audit_input_commitment =
        atomic_private_settlement_audit_input_commitment_v1(&plaintext.inputs)?;
    statement.encrypted_outputs = prepare_atomic_private_settlement_outputs_v1(
        &mut output_rng,
        manifest,
        &statement,
        &mut plaintext.outputs,
    )?;
    statement.output_commitments = plaintext
        .outputs
        .iter()
        .map(|output| output.note.commitment)
        .collect();
    let canonical_plaintext = norito::encode_canonical(&plaintext)?;
    let aad = PrivateSettlementAuditAadV1 {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal,
        route: governed.route,
        authority_digest,
        authority_context_height: manifest.authority_context_height,
        audit_policy_digest: governed.policy.policy_digest,
        audit_key_epoch: governed.policy.body.key_epoch,
        plaintext_commitment: statement.audit_plaintext_commitment,
    };
    let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
        &canonical_plaintext,
        aad,
        PrivateSettlementCapsulePaddingV1::KiB16,
        &governed.policy,
        &mut capsule_rng,
    )?;
    statement.audit_capsule_digest = capsule.digest()?;
    let outputs: [PrivacyCommitmentV1; 3] = statement
        .output_commitments
        .as_slice()
        .try_into()
        .map_err(|_| eyre!("output commitment shape changed"))?;
    let input_witnesses = match spend {
        Spend::Bootstrap(funding) => {
            let bootstrap = plan_atomic_private_settlement_bootstrap_v1(
                statement.pool_id,
                funding.input_commitments,
                outputs,
                input_secrets,
            )?;
            ensure!(
                bootstrap.initial_commitments == funding.activation_commitments(),
                "bootstrap origin differs from the activated funding"
            );
            statement.old_root = bootstrap.old_root;
            statement.new_root = bootstrap.new_root;
            statement.old_epoch = bootstrap.old_epoch;
            statement.new_epoch = bootstrap.new_epoch;
            bootstrap.into_input_secrets()
        }
        Spend::Continue { opening, tree, epoch, .. } => {
            let position = tree
                .position(opening.commitment)
                .ok_or_else(|| eyre!("leg {ordinal}: payer note is not in the pool"))?;
            let mut successor = tree.clone();
            successor.append(&outputs)?;
            statement.old_root = tree.root();
            statement.new_root = successor.root();
            statement.old_epoch = epoch;
            statement.new_epoch = epoch + 1;
            // Input 1 is a virtual dummy: never inserted, any non-zero path (upstream relation.rs
            // wallet_continues_settlement_with_fresh_virtual_dummy_without_bootstrap).
            [
                AtomicPrivateSettlementInputSecretV1::new(input_secrets[0], u32::try_from(position)?, tree.path(position)?)?,
                AtomicPrivateSettlementInputSecretV1::new(
                    input_secrets[1],
                    u32::try_from(position ^ 1)?,
                    [[0xED; 32]; crate::tree::DEPTH],
                )?,
            ]
        }
    };
    statement.validate()?;
    let wallet_id = format!("rd-dfabi-leg-{ordinal}");
    let owner_bundle = encode_atomic_private_settlement_wallet_bundle_v1(
        &wallet_id,
        manifest,
        &statement,
        &capsule,
        &governed.policy,
        &plaintext,
        &input_witnesses,
    )?;
    let mut owner_material = owner_bundle.to_vec();
    let prepared = consume_atomic_private_settlement_wallet_bundle_v1(
        &mut owner_material,
        &wallet_id,
        manifest,
        &statement,
        &capsule,
        &governed.policy,
        *manifest.network_id.as_genesis_hash().as_ref(),
        manifest.authority_context_height,
    )?;
    ensure!(owner_material.iter().all(|byte| *byte == 0), "owner bundle was not wiped");
    Ok(complete_atomic_private_settlement_prepared_leg_v1(prepared)?)
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
