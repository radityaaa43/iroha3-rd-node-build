//! BI auditor service (Deployment `bi-auditor`, separate from node `bi`).
//!
//! Torii has no "pending legs" route, so the coordinator asks for approval of one leg
//! over `POST /approve`. The auditor itself fetches the encrypted capsule from a committee
//! quorum, decrypts it with BI's key, applies local rules, submits the approval quorum, and
//! keeps the plaintext in its store (O5). Logs carry digests only.

use std::{
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

use eyre::{Result, WrapErr, ensure, eyre};
use iroha::{
    blocking::Client,
    client::{
        BorrowedKeyPairIdentityRequestSignerV1, PrivateSettlementAuditApprovalRequestV1,
        PrivateSettlementAuditorCapsuleRequestV1, PrivateSettlementLifecycleDtoV1,
    },
    data_model::{
        account::AccountId,
        asset::AssetDefinitionId,
        nexus::{
            PrivateSettlementAuditPlaintextV1, PrivateSettlementAuditPolicyV1,
            PrivateSettlementHybridPublicKeyV1, PrivateSettlementPoolGovernanceV1,
        },
    },
};
use iroha_core::private_settlement::{
    PrivateSettlementAuditEvaluationV1, PrivateSettlementAuditorSidecarViewV1,
    PrivateSettlementSidecarLifecycleV1, approve_private_settlement_leg_v1,
};
use iroha_crypto::{Hash, HybridKeyPair, HybridSecretKey, KeyPair, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    aps::{committee, dec, enc},
    config::{Config, signing_key},
};

/// Local approval rules (plan Task 4).
pub struct Rules {
    pub max_amount: Vec<(AssetDefinitionId, u128)>,
    pub parties: Vec<AccountId>,
}

impl Rules {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        Ok(Self {
            max_amount: vec![
                (cfg.assets.rd.parse()?, cfg.auditor.max_rd),
                (cfg.assets.dfabi.parse()?, cfg.auditor.max_dfabi),
            ],
            parties: cfg
                .auditor
                .parties
                .iter()
                .map(|key| Ok(AccountId::new(key.parse::<PublicKey>()?)))
                .collect::<Result<_>>()?,
        })
    }
}

pub fn evaluate(
    rules: &Rules,
    asset: &AssetDefinitionId,
    amount: u128,
    payer: &AccountId,
    recipient: &AccountId,
) -> Result<(), &'static str> {
    if !rules.parties.contains(payer) || !rules.parties.contains(recipient) {
        return Err("unknown party");
    }
    let (_, max) = rules
        .max_amount
        .iter()
        .find(|(id, _)| id == asset)
        .ok_or("unknown asset")?;
    if amount > *max {
        return Err("over limit");
    }
    Ok(())
}

/// BI's capsule decryption key (X25519 + ML-KEM-768), stored as `<x25519 hex>:<ml-kem hex>`.
/// It cannot be derived from the signing seed: upstream ML-KEM generation is hedged with OS
/// entropy (`iroha_crypto::hybrid::HybridKeyPair::try_generate`). A restarted pod must load the
/// same key named in already-activated pool policies, and old keys stay readable for O5.
pub fn write_hybrid(path: &Path) -> Result<()> {
    let pair = HybridKeyPair::generate(&mut rand::rngs::OsRng)?;
    let (x25519, kyber) = pair.secret().to_bytes();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(format!("{}:{}", hex::encode(x25519), hex::encode(kyber)).as_bytes())?;
    Ok(())
}

pub fn read_hybrid(path: &Path) -> Result<HybridSecretKey> {
    let text = std::fs::read_to_string(path).wrap_err_with(|| format!("read {}", path.display()))?;
    let (x25519, kyber) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| eyre!("{} is not <x25519>:<ml-kem>", path.display()))?;
    Ok(HybridSecretKey::from_bytes(hex::decode(x25519)?, hex::decode(kyber)?)?)
}

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub signing: String,
    /// Canonical Norito hex of `PrivateSettlementHybridPublicKeyV1`.
    pub encryption: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApproveRequest {
    /// Canonical Norito hex of each value.
    pub governance: String,
    pub policy: String,
    pub payload_digest: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApproveResponse {
    pub approved: bool,
    pub reason: String,
}

/// Plaintext record kept in the audit store, one file per leg.
#[derive(Serialize, Deserialize)]
struct Record {
    bundle_id: String,
    leg: u8,
    verdict: String,
    payer: String,
    recipient: String,
    asset: String,
    amount: String,
    memo_hex: String,
    plaintext_norito_hex: String,
}

struct Auditor {
    cfg: Config,
    rules: Rules,
    signing: KeyPair,
    hybrid: HybridSecretKey,
    client: Client,
}

pub fn run(cfg: Config) -> Result<()> {
    let signing = signing_key(&cfg.seed(cfg.auditor_key_name()?)?);
    let hybrid = read_hybrid(&cfg.auditor_hybrid_path())?;
    std::fs::create_dir_all(&cfg.auditor.store_dir)?;
    let auditor = Auditor {
        rules: Rules::from_config(&cfg)?,
        client: cfg.client_with_key(&cfg.party, &signing)?,
        signing,
        hybrid,
        cfg,
    };
    eprintln!("bi-auditor signing key {}", auditor.signing.public_key());
    let listen = auditor.cfg.auditor.listen.clone();
    crate::http::serve(&listen, |method, path, body| {
        let result = match (method, path) {
            ("GET", "/healthz") => Ok("{}".to_owned()),
            ("GET", "/keys") => auditor.keys(),
            ("GET", "/records") => list_records(&auditor.cfg.auditor.store_dir).and_then(|r| records_json(&r)),
            ("GET", p) if p.starts_with("/records/") => auditor.records(&p["/records/".len()..]),
            ("POST", "/approve") => serde_json::from_str(body)
                .map_err(Into::into)
                .and_then(|request| auditor.approve(&request))
                .and_then(|response| Ok(serde_json::to_string(&response)?)),
            _ => Err(eyre!("not found")),
        };
        match result {
            Ok(body) => (200, body),
            Err(error) => {
                let status = status_of(&error);
                if status == 500 {
                    eprintln!("{method} {path}: {error:#}");
                }
                (status, serde_json::json!({ "error": format!("{error:#}") }).to_string())
            }
        }
    })
}

impl Auditor {
    /// BI's own decrypted records for one bundle (Lensa's BI lens). Read-only; the store only
    /// holds legs this auditor decided. The id is checked as 64 hex so it cannot leave store_dir.
    fn records(&self, bundle_id: &str) -> Result<String> {
        ensure!(
            bundle_id.len() == 64 && bundle_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "bad bundle id"
        );
        let dir = self.cfg.auditor.store_dir.join(bundle_id.to_ascii_lowercase());
        let mut records = Vec::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let record: Record = serde_json::from_slice(&std::fs::read(entry?.path())?)?;
                records.push(record);
            }
        }
        records.sort_by_key(|record| record.leg);
        records_json(&records)
    }

    fn keys(&self) -> Result<String> {
        Ok(serde_json::to_string(&Keys {
            signing: self.signing.public_key().to_string(),
            encryption: enc(&PrivateSettlementHybridPublicKeyV1::from_hybrid(
                self.hybrid.public(),
            ))?,
        })?)
    }

    fn approve(&self, request: &ApproveRequest) -> Result<ApproveResponse> {
        let governance: PrivateSettlementPoolGovernanceV1 = dec(&request.governance)?;
        let policy: PrivateSettlementAuditPolicyV1 = dec(&request.policy)?;
        let payload_digest: Hash = dec(&request.payload_digest)?;
        ensure!(
            governance.body.audit_policy_digest == policy.policy_digest,
            "policy does not match pool governance"
        );
        let (authority, endpoints) = committee(&self.cfg, governance.body.route)?;
        let signer = BorrowedKeyPairIdentityRequestSignerV1::new(&self.signing);
        let capsule_request = PrivateSettlementAuditorCapsuleRequestV1 {
            audit_policy: policy.clone(),
        };
        let fetch = || {
            self.client
                .client()
                .private_settlement_auditor_capsule_quorum_for_authority_v1(
                    &endpoints,
                    &authority,
                    payload_digest,
                    &capsule_request,
                    &signer,
                )
                .wrap_err("fetch audit capsule")
        };
        let fetched = fetch()?;
        let lifecycle = fetched.lifecycle;
        let bundle_id = hex::encode(fetched.manifest.bundle_id.as_ref());
        let leg = fetched.statement.leg_ordinal;
        let record_path = self.record_path(&bundle_id, leg);
        if let Some(previous) = read_record(&record_path)? {
            eprintln!("bundle={bundle_id} leg={leg} already decided: {}", previous.verdict);
            return Ok(ApproveResponse {
                approved: previous.verdict == "approved",
                reason: "already decided".into(),
            });
        }
        ensure!(stage(lifecycle) != Stage::Dead, "leg is {lifecycle:?}: it never settled");
        let view = PrivateSettlementAuditorSidecarViewV1 {
            manifest: fetched.manifest,
            policy: fetched.audit_policy,
            authority: fetched.committee_authority,
            statement: fetched.statement,
            delta: fetched.delta,
            audit_capsule: fetched.audit_capsule,
            availability: fetched.availability,
            lifecycle: PrivateSettlementSidecarLifecycleV1::Collecting,
        };
        let seen: Mutex<Option<(Result<(), &'static str>, PrivateSettlementAuditPlaintextV1)>> =
            Mutex::new(None);
        let evaluator = |context: PrivateSettlementAuditEvaluationV1<'_>| {
            let plain = context.plaintext;
            let verdict = evaluate(
                &self.rules,
                &plain.asset_definition_id,
                plain.amount,
                &plain.payer,
                &plain.recipient,
            );
            *seen.lock().expect("evaluator lock") = Some((verdict, plain.clone()));
            verdict.is_ok()
        };
        let approval = approve_private_settlement_leg_v1(
            &view,
            &governance,
            fetched.authoritative_height,
            &AccountId::new(self.signing.public_key().clone()),
            &self.hybrid,
            &self.signing,
            &evaluator,
        );
        let Some((verdict, plaintext)) = seen.into_inner().expect("evaluator lock") else {
            return Err(eyre!("capsule did not decrypt: {:?}", approval.err()));
        };
        if let Err(reason) = verdict {
            write_record(&record_path, &bundle_id, leg, &format!("rejected: {reason}"), &plaintext)?;
            eprintln!("bundle={bundle_id} leg={leg} rejected: {reason}");
            return Ok(ApproveResponse { approved: false, reason: reason.into() });
        }
        if stage(lifecycle) == Stage::Closed {
            return record_late(&record_path, &bundle_id, leg, lifecycle, &plaintext);
        }
        let approval = approval.map_err(|e| eyre!("approve leg: {e:?}"))?;
        let submitted = self
            .client
            .client()
            .submit_private_settlement_audit_approval_quorum_for_authority_v1(
                &endpoints,
                &authority,
                payload_digest,
                &signer,
                &PrivateSettlementAuditApprovalRequestV1 {
                    audit_policy: policy,
                    approval,
                },
            )
            .wrap_err("submit approval quorum");
        let response = match submitted {
            Ok(response) => response,
            // The committee refuses an approval once the leg left Collecting | Audited. Only then is the verdict
            // recorded late; any other failure stays retryable (no record).
            Err(error) => match fetch().map(|now| now.lifecycle) {
                Ok(now) if stage(now) == Stage::Closed => {
                    return record_late(&record_path, &bundle_id, leg, now, &plaintext);
                }
                _ => return Err(error),
            },
        };
        ensure!(approval_durable(response.lifecycle, response.collected), "approval quorum was not durable");
        // Written only after the quorum is durable: a crash before this line re-approves
        // the same leg on retry instead of skipping it forever.
        write_record(&record_path, &bundle_id, leg, "approved", &plaintext)?;
        eprintln!("bundle={bundle_id} leg={leg} approved");
        Ok(ApproveResponse { approved: true, reason: String::new() })
    }

    fn record_path(&self, bundle_id: &str, leg: u8) -> PathBuf {
        self.cfg.auditor.store_dir.join(bundle_id).join(format!("{leg}.json"))
    }
}

/// Where a leg is relative to the audit: Open takes an approval (upstream accepts Collecting | Audited), Closed is past
/// it (the bundle went on with other auditors), Dead never settled.
#[derive(Debug, PartialEq, Eq)]
enum Stage {
    Open,
    Closed,
    Dead,
}

fn stage(lifecycle: PrivateSettlementLifecycleDtoV1) -> Stage {
    use PrivateSettlementLifecycleDtoV1::*;
    match lifecycle {
        Collecting | Audited => Stage::Open,
        Prepared | CommitCertified | Finalized => Stage::Closed,
        Aborted | Expired => Stage::Dead,
    }
}

fn late_verdict(lifecycle: PrivateSettlementLifecycleDtoV1) -> String {
    format!("approved (late: {lifecycle:?}, not counted)")
}

/// An approve call that came after the audit closed: the verdict is kept, the approval did not count.
#[derive(Debug)]
struct Late(String);

impl std::fmt::Display for Late {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Late {}

fn status_of(error: &eyre::Report) -> u16 {
    if error.is::<Late>() { 409 } else { 500 }
}

/// Keep the decrypted leg in the store (BI's lens must not miss it) and answer 409: the coordinator counts it Unavailable.
fn record_late(
    path: &PathBuf,
    bundle_id: &str,
    leg: u8,
    lifecycle: PrivateSettlementLifecycleDtoV1,
    plain: &PrivateSettlementAuditPlaintextV1,
) -> Result<ApproveResponse> {
    let verdict = late_verdict(lifecycle);
    write_record(path, bundle_id, leg, &verdict, plain)?;
    eprintln!("bundle={bundle_id} leg={leg} {verdict}");
    Err(Late(verdict).into())
}

/// A submitted approval is durable once the committee counts it: below a k > 1 threshold the leg stays Collecting
/// (collected >= 1); the k-th approval moves it to Audited and later stages. Aborted or Expired legs count nothing.
fn approval_durable(lifecycle: PrivateSettlementLifecycleDtoV1, collected: u8) -> bool {
    use PrivateSettlementLifecycleDtoV1::*;
    match lifecycle {
        Collecting => collected >= 1,
        Audited | Prepared | CommitCertified | Finalized => true,
        Aborted | Expired => false,
    }
}

/// What GET /records returns: the fields Lensa's adapter reads (iroha3-aps.ts AuditRecord). The stored
/// record also holds the memo and the full plaintext; those stay on disk.
#[derive(Serialize)]
struct RecordView<'a> {
    bundle_id: &'a str,
    leg: u8,
    verdict: &'a str,
    payer: &'a str,
    recipient: &'a str,
    asset: &'a str,
    amount: &'a str,
}

/// Body of both GET /records routes.
fn records_json(records: &[Record]) -> Result<String> {
    let views = records
        .iter()
        .map(|r| RecordView {
            bundle_id: &r.bundle_id,
            leg: r.leg,
            verdict: &r.verdict,
            payer: &r.payer,
            recipient: &r.recipient,
            asset: &r.asset,
            amount: &r.amount,
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_string(&views)?)
}

/// Every leg this auditor decided (BI's history across all bundles), by bundle then leg.
/// Callers order bundles by height from the public pool index.
fn list_records(store_dir: &Path) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    if store_dir.is_dir() {
        for bundle in std::fs::read_dir(store_dir)? {
            let bundle = bundle?.path();
            if !bundle.is_dir() {
                continue;
            }
            for leg in std::fs::read_dir(bundle)? {
                records.push(serde_json::from_slice::<Record>(&std::fs::read(leg?.path())?)?);
            }
        }
    }
    records.sort_by(|a, b| (&a.bundle_id, a.leg).cmp(&(&b.bundle_id, b.leg)));
    Ok(records)
}

fn read_record(path: &PathBuf) -> Result<Option<Record>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(serde_json::from_str(&text)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_record(
    path: &PathBuf,
    bundle_id: &str,
    leg: u8,
    verdict: &str,
    plain: &PrivateSettlementAuditPlaintextV1,
) -> Result<()> {
    let record = Record {
        bundle_id: bundle_id.into(),
        leg,
        verdict: verdict.into(),
        payer: plain.payer.to_string(),
        recipient: plain.recipient.to_string(),
        asset: plain.asset_definition_id.to_string(),
        amount: plain.amount.to_string(),
        memo_hex: hex::encode(&plain.memo),
        plaintext_norito_hex: enc(plain)?,
    };
    std::fs::create_dir_all(path.parent().expect("record has a bundle dir"))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&record)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use PrivateSettlementLifecycleDtoV1::*;

    /// Live RED (a) 2026-11-12T19:03Z, 2-of-3: bank-a's approval was recorded (lifecycle Collecting, collected 1 of 2) but the
    /// auditor demanded Audited and answered 500 "approval quorum was not durable"; the client counted it Unavailable and the
    /// bundle aborted although bank-b's approval completed the threshold. Only the k-th approval sees Audited.
    #[test]
    fn an_approval_is_durable_once_counted_even_below_the_threshold() {
        assert!(approval_durable(Collecting, 1));
        assert!(approval_durable(Audited, 2));
        for later in [Prepared, CommitCertified, Finalized] {
            assert!(approval_durable(later, 2), "{later:?}");
        }
        assert!(!approval_durable(Collecting, 0), "nothing counted");
        assert!(!approval_durable(Aborted, 1));
        assert!(!approval_durable(Expired, 1));
    }

    /// Live baseline 2026-11-12T19:31Z, 2-of-3 with all three auditors up: the coordinator prepared the bundle after the
    /// second approval, the committee refused the third (upstream sidecar_store record_audit_approval accepts only
    /// Collecting | Audited) and that auditor kept NO record of a leg it had decrypted, so BI's lens can miss legs.
    /// Collecting and Audited still take an approval (upstream approve_private_settlement_leg_v1); a leg past the audit
    /// is recorded locally, marked late; an aborted or expired leg never settled and is not recorded.
    #[test]
    fn a_leg_past_the_audit_is_recorded_late_not_submitted() {
        assert_eq!(stage(Collecting), Stage::Open);
        assert_eq!(stage(Audited), Stage::Open);
        for later in [Prepared, CommitCertified, Finalized] {
            assert_eq!(stage(later), Stage::Closed, "{later:?}");
        }
        assert_eq!(stage(Aborted), Stage::Dead);
        assert_eq!(stage(Expired), Stage::Dead);
        assert_eq!(late_verdict(Prepared), "approved (late: Prepared, not counted)");
        assert_ne!(late_verdict(Finalized), "approved", "a late verdict never reads as a counted approval");
    }

    #[test]
    fn a_late_answer_is_a_409_not_a_500() {
        let late: eyre::Report = Late(late_verdict(Prepared)).into();
        assert_eq!(status_of(&late), 409);
        assert_eq!(status_of(&eyre!("submit approval quorum")), 500);
    }

    const RD: &str = "7onbjg2gRXveoAAUFsohCZyGW98t";
    const DFABI: &str = "4mBWK1JCwQdHLDPpuVKc56eLsXka";

    fn account(seed: u8) -> AccountId {
        AccountId::new(signing_key(&[seed; 32]).public_key().clone())
    }

    fn rules() -> Rules {
        Rules {
            max_amount: vec![(RD.parse().unwrap(), 1_000_000), (DFABI.parse().unwrap(), 10_000)],
            parties: vec![account(1), account(2)],
        }
    }

    #[test]
    fn records_lists_every_bundle_by_bundle_then_leg() {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-records-{}", rand::random::<u64>()));
        for (bundle, leg) in [("bb", 1u8), ("aa", 1), ("bb", 0), ("aa", 0)] {
            let path = dir.join(bundle).join(format!("{leg}.json"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let record = Record {
                bundle_id: bundle.into(), leg, verdict: "approved".into(), payer: "p".into(), recipient: "r".into(),
                asset: "a".into(), amount: "1".into(), memo_hex: String::new(), plaintext_norito_hex: String::new(),
            };
            std::fs::write(path, serde_json::to_string(&record).unwrap()).unwrap();
        }
        let got = list_records(&dir).unwrap().iter().map(|r| (r.bundle_id.clone(), r.leg)).collect::<Vec<_>>();
        assert_eq!(got, [("aa".into(), 0), ("aa".into(), 1), ("bb".into(), 0), ("bb".into(), 1)]);
        assert!(list_records(&dir.join("missing")).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The HTTP routes are reachable inside the cluster: they carry only what the Lensa adapter reads
    /// (iroha3-aps.ts AuditRecord), not the memo or the full plaintext.
    #[test]
    fn records_json_has_only_the_fields_the_adapter_reads() {
        let record = Record {
            bundle_id: "b".into(), leg: 0, verdict: "approved".into(), payer: "p".into(), recipient: "r".into(),
            asset: "a".into(), amount: "1".into(), memo_hex: "aa".into(), plaintext_norito_hex: "bb".into(),
        };
        let json: serde_json::Value = serde_json::from_str(&records_json(&[record]).unwrap()).unwrap();
        let mut keys = json[0].as_object().unwrap().keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["amount", "asset", "bundle_id", "leg", "payer", "recipient", "verdict"]);
    }

    #[test]
    fn approves_known_parties_within_limit() {
        let rd = RD.parse().unwrap();
        assert_eq!(evaluate(&rules(), &rd, 1_000_000, &account(1), &account(2)), Ok(()));
    }

    #[test]
    fn rejects_unknown_party() {
        let rd = RD.parse().unwrap();
        assert_eq!(evaluate(&rules(), &rd, 1, &account(1), &account(9)), Err("unknown party"));
    }

    #[test]
    fn rejects_over_limit() {
        let dfabi = DFABI.parse().unwrap();
        assert_eq!(evaluate(&rules(), &dfabi, 10_001, &account(2), &account(1)), Err("over limit"));
    }

    #[test]
    fn rejects_unknown_asset() {
        let other = "4Zust3cNxfvUrJRuFjSMmNXho9rF".parse().unwrap();
        assert_eq!(evaluate(&rules(), &other, 1, &account(1), &account(2)), Err("unknown asset"));
    }

    #[test]
    fn hybrid_key_survives_a_file_round_trip() {
        let path = std::env::temp_dir().join(format!("rd-dfabi-hybrid-{}", std::process::id()));
        write_hybrid(&path).unwrap();
        assert!(write_hybrid(&path).is_err(), "must refuse to overwrite");
        let (a, b) = (read_hybrid(&path).unwrap(), read_hybrid(&path).unwrap());
        assert_eq!(
            enc(&PrivateSettlementHybridPublicKeyV1::from_hybrid(a.public())).unwrap(),
            enc(&PrivateSettlementHybridPublicKeyV1::from_hybrid(b.public())).unwrap()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn second_approval_for_same_leg_is_skipped() {
        let dir = std::env::temp_dir().join(format!("rd-dfabi-audit-{}", std::process::id()));
        let path = dir.join("bundle").join("0.json");
        assert!(read_record(&path).unwrap().is_none());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"bundle_id":"b","leg":0,"verdict":"approved","payer":"","recipient":"","asset":"","amount":"1","memo_hex":"","plaintext_norito_hex":""}"#,
        )
        .unwrap();
        assert_eq!(read_record(&path).unwrap().unwrap().verdict, "approved");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
