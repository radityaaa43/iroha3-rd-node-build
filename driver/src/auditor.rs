//! BI auditor service (Deployment `bi-auditor`, separate from node `bi`).
//!
//! Torii has no "pending legs" route, so the coordinator asks for approval of one leg
//! over `POST /approve`. The auditor itself fetches the encrypted capsule from a committee
//! quorum, decrypts it with BI's key, applies local rules, submits the approval quorum, and
//! keeps the plaintext in its store (O5). Logs carry digests only.

use std::{path::PathBuf, sync::Mutex};

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
use iroha_crypto::{Hash, HybridKeyPair, KeyPair, PublicKey};
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

/// BI's signing key and hybrid (X25519 + ML-KEM-768) capsule key, both from one seed so
/// a restarted pod keeps the identity named in already-activated pool policies.
pub fn auditor_keys(seed: &[u8; 32]) -> Result<(KeyPair, HybridKeyPair)> {
    let mut rng = iroha_crypto::rng_from_seed_slice(
        &[b"rd-dfabi:bi-auditor:hybrid:v1".as_slice(), seed.as_slice()].concat(),
    );
    Ok((signing_key(seed), HybridKeyPair::generate(&mut rng)?))
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
    hybrid: HybridKeyPair,
    client: Client,
}

pub fn run(cfg: Config) -> Result<()> {
    let (signing, hybrid) = auditor_keys(&cfg.seed("bi-auditor")?)?;
    std::fs::create_dir_all(&cfg.auditor.store_dir)?;
    let auditor = Auditor {
        rules: Rules::from_config(&cfg)?,
        client: cfg.client_with_key("bi", &signing)?,
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
            ("POST", "/approve") => serde_json::from_str(body)
                .map_err(Into::into)
                .and_then(|request| auditor.approve(&request))
                .and_then(|response| Ok(serde_json::to_string(&response)?)),
            _ => Err(eyre!("not found")),
        };
        match result {
            Ok(body) => (200, body),
            Err(error) => {
                eprintln!("{method} {path}: {error:#}");
                (500, serde_json::json!({ "error": format!("{error:#}") }).to_string())
            }
        }
    })
}

impl Auditor {
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
        let fetched = self
            .client
            .client()
            .private_settlement_auditor_capsule_quorum_for_authority_v1(
                &endpoints,
                &authority,
                payload_digest,
                &capsule_request,
                &signer,
            )
            .wrap_err("fetch audit capsule")?;
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
        ensure!(
            fetched.lifecycle == PrivateSettlementLifecycleDtoV1::Collecting,
            "leg is not collecting audit approvals"
        );
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
            self.hybrid.secret(),
            &self.signing,
            &evaluator,
        );
        let (verdict, plaintext) = seen
            .into_inner()
            .expect("evaluator lock")
            .ok_or_else(|| eyre!("capsule did not decrypt: {:?}", approval.err()))?;
        if let Err(reason) = verdict {
            write_record(&record_path, &bundle_id, leg, &format!("rejected: {reason}"), &plaintext)?;
            eprintln!("bundle={bundle_id} leg={leg} rejected: {reason}");
            return Ok(ApproveResponse { approved: false, reason: reason.into() });
        }
        let approval = approval.map_err(|e| eyre!("approve leg: {e:?}"))?;
        let response = self
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
            .wrap_err("submit approval quorum")?;
        ensure!(
            response.lifecycle == PrivateSettlementLifecycleDtoV1::Audited,
            "approval quorum was not durable"
        );
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
    fn auditor_keys_are_stable_for_a_seed() {
        let (a, ha) = auditor_keys(&[7; 32]).unwrap();
        let (b, hb) = auditor_keys(&[7; 32]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(
            enc(&PrivateSettlementHybridPublicKeyV1::from_hybrid(ha.public())).unwrap(),
            enc(&PrivateSettlementHybridPublicKeyV1::from_hybrid(hb.public())).unwrap()
        );
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
