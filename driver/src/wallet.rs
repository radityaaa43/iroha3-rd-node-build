//! A party's private notes: its note keys and the notes it can open from a pool's outputs.

use eyre::{Result, eyre};
use iroha::data_model::{
    nexus::PrivateSettlementAuditNoteOpeningV1,
    privacy::{PrivacyCommitmentV1, PrivacyEncryptedOutputV1, PrivacyNullifierV1, PrivacyPoolIdV1},
};
use iroha_core::privacy_engines::{
    atomic_private_settlement::atomic_private_settlement_program_id_v1,
    ivm_private_note::{
        decrypt_ivm_private_wallet_note_v1, derive_note_authority_v1, derive_note_nullifier_v1,
        ivm_private_recipient_public_key_v1,
    },
};

/// Spend secret (authorizes spending) and view secret (decrypts received notes) of one party.
#[derive(Clone)]
pub struct NoteKeys {
    pub spend: [u8; 32],
    pub view: [u8; 32],
}

impl NoteKeys {
    pub fn random() -> Self {
        Self { spend: rand::random(), view: rand::random() }
    }

    pub fn authority(&self) -> Result<[u8; 32]> {
        Ok(derive_note_authority_v1(&self.spend)?)
    }

    pub fn view_public(&self) -> Result<[u8; 32]> {
        Ok(ivm_private_recipient_public_key_v1(&self.view)?)
    }
    /// One-time keys for one output: same spend secret, a view secret derived from the party's own
    /// view secret, the bundle, the pool and the output role (0 recipient, 1 change). A recipient id is
    /// public on chain, so a fixed view key would link every payment of a party; a leg's outputs and
    /// a bundle's outputs must also have distinct recipient ids (data model validate_output_authorizations,
    /// PrivateSettlementPrepareBarrierV1::validate_shape). The owner re-derives it when scanning.
    pub fn one_time(&self, bundle_id: &[u8; 32], pool_id: &[u8; 32], role: u8) -> Self {
        use sha2::{Digest as _, Sha256};
        let mut h = Sha256::new();
        h.update(b"rd-dfabi.one-time-view.v1");
        h.update(self.view);
        h.update(bundle_id);
        h.update(pool_id);
        h.update([role]);
        Self { spend: self.spend, view: h.finalize().into() }
    }
}

/// Open one encrypted pool output with `keys`; `None` when it is not addressed to them.
pub fn open_output(
    pool_id: PrivacyPoolIdV1,
    commitment: PrivacyCommitmentV1,
    encrypted: &PrivacyEncryptedOutputV1,
    keys: &NoteKeys,
) -> Result<Option<PrivateSettlementAuditNoteOpeningV1>> {
    let program_id = atomic_private_settlement_program_id_v1()?;
    let Ok(note) = decrypt_ivm_private_wallet_note_v1(pool_id, program_id, commitment, encrypted, &keys.view) else {
        return Ok(None);
    };
    if *note.spending_authority() != keys.authority()? {
        return Err(eyre!("note decrypts with our view key but is not spendable by our spend key"));
    }
    Ok(Some(PrivateSettlementAuditNoteOpeningV1 {
        active: true,
        commitment,
        value: note.value(),
        spending_authority: *note.spending_authority(),
        rho: *note.rho(),
        blinding: *note.blinding(),
        memo_digest: *note.memo_digest(),
        dummy_domain: None,
    }))
}

/// The stable pool-scoped nullifier the chain publishes when `opening` is spent. It depends only
/// on the spend secret, rho, commitment, pool and program (iroha_core ivm_private_note
/// relation.rs derive_note_nullifier_v1); the statement is a carrier for pool and program ids.
pub fn note_nullifier(pool_id: PrivacyPoolIdV1, secret: &[u8; 32], opening: &PrivateSettlementAuditNoteOpeningV1) -> Result<PrivacyNullifierV1> {
    use iroha::data_model::{
        asset::AssetBalanceScope,
        privacy::{
            IrohaIvmPrivateNoteStarkStatementV1, PrivacyActionDigestV1, PrivacyEngineManifestDigestV1,
            PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyRootV1, PrivacyStatementContextV1,
            PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1, PrivacyValueBalanceV1,
            PrivacyVerifierDigestV1,
        },
    };
    let statement = IrohaIvmPrivateNoteStarkStatementV1 {
        context: PrivacyStatementContextV1 {
            network_id: iroha::data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"nullifier-carrier"))),
            action_index: 0,
            transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([1; 32]),
            parameter_id: PrivacyParameterIdV1::new([1; 32]),
            parameter_digest: PrivacyParameterDigestV1::new([1; 32]),
            verifier_digest: PrivacyVerifierDigestV1::new([1; 32]),
            statement_schema_digest: PrivacyStatementSchemaDigestV1::new([1; 32]),
            engine_manifest_digest: PrivacyEngineManifestDigestV1::new([1; 32]),
        },
        asset_definition_id: "7onbjg2gRXveoAAUFsohCZyGW98t".parse()?,
        public_balance_scope: AssetBalanceScope::Global,
        pool_id,
        program_id: atomic_private_settlement_program_id_v1()?,
        action_digest: PrivacyActionDigestV1::new([1; 32]),
        state_root: PrivacyRootV1::new([1; 32]),
        root_epoch: 1,
        nullifiers: Vec::new(),
        output_commitments: Vec::new(),
        encrypted_outputs: Vec::new(),
        value_balance: PrivacyValueBalanceV1::balanced(),
        execution_epoch: 1,
    };
    Ok(derive_note_nullifier_v1(&statement, secret, &opening.rho, opening.commitment)?)
}

/// One unspent note a party can spend.
#[derive(Clone)]
pub struct OwnedNote {
    pub opening: PrivateSettlementAuditNoteOpeningV1,
    pub bundle_id: Option<String>,
    pub height: u64,
}

/// Every note in `history` addressed to `keys` (plus `origin` notes the party was issued at pool
/// activation), each once, split into unspent and spent by the nullifiers on chain.
pub fn scan(
    history: &crate::history::PoolHistory,
    keys: &NoteKeys,
    origin: &[PrivateSettlementAuditNoteOpeningV1],
) -> Result<(Vec<OwnedNote>, Vec<(OwnedNote, String)>)> {
    let mut seen = std::collections::BTreeSet::new();
    let mut found = Vec::new();
    for opening in origin {
        if seen.insert(opening.commitment) {
            found.push(OwnedNote { opening: opening.clone(), bundle_id: None, height: 0 });
        }
    }
    for row in &history.outputs {
        let bundle: [u8; 32] = hex::decode(&row.bundle_id)?.try_into().map_err(|_| eyre!("bundle id"))?;
        let pool = *history.pool_id.as_ref();
        let mut opened = None;
        for role in [0, 1] {
            if let Some(opening) = open_output(history.pool_id, row.commitment, &row.encrypted, &keys.one_time(&bundle, &pool, role))? {
                opened = Some(opening);
                break;
            }
        }
        if let Some(opening) = opened {
            if seen.insert(opening.commitment) && opening.value > 0 {
                found.push(OwnedNote { opening, bundle_id: Some(row.bundle_id.clone()), height: row.height });
            }
        }
    }
    let mut unspent = Vec::new();
    let mut spent = Vec::new();
    for note in found {
        let nullifier = note_nullifier(history.pool_id, &keys.spend, &note.opening)?;
        match history.spent_in.get(&nullifier) {
            Some(bundle) => spent.push((note, bundle.clone())),
            None => unspent.push(note),
        }
    }
    Ok((unspent, spent))
}

/// Smallest unspent note strictly larger than `need` (a zero change note is not provable).
pub fn pick_note(notes: &[OwnedNote], need: u128) -> Result<OwnedNote> {
    notes
        .iter()
        .filter(|n| n.opening.value > need)
        .min_by_key(|n| n.opening.value)
        .cloned()
        .ok_or_else(|| eyre!("no single note covers the amount plus change"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(value: u128) -> OwnedNote {
        OwnedNote {
            opening: PrivateSettlementAuditNoteOpeningV1 {
                active: true,
                commitment: PrivacyCommitmentV1::new(rand::random()),
                value,
                spending_authority: rand::random(),
                rho: rand::random(),
                blinding: rand::random(),
                memo_digest: rand::random(),
                dummy_domain: None,
            },
            bundle_id: None,
            height: 0,
        }
    }

    #[test]
    fn pick_note_rejects_when_no_single_note_covers() {
        let notes = [note(5), note(5)];
        assert!(pick_note(&notes, 8).is_err());
        assert_eq!(pick_note(&notes, 4).unwrap().opening.value, 5);
    }

    #[test]
    fn one_time_keys_differ_per_bundle_pool_and_role_and_keep_the_spend_key() {
        let k = NoteKeys::random();
        let (b1, b2, p) = ([1; 32], [2; 32], [3; 32]);
        let views = [k.one_time(&b1, &p, 0).view, k.one_time(&b1, &p, 1).view, k.one_time(&b2, &p, 0).view, k.view];
        assert_eq!(views.iter().collect::<std::collections::BTreeSet<_>>().len(), 4);
        assert_eq!(k.one_time(&b1, &p, 0).spend, k.spend);
        assert_eq!(k.one_time(&b1, &p, 0).view, k.one_time(&b1, &p, 0).view);
    }

    #[test]
    fn pick_note_requires_change() {
        assert!(pick_note(&[note(5)], 5).is_err());
        assert_eq!(pick_note(&[note(9), note(6), note(50)], 5).unwrap().opening.value, 6);
    }
}
