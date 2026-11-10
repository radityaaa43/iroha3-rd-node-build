//! A party's private notes: its note keys and the notes it can open from a pool's outputs.

use eyre::{Result, eyre};
use iroha::data_model::{
    nexus::PrivateSettlementAuditNoteOpeningV1,
    privacy::{PrivacyCommitmentV1, PrivacyEncryptedOutputV1, PrivacyPoolIdV1},
};
use iroha_core::privacy_engines::{
    atomic_private_settlement::atomic_private_settlement_program_id_v1,
    ivm_private_note::{decrypt_ivm_private_wallet_note_v1, derive_note_authority_v1, ivm_private_recipient_public_key_v1},
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
