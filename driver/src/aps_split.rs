//! Payer-only APS leg: each output owner signs its own view-key authorization before proving, so the
//! payer needs no secret of the recipient or the sponsor.
//!
//! The authorization body (iroha@071e281e crates/iroha_data_model/src/nexus/private_settlement.rs:1645-1684
//! `output_view_key_authorization_body`) holds network id, bundle id, leg ordinal, route, output ordinal and role,
//! the owner account, the output's view key, active flag and spending authority, and the expiry height. It holds
//! no value and no commitment, so the owner can sign it without seeing the leg.

use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    nexus::{
        ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, AtomicPrivateSettlementV1, PrivateSettlementAuditAadV1,
        PrivateSettlementAuditEncryptionOpeningV1, PrivateSettlementAuditOutputRoleV1,
        PrivateSettlementAuditOutputV1, PrivateSettlementAuditPayerAuthorizationV1,
        PrivateSettlementAuditPayerSignatureV1, PrivateSettlementAuditPlaintextV1,
        PrivateSettlementAuditViewKeyAuthorizationBodyV1, PrivateSettlementAuditViewKeyAuthorizationV1,
        PrivateSettlementAuditViewKeySignatureV1, PrivateSettlementCapsulePaddingV1,
        PrivateSettlementProofProfileV1, PrivateSettlementProofStatementV1, PrivateSettlementRouteV1,
    },
    privacy::{PrivacyNullifierV1, PrivacyRootV1},
};
use iroha_core::{
    privacy_engines::atomic_private_settlement::{
        AtomicPrivateSettlementInputSecretV1, AtomicPrivateSettlementPreparedLegV1,
        atomic_private_settlement_audit_input_commitment_v1, complete_atomic_private_settlement_prepared_leg_v1,
        consume_atomic_private_settlement_wallet_bundle_v1, derive_atomic_private_settlement_input_nullifiers_v1,
        encode_atomic_private_settlement_wallet_bundle_v1, plan_atomic_private_settlement_bootstrap_v1,
        prepare_atomic_private_settlement_input_openings_v1, prepare_atomic_private_settlement_outputs_v1,
    },
    privacy_engines::ivm_private_note::derive_note_authority_v1,
    private_settlement::seal_private_settlement_audit_capsule_v1_with_rng,
};
use iroha_crypto::{Hash, KeyPair, PublicKey, SignatureOf};

use crate::{
    aps::{
        Governed, SPONSOR_REIMBURSEMENT, Spend, bytes, hash, note_opening, placeholder_encrypted_output,
        placeholder_payer_authorization, rnd,
    },
    wallet::NoteKeys,
};

/// iroha@071e281e nexus/private_settlement.rs:161 `OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1` (private upstream).
const OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1: &[u8] = b"iroha:nexus:private-settlement:output-view-key-authorization:v1\0";

/// What every output's authorization body binds that is known before the leg exists.
pub struct OutputCtx {
    pub network_id: NetworkId,
    pub bundle_id: Hash,
    pub leg_ordinal: u8,
    pub route: PrivateSettlementRouteV1,
    pub expiry_height: u64,
}

/// One output as its owner publishes it: the note's public keys and the owner's signed authorization.
pub struct OutputKey {
    pub authority: [u8; 32],
    pub view_public: [u8; 32],
    pub authorization: PrivateSettlementAuditViewKeyAuthorizationV1,
    pub active: bool,
}

/// The payer's side of one leg. The recipient is a public key only.
pub struct LegPayer {
    pub lane: u32,
    pub asset: AssetDefinitionId,
    pub payer: KeyPair,
    pub recipient: PublicKey,
    pub amount: u128,
}

/// Sign the authorization of output `output_ordinal` (0 recipient, 1 payer change, 2 sponsor) with its owner's key.
pub fn sign_output_key(
    signer: &KeyPair,
    ctx: &OutputCtx,
    output_ordinal: u8,
    role: PrivateSettlementAuditOutputRoleV1,
    keys: &NoteKeys,
    active: bool,
) -> Result<OutputKey> {
    sign_output_public(signer, ctx, output_ordinal, role, keys.authority()?, keys.view_public()?, active)
}

/// `sign_output_key` for an output whose keys are already public values (spending authority, x25519 view key).
pub(crate) fn sign_output_public(
    signer: &KeyPair,
    ctx: &OutputCtx,
    output_ordinal: u8,
    role: PrivateSettlementAuditOutputRoleV1,
    authority: [u8; 32],
    view_public: [u8; 32],
    active: bool,
) -> Result<OutputKey> {
    let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        purpose: Hash::new(OUTPUT_VIEW_KEY_AUTHORIZATION_DOMAIN_V1),
        network_id: ctx.network_id,
        bundle_id: ctx.bundle_id,
        leg_ordinal: ctx.leg_ordinal,
        route: ctx.route,
        output_ordinal,
        role,
        authorized_account: AccountId::new(signer.public_key().clone()),
        recipient_view_key: view_public,
        output_active: active,
        note_spending_authority: authority,
        expiry_height: ctx.expiry_height,
    };
    let authorization = PrivateSettlementAuditViewKeyAuthorizationV1::new(
        body.clone(),
        vec![PrivateSettlementAuditViewKeySignatureV1::new(
            signer.public_key().clone(),
            SignatureOf::try_new(signer.private_key(), &body)?,
        )],
    );
    Ok(OutputKey { authority, view_public, authorization, active })
}

/// The authorization carried for output `index` is the one upstream derives from this plaintext, signed by that output's owner.
fn ensure_authorization(plaintext: &PrivateSettlementAuditPlaintextV1, index: usize, key: &OutputKey) -> Result<()> {
    let authorization = &key.authorization;
    ensure!(
        authorization.body == plaintext.output_view_key_authorization_body(index)?,
        "output {index}: authorization does not match this leg (wrong account, role, bundle, route or keys)"
    );
    ensure!(
        authorization.signatures.iter().any(|entry| {
            authorization.body.authorized_account.signatory_matches(&entry.signer)
                && entry.signature.verify(&entry.signer, &authorization.body).is_ok()
        }),
        "output {index}: authorization is not signed by the output owner"
    );
    Ok(())
}

/// Prove one leg with the payer's secrets only. Outputs 0 (recipient) and 2 (sponsor) arrive as the owners' public
/// `OutputKey`s and are used as given; output 1 (payer change) is signed here with the payer's key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_leg_split(
    ordinal: usize,
    leg: &LegPayer,
    governed: &Governed,
    spend: Spend,
    change: &NoteKeys,
    recipient_output: &OutputKey,
    sponsor_output: &OutputKey,
    sponsor: &PublicKey,
    manifest: &AtomicPrivateSettlementV1,
    authority_digest: Hash,
    reimbursement_salt: [u8; 32],
) -> Result<AtomicPrivateSettlementPreparedLegV1> {
    ensure!(manifest.sponsor == AccountId::new(sponsor.clone()), "sponsor key is not the manifest sponsor");
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
    let (positive_input, positive_secret) = match &spend {
        Spend::Bootstrap(funding) => (funding.opening.clone(), funding.spending_secret),
        Spend::Continue { opening, secret, .. } => (opening.clone(), *secret),
    };
    let input_secrets = [positive_secret, rnd()];
    let ephemeral_secrets = [rnd(), rnd(), rnd()];
    let reimbursement = if ordinal == 0 { SPONSOR_REIMBURSEMENT } else { 0 };
    let value = spend
        .value()
        .checked_sub(leg.amount + reimbursement)
        .ok_or_else(|| eyre!("leg {ordinal}: insufficient payer note"))?;
    let ctx = OutputCtx {
        network_id: manifest.network_id,
        bundle_id: manifest.bundle_id,
        leg_ordinal,
        route: governed.route,
        expiry_height: manifest.expiry_height,
    };
    let change_output = sign_output_key(payer, &ctx, 1, PrivateSettlementAuditOutputRoleV1::PayerChange, change, true)?;
    let output = |role, key: &OutputKey, ephemeral_secret, value| {
        let mut note = note_opening(key.active, value);
        note.spending_authority = key.authority;
        PrivateSettlementAuditOutputV1 {
            role,
            recipient_view_key: key.view_public,
            view_key_authorization: key.authorization.clone(),
            encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 { ephemeral_secret },
            note,
        }
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
        recipient: AccountId::new(leg.recipient.clone()),
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
            output(PrivateSettlementAuditOutputRoleV1::SettlementRecipient, recipient_output, ephemeral_secrets[0], leg.amount),
            output(PrivateSettlementAuditOutputRoleV1::PayerChange, &change_output, ephemeral_secrets[1], value),
            output(PrivateSettlementAuditOutputRoleV1::SponsorReimbursement, sponsor_output, ephemeral_secrets[2], reimbursement),
        ],
    };
    // Refuse a foreign authorization before any proving work.
    for (index, key) in [recipient_output, &change_output, sponsor_output].into_iter().enumerate() {
        ensure_authorization(&plaintext, index, key)?;
    }
    for (opening, secret) in plaintext.inputs.iter_mut().zip(input_secrets) {
        opening.spending_authority = derive_note_authority_v1(&secret)?;
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use eyre::Result;

    use iroha::data_model::{
        NetworkId,
        account::AccountId,
        nexus::{
            ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementAuditEncryptionOpeningV1,
            PrivateSettlementAuditOutputRoleV1, PrivateSettlementAuditOutputV1,
            PrivateSettlementAuditPlaintextV1, PrivateSettlementHybridPublicKeyV1,
            PrivateSettlementRouteV1,
        },
    };
    use iroha_core::privacy_engines::atomic_private_settlement::verify_atomic_private_settlement_v1;
    use iroha_crypto::{Hash, HashOf, KeyPair};
    use iroha_model_base::topology::{DataSpaceId, LaneId};

    use super::*;
    use crate::{
        aps::{
            EXPIRY_BLOCKS, Governed, Spend, bounded_fee_for, bytes, committee_authority, fixture_key, funding, govern, hash,
            note_opening, on_big_stack, placeholder_payer_authorization, proof_manifest, rnd,
        },
        wallet::{NoteKeys, open_output},
    };

    const ROLES: [PrivateSettlementAuditOutputRoleV1; 3] = [
        PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
        PrivateSettlementAuditOutputRoleV1::PayerChange,
        PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
    ];

    struct World {
        governed: Governed,
        manifest: iroha::data_model::nexus::AtomicPrivateSettlementV1,
        authority_digest: Hash,
        genesis: [u8; 32],
        ctx: OutputCtx,
        salt: [u8; 32],
        sponsor: KeyPair,
    }

    /// Same synthetic network the offline selftests use; nobody's secret here is shared between the parties.
    fn world() -> World {
        let route = |lane: u32| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(u64::from(lane)),
            lane_id: LaneId::new(lane),
            lane_incarnation: Hash::new(b"rd-dfabi-selftest"),
        };
        let peers = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/peers.json"));
        let (authority, _) = committee_authority(peers, route(1)).unwrap();
        let network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"rd-dfabi-selftest-network")));
        let mut rng = iroha_crypto::rng_from_seed_slice(&rnd());
        let hybrid = iroha_crypto::HybridKeyPair::generate(&mut rng).unwrap();
        let encryption = PrivateSettlementHybridPublicKeyV1::from_hybrid(hybrid.public());
        let auditor = fixture_key(0x30);
        let governed = [(1, "7onbjg2gRXveoAAUFsohCZyGW98t"), (2, "4mBWK1JCwQdHLDPpuVKc56eLsXka")]
            .into_iter()
            .map(|(lane, asset)| govern(route(lane), asset.parse().unwrap(), 100, 100 + EXPIRY_BLOCKS, auditor.public_key(), &encryption))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let sponsor = fixture_key(0x31);
        let salt = rnd();
        let manifest = proof_manifest(
            network_id,
            101,
            100 + EXPIRY_BLOCKS,
            AccountId::new(sponsor.public_key().clone()),
            bounded_fee_for("6TEAJqbb8oEPmLncoNiMRbLEK6tw").unwrap(),
            &governed,
            salt,
        )
        .unwrap();
        let ctx = OutputCtx {
            network_id,
            bundle_id: manifest.bundle_id,
            leg_ordinal: 0,
            route: governed[0].route,
            expiry_height: manifest.expiry_height,
        };
        World {
            governed: governed.into_iter().next().unwrap(),
            authority_digest: authority.digest().unwrap(),
            genesis: *network_id.as_genesis_hash().as_ref(),
            manifest,
            ctx,
            salt,
            sponsor,
        }
    }

    fn payer_leg(world: &World, recipient: &KeyPair) -> LegPayer {
        LegPayer {
            lane: 1,
            asset: world.governed.governance.body.asset_definition_id.clone(),
            payer: fixture_key(0x32),
            recipient: recipient.public_key().clone(),
            amount: 100,
        }
    }

    /// The payer side runs with: its own key pair, its change keys, and the other two parties' PUBLIC outputs.
    /// No recipient or sponsor `KeyPair` or `NoteKeys` is a parameter.
    #[test]
    fn split_leg_needs_no_foreign_secret() {
        let world = world();
        let recipient = fixture_key(0x33);
        let recipient_keys = NoteKeys::random();
        let recipient_output =
            sign_output_key(&recipient, &world.ctx, 0, ROLES[0], &recipient_keys, true).unwrap();
        let sponsor_output =
            sign_output_key(&world.sponsor, &world.ctx, 2, ROLES[2], &NoteKeys::random(), true).unwrap();
        let leg = payer_leg(&world, &recipient);
        let change = NoteKeys::random();
        let funding = funding(1_000).unwrap();
        let prepared = on_big_stack(|| {
            prepare_leg_split(
                0,
                &leg,
                &world.governed,
                Spend::Bootstrap(funding),
                &change,
                &recipient_output,
                &sponsor_output,
                world.sponsor.public_key(),
                &world.manifest,
                world.authority_digest,
                world.salt,
            )
        })
        .unwrap();
        verify_atomic_private_settlement_v1(&world.manifest, &prepared.statement, world.genesis, 101, &prepared.proof)
            .unwrap_or_else(|e| panic!("proof rejected: {e:?}"));
        let pool_id = world.governed.governance.body.pool_id;
        let opened = prepared
            .statement
            .output_commitments
            .iter()
            .zip(&prepared.statement.encrypted_outputs)
            .find_map(|(commitment, encrypted)| open_output(pool_id, *commitment, encrypted, &recipient_keys).unwrap())
            .expect("the recipient found no note addressed to its public output");
        assert_eq!(opened.value, 100);
    }

    /// Our body for each output equals what upstream derives from the leg plaintext, so a party can sign before the leg exists.
    #[test]
    fn output_key_body_matches_upstream() {
        let world = world();
        let payer = fixture_key(0x32);
        let recipient = fixture_key(0x33);
        let signers = [&recipient, &payer, &world.sponsor];
        let keys = [NoteKeys::random(), NoteKeys::random(), NoteKeys::random()];
        let signed: Vec<OutputKey> = signers
            .iter()
            .zip(&keys)
            .enumerate()
            .map(|(index, (signer, keys))| sign_output_key(signer, &world.ctx, index as u8, ROLES[index], keys, true).unwrap())
            .collect();
        let outputs = signed
            .iter()
            .zip(&keys)
            .enumerate()
            .map(|(index, (key, keys))| {
                let mut note = note_opening(key.active, 1);
                note.spending_authority = keys.authority().unwrap();
                PrivateSettlementAuditOutputV1 {
                    role: ROLES[index],
                    recipient_view_key: keys.view_public().unwrap(),
                    view_key_authorization: key.authorization.clone(),
                    encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 { ephemeral_secret: rnd() },
                    note,
                }
            })
            .collect();
        let plaintext = PrivateSettlementAuditPlaintextV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            network_id: world.ctx.network_id,
            bundle_id: world.ctx.bundle_id,
            leg_ordinal: world.ctx.leg_ordinal,
            route: world.ctx.route,
            pool_id: world.governed.governance.body.pool_id,
            payer: AccountId::new(payer.public_key().clone()),
            payer_authorization: placeholder_payer_authorization(world.ctx.network_id, world.ctx.route, &payer, world.ctx.expiry_height),
            recipient: AccountId::new(recipient.public_key().clone()),
            sponsor: world.manifest.sponsor.clone(),
            asset_definition_id: world.governed.governance.body.asset_definition_id.clone(),
            asset_binding_salt: bytes(9),
            amount: 100,
            sponsor_reimbursement_amount: 1,
            fee_intent_digest: hash(7),
            settlement_expiry_height: world.ctx.expiry_height,
            reimbursement_terms_salt: world.salt,
            memo: Vec::new(),
            policy_references: Vec::new(),
            inputs: Vec::new(),
            outputs,
        };
        for (index, key) in signed.iter().enumerate() {
            assert!(
                key.authorization.body == plaintext.output_view_key_authorization_body(index).unwrap(),
                "output {index}: body differs from upstream"
            );
            assert_eq!(key.authority, keys[index].authority().unwrap());
            assert_eq!(key.view_public, keys[index].view_public().unwrap());
        }
    }

    /// An output key signed by an account other than the leg's recipient or sponsor stops the payer before any proving.
    #[test]
    fn a_foreign_authorization_is_refused() {
        let world = world();
        let recipient = fixture_key(0x33);
        let stranger = fixture_key(0x34);
        let good_recipient = sign_output_key(&recipient, &world.ctx, 0, ROLES[0], &NoteKeys::random(), true).unwrap();
        let good_sponsor = sign_output_key(&world.sponsor, &world.ctx, 2, ROLES[2], &NoteKeys::random(), true).unwrap();
        let foreign_recipient = sign_output_key(&stranger, &world.ctx, 0, ROLES[0], &NoteKeys::random(), true).unwrap();
        let foreign_sponsor = sign_output_key(&stranger, &world.ctx, 2, ROLES[2], &NoteKeys::random(), true).unwrap();
        let leg = payer_leg(&world, &recipient);
        let change = NoteKeys::random();
        for (index, (recipient_output, sponsor_output)) in
            [(&foreign_recipient, &good_sponsor), (&good_recipient, &foreign_sponsor)].into_iter().enumerate()
        {
            let funding = funding(1_000).unwrap();
            let refused = on_big_stack(|| {
                prepare_leg_split(
                    0,
                    &leg,
                    &world.governed,
                    Spend::Bootstrap(funding),
                    &change,
                    recipient_output,
                    sponsor_output,
                    world.sponsor.public_key(),
                    &world.manifest,
                    world.authority_digest,
                    world.salt,
                )
            })
            .err()
            .expect("a foreign authorization must be refused");
            let expected = format!("output {}", index * 2);
            assert!(refused.to_string().contains(&expected), "unexpected error: {refused}");
        }
    }
}
