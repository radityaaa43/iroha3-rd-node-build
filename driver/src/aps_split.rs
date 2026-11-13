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
            .expect_err("a foreign authorization must be refused");
            let expected = format!("output {}", index * 2);
            assert!(refused.to_string().contains(&expected), "unexpected error: {refused}");
        }
    }
}
