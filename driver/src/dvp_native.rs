//! D-native atomic DvP (iroha3 PLAN S17, user decision "iroha dvp 1"): each bank signs with its OWN key.
//!
//! The debited counterparty grants `CanExecuteSettlement` (`settle-grant`) bound to the exact DvP intent; the other
//! side then submits one `DvpIsi` (`dvp-native`) with `AllOrNothing` atomicity. Core accepts the DvP only when the
//! authority holds a consent whose `intent_hash` equals `DvpIsi::intent_hash()` and whose `settlement_id` matches
//! (iroha@071e281e crates/iroha_core/src/smartcontracts/isi/settlement.rs:561-576 and :624; permission payload at
//! crates/iroha_executor_data_model/src/permission.rs:792-799). Only public terms pass through here; no key is read
//! except the config's own client.toml key, and nothing secret is printed.
//!
//! The 32-byte `--intent` (Lensa's intent id) becomes the one-shot `settlement_id` `dvp_<hex>`, so it sits inside the
//! hashed instruction. Both sides pass the same terms, each from its own point of view (`--give` leaves me, `--take`
//! arrives at me), and derive the same `intent_hash`.

use std::str::FromStr;

use eyre::{Result, WrapErr, ensure, eyre};
use iroha::{
    blocking::Client,
    client::AccountTransactionDraft,
    data_model::{
        account::AccountId,
        asset::{AssetDefinitionId, AssetId},
        isi::{
            DvpIsi, Grant, InstructionBox, SettlementAtomicity, SettlementExecutionOrder, SettlementId, SettlementLeg,
            SettlementPlan,
        },
    },
    executor_data_model::permission::settlement::CanExecuteSettlement,
};
use iroha_crypto::PublicKey;
use iroha_model_base::metadata::Metadata;

use crate::{aps::bounded_fee, config::Config};

/// One side of the exchange: `<asset-definition-id>:<amount>`, amount a non-zero integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Side {
    pub asset: AssetDefinitionId,
    pub amount: u128,
}

impl Side {
    pub fn parse(text: &str) -> Result<Self> {
        // The asset literal is base58 and holds no ':', so the last ':' separates the amount.
        let (asset, amount) = text.rsplit_once(':').ok_or_else(|| eyre!("expected <asset>:<amount>, got {text:?}"))?;
        // Digits only: `u128::from_str` would also take a leading '+'.
        ensure!(!amount.is_empty() && amount.bytes().all(|b| b.is_ascii_digit()), "amount {amount:?} is not a plain integer");
        let amount: u128 = amount.parse().wrap_err("amount does not fit u128")?;
        ensure!(amount > 0, "amount must be greater than zero");
        let asset = AssetDefinitionId::from_str(asset).map_err(|e| eyre!("asset {asset:?}: {e}"))?;
        Ok(Self { asset, amount })
    }
}

/// 32-byte intent id, 64 hex characters.
pub fn parse_intent(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text).wrap_err("intent is not hex")?;
    bytes.try_into().map_err(|_| eyre!("intent must be exactly 32 bytes (64 hex characters)"))
}

/// Counterparty account from its public key (`ed0120...`): an account id is the key itself.
pub fn parse_account(text: &str) -> Result<AccountId> {
    let key = PublicKey::from_str(text).map_err(|e| eyre!("account public key {text:?}: {e}"))?;
    Ok(AccountId::new(key))
}

/// The DvP exactly as `submitter` signs it: `give` leaves the submitter (delivery leg), `take` arrives at it (payment leg).
pub fn build_dvp(submitter: &AccountId, counterparty: &AccountId, give: &Side, take: &Side, intent: &[u8; 32]) -> Result<DvpIsi> {
    ensure!(submitter != counterparty, "counterparty must differ from the submitting account");
    ensure!(give.asset != take.asset, "the two legs must use different assets");
    let settlement_id = SettlementId::from_str(&format!("dvp_{}", hex::encode(intent))).map_err(|e| eyre!("settlement id: {e}"))?;
    Ok(DvpIsi::new(
        settlement_id,
        SettlementLeg::new(give.asset.clone(), give.amount, submitter.clone(), counterparty.clone()),
        SettlementLeg::new(take.asset.clone(), take.amount, counterparty.clone(), submitter.clone()),
        SettlementPlan::new(SettlementExecutionOrder::DeliveryThenPayment, SettlementAtomicity::AllOrNothing),
    ))
}

/// The consent `grantor` gives to `to` (the future submitter), in the grantor's own give/take terms.
pub fn build_consent(grantor: &AccountId, to: &AccountId, give: &Side, take: &Side, intent: &[u8; 32]) -> Result<CanExecuteSettlement> {
    // The grantee submits, so what the grantor gives is the grantee's take (payment leg, debited from the grantor).
    let dvp = build_dvp(to, grantor, take, give, intent)?;
    Ok(CanExecuteSettlement {
        debited_asset: AssetId::new(dvp.payment_leg.asset_definition_id.clone(), grantor.clone()),
        settlement_id: dvp.settlement_id.clone(),
        intent_hash: dvp.intent_hash(),
    })
}

/// `Grant<CanExecuteSettlement>` from `grantor` to `to`.
pub fn build_grant(grantor: &AccountId, to: &AccountId, give: &Side, take: &Side, intent: &[u8; 32]) -> Result<InstructionBox> {
    Ok(Grant::account_permission(build_consent(grantor, to, give, take, intent)?, to.clone()).into())
}

/// Client of the config's OWN account (its client.toml: own key, own Torii) and that account id.
fn own_client(cfg: &Config) -> Result<(Client, AccountId)> {
    let config = iroha::config::Config::load_file(&cfg.client_toml)
        .map_err(|e| eyre!("load {}: {e:?}", cfg.client_toml.display()))?;
    let own = AccountId::new(config.key_pair.public_key().clone());
    Ok((Client::new(config)?, own))
}

/// Sign with the own key, pay the bounded fee like every other command, wait for `Applied`; return the transaction hash.
fn submit(cfg: &Config, client: &Client, instruction: InstructionBox) -> Result<String> {
    let account = client.account_client();
    let transaction = account
        .prepare_transaction(AccountTransactionDraft::new(vec![instruction], bounded_fee(cfg)?, Metadata::default()))
        .and_then(|payload| account.sign_transaction(payload))
        .wrap_err("build transaction")?;
    let hash = client.submit_transaction_and_wait(&transaction).wrap_err("submit transaction")?;
    Ok(hash.to_string())
}

/// `rd-dfabi settle-grant`: grant `CanExecuteSettlement` from the config's own account to `to`.
pub fn settle_grant(cfg: &Config, to: &str, give: &str, take: &str, intent: &str) -> Result<String> {
    let (client, own) = own_client(cfg)?;
    let grant = build_grant(&own, &parse_account(to)?, &Side::parse(give)?, &Side::parse(take)?, &parse_intent(intent)?)?;
    submit(cfg, &client, grant)
}

/// `rd-dfabi dvp-native`: submit the `DvpIsi` from the config's own account.
pub fn dvp_native(cfg: &Config, counterparty: &str, give: &str, take: &str, intent: &str) -> Result<String> {
    let (client, own) = own_client(cfg)?;
    let dvp = build_dvp(&own, &parse_account(counterparty)?, &Side::parse(give)?, &Side::parse(take)?, &parse_intent(intent)?)?;
    submit(cfg, &client, dvp.into())
}

#[cfg(test)]
mod tests {
    use iroha_crypto::KeyPair;
    use iroha_primitives::numeric::Quantity;

    use super::*;
    use crate::config::signing_key;

    fn key(seed: u8) -> KeyPair {
        signing_key(&[seed; 32])
    }

    fn account(seed: u8) -> AccountId {
        AccountId::new(key(seed).public_key().clone())
    }

    /// Valid asset definition id literal (UUIDv4 bytes), distinct per `n`.
    fn asset_literal(n: u8) -> String {
        AssetDefinitionId::from_uuid_bytes([n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]).unwrap().to_string()
    }

    fn asset(n: u8) -> AssetDefinitionId {
        asset_literal(n).parse().unwrap()
    }

    fn side(n: u8, amount: u128) -> Side {
        Side { asset: asset(n), amount }
    }

    fn intent(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn side_parses_asset_and_amount() {
        assert_eq!(Side::parse(&format!("{}:250", asset_literal(1))).unwrap(), side(1, 250));
        let max = u128::MAX.to_string();
        assert_eq!(Side::parse(&format!("{}:{max}", asset_literal(2))).unwrap(), side(2, u128::MAX));
    }

    #[test]
    fn side_refuses_zero_amount() {
        assert!(Side::parse(&format!("{}:0", asset_literal(1))).is_err());
        assert!(Side::parse(&format!("{}:000", asset_literal(1))).is_err());
    }

    #[test]
    fn side_refuses_non_numeric_amount() {
        for bad in ["", "abc", "-5", "+5", "1.5", "1e3", " 5", "5 ", "0x10", "340282366920938463463374607431768211456"] {
            assert!(Side::parse(&format!("{}:{bad}", asset_literal(1))).is_err(), "amount {bad:?} must be refused");
        }
    }

    #[test]
    fn side_refuses_missing_separator_or_bad_asset() {
        assert!(Side::parse(&asset_literal(1)).is_err());
        assert!(Side::parse("5").is_err());
        assert!(Side::parse(":5").is_err());
        assert!(Side::parse("not-an-asset-id:5").is_err());
    }

    #[test]
    fn intent_parses_exactly_32_bytes_of_hex() {
        assert_eq!(parse_intent(&"ab".repeat(32)).unwrap(), intent(0xab));
        assert_eq!(parse_intent(&"AB".repeat(32)).unwrap(), intent(0xab));
        assert!(parse_intent(&"ab".repeat(31)).is_err());
        assert!(parse_intent(&"ab".repeat(33)).is_err());
        assert!(parse_intent(&"zz".repeat(32)).is_err());
        assert!(parse_intent("").is_err());
    }

    #[test]
    fn account_parses_public_key_and_refuses_garbage() {
        assert_eq!(parse_account(&key(7).public_key().to_string()).unwrap(), account(7));
        assert!(parse_account("not-a-key").is_err());
        assert!(parse_account("").is_err());
    }

    #[test]
    fn dvp_is_two_reciprocal_legs_all_or_nothing_with_the_intent_as_settlement_id() {
        let (a, b) = (account(1), account(2));
        let dvp = build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(0xcd)).unwrap();
        let settlement_id: SettlementId = format!("dvp_{}", "cd".repeat(32)).parse().unwrap();
        let expected = DvpIsi {
            settlement_id,
            delivery_leg: SettlementLeg::new(asset(1), 5u128, a.clone(), b.clone()),
            payment_leg: SettlementLeg::new(asset(2), 10u128, b, a),
            plan: SettlementPlan::new(SettlementExecutionOrder::DeliveryThenPayment, SettlementAtomicity::AllOrNothing),
            metadata: Metadata::default(),
        };
        assert_eq!(dvp, expected);
        assert_eq!(dvp.plan.atomicity(), SettlementAtomicity::AllOrNothing);
        assert_eq!(dvp.delivery_leg.quantity, Quantity::from(5u128));
        assert_eq!(dvp.payment_leg.quantity, Quantity::from(10u128));
    }

    #[test]
    fn dvp_intent_hash_binds_intent_terms_and_roles() {
        let (a, b) = (account(1), account(2));
        let base = build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(1)).unwrap();
        assert_eq!(base.intent_hash(), build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(1)).unwrap().intent_hash());
        for other in [
            build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(2)).unwrap(),
            build_dvp(&a, &b, &side(1, 6), &side(2, 10), &intent(1)).unwrap(),
            build_dvp(&a, &b, &side(1, 5), &side(2, 11), &intent(1)).unwrap(),
            build_dvp(&b, &a, &side(1, 5), &side(2, 10), &intent(1)).unwrap(),
        ] {
            assert_ne!(base.intent_hash(), other.intent_hash());
        }
    }

    #[test]
    fn dvp_refuses_the_same_asset_on_both_legs() {
        assert!(build_dvp(&account(1), &account(2), &side(1, 5), &side(1, 10), &intent(1)).is_err());
    }

    #[test]
    fn dvp_refuses_a_counterparty_equal_to_the_submitter() {
        assert!(build_dvp(&account(1), &account(1), &side(1, 5), &side(2, 10), &intent(1)).is_err());
    }

    #[test]
    fn grant_is_the_exact_can_execute_settlement_for_the_payment_balance() {
        let (a, b) = (account(1), account(2));
        // B grants A. B gives asset 2 (payment leg, debited from B) and takes asset 1.
        let grant = build_grant(&b, &a, &side(2, 10), &side(1, 5), &intent(9)).unwrap();
        let dvp = build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(9)).unwrap();
        let token = CanExecuteSettlement {
            debited_asset: AssetId::new(asset(2), b),
            settlement_id: dvp.settlement_id.clone(),
            intent_hash: dvp.intent_hash(),
        };
        assert_eq!(grant, InstructionBox::from(Grant::account_permission(token, a)));
    }

    #[test]
    fn consent_matches_the_counterpartys_dvp_and_nothing_else() {
        let (a, b) = (account(1), account(2));
        let consent = build_consent(&b, &a, &side(2, 10), &side(1, 5), &intent(9)).unwrap();
        let dvp = build_dvp(&a, &b, &side(1, 5), &side(2, 10), &intent(9)).unwrap();
        assert_eq!(consent.intent_hash, dvp.intent_hash());
        assert_eq!(consent.settlement_id, dvp.settlement_id);
        let other_amount = build_consent(&b, &a, &side(2, 11), &side(1, 5), &intent(9)).unwrap();
        assert_ne!(other_amount.intent_hash, dvp.intent_hash());
        let other_intent = build_consent(&b, &a, &side(2, 10), &side(1, 5), &intent(8)).unwrap();
        assert_ne!(other_intent.intent_hash, dvp.intent_hash());
        assert_ne!(other_intent.settlement_id, dvp.settlement_id);
    }

    #[test]
    fn grant_refuses_the_same_asset_on_both_legs_and_a_self_grant() {
        assert!(build_grant(&account(2), &account(1), &side(2, 10), &side(2, 5), &intent(1)).is_err());
        assert!(build_grant(&account(2), &account(2), &side(2, 10), &side(1, 5), &intent(1)).is_err());
    }
}
