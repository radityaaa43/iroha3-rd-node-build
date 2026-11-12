//! `POST /transfer` and `rd-dfabi transfer`: ONE native `Transfer` of RD or DFABI from the config's OWN account to another
//! account, signed by the own client.toml key (iroha3 live scenario "transfer RD/DFABI antar bank", user 2026-11-12).
//!
//! Body `{to, asset, amount}` (the `/mint` shape). Only the two configured assets move here; the chain still checks the
//! balance. The source is the own balance as a Global id: core resolves it, and the destination, into the execution
//! dataspace that the router picks from the asset definition (iroha@071e281e isi/asset.rs execute_user_numeric_asset_transfer).

use std::str::FromStr;

use eyre::{Result, ensure, eyre};
use iroha::data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    isi::{InstructionBox, Transfer},
};

use crate::{config::Config, dvp_native, mint::MintTerms};

/// The assets that may move here: the config's RD and DFABI.
pub fn allowed(cfg: &Config) -> Result<Vec<AssetDefinitionId>> {
    [&cfg.assets.rd, &cfg.assets.dfabi].iter().map(|id| AssetDefinitionId::from_str(id).map_err(|e| eyre!("config asset {id:?}: {e}"))).collect()
}

/// Validate the terms without any key or chain access (the server answers 400 on failure).
pub fn check_transfer(terms: &MintTerms, allowed: &[AssetDefinitionId]) -> Result<(AccountId, AssetDefinitionId, u128)> {
    let to = dvp_native::parse_account(&terms.to)?;
    let amount = dvp_native::parse_amount(&terms.amount)?;
    let asset = AssetDefinitionId::from_str(&terms.asset).map_err(|e| eyre!("asset {:?}: {e}", terms.asset))?;
    ensure!(allowed.contains(&asset), "asset {:?} cannot be transferred here (RD and DFABI only)", terms.asset);
    Ok((to, asset, amount))
}

/// The one instruction: move `amount` of the own `asset` balance to `to`.
pub fn build_transfer(own: &AccountId, to: &AccountId, asset: &AssetDefinitionId, amount: u128) -> Result<InstructionBox> {
    ensure!(own != to, "the destination must differ from the own account");
    Ok(Transfer::asset_quantity(AssetId::new(asset.clone(), own.clone()), amount, to.clone()).into())
}

/// Check, sign with the own key, pay the bounded fee, wait for `Applied`; return the transaction hash.
pub fn transfer(cfg: &Config, terms: &MintTerms) -> Result<String> {
    let (to, asset, amount) = check_transfer(terms, &allowed(cfg)?)?;
    let (client, own) = dvp_native::own_client(cfg)?;
    dvp_native::submit(cfg, &client, build_transfer(&own, &to, &asset, amount)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::signing_key;

    fn asset(n: u8) -> AssetDefinitionId {
        AssetDefinitionId::from_uuid_bytes([n, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    fn account(seed: u8) -> AccountId {
        AccountId::new(signing_key(&[seed; 32]).public_key().clone())
    }

    fn terms(to: u8, asset_n: u8, amount: &str) -> MintTerms {
        MintTerms { to: signing_key(&[to; 32]).public_key().to_string(), asset: asset(asset_n).to_string(), amount: amount.to_owned() }
    }

    #[test]
    fn a_configured_asset_with_a_plain_positive_amount_is_accepted() {
        assert_eq!(check_transfer(&terms(2, 1, "7"), &[asset(1), asset(2)]).unwrap(), (account(2), asset(1), 7));
        assert_eq!(check_transfer(&terms(2, 2, "7"), &[asset(1), asset(2)]).unwrap().1, asset(2));
    }

    #[test]
    fn another_asset_a_zero_or_garbage_amount_and_a_bad_key_are_refused() {
        let allowed = [asset(1), asset(2)];
        for bad in [terms(2, 3, "7"), terms(2, 1, "0"), terms(2, 1, "-7"), terms(2, 1, "1.5"), MintTerms { to: "x".to_owned(), ..terms(2, 1, "7") }] {
            assert!(check_transfer(&bad, &allowed).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_instruction_moves_the_own_balance_to_the_destination() {
        let (own, to) = (account(1), account(2));
        assert_eq!(
            build_transfer(&own, &to, &asset(1), 7).unwrap(),
            InstructionBox::from(Transfer::asset_quantity(AssetId::new(asset(1), own), 7u128, to))
        );
    }

    #[test]
    fn a_transfer_to_the_own_account_is_refused() {
        assert!(build_transfer(&account(1), &account(1), &asset(1), 7).is_err());
    }
}
