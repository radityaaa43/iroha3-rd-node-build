//! Bundle planner (spec 4.3): which two of the four pools a submit uses, chosen from per-pool capacities.
//!
//! A bundle has one leg per dataspace lane, sorted by lane (leg 0 = the lowest lane, its payer also pays the sponsor's
//! reimbursement `R`). A one-asset payment X is a main leg in one lane plus a BI -> BI companion of 1 X in the other lane (the
//! same asset, so the pool pair does not tell RD from DFABI); its lane is random among the lanes that cover it, except issuance,
//! which goes to the pool where the recipient holds less. When no single pool of the payer covers the amount, the payment is
//! split into two legs payer -> recipient, one per lane. A DvP puts its RD leg in a random covering lane, DFABI in the other.

use rand::{Rng, seq::IndexedRandom};
use serde::{Deserialize, Serialize};

use crate::{
    aps::SPONSOR_REIMBURSEMENT as R,
    pools::{Asset, PoolKey},
};

/// The whole 422 message: no amounts, no parties (it reaches Lensa and the logs).
pub const NO_ARRANGEMENT: &str = "no pool arrangement covers the payment";

/// A submit, as `POST /aps/submit` carries it (accounts are `ed0120...` keys).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Pay { asset: Asset, from: String, to: String, amount: u128, intent: String },
    Dvp { buyer: String, seller: String, rd: u128, dfabi: u128, intent_rd: String, intent_dfabi: String },
}

/// What one party can spend from one pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    /// The largest amount one leg can spend: `wallet::pick_notes` takes one or two notes strictly greater than the amount (the
    /// change output), so (the two largest unspent notes, or the only one) - 1; 0 without notes.
    pub two_notes: u128,
    /// All unspent notes.
    pub total: u128,
}

impl Capacity {
    /// From the values of the unspent notes in one pool.
    pub fn of(values: &[u128]) -> Self {
        let mut sorted = values.to_vec();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let top: u128 = sorted.iter().take(2).sum();
        Self { two_notes: top.saturating_sub(1), total: values.iter().sum() }
    }
}

/// One leg of the planned bundle. `None` payer/recipient = the coordinator BI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLeg {
    pub key: PoolKey,
    pub payer: Option<String>,
    pub recipient: Option<String>,
    pub amount: u128,
    /// `None` only for the companion leg, which BI pays itself.
    pub intent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// HTTP 422; the text is `NO_ARRANGEMENT`.
    Insufficient(String),
}

/// Plan the two legs of `req`. `bi` is the coordinator's account (it becomes `None`); `lanes` the two dataspace lanes, ascending;
/// `cap(party, pool)` what `party` (`None` = BI) can spend there. Legs come back sorted by lane.
pub fn plan(
    req: &Request,
    bi: &str,
    lanes: [u32; 2],
    cap: &dyn Fn(Option<&str>, PoolKey) -> Capacity,
    rng: &mut impl Rng,
) -> Result<[PlannedLeg; 2], PlanError> {
    let party = |key: &str| (!key.eq_ignore_ascii_case(bi)).then(|| key.to_owned());
    // The payer of leg 0 (the lowest lane) also pays the sponsor's reimbursement.
    let need = |amount: u128, lane: u32| amount.saturating_add(if lane == lanes[0] { R } else { 0 });
    let other = |lane: u32| if lane == lanes[0] { lanes[1] } else { lanes[0] };
    let insufficient = || PlanError::Insufficient(NO_ARRANGEMENT.to_owned());
    let mut legs = match req {
        Request::Pay { asset, from, to, amount, intent } => {
            let (payer, recipient, a) = (party(from), party(to), *amount);
            let at = |lane: u32| PoolKey { lane, asset: *asset };
            let main = |lane: u32, amount: u128| PlannedLeg {
                key: at(lane),
                payer: payer.clone(),
                recipient: recipient.clone(),
                amount,
                intent: Some(intent.clone()),
            };
            let feasible: Vec<u32> = lanes
                .into_iter()
                .filter(|&l| cap(payer.as_deref(), at(l)).two_notes >= need(a, l) && cap(None, at(other(l))).two_notes >= need(1, other(l)))
                .collect();
            let chosen = if payer.is_none() {
                // Issuance keeps each bank about 50/50 per lane: the pool where the recipient holds less.
                let held = |l: u32| cap(recipient.as_deref(), at(l)).total;
                let least = feasible.iter().map(|&l| held(l)).min();
                let ties: Vec<u32> = feasible.iter().copied().filter(|&l| Some(held(l)) == least).collect();
                ties.choose(rng).copied()
            } else {
                feasible.choose(rng).copied()
            };
            match chosen {
                Some(l) => {
                    let companion = PlannedLeg { key: at(other(l)), payer: None, recipient: None, amount: 1, intent: None };
                    [main(l, a), companion]
                }
                None => {
                    // Split: as much as leg 0 can carry next to the reimbursement, the rest in the other lane.
                    let a1 = cap(payer.as_deref(), at(lanes[0])).two_notes.saturating_sub(R).min(a.saturating_sub(1));
                    let a2 = a - a1;
                    if a1 < 1 || a2 > cap(payer.as_deref(), at(lanes[1])).two_notes {
                        return Err(insufficient());
                    }
                    [main(lanes[0], a1), main(lanes[1], a2)]
                }
            }
        }
        Request::Dvp { buyer, seller, rd, dfabi, intent_rd, intent_dfabi } => {
            let (buyer, seller) = (party(buyer), party(seller));
            let rd_at = |lane: u32| PoolKey { lane, asset: Asset::Rd };
            let dfabi_at = |lane: u32| PoolKey { lane, asset: Asset::Dfabi };
            let feasible: Vec<u32> = lanes
                .into_iter()
                .filter(|&l| {
                    cap(buyer.as_deref(), rd_at(l)).two_notes >= need(*rd, l)
                        && cap(seller.as_deref(), dfabi_at(other(l))).two_notes >= need(*dfabi, other(l))
                })
                .collect();
            let l = *feasible.choose(rng).ok_or_else(insufficient)?;
            [
                PlannedLeg { key: rd_at(l), payer: buyer.clone(), recipient: seller.clone(), amount: *rd, intent: Some(intent_rd.clone()) },
                PlannedLeg { key: dfabi_at(other(l)), payer: seller, recipient: buyer, amount: *dfabi, intent: Some(intent_dfabi.clone()) },
            ]
        }
    };
    legs.sort_by_key(|leg| leg.key.lane);
    Ok(legs)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use super::*;

    const BI: &str = "ed0120b1";
    const P: &str = "ed0120aa";
    const Q: &str = "ed0120bb";

    fn rng(seed: u64) -> rand::rngs::StdRng {
        rand::SeedableRng::seed_from_u64(seed)
    }

    fn key(lane: u32, asset: Asset) -> PoolKey {
        PoolKey { lane, asset }
    }

    /// `(party, lane, asset, two_notes, total)`; `None` = BI; anything not listed is empty.
    fn caps(rows: &[(Option<&str>, u32, Asset, u128, u128)]) -> impl Fn(Option<&str>, PoolKey) -> Capacity {
        let table: HashMap<(Option<String>, PoolKey), Capacity> = rows
            .iter()
            .map(|(who, lane, asset, two_notes, total)| ((who.map(str::to_owned), key(*lane, *asset)), Capacity { two_notes: *two_notes, total: *total }))
            .collect();
        move |who: Option<&str>, at: PoolKey| table.get(&(who.map(str::to_owned), at)).copied().unwrap_or_default()
    }

    fn pay(asset: Asset, from: &str, to: &str, amount: u128) -> Request {
        Request::Pay { asset, from: from.into(), to: to.into(), amount, intent: "i".into() }
    }

    fn dvp(rd: u128, dfabi: u128) -> Request {
        Request::Dvp { buyer: P.into(), seller: Q.into(), rd, dfabi, intent_rd: "ir".into(), intent_dfabi: "id".into() }
    }

    fn leg(lane: u32, asset: Asset, payer: Option<&str>, recipient: Option<&str>, amount: u128, intent: Option<&str>) -> PlannedLeg {
        PlannedLeg { key: key(lane, asset), payer: payer.map(Into::into), recipient: recipient.map(Into::into), amount, intent: intent.map(Into::into) }
    }

    #[test]
    fn capacity_is_the_two_largest_notes_minus_one() {
        assert_eq!(Capacity::of(&[]), Capacity { two_notes: 0, total: 0 });
        assert_eq!(Capacity::of(&[7]), Capacity { two_notes: 6, total: 7 });
        assert_eq!(Capacity::of(&[3, 9, 5]), Capacity { two_notes: 13, total: 17 });
    }

    #[test]
    fn single_leg_with_same_asset_companion() {
        // P can pay only from lane 2: the companion (BI -> BI 1, same asset) takes lane 1 and, as leg 0, BI pays the reimbursement.
        let cap = caps(&[(Some(P), 2, Asset::Dfabi, 5, 5), (None, 1, Asset::Dfabi, 2, 2), (None, 2, Asset::Dfabi, 100, 100)]);
        let legs = plan(&pay(Asset::Dfabi, P, Q, 5), BI, [1, 2], &cap, &mut rng(1)).unwrap();
        assert_eq!(legs, [leg(1, Asset::Dfabi, None, None, 1, None), leg(2, Asset::Dfabi, Some(P), Some(Q), 5, Some("i"))]);
        // the other way round: P only in lane 1 (needs 5 + 1), the companion in lane 2
        let cap = caps(&[(Some(P), 1, Asset::Rd, 6, 6), (None, 2, Asset::Rd, 1, 1)]);
        let legs = plan(&pay(Asset::Rd, P, Q, 5), BI, [1, 2], &cap, &mut rng(1)).unwrap();
        assert_eq!(legs, [leg(1, Asset::Rd, Some(P), Some(Q), 5, Some("i")), leg(2, Asset::Rd, None, None, 1, None)]);
        // a companion in lane 1 needs 1 + 1 of BI
        let cap = caps(&[(Some(P), 2, Asset::Rd, 50, 50), (None, 1, Asset::Rd, 1, 1)]);
        assert!(plan(&pay(Asset::Rd, P, Q, 5), BI, [1, 2], &cap, &mut rng(1)).is_err());
    }

    #[test]
    fn issuance_prefers_recipients_smaller_pool() {
        let cap = caps(&[
            (None, 1, Asset::Rd, 1000, 1000),
            (None, 2, Asset::Rd, 1000, 1000),
            (Some(Q), 1, Asset::Rd, 49, 50),
            (Some(Q), 2, Asset::Rd, 9, 10),
        ]);
        for seed in 0..16 {
            let legs = plan(&pay(Asset::Rd, BI, Q, 5), BI, [1, 2], &cap, &mut rng(seed)).unwrap();
            assert_eq!(legs, [leg(1, Asset::Rd, None, None, 1, None), leg(2, Asset::Rd, None, Some(Q), 5, Some("i"))], "seed {seed}");
        }
    }

    #[test]
    fn split_when_no_single_pool_covers() {
        let cap = caps(&[(Some(P), 1, Asset::Rd, 6, 6), (Some(P), 2, Asset::Rd, 5, 5), (None, 1, Asset::Rd, 100, 100), (None, 2, Asset::Rd, 100, 100)]);
        let legs = plan(&pay(Asset::Rd, P, Q, 9), BI, [1, 2], &cap, &mut rng(1)).unwrap();
        assert_eq!(legs, [leg(1, Asset::Rd, Some(P), Some(Q), 5, Some("i")), leg(2, Asset::Rd, Some(P), Some(Q), 4, Some("i"))]);
        // one more and the two pools no longer cover it
        assert!(plan(&pay(Asset::Rd, P, Q, 11), BI, [1, 2], &cap, &mut rng(1)).is_err());
    }

    #[test]
    fn reimbursement_follows_leg0_asset() {
        // A DFABI pay forced onto lane 1: leg 0 is DFABI and its payer needs the amount plus 1 DFABI.
        let enough = caps(&[(Some(P), 1, Asset::Dfabi, 8, 8), (None, 2, Asset::Dfabi, 1, 1)]);
        let legs = plan(&pay(Asset::Dfabi, P, Q, 7), BI, [1, 2], &enough, &mut rng(1)).unwrap();
        assert_eq!(legs[0], leg(1, Asset::Dfabi, Some(P), Some(Q), 7, Some("i")));
        let short = caps(&[(Some(P), 1, Asset::Dfabi, 7, 7), (None, 2, Asset::Dfabi, 1, 1)]);
        assert!(plan(&pay(Asset::Dfabi, P, Q, 7), BI, [1, 2], &short, &mut rng(1)).is_err());
    }

    #[test]
    fn dvp_picks_only_feasible_arrangement() {
        // RD only in lane 2 for the buyer, DFABI only in lane 1 for the seller (leg 0: the seller pays 7 + 1).
        let cap = caps(&[(Some(P), 2, Asset::Rd, 5, 5), (Some(P), 1, Asset::Rd, 100, 100), (Some(Q), 1, Asset::Dfabi, 8, 8)]);
        for seed in 0..16 {
            let legs = plan(&dvp(5, 7), BI, [1, 2], &cap, &mut rng(seed)).unwrap();
            assert_eq!(legs, [leg(1, Asset::Dfabi, Some(Q), Some(P), 7, Some("id")), leg(2, Asset::Rd, Some(P), Some(Q), 5, Some("ir"))], "seed {seed}");
        }
        let short = caps(&[(Some(P), 2, Asset::Rd, 5, 5), (Some(Q), 1, Asset::Dfabi, 7, 7)]);
        assert!(plan(&dvp(5, 7), BI, [1, 2], &short, &mut rng(1)).is_err());
    }

    #[test]
    fn insufficient_names_no_amount() {
        let cap = caps(&[]);
        for req in [pay(Asset::Rd, P, Q, 987), pay(Asset::Dfabi, BI, Q, 987), dvp(987, 654)] {
            let PlanError::Insufficient(text) = plan(&req, BI, [1, 2], &cap, &mut rng(1)).unwrap_err();
            assert_eq!(text, NO_ARRANGEMENT);
            assert!(!text.bytes().any(|b| b.is_ascii_digit()), "{text}");
        }
    }

    #[test]
    fn placement_is_random() {
        let cap = caps(&[(Some(P), 1, Asset::Rd, 100, 100), (Some(P), 2, Asset::Rd, 100, 100), (None, 1, Asset::Rd, 100, 100), (None, 2, Asset::Rd, 100, 100)]);
        let mut main_lanes = BTreeSet::new();
        let mut rd_lanes = BTreeSet::new();
        let dvp_cap = caps(&[
            (Some(P), 1, Asset::Rd, 100, 100),
            (Some(P), 2, Asset::Rd, 100, 100),
            (Some(Q), 1, Asset::Dfabi, 100, 100),
            (Some(Q), 2, Asset::Dfabi, 100, 100),
        ]);
        for seed in 0..64 {
            let legs = plan(&pay(Asset::Rd, P, Q, 5), BI, [1, 2], &cap, &mut rng(seed)).unwrap();
            main_lanes.insert(legs.iter().find(|leg| leg.payer.is_some()).unwrap().key.lane);
            let legs = plan(&dvp(5, 7), BI, [1, 2], &dvp_cap, &mut rng(seed)).unwrap();
            rd_lanes.insert(legs.iter().find(|leg| leg.key.asset == Asset::Rd).unwrap().key.lane);
        }
        assert_eq!(main_lanes, BTreeSet::from([1, 2]));
        assert_eq!(rd_lanes, BTreeSet::from([1, 2]));
    }
}
