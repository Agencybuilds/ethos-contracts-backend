use alloc::vec::Vec as StdVec;
use core::num::NonZeroU128;
use soroban_sdk::{contracttype, symbol_short, Address, Env, Map};

pub const RANKING_SET_TOPIC: soroban_sdk::Symbol = symbol_short!("rank_set");
pub const DISTRIBUTED_BY_RANK_TOPIC: soroban_sdk::Symbol = symbol_short!("dist_rank");

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RankedBeneficiary {
    pub address: Address,
    pub priority: u32,
    pub allocation_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct RankingSetEvent {
    pub beneficiary: Address,
    pub priority: u32,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct DistributedByRankEvent {
    pub beneficiary: Address,
    pub priority: u32,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone)]
pub enum RankingKey {
    BeneficiaryRanks,
    /// `true` when the cached rank positions may be out of date and must be
    /// recomputed on the next `get_rank` call.
    RankStale,
    /// Cached 1-based rank position for a beneficiary (1 == highest priority).
    CachedRank(Address),
}

pub fn set_rank(env: &Env, caller: &Address, beneficiary: Address, priority: u32) {
    caller.require_auth();

    let mut ranks: Map<Address, RankedBeneficiary> = env
        .storage()
        .persistent()
        .get(&RankingKey::BeneficiaryRanks)
        .unwrap_or_else(|| Map::new(env));

    let allocation_bps = ranks
        .get(beneficiary.clone())
        .map_or(10_000, |b| b.allocation_bps);

    ranks.set(
        beneficiary.clone(),
        RankedBeneficiary {
            address: beneficiary.clone(),
            priority,
            allocation_bps,
        },
    );
    env.storage()
        .persistent()
        .set(&RankingKey::BeneficiaryRanks, &ranks);

    // A priority change reorders the field — cached ranks are now stale.
    invalidate_ranks(env);

    env.events().publish(
        (RANKING_SET_TOPIC,),
        RankingSetEvent {
            beneficiary,
            priority,
        },
    );
}

/// Mark the cached rank positions as stale.
///
/// Call this from any path whose output feeds ranking (e.g. recording a slice
/// performance sample) so the next [`get_rank`] recomputes instead of returning
/// a stale position.
pub fn invalidate_ranks(env: &Env) {
    env.storage()
        .persistent()
        .set(&RankingKey::RankStale, &true);
}

/// `true` when the cached rank positions are stale.
pub fn ranks_are_stale(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&RankingKey::RankStale)
        .unwrap_or(false)
}

/// Sort beneficiaries in-place by ascending `priority` using an infallible,
/// stable binary-insertion sort over bounded checked slices.
///
/// Equal priorities preserve their input order, every slice access is
/// bounds-checked, and sorting uses no scratch buffer (avoiding `driftsort`
/// WASM code-size bloat in `opt-level = "z"` builds).
fn sort_by_priority_infallible(items: &mut [RankedBeneficiary]) {
    for pass in 1..items.len() {
        let Some(key_priority) = items.get(pass).map(|entry| entry.priority) else {
            break;
        };
        let Some(sorted_prefix) = items.get(..pass) else {
            break;
        };
        if sorted_prefix
            .last()
            .is_none_or(|last| last.priority <= key_priority)
        {
            continue;
        }
        let insert_at = sorted_prefix.partition_point(|entry| entry.priority <= key_priority);
        if let Some(window) = items.get_mut(insert_at..=pass) {
            window.rotate_right(1);
        }
    }
}

/// Load all ranked beneficiaries from `ranks` via `Map::values()` (skipping
/// unused `Address` key decoding) and sort them in guest memory by ascending
/// `priority` (ties broken by `Map` iteration order).
fn load_sorted_ranks_from_map(
    ranks: &Map<Address, RankedBeneficiary>,
) -> StdVec<RankedBeneficiary> {
    let mut ordered: StdVec<RankedBeneficiary> = ranks.values().iter().collect();
    sort_by_priority_infallible(&mut ordered);
    ordered
}

/// Compute `min(remaining, floor(remaining * weight / total_weight))` without
/// intermediate `i128` multiplication overflow.
fn proportional_share(remaining: i128, weight: u32, total_weight: u64) -> i128 {
    let Some(divisor) = NonZeroU128::new(u128::from(total_weight)) else {
        return 0;
    };
    if remaining <= 0 || weight == 0 {
        return 0;
    }

    let weight_u128 = u128::from(weight);
    if weight_u128 >= divisor.get() {
        return remaining;
    }

    let rem_u128 = remaining as u128;
    let share = if let Some(product) = rem_u128.checked_mul(weight_u128) {
        product / divisor
    } else {
        // `remainder < total_weight <= u64::MAX` and `weight <= u32::MAX`,
        // so `remainder * weight < 2^96 < u128::MAX` cannot overflow.
        let quotient = rem_u128 / divisor;
        let remainder = rem_u128 % divisor;
        quotient
            .saturating_mul(weight_u128)
            .saturating_add(remainder.saturating_mul(weight_u128) / divisor)
    };
    i128::try_from(share).unwrap_or(remaining)
}

/// Recompute and cache the 1-based rank position of every ranked beneficiary,
/// ordered by ascending `priority` (ties broken by map iteration order), then
/// clear the stale flag.
pub fn recompute_ranks(env: &Env) {
    if let Some(ranks) = env
        .storage()
        .persistent()
        .get::<RankingKey, Map<Address, RankedBeneficiary>>(&RankingKey::BeneficiaryRanks)
    {
        for (position, beneficiary) in (1u32..).zip(load_sorted_ranks_from_map(&ranks)) {
            env.storage()
                .persistent()
                .set(&RankingKey::CachedRank(beneficiary.address), &position);
        }
    }

    env.storage()
        .persistent()
        .set(&RankingKey::RankStale, &false);
}

/// Return the cached 1-based rank position for `beneficiary`.
///
/// If the cache is stale, all ranks are recomputed first (lazy recomputation).
/// Returns `None` when the beneficiary has no ranking entry.
pub fn get_rank(env: &Env, beneficiary: &Address) -> Option<u32> {
    if ranks_are_stale(env) {
        recompute_ranks(env);
    }
    env.storage()
        .persistent()
        .get(&RankingKey::CachedRank(beneficiary.clone()))
}

/// Distribute `remaining` proportionally to `allocation_bps` across a single
/// equal-priority tier, returning the undistributed remainder.
///
/// `tier_remaining_bps` is decremented alongside `remaining` as each
/// beneficiary is paid so the applied ratio stays consistent without
/// compounding shrinkage.
fn pay_tier(
    env: &Env,
    tier: &[RankedBeneficiary],
    total_bps: u64,
    mut remaining: i128,
    distributions: &mut Map<Address, i128>,
) -> i128 {
    let mut tier_remaining_bps = total_bps;
    for beneficiary in tier {
        if remaining <= 0 {
            break;
        }
        let amount = proportional_share(remaining, beneficiary.allocation_bps, tier_remaining_bps);
        distributions.set(beneficiary.address.clone(), amount);
        remaining = remaining.saturating_sub(amount);
        tier_remaining_bps =
            tier_remaining_bps.saturating_sub(u64::from(beneficiary.allocation_bps));
        env.events().publish(
            (DISTRIBUTED_BY_RANK_TOPIC,),
            DistributedByRankEvent {
                beneficiary: beneficiary.address.clone(),
                priority: beneficiary.priority,
                amount,
            },
        );
    }
    remaining
}

pub fn distribute_by_rank(env: &Env, total_amount: i128) -> Map<Address, i128> {
    let mut distributions = Map::new(env);
    if total_amount <= 0 {
        return distributions;
    }

    let Some(ranks) = env
        .storage()
        .persistent()
        .get::<RankingKey, Map<Address, RankedBeneficiary>>(&RankingKey::BeneficiaryRanks)
    else {
        return distributions;
    };

    let ordered = load_sorted_ranks_from_map(&ranks);
    let mut remaining = total_amount;

    for tier in ordered.chunk_by(|left, right| left.priority == right.priority) {
        if remaining <= 0 {
            break;
        }
        let total_bps = tier.iter().fold(0u64, |acc, beneficiary| {
            acc.saturating_add(u64::from(beneficiary.allocation_bps))
        });
        remaining = pay_tier(env, tier, total_bps, remaining, &mut distributions);
    }

    distributions
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, IntoVal, TryIntoVal, Val, Vec,
    };

    fn distributed_events(env: &Env) -> StdVec<DistributedByRankEvent> {
        env.events()
            .all()
            .iter()
            .filter_map(|event| {
                let topics: Vec<Val> = event.1.clone().into_val(env);
                let is_dist = topics
                    .get(0)
                    .and_then(|topic| topic.try_into_val(env).ok())
                    .is_some_and(|topic: soroban_sdk::Symbol| topic == DISTRIBUTED_BY_RANK_TOPIC);
                if is_dist {
                    event.2.try_into_val(env).ok()
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn higher_priority_receives_before_lower_priority() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 1));
        env.as_contract(&contract_id, || set_rank(&env, &admin, bob.clone(), 2));
        let result = env.as_contract(&contract_id, || distribute_by_rank(&env, 500));

        assert_eq!(result.get(alice.clone()), Some(500));
        assert_eq!(result.get(bob).unwrap_or(0), 0);

        let events = distributed_events(&env);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events
                .first()
                .map(|e| (&e.beneficiary, e.priority, e.amount)),
            Some((&alice, 1, 500))
        );
    }

    #[test]
    fn same_priority_splits_by_allocation_bps() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 1));
        env.as_contract(&contract_id, || set_rank(&env, &admin, bob.clone(), 1));
        let result = env.as_contract(&contract_id, || distribute_by_rank(&env, 1_000));

        assert_eq!(result.get(alice), Some(500));
        assert_eq!(result.get(bob), Some(500));
    }

    #[test]
    fn empty_and_single_beneficiary_do_not_panic() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);

        env.as_contract(&contract_id, || {
            recompute_ranks(&env);
            assert!(!ranks_are_stale(&env));
            assert!(distribute_by_rank(&env, 1_000).is_empty());
        });

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 7));
        env.as_contract(&contract_id, || {
            assert_eq!(get_rank(&env, &alice), Some(1));
            assert_eq!(distribute_by_rank(&env, 777).get(alice), Some(777));
        });
    }

    #[test]
    fn non_positive_amount_returns_empty_distribution() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 1));
        env.as_contract(&contract_id, || {
            assert!(distribute_by_rank(&env, 0).is_empty());
            assert!(distribute_by_rank(&env, -500).is_empty());
        });
    }

    #[test]
    fn recompute_ranks_handles_reverse_and_extreme_priorities() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let p_max = Address::generate(&env);
        let p_mid_a = Address::generate(&env);
        let p_mid_b = Address::generate(&env);
        let p_zero = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_rank(&env, &admin, p_max.clone(), u32::MAX);
        });
        env.as_contract(&contract_id, || {
            set_rank(&env, &admin, p_mid_a.clone(), 10);
        });
        env.as_contract(&contract_id, || {
            set_rank(&env, &admin, p_mid_b.clone(), 10);
        });
        env.as_contract(&contract_id, || set_rank(&env, &admin, p_zero.clone(), 0));

        env.as_contract(&contract_id, || {
            assert_eq!(get_rank(&env, &p_zero), Some(1));
            // Equal priorities break ties by Map (Address) key order.
            let r_a = get_rank(&env, &p_mid_a);
            let r_b = get_rank(&env, &p_mid_b);
            assert!(matches!(
                (r_a, r_b),
                (Some(2), Some(3)) | (Some(3), Some(2))
            ));
            assert_eq!(get_rank(&env, &p_max), Some(4));
        });
    }

    #[test]
    fn zero_bps_tiers_advance_to_next_funded_tier() {
        let env = Env::default();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let z1 = Address::generate(&env);
        let z2 = Address::generate(&env);
        let p3_a = Address::generate(&env);
        let p3_b = Address::generate(&env);
        let p4 = Address::generate(&env);

        env.as_contract(&contract_id, || {
            let mut ranks: Map<Address, RankedBeneficiary> = Map::new(&env);
            for (addr, priority, allocation_bps) in [
                (p4.clone(), 40, 10_000),
                (z2.clone(), 20, 0),
                (p3_a.clone(), 30, 3_000),
                (z1.clone(), 10, 0),
                (p3_b.clone(), 30, 7_000),
            ] {
                ranks.set(
                    addr.clone(),
                    RankedBeneficiary {
                        address: addr,
                        priority,
                        allocation_bps,
                    },
                );
            }
            env.storage()
                .persistent()
                .set(&RankingKey::BeneficiaryRanks, &ranks);

            let dist = distribute_by_rank(&env, 1_000);
            assert_eq!(dist.get(z1), Some(0));
            assert_eq!(dist.get(z2), Some(0));
            assert_eq!(dist.get(p3_a), Some(300));
            assert_eq!(dist.get(p3_b), Some(700));
            assert_eq!(dist.get(p4), None);
        });
    }

    #[test]
    fn large_amount_distribution_does_not_overflow() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 1));
        env.as_contract(&contract_id, || set_rank(&env, &admin, bob.clone(), 1));

        for huge in [i128::MAX / 2, i128::MAX] {
            let dist = env.as_contract(&contract_id, || distribute_by_rank(&env, huge));
            let share_a = dist.get(alice.clone()).unwrap_or(0);
            let share_b = dist.get(bob.clone()).unwrap_or(0);
            assert_eq!(share_a.checked_add(share_b), Some(huge));
            assert_eq!(share_a, huge / 2);
            assert_eq!(share_b, huge - huge / 2);
        }
    }

    #[test]
    fn infallible_sort_matches_reference_stable_sort() {
        let env = Env::default();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;

        for len in 0usize..=64 {
            let mut input = StdVec::with_capacity(len);
            for idx in 0..len {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let priority = ((seed >> 32) as u32) % 7;
                input.push(RankedBeneficiary {
                    address: Address::generate(&env),
                    priority,
                    allocation_bps: (idx as u32) + 1,
                });
            }

            let mut expected = input.clone();
            expected.sort_by_key(|entry| entry.priority);

            let mut actual = input;
            sort_by_priority_infallible(&mut actual);

            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn proportional_share_handles_edge_and_overflow_inputs() {
        assert_eq!(proportional_share(0, 5_000, 10_000), 0);
        assert_eq!(proportional_share(-100, 5_000, 10_000), 0);
        assert_eq!(proportional_share(1_000, 0, 10_000), 0);
        assert_eq!(proportional_share(1_000, 5_000, 0), 0);
        assert_eq!(proportional_share(1_234, 10_000, 10_000), 1_234);
        assert_eq!(proportional_share(1_000, 3_333, 10_000), 333);
        assert_eq!(proportional_share(i128::MAX, 5_000, 10_000), i128::MAX / 2);
        // floor((2^127 - 1) * (2^32 - 1) / (2^64 - 1)) via quotient/remainder path:
        // (2^127 - 1) / (2^64 - 1) = 2^63, rem = 2^63 - 1;
        // 2^63 * (2^32 - 1) + floor((2^63 - 1) * (2^32 - 1) / (2^64 - 1))
        let q = (i128::MAX as u128) / u128::from(u64::MAX);
        let r = (i128::MAX as u128) % u128::from(u64::MAX);
        let expected = q * u128::from(u32::MAX) + (r * u128::from(u32::MAX)) / u128::from(u64::MAX);
        assert_eq!(
            Ok(proportional_share(i128::MAX, u32::MAX, u64::MAX)),
            i128::try_from(expected)
        );
    }

    #[test]
    fn get_rank_returns_none_for_unranked_beneficiary() {
        let env = Env::default();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let stranger = Address::generate(&env);
        env.as_contract(&contract_id, || {
            assert_eq!(get_rank(&env, &stranger), None);
        });
    }

    #[test]
    fn invalidate_ranks_sets_the_stale_flag() {
        let env = Env::default();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        env.as_contract(&contract_id, || {
            assert!(!ranks_are_stale(&env));
            invalidate_ranks(&env);
            assert!(ranks_are_stale(&env));
        });
    }

    #[test]
    fn get_rank_recomputes_lazily_when_stale() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 5));
        env.as_contract(&contract_id, || set_rank(&env, &admin, bob.clone(), 10));

        // set_rank left the cache stale; the first get_rank recomputes it.
        env.as_contract(&contract_id, || {
            assert!(ranks_are_stale(&env));
            assert_eq!(get_rank(&env, &alice), Some(1));
            assert_eq!(get_rank(&env, &bob), Some(2));
            assert!(!ranks_are_stale(&env));
        });

        // Reordering bob ahead of alice must invalidate and reflect on next read.
        env.as_contract(&contract_id, || set_rank(&env, &admin, bob.clone(), 1));
        env.as_contract(&contract_id, || {
            assert!(ranks_are_stale(&env));
            assert_eq!(get_rank(&env, &bob), Some(1));
            assert_eq!(get_rank(&env, &alice), Some(2));
        });
    }

    #[test]
    fn recording_slice_performance_invalidates_cached_rank() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let attestor = Address::generate(&env);

        env.as_contract(&contract_id, || set_rank(&env, &admin, alice.clone(), 1));
        env.as_contract(&contract_id, || {
            let _ = get_rank(&env, &alice);
            assert!(!ranks_are_stale(&env));
        });

        env.as_contract(&contract_id, || {
            crate::slice_performance::record_attestor_performance(&env, 1, &attestor, true, 100);
            assert!(ranks_are_stale(&env));
        });
    }

    #[test]
    fn ranking_set_event_is_emitted() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, crate::TtlVaultContract);
        let admin = Address::generate(&env);
        let alice = Address::generate(&env);

        env.as_contract(&contract_id, || {
            set_rank(&env, &admin, alice, 1);
        });

        assert!(env.events().all().iter().any(|event| {
            let topics: Vec<Val> = event.1.clone().into_val(&env);
            topics
                .get(0)
                .and_then(|topic| topic.try_into_val(&env).ok())
                .is_some_and(|topic: soroban_sdk::Symbol| topic == RANKING_SET_TOPIC)
        }));
    }
}
