//! Weighted traffic split / canary (ADR 000034): a route forwards not to one upstream but to a
//! weighted set of backends, in proportion to integer weights (`weight / Σweights`, Gateway-API
//! semantics). This sits ONE layer above the per-instance load balancer: it picks which
//! [`UpstreamGroup`] a request goes to; the chosen group then picks a healthy instance with its
//! own round-robin (ADR 000017 / 000024) and applies its own retry / circuit-breaker / health.
//!
//! ## Selection algorithm — error-diffusion / Webster apportionment (maximum-deficit rule)
//!
//! We want the weighted sequence to be EVENLY INTERLEAVED (a 5/95 split should emit the minority
//! every ~20th request, not 5 in a row), deterministically. The classical technique for this is
//! *apportionment*: at each step credit every backend its weight as a running "deficit" (how far
//! below its fair share it is) and serve the one with the LARGEST deficit, then debit the total
//! weight from it. This is the Webster / Sainte-Laguë highest-averages method (the unique *unbiased*
//! divisor method — Balinski & Young, *Fair Representation*, 1982); for a single ratio it is exactly
//! integer error diffusion (Bresenham, 1965); and the resulting sequence minimises the worst-case
//! deviation from the ideal proportion (Tijdeman's chairman-assignment problem, 1980), staying
//! within `< 1` of every backend's ideal cumulative count at all times. (Proxy folklore calls the
//! same rule "smooth weighted round-robin"; we implement the cited apportionment technique, not any
//! one proxy's code.)
//!
//! ## Plecto's adaptation — precompute once, pick lock-free
//!
//! The naive rule needs a per-pick read-modify-write of shared deficits, which would put a lock on
//! the hot path — at odds with the lock-free tenet ADR 000024 went to lengths to preserve. Because
//! the rule is PERIODIC with period `L = Σ(gcd-reduced weights)` (after `L` picks each backend has
//! been served exactly its reduced weight and the deficits return to zero), one period IS the entire
//! infinite schedule. So we run the apportionment ONCE at build into a `table` of backend indices
//! and let a request just advance a single atomic cursor: `table[cursor.fetch_add(1) % L]`.
//!
//! A backend whose group has no eligible instance is **skipped forward** in the table to the next
//! eligible one (renormalize over healthy), exactly as `UpstreamGroup::pick_inner` skips an
//! unhealthy instance. When NO backend is eligible the pick is `None` and the fast path fails
//! closed 503 — the same no-healthy fault as a single upstream (ADR 000017 / 000024).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::manifest::MAX_BACKEND_WEIGHT;
use crate::upstream::UpstreamGroup;

/// Upper bound on the gcd-reduced schedule length (ADR 000034 5b). Typical canary ratios reduce
/// tiny ({5,95}→20); only pathological coprime large weights blow past this, and those are rejected
/// at build (fail-closed) with a message steering the operator to smaller proportional weights.
/// Bounds both the build-time table memory and the worst-case skip-forward scan.
pub(crate) const MAX_TABLE_LEN: usize = 65_536;

/// A route's weighted backend set, compiled (ADR 000034). The `groups` are the distinct backends
/// with a NON-ZERO weight (a `weight 0` backend is drained — excluded entirely); `table` is the
/// precomputed apportionment schedule (each entry an index into `groups`); `cursor` advances once
/// per pick. A single-upstream route compiles to a one-element set (weight 1), so the runtime has
/// one path.
#[derive(Debug)]
pub(crate) struct WeightedBackends {
    /// The distinct, non-drained backend groups, in manifest order.
    groups: Vec<Arc<UpstreamGroup>>,
    /// The apportionment pick order: each entry is an index into `groups`. Length is the gcd-reduced
    /// sum of weights (≤ [`MAX_TABLE_LEN`]). `u16` indices: a route never has 65k distinct backends.
    table: Box<[u16]>,
    /// Lock-free pick cursor — like `UpstreamGroup`'s `rr`, only advances; `Relaxed` suffices.
    cursor: AtomicUsize,
}

impl WeightedBackends {
    /// Compile a weighted backend set from `(group, weight)` pairs. Assumes the weights were already
    /// validated by [`validate_split`] in the pre-reconcile pass (so this is effectively infallible),
    /// but re-validates to stay self-contained and total (no panic on the data-plane build path).
    pub(crate) fn new(targets: Vec<(Arc<UpstreamGroup>, u32)>) -> Result<Self, String> {
        let weights: Vec<u32> = targets.iter().map(|(_, w)| *w).collect();
        validate_split(&weights)?;

        // Keep only non-zero-weight backends (weight 0 = drain) and reduce by their gcd so the
        // precomputed schedule is as short as the ratio allows ({5,95} → {1,19}, length 20).
        let groups: Vec<Arc<UpstreamGroup>> = targets
            .iter()
            .filter(|(_, w)| *w > 0)
            .map(|(g, _)| g.clone())
            .collect();
        let nonzero: Vec<u32> = weights.into_iter().filter(|&w| w > 0).collect();
        let divisor = nonzero.iter().copied().reduce(gcd).unwrap_or(1).max(1);
        let reduced: Vec<u32> = nonzero.iter().map(|&w| w / divisor).collect();

        Ok(Self {
            groups,
            table: weighted_schedule(&reduced),
            cursor: AtomicUsize::new(0),
        })
    }

    /// Pick the backend group for one request: the next in apportionment order whose group has an
    /// eligible instance, skipping forward past any with none (renormalize over healthy). `None`
    /// when no backend is eligible (the fast path then fails closed 503). Lock-free: one atomic
    /// `fetch_add` plus a read-only table scan and the lock-free `has_eligible` probe.
    pub(crate) fn pick(&self) -> Option<Arc<UpstreamGroup>> {
        // Fast-out of a full outage: if nothing is eligible, fail closed without scanning the
        // (possibly large) table. O(backends) — backends are few.
        if !self.groups.iter().any(|g| g.has_eligible()) {
            return None;
        }
        let len = self.table.len();
        // `new` guarantees a non-empty table (validated), but guard `% len` locally so the data-plane
        // no-panic property holds without depending on that invariant (CWE-369 defence-in-depth).
        if len == 0 {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
        // Skip forward over backends with no eligible instance; the early-out above proved one
        // exists, so this terminates with `Some`. Bounded by `len` regardless (data-plane no-panic).
        for off in 0..len {
            let backend = self.table[(start + off) % len] as usize;
            if self.groups[backend].has_eligible() {
                return Some(self.groups[backend].clone());
            }
        }
        None
    }
}

/// Validate a route's backend weights and return the gcd-reduced apportionment-schedule length (ADR
/// 000034 5b). Pure — needs no resolved groups — so it runs in the pre-reconcile validation pass,
/// keeping a bad split a build-time fail-closed rejection BEFORE the persistent upstream registry
/// is mutated (all-or-nothing reload). Rejects: empty backends, a weight over the cap, every
/// weight zero (the whole route drained), or a reduced schedule that exceeds [`MAX_TABLE_LEN`].
pub(crate) fn validate_split(weights: &[u32]) -> Result<usize, String> {
    if weights.is_empty() {
        return Err("a route has no backends".to_string());
    }
    if let Some(&w) = weights.iter().find(|&&w| w > MAX_BACKEND_WEIGHT) {
        return Err(format!(
            "backend weight {w} exceeds the maximum {MAX_BACKEND_WEIGHT}"
        ));
    }
    let divisor = weights.iter().copied().filter(|&w| w > 0).reduce(gcd);
    let Some(divisor) = divisor else {
        return Err("every backend weight is zero (the whole route is drained)".to_string());
    };
    let total: usize = weights.iter().map(|&w| (w / divisor) as usize).sum();
    if total > MAX_TABLE_LEN {
        return Err(format!(
            "reduced traffic-split table ({total}) exceeds {MAX_TABLE_LEN}; use smaller proportional weights"
        ));
    }
    Ok(total)
}

/// Greatest common divisor (Euclid). `gcd(x, 0) == x`, so reducing a single weight by itself yields
/// 1 (a one-element schedule).
fn gcd(a: u32, b: u32) -> u32 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Precompute the weighted pick order by running the Webster / Sainte-Laguë apportionment
/// (maximum-deficit error diffusion) for one full period (`Σweights` steps, weights already
/// gcd-reduced). Each step credits every backend its weight into a running `deficit` (how far below
/// its fair share it is), serves the index with the greatest deficit, and debits the total from it.
/// The result is the evenly-interleaved sequence with `< 1` deviation from each backend's ideal
/// count, and it returns to the zero state after one period — so this one period is the exact,
/// repeating schedule. `weights` is non-empty with a positive sum (validated upstream).
fn weighted_schedule(weights: &[u32]) -> Box<[u16]> {
    let total: i64 = weights.iter().map(|&w| w as i64).sum();
    let mut deficit = vec![0i64; weights.len()];
    let mut schedule: Vec<u16> = Vec::with_capacity(total as usize);
    for _ in 0..total {
        let mut best = 0usize;
        for i in 0..weights.len() {
            deficit[i] += weights[i] as i64;
            // Strictly-greater keeps the lowest index on a tie, for a reproducible table.
            if deficit[i] > deficit[best] {
                best = i;
            }
        }
        deficit[best] -= total;
        schedule.push(best as u16);
    }
    schedule.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        AddressSpec, CircuitBreaker, HealthConfig, LbAlgorithm, OutlierDetection, Upstream,
    };
    use crate::upstream::UpstreamRegistry;

    /// A live upstream group named `name` with one instance. The instance starts pessimistic
    /// (unhealthy); when `healthy` we promote it with a success probe so `has_eligible()` is true.
    fn group(name: &str, healthy: bool) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: name.to_string(),
            addresses: vec![AddressSpec::Bare("127.0.0.1:9000".to_string())],
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
            health: HealthConfig {
                path: "/healthz".to_string(),
                interval_ms: 1000,
                timeout_ms: 500,
                healthy_threshold: 1,
                unhealthy_threshold: 1,
            },
            request_timeout_ms: 30_000,
            max_retries: 1,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        let g = reg.group(name).unwrap();
        if healthy {
            g.instances[0].record_probe_success();
        }
        g
    }

    /// Distribution of `n` picks over the backends, by group name.
    fn distribution(w: &WeightedBackends, n: usize) -> std::collections::HashMap<String, usize> {
        let mut counts = std::collections::HashMap::new();
        for _ in 0..n {
            let g = w.pick().expect("a healthy backend exists");
            *counts.entry(g.name.clone()).or_insert(0) += 1;
        }
        counts
    }

    #[test]
    fn gcd_reduces_ratio() {
        assert_eq!(gcd(5, 95), 5);
        assert_eq!(gcd(95, 5), 5);
        assert_eq!(gcd(7, 0), 7);
        assert_eq!(gcd(50, 50), 50);
    }

    #[test]
    fn validate_split_rejects_degenerate_weights() {
        assert!(validate_split(&[]).is_err(), "no backends");
        assert!(
            validate_split(&[0, 0]).is_err(),
            "every weight zero is rejected"
        );
        assert!(
            validate_split(&[MAX_BACKEND_WEIGHT + 1]).is_err(),
            "over-cap weight is rejected"
        );
        // two coprime near-max weights blow past the reduced-table cap → rejected fail-closed.
        assert!(
            validate_split(&[999_983, 999_979]).is_err(),
            "a pathological coprime split is rejected by the table cap"
        );
        // a normal canary and a single upstream are fine, with the expected reduced lengths.
        assert_eq!(validate_split(&[5, 95]).unwrap(), 20);
        assert_eq!(validate_split(&[1]).unwrap(), 1);
        assert_eq!(
            validate_split(&[0, 7]).unwrap(),
            1,
            "a drained backend drops out"
        );
    }

    #[test]
    fn schedule_has_exact_per_item_counts() {
        // One apportionment period emits each backend exactly its reduced weight: {1,19} (a 5/95
        // canary reduced) → backend 0 once, backend 1 nineteen times, total length 20.
        let schedule = weighted_schedule(&[1, 19]);
        assert_eq!(schedule.len(), 20);
        assert_eq!(schedule.iter().filter(|&&b| b == 0).count(), 1);
        assert_eq!(schedule.iter().filter(|&&b| b == 1).count(), 19);
    }

    #[test]
    fn schedule_is_evenly_interleaved_not_blocky() {
        // The defining property over blocky WRR / weighted-random: the minority backend's single
        // slot lands in the INTERIOR, splitting the majority run, not clustered at an end.
        let schedule = weighted_schedule(&[1, 19]);
        assert_ne!(schedule[0], 0, "minority is not at the front (blocky)");
        assert_ne!(schedule[19], 0, "minority is not at the back (blocky)");

        // For {3,7} the three minority slots are spread, so the max gap between successive minority
        // picks (cyclically) is near the ideal 10/3 ≈ 3.3, not clustered into one run.
        let s = weighted_schedule(&[3, 7]);
        let zeros: Vec<usize> = s
            .iter()
            .enumerate()
            .filter_map(|(i, &b)| (b == 0).then_some(i))
            .collect();
        assert_eq!(zeros.len(), 3);
        let max_gap = zeros
            .iter()
            .zip(zeros.iter().cycle().skip(1))
            .map(|(&a, &b)| if b > a { b - a } else { b + s.len() - a })
            .max()
            .unwrap();
        assert!(
            max_gap <= 4,
            "minority is evenly spread (max gap {max_gap} ≤ 4)"
        );
    }

    #[test]
    fn split_is_proportional_over_a_full_cycle() {
        // {5,95} over 100 picks lands exactly on the ratio (a full reduced period is 20 picks, so
        // 100 is 5 periods): deterministic apportionment has no epsilon at a period boundary.
        let w =
            WeightedBackends::new(vec![(group("v2", true), 5), (group("v1", true), 95)]).unwrap();
        let d = distribution(&w, 100);
        assert_eq!(d.get("v2"), Some(&5));
        assert_eq!(d.get("v1"), Some(&95));
    }

    #[test]
    fn single_backend_takes_all_traffic() {
        let w = WeightedBackends::new(vec![(group("only", true), 1)]).unwrap();
        let d = distribution(&w, 50);
        assert_eq!(d.get("only"), Some(&50));
    }

    #[test]
    fn unhealthy_backend_renormalizes_to_healthy() {
        // A 50/50 split where one backend has no eligible instance: every pick goes to the healthy
        // one (renormalize over healthy), never `None` while one is up.
        let w =
            WeightedBackends::new(vec![(group("up", true), 1), (group("down", false), 1)]).unwrap();
        let d = distribution(&w, 40);
        assert_eq!(
            d.get("up"),
            Some(&40),
            "the dead backend's share moves to the healthy one"
        );
        assert_eq!(d.get("down"), None);
    }

    #[test]
    fn all_unhealthy_fails_closed_none() {
        let w =
            WeightedBackends::new(vec![(group("a", false), 1), (group("b", false), 1)]).unwrap();
        assert!(
            w.pick().is_none(),
            "no eligible backend → None → the fast path 503s"
        );
    }
}
