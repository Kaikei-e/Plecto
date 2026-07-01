//! Per-instance load-balancing (ADR 000035): round-robin (default), weighted least-request
//! (power-of-two-choices), and weighted Maglev consistent hashing.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::maglev::MaglevTable;
use crate::rng;

use super::instance::UpstreamInstance;
use super::{UpstreamGroup, now_millis};

/// The request attribute a Maglev upstream hashes for affinity (ADR 000035), resolved from the
/// manifest `[upstream.hash]`. The fast path turns this into a [`HashInput`] per request.
#[derive(Debug, Clone)]
pub enum HashKeySource {
    /// Hash a named request header's value (the name is stored lower-cased for case-insensitive lookup).
    Header(String),
    /// Hash the connection peer's IP address.
    SourceIp,
}

/// A request attribute to hash for Maglev affinity (ADR 000035), borrowed so the hot path allocates
/// nothing: a header value's bytes (borrowed from the request) or the peer IP (hashed as its
/// canonical octets, not a string). The fast path builds this from a group's [`HashKeySource`].
/// `Copy` so it can be passed to the initial `pick` and each retry's `pick_excluding` unchanged.
#[derive(Debug, Clone, Copy)]
pub enum HashInput<'a> {
    Bytes(&'a [u8]),
    Ip(IpAddr),
}

impl HashInput<'_> {
    /// The stable 64-bit hash of this key, fed to the Maglev table lookup.
    fn hash(&self) -> u64 {
        match self {
            HashInput::Bytes(b) => crate::hash::hash64(b),
            HashInput::Ip(IpAddr::V4(a)) => crate::hash::hash64(&a.octets()),
            HashInput::Ip(IpAddr::V6(a)) => crate::hash::hash64(&a.octets()),
        }
    }
}

/// The compiled per-instance load-balancing state of a group (ADR 000035). `Maglev` carries its
/// precomputed lookup table; the other two need no extra state (round-robin uses the group's `rr`
/// cursor, least-request reads the per-instance `in_flight`).
#[derive(Debug)]
pub(super) enum LbState {
    RoundRobin,
    LeastRequest,
    Maglev(MaglevTable),
}

/// A chosen instance plus a guard tracking its load (ADR 000035). For `least_request` the guard
/// holds the selected instance's incremented active-request count and decrements it on drop — on
/// EVERY forward return path (success, retry, transport error) and on each retry hand-off, because
/// replacing the `Pick` drops the previous guard. For round-robin / maglev the guard is a no-op.
/// `Deref`s to the instance so callers read `address()` / `is_healthy()` directly.
pub struct Pick {
    instance: Arc<UpstreamInstance>,
    _load: InstanceLoad,
}

impl Pick {
    /// The chosen instance (for `pick_excluding` / `record_outcome` / passive-failure book-keeping).
    pub fn instance(&self) -> &Arc<UpstreamInstance> {
        &self.instance
    }
}

impl std::ops::Deref for Pick {
    type Target = UpstreamInstance;
    fn deref(&self) -> &UpstreamInstance {
        &self.instance
    }
}

/// RAII guard decrementing an instance's active-request count on drop (ADR 000035). `None` for
/// algorithms that do not track per-instance load (round-robin / maglev): a zero-cost no-op, so the
/// default RR hot path gains no atomic.
pub struct InstanceLoad {
    instance: Option<Arc<UpstreamInstance>>,
}

impl Drop for InstanceLoad {
    fn drop(&mut self) {
        if let Some(inst) = &self.instance {
            inst.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Whether instance `a` has the lower `(in_flight + 1) / weight` than `b` (ADR 000035) — the
/// weighted least-request comparison, by integer cross-product so there is no float, and a tie keeps
/// `a` (the first sampled). `u128` keeps the product overflow-free for any `in_flight` / `weight`.
fn lower_load(a: &Arc<UpstreamInstance>, b: &Arc<UpstreamInstance>) -> bool {
    let la = (a.in_flight() as u128 + 1) * b.weight() as u128;
    let lb = (b.in_flight() as u128 + 1) * a.weight() as u128;
    la <= lb
}

impl UpstreamGroup {
    /// Pick an instance per the upstream's LB algorithm (ADR 000035), or `None` when nothing is
    /// eligible (the fast path then fails closed 503 — ADR 000017). `key` is the request's hash key
    /// for `maglev`; round-robin / least-request ignore it, and `None` (no key) falls back to
    /// round-robin.
    pub fn pick(&self, key: Option<HashInput<'_>>) -> Option<Pick> {
        self.pick_dispatch(None, key)
    }

    /// Pick an instance OTHER than `exclude`, to retry a failed forward on a different instance (ADR
    /// 000023). Same algorithm dispatch as `pick`; for `maglev` the affinity target is excluded, so
    /// it falls back to round-robin over the remaining eligible set.
    pub fn pick_excluding(
        &self,
        exclude: &Arc<UpstreamInstance>,
        key: Option<HashInput<'_>>,
    ) -> Option<Pick> {
        self.pick_dispatch(Some(exclude), key)
    }

    fn pick_dispatch(
        &self,
        exclude: Option<&Arc<UpstreamInstance>>,
        key: Option<HashInput<'_>>,
    ) -> Option<Pick> {
        match &self.lb {
            LbState::RoundRobin => self.round_robin_pick(exclude),
            LbState::LeastRequest => self.least_request_pick(exclude),
            LbState::Maglev(table) => self.maglev_pick(table, exclude, key),
        }
    }

    /// The clock context for eligibility: whether outlier detection is on and, if so, `now` in ms.
    /// Read once per pick, and the clock only when the policy is enabled, so a disabled policy keeps
    /// the pre-000032 cost (a single lock-free `is_healthy` read).
    fn eligibility_ctx(&self) -> (bool, u64) {
        let check_outlier = self.outlier_enabled();
        let now_ms = if check_outlier { now_millis() } else { 0 };
        (check_outlier, now_ms)
    }

    /// Whether `inst` may serve this request: healthy, not outlier-ejected, and not the retry
    /// `exclude`.
    fn is_eligible(
        &self,
        inst: &Arc<UpstreamInstance>,
        exclude: Option<&Arc<UpstreamInstance>>,
        (check_outlier, now_ms): (bool, u64),
    ) -> bool {
        inst.is_healthy()
            && (!check_outlier || !inst.is_outlier_ejected(now_ms))
            && exclude.is_none_or(|ex| !Arc::ptr_eq(inst, ex))
    }

    /// Round-robin over the *eligible set* (ADR 000024): count the eligible, advance the cursor mod
    /// that count, index into them. An ejected/excluded instance's slot is never absorbed by its
    /// neighbour (degraded distribution stays even instead of skewing ~1:2). Two allocation-free
    /// passes; if an instance flips between them we return the last eligible seen rather than a
    /// spurious `None`. No per-instance load is metered — round-robin is the zero-overhead default.
    pub(super) fn round_robin_pick(&self, exclude: Option<&Arc<UpstreamInstance>>) -> Option<Pick> {
        let ctx = self.eligibility_ctx();
        let eligible = self
            .instances
            .iter()
            .filter(|i| self.is_eligible(i, exclude, ctx))
            .count();
        if eligible == 0 {
            return None;
        }
        let target = self.rr.fetch_add(1, Ordering::Relaxed) % eligible;
        let mut seen = 0;
        let mut last = None;
        for inst in &self.instances {
            if self.is_eligible(inst, exclude, ctx) {
                last = Some(inst);
                if seen == target {
                    return Some(self.unmetered_pick(inst.clone()));
                }
                seen += 1;
            }
        }
        last.cloned().map(|i| self.unmetered_pick(i))
    }

    /// Weighted least-request via power-of-two-choices (ADR 000035): sample two distinct eligible
    /// instances and forward to the one with the smaller `(in_flight + 1) / weight` (compared by
    /// integer cross-product, no float; `+1` lets weight bias even idle instances). Two passes over
    /// the small instance list. The selected instance's load is metered (incremented now, decremented
    /// when the returned `Pick` drops — across the retry hand-off too).
    fn least_request_pick(&self, exclude: Option<&Arc<UpstreamInstance>>) -> Option<Pick> {
        let ctx = self.eligibility_ctx();
        let n = self
            .instances
            .iter()
            .filter(|i| self.is_eligible(i, exclude, ctx))
            .count();
        if n == 0 {
            return None;
        }
        if n == 1 {
            let only = self
                .instances
                .iter()
                .find(|i| self.is_eligible(i, exclude, ctx))?;
            return Some(self.metered_pick(only.clone()));
        }
        let (a, b) = rng::two_distinct_below(n as u32);
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        // One pass capturing the lo-th and hi-th eligible instances by ordinal.
        let mut cand_lo = None;
        let mut cand_hi = None;
        let mut seen = 0u32;
        for inst in &self.instances {
            if self.is_eligible(inst, exclude, ctx) {
                if seen == lo {
                    cand_lo = Some(inst);
                }
                if seen == hi {
                    cand_hi = Some(inst);
                }
                seen += 1;
            }
        }
        let (x, y) = (cand_lo?, cand_hi?);
        let chosen = if lower_load(x, y) { x } else { y };
        Some(self.metered_pick(chosen.clone()))
    }

    /// Consistent hashing via the Maglev table (ADR 000035): map the request key to a stable instance
    /// for affinity. When the primary is ineligible (unhealthy / outlier-ejected / the retry
    /// `exclude`) or there is no key, fall back to the eligible-set round-robin (best-effort affinity,
    /// fail-soft). No per-instance load is metered (selection is by hash, not load).
    fn maglev_pick(
        &self,
        table: &MaglevTable,
        exclude: Option<&Arc<UpstreamInstance>>,
        key: Option<HashInput<'_>>,
    ) -> Option<Pick> {
        if let Some(k) = key {
            let ctx = self.eligibility_ctx();
            if let Some(idx) = table.lookup(k.hash())
                && let Some(inst) = self.instances.get(idx)
                && self.is_eligible(inst, exclude, ctx)
            {
                return Some(self.unmetered_pick(inst.clone()));
            }
        }
        // No key, or the affinity target can't serve → fall back to round-robin over the eligible set.
        self.round_robin_pick(exclude)
    }

    /// Wrap an instance in a `Pick` with NO load metering (round-robin / maglev).
    fn unmetered_pick(&self, instance: Arc<UpstreamInstance>) -> Pick {
        Pick {
            instance,
            _load: InstanceLoad { instance: None },
        }
    }

    /// Wrap an instance in a `Pick` that meters its load (least-request): increment its active-request
    /// count now and hand back a guard that decrements it on drop.
    fn metered_pick(&self, instance: Arc<UpstreamInstance>) -> Pick {
        instance.in_flight.fetch_add(1, Ordering::Relaxed);
        Pick {
            instance: instance.clone(),
            _load: InstanceLoad {
                instance: Some(instance),
            },
        }
    }

    /// Whether this upstream has at least one eligible instance (healthy and not outlier-ejected).
    /// A cursor-free, allocation-free probe the weighted traffic split (ADR 000034) uses to skip a
    /// backend whose group can serve nothing (renormalize over healthy). Same eligibility as the
    /// pick path minus the retry `exclude`; a `false` here means a `pick` would return `None`.
    pub fn has_eligible(&self) -> bool {
        let (check_outlier, now_ms) = self.eligibility_ctx();
        self.instances
            .iter()
            .any(|inst| inst.is_healthy() && (!check_outlier || !inst.is_outlier_ejected(now_ms)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::manifest::{
        AddressSpec, CircuitBreaker, HashConfig, HashKeyKind, HealthConfig, LbAlgorithm,
        OutlierDetection, Upstream, WeightedAddress,
    };
    use crate::upstream::UpstreamRegistry;

    fn health(healthy_threshold: u32, unhealthy_threshold: u32) -> HealthConfig {
        HealthConfig {
            path: "/healthz".to_string(),
            interval_ms: 100,
            timeout_ms: 50,
            healthy_threshold,
            unhealthy_threshold,
            port: None,
        }
    }

    fn upstream(name: &str, addrs: &[&str], h: HealthConfig) -> Upstream {
        Upstream {
            name: name.to_string(),
            addresses: addrs
                .iter()
                .map(|s| AddressSpec::Bare(s.to_string()))
                .collect(),
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
            health: h,
            request_timeout_ms: 30_000,
            max_retries: 1,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
        }
    }

    /// Resolve a `Pick`'s address (the common assertion after the `Pick` return type, ADR 000035).
    fn addr_of(p: &Pick) -> String {
        p.address().to_string()
    }

    #[test]
    fn pick_excluding_returns_a_different_healthy_instance_or_none() {
        // ADR 000023: a retry must land on a DIFFERENT instance; when the failed one is the only
        // healthy member there is nothing to retry onto.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream(
            "pool",
            &["127.0.0.1:9000", "127.0.0.1:9001"],
            health(1, 3),
        )])
        .unwrap();
        let group = reg.group("pool").unwrap();
        // promote both (cold-start: one success each).
        group.instances[0].record_probe_success();
        group.instances[1].record_probe_success();

        let a = group.instances[0].clone();
        let other = group
            .pick_excluding(&a, None)
            .expect("a different healthy instance exists");
        assert!(
            Arc::ptr_eq(other.instance(), &group.instances[1]),
            "pick_excluding skips the excluded instance"
        );

        // eject instance[1] (unhealthy_threshold = 3) → `a` is the only healthy one left.
        for _ in 0..3 {
            group.instances[1].record_probe_failure();
        }
        assert!(!group.instances[1].is_healthy(), "instance[1] is ejected");
        assert!(
            group.pick_excluding(&a, None).is_none(),
            "the only healthy instance can't be retried around"
        );
    }

    #[test]
    fn round_robin_distributes_over_healthy_only() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();

        assert!(
            g.pick(None).is_none(),
            "all pessimistic → no pick (fail-closed)"
        );

        // make a and c healthy, leave b unhealthy
        g.instances[0].record_probe_success();
        g.instances[2].record_probe_success();

        let mut seen = HashSet::new();
        for _ in 0..6 {
            seen.insert(g.pick(None).unwrap().address().to_string());
        }
        assert_eq!(
            seen,
            HashSet::from(["a:1".to_string(), "c:3".to_string()]),
            "round-robin only ever returns the healthy instances"
        );
    }

    #[test]
    fn round_robin_is_even_over_the_healthy_set_when_degraded() {
        // With a MIDDLE instance ejected, the rotation must split evenly over whoever is left.
        // The old forward-scan-from-cursor handed the dead instance's slot to its neighbour, so
        // `[a, b(down), c]` skewed a:c to ~1:2. Rotating over the healthy SET removes that.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();
        g.instances[0].record_probe_success(); // a:1 healthy
        g.instances[2].record_probe_success(); // c:3 healthy, b:2 stays ejected

        let mut a = 0u32;
        let mut c = 0u32;
        for _ in 0..600 {
            match g.pick(None).unwrap().address() {
                "a:1" => a += 1,
                "c:3" => c += 1,
                other => panic!("picked a down/unknown instance: {other}"),
            }
        }
        assert_eq!(
            a, c,
            "degraded round-robin must split evenly over the healthy set (was ~1:2)"
        );
    }

    #[test]
    fn reconcile_carries_the_round_robin_cursor() {
        // A reload must not reset the cursor to 0, or the first post-reload pick always lands on
        // the head of the rotation — an index-0 bias under frequent reloads.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 3))])
            .unwrap();
        let g0 = reg.group("u").unwrap();
        for i in 0..3 {
            g0.instances[i].record_probe_success(); // all three healthy
        }
        // advance the cursor two steps: a:1, b:2 (cursor now at 2)
        assert_eq!(g0.pick(None).unwrap().address(), "a:1");
        assert_eq!(g0.pick(None).unwrap().address(), "b:2");

        // reload with the SAME upstream + health policy → instances and health are preserved
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 3))])
            .unwrap();
        let g1 = reg.group("u").unwrap();
        assert!(
            g1.instances.iter().all(|i| i.is_healthy()),
            "health survives an unchanged-policy reload (ADR 000017)"
        );
        assert_eq!(
            g1.pick(None).unwrap().address(),
            "c:3",
            "the cursor carried across reload (would be a:1 if reset to 0)"
        );
    }

    /// A healthy upstream group with the given instances and LB config (ADR 000035).
    fn lb_group(
        addresses: Vec<AddressSpec>,
        algo: LbAlgorithm,
        hash: Option<HashConfig>,
    ) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses,
            lb_algorithm: algo,
            hash,
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        let g = reg.group("u").unwrap();
        for inst in &g.instances {
            inst.record_probe_success(); // cold-start: all healthy
        }
        g
    }

    fn bare(addrs: &[&str]) -> Vec<AddressSpec> {
        addrs
            .iter()
            .map(|s| AddressSpec::Bare(s.to_string()))
            .collect()
    }

    #[test]
    fn least_request_avoids_the_busier_instance() {
        // With two instances, P2C compares both, so it deterministically routes to the one with the
        // lower (in_flight + 1) / weight. Holding a pick inflates its in-flight; the next pick must
        // then avoid it.
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        let p1 = g.pick(None).unwrap();
        let busy = addr_of(&p1);
        let p2 = g.pick(None).unwrap();
        assert_ne!(
            addr_of(&p2),
            busy,
            "least-request must avoid the instance already carrying a request"
        );
    }

    #[test]
    fn least_request_weight_biases_toward_higher_capacity() {
        // Both idle, so (0+1)/weight decides: the weight-3 instance (ratio 1/3) beats the weight-1
        // (ratio 1/1). With two instances P2C compares both, so the idle pick is deterministic.
        let g = lb_group(
            vec![
                AddressSpec::Bare("small".to_string()),
                AddressSpec::Weighted(WeightedAddress {
                    address: "big".to_string(),
                    weight: 3,
                }),
            ],
            LbAlgorithm::LeastRequest,
            None,
        );
        assert_eq!(
            addr_of(&g.pick(None).unwrap()),
            "big",
            "a higher-weight idle instance is preferred"
        );
    }

    #[test]
    fn least_request_meters_in_flight_and_releases_on_drop() {
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        let total =
            |g: &UpstreamGroup| -> usize { g.instances.iter().map(|i| i.in_flight()).sum() };
        assert_eq!(total(&g), 0);
        {
            let _p = g.pick(None).unwrap();
            assert_eq!(total(&g), 1, "one in-flight while the Pick is held");
            let _q = g.pick(None).unwrap();
            assert_eq!(total(&g), 2, "two in-flight while both Picks are held");
        }
        assert_eq!(
            total(&g),
            0,
            "active-request counts released when the Picks drop"
        );
    }

    #[test]
    fn least_request_fails_closed_when_all_unhealthy() {
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        for inst in &g.instances {
            inst.record_probe_failure(); // unhealthy_threshold = 1 → ejected
        }
        assert!(g.pick(None).is_none(), "no eligible instance → None → 503");
    }

    fn header_hash(m: u32) -> Option<HashConfig> {
        Some(HashConfig {
            key: HashKeyKind::Header,
            header: Some("x-user".to_string()),
            table_size: m,
        })
    }

    #[test]
    fn maglev_pins_a_key_to_one_instance() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"session-42");
        let pinned = addr_of(&g.pick(Some(key)).unwrap());
        for _ in 0..30 {
            assert_eq!(
                addr_of(&g.pick(Some(key)).unwrap()),
                pinned,
                "the same key always resolves to the same instance (affinity)"
            );
        }
    }

    #[test]
    fn maglev_spreads_distinct_keys() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let mut seen = HashSet::new();
        for i in 0..300 {
            let key = format!("user-{i}");
            seen.insert(addr_of(
                &g.pick(Some(HashInput::Bytes(key.as_bytes()))).unwrap(),
            ));
        }
        assert_eq!(seen.len(), 3, "distinct keys reach every instance");
    }

    #[test]
    fn maglev_falls_back_to_round_robin_without_a_key() {
        // No key (e.g. the configured header is absent) → round-robin over the eligible set, never None
        // while one is up.
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::Maglev, header_hash(97));
        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(addr_of(&g.pick(None).unwrap()));
        }
        assert_eq!(
            seen.len(),
            2,
            "keyless maglev round-robins across instances"
        );
    }

    #[test]
    fn maglev_falls_back_when_the_primary_is_unhealthy() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"sticky-key");
        let primary = addr_of(&g.pick(Some(key)).unwrap());
        // eject the affinity target (unhealthy_threshold = 1).
        g.instances
            .iter()
            .find(|i| i.address() == primary)
            .unwrap()
            .record_probe_failure();
        let alt = g.pick(Some(key)).unwrap();
        assert_ne!(
            addr_of(&alt),
            primary,
            "a down primary falls back to another healthy instance"
        );
        assert!(alt.is_healthy());
    }

    #[test]
    fn maglev_excludes_on_retry() {
        // A retry must land elsewhere even for the affinity target (ADR 000023 semantics preserved).
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"retry-key");
        let first = g.pick(Some(key)).unwrap();
        let retried = g.pick_excluding(first.instance(), Some(key)).unwrap();
        assert_ne!(
            addr_of(&retried),
            addr_of(&first),
            "retry skips the just-tried instance"
        );
    }
}
