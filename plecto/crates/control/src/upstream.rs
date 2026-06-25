//! Upstream instances, active-health-check state, and round-robin load balancing (ADR 000017).
//!
//! A manifest [`Upstream`] becomes a [`UpstreamGroup`] of [`UpstreamInstance`]s. Each instance
//! owns a single health state machine fed by BOTH sources: the background active-health prober
//! (the fast-path server runs it) and passive signals from real forwarded requests (a connect
//! failure demotes). The fast path picks a healthy instance per request by round-robin; when none
//! are healthy the upstream is fail-closed (the server responds 503).
//!
//! **The registry lives on `Control`, OUTSIDE the atomically-swapped `ActiveConfig`**, so health
//! state SURVIVES a reload (ADR 000017). [`UpstreamRegistry::reconcile`] diffs the manifest's
//! upstreams against the running set by `(name, address)`: an unchanged instance keeps its health,
//! a new address starts pessimistic (unhealthy), a removed one is dropped. Routing's
//! `CompiledRoute` holds an `Arc<UpstreamGroup>` rebuilt to point at the reconciled group on every
//! reload, so the per-request hot path never touches the registry lock.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::ControlError;
use crate::manifest::{HealthConfig, Upstream};

/// One backend instance (`host:port`) of an upstream, with its health state (ADR 000017).
///
/// The hot path (`pick` → [`UpstreamInstance::is_healthy`]) reads a lock-free `AtomicBool`. State
/// transitions take a small per-instance `Mutex` so "increment a counter, compare the threshold,
/// flip the bit, reset" is race-free — but the mutex is touched only on a probe (cold, every
/// interval) or a passive connect failure (rare), never on the success hot path.
#[derive(Debug)]
pub struct UpstreamInstance {
    address: String,
    /// The lock-free read surface for `pick`. Written only while holding `counters`.
    healthy: AtomicBool,
    counters: Mutex<HealthCounters>,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
}

#[derive(Debug)]
struct HealthCounters {
    consecutive_ok: u32,
    consecutive_fail: u32,
    /// Whether this instance has EVER been healthy. While `false`, a single successful probe
    /// promotes it (cold-start fast path, ADR 000017); afterwards the full `healthy_threshold`
    /// applies for re-entry after an eject.
    ever_healthy: bool,
}

impl UpstreamInstance {
    fn new(address: String, health: &HealthConfig) -> Self {
        Self {
            address,
            // pessimistic: a fresh instance is out of rotation until a probe passes (ADR 000017).
            healthy: AtomicBool::new(false),
            counters: Mutex::new(HealthCounters {
                consecutive_ok: 0,
                consecutive_fail: 0,
                ever_healthy: false,
            }),
            // a 0 threshold would be a footgun (never promote / instant eject); clamp to >= 1.
            healthy_threshold: health.healthy_threshold.max(1),
            unhealthy_threshold: health.unhealthy_threshold.max(1),
        }
    }

    /// This instance's `host:port`.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Whether this instance is currently in rotation. Lock-free — the round-robin hot path.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Record a successful active probe (a 2xx within the timeout). Promotes a pessimistic / ejected
    /// instance once it reaches its threshold — one success the first time ever, `healthy_threshold`
    /// after a later eject — and resets the consecutive-failure streak.
    pub fn record_probe_success(&self) {
        // a poisoned lock means a thread panicked mid-transition; fail safe (leave state as-is).
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.consecutive_fail = 0;
        if self.healthy.load(Ordering::Acquire) {
            return; // already in rotation; nothing to promote
        }
        c.consecutive_ok = c.consecutive_ok.saturating_add(1);
        let need = if c.ever_healthy {
            self.healthy_threshold
        } else {
            1 // cold-start fast path: first ever promotion needs a single success
        };
        if c.consecutive_ok >= need {
            c.ever_healthy = true;
            c.consecutive_ok = 0;
            self.healthy.store(true, Ordering::Release);
        }
    }

    /// Record a failed active probe (non-2xx, timeout, or connect error).
    pub fn record_probe_failure(&self) {
        self.record_failure();
    }

    /// Record a *passive* failure — a real forwarded request that could not even connect to this
    /// instance (ADR 000017). It demotes exactly like a probe failure, but can only ever demote: an
    /// ejected instance receives no traffic, so only the active prober restores it.
    pub fn record_passive_failure(&self) {
        self.record_failure();
    }

    fn record_failure(&self) {
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.consecutive_ok = 0;
        c.consecutive_fail = c.consecutive_fail.saturating_add(1);
        if self.healthy.load(Ordering::Acquire) && c.consecutive_fail >= self.unhealthy_threshold {
            c.consecutive_fail = 0;
            self.healthy.store(false, Ordering::Release);
        }
    }
}

/// A named upstream: its instances, the round-robin cursor, and the health policy (ADR 000017).
#[derive(Debug)]
pub struct UpstreamGroup {
    /// The upstream `name` routes refer to.
    pub name: String,
    /// The active-health-check policy (the prober reads `path` / `interval_ms` / `timeout_ms`).
    pub health: HealthConfig,
    /// The instances, in manifest address order. Fixed for the life of this group value; a reload
    /// builds a NEW group, reusing unchanged instances' `Arc`s to preserve their health.
    pub instances: Vec<Arc<UpstreamInstance>>,
    /// End-to-end timeout for forwarding to this upstream (ADR 000019); `Duration::ZERO` disables
    /// it. The fast path wraps the upstream call in this and fails closed with 504 on overrun. Not
    /// part of `health`, so a timeout-only change rebuilds the group but preserves instance health.
    request_timeout: Duration,
    /// Max retries to a DIFFERENT instance after a retryable forward failure (ADR 000023); `0`
    /// disables retry. Like `request_timeout`, not part of `health`, so a retry-only change rebuilds
    /// the group but preserves instance health.
    max_retries: u64,
    /// Round-robin cursor. `Relaxed` suffices: it only needs to advance, not synchronise memory.
    rr: AtomicUsize,
}

impl UpstreamGroup {
    /// Pick the next healthy instance by round-robin, or `None` when every instance is unhealthy
    /// (the fast path then fails closed with 503 — ADR 000017). Scans at most `instances.len()`
    /// from the rotating cursor, so it is O(n) worst case and allocation-free.
    pub fn pick(&self) -> Option<Arc<UpstreamInstance>> {
        let n = self.instances.len();
        if n == 0 {
            return None;
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let i = start.wrapping_add(off) % n;
            // `i < n` by construction, but use `get` to keep the data plane panic-free (bp-rust).
            if let Some(inst) = self.instances.get(i)
                && inst.is_healthy()
            {
                return Some(inst.clone());
            }
        }
        None
    }

    /// Pick the next healthy instance OTHER than `exclude` (round-robin), or `None` when `exclude`
    /// is the only healthy one. Used to retry a failed forward on a different instance (ADR 000023).
    pub fn pick_excluding(&self, exclude: &Arc<UpstreamInstance>) -> Option<Arc<UpstreamInstance>> {
        let n = self.instances.len();
        if n == 0 {
            return None;
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed);
        for off in 0..n {
            let i = start.wrapping_add(off) % n;
            if let Some(inst) = self.instances.get(i)
                && inst.is_healthy()
                && !Arc::ptr_eq(inst, exclude)
            {
                return Some(inst.clone());
            }
        }
        None
    }

    /// The end-to-end timeout the fast path applies to a forward to this upstream (ADR 000019).
    /// `Duration::ZERO` means no timeout (the operator opted out for a streaming / long-poll
    /// backend); otherwise the call is bounded and overrun fails closed with 504.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The max number of retries to a different instance on a retryable forward failure (ADR
    /// 000023); `0` disables retry.
    pub fn max_retries(&self) -> u64 {
        self.max_retries
    }
}

/// The live set of upstreams, keyed by name. Owned by `Control`, OUTSIDE the swapped
/// `ActiveConfig`, so health state survives a reload (ADR 000017). The `Mutex` is contended only by
/// `reconcile` (on reload) and the prober supervisor (`groups`) / a config build (`group`) — never
/// the per-request hot path, which holds an `Arc<UpstreamGroup>` resolved at build time.
#[derive(Debug, Default)]
pub struct UpstreamRegistry {
    groups: Mutex<HashMap<String, Arc<UpstreamGroup>>>,
}

impl UpstreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconcile the registry to `upstreams` (ADR 000017). Validation (duplicate name, empty
    /// addresses) runs FIRST against the whole list, so a bad manifest leaves the running set
    /// untouched (all-or-nothing, like the rest of a reload). Then, per upstream: build a new group
    /// whose instances reuse the existing `Arc<UpstreamInstance>` for any unchanged `(name,
    /// address)` *when the health policy is unchanged* (preserving health), create a fresh
    /// pessimistic instance otherwise, and drop upstreams no longer present.
    pub fn reconcile(&self, upstreams: &[Upstream]) -> Result<(), ControlError> {
        let mut seen = HashSet::new();
        for up in upstreams {
            if up.addresses.is_empty() {
                return Err(ControlError::EmptyUpstreamAddresses(up.name.clone()));
            }
            if !seen.insert(up.name.as_str()) {
                return Err(ControlError::DuplicateUpstream(up.name.clone()));
            }
        }

        let mut groups = self
            .groups
            .lock()
            .map_err(|_| ControlError::UpstreamRegistryPoisoned)?;
        let mut next: HashMap<String, Arc<UpstreamGroup>> = HashMap::with_capacity(upstreams.len());
        for up in upstreams {
            // reuse the prior group's instances only if the health policy is identical; a policy
            // change re-probes the upstream from pessimistic (so new thresholds actually apply).
            let prev = groups.get(&up.name).filter(|g| g.health == up.health);
            let instances = up
                .addresses
                .iter()
                .map(|addr| {
                    prev.and_then(|g| g.instances.iter().find(|i| i.address() == addr).cloned())
                        .unwrap_or_else(|| {
                            Arc::new(UpstreamInstance::new(addr.clone(), &up.health))
                        })
                })
                .collect();
            next.insert(
                up.name.clone(),
                Arc::new(UpstreamGroup {
                    name: up.name.clone(),
                    health: up.health.clone(),
                    instances,
                    request_timeout: Duration::from_millis(up.request_timeout_ms),
                    max_retries: up.max_retries,
                    rr: AtomicUsize::new(0),
                }),
            );
        }
        *groups = next;
        Ok(())
    }

    /// The group named `name`, if present — used to resolve a route's upstream at config-build time.
    pub fn group(&self, name: &str) -> Option<Arc<UpstreamGroup>> {
        self.groups.lock().ok()?.get(name).cloned()
    }

    /// A snapshot of every current group, for the health-check supervisor to probe.
    pub fn groups(&self) -> Vec<Arc<UpstreamGroup>> {
        self.groups
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::HealthConfig;

    fn health(healthy_threshold: u32, unhealthy_threshold: u32) -> HealthConfig {
        HealthConfig {
            path: "/healthz".to_string(),
            interval_ms: 100,
            timeout_ms: 50,
            healthy_threshold,
            unhealthy_threshold,
        }
    }

    fn upstream(name: &str, addrs: &[&str], h: HealthConfig) -> Upstream {
        Upstream {
            name: name.to_string(),
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
            health: h,
            request_timeout_ms: 30_000,
            max_retries: 1,
        }
    }

    fn instance(h: &HealthConfig) -> UpstreamInstance {
        UpstreamInstance::new("127.0.0.1:9000".to_string(), h)
    }

    #[test]
    fn starts_pessimistic_and_first_probe_promotes() {
        // ADR 000017: a fresh instance is unhealthy; the FIRST successful probe alone promotes it,
        // even when healthy_threshold > 1 (cold-start fast path).
        let h = health(3, 3);
        let inst = instance(&h);
        assert!(!inst.is_healthy(), "fresh instance starts pessimistic");
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success promotes a never-yet-healthy instance"
        );
    }

    #[test]
    fn ejects_after_unhealthy_threshold_then_needs_full_healthy_threshold() {
        // healthy_threshold=2, unhealthy_threshold=2.
        let h = health(2, 2);
        let inst = instance(&h);
        inst.record_probe_success(); // cold-start: healthy after 1
        assert!(inst.is_healthy());

        inst.record_probe_failure();
        assert!(
            inst.is_healthy(),
            "one failure is below the eject threshold"
        );
        inst.record_probe_failure();
        assert!(!inst.is_healthy(), "two consecutive failures eject");

        // re-entry now needs the FULL healthy_threshold (it has been healthy before)
        inst.record_probe_success();
        assert!(
            !inst.is_healthy(),
            "one success is not enough to re-enter after an eject"
        );
        inst.record_probe_success();
        assert!(inst.is_healthy(), "healthy_threshold successes restore it");
    }

    #[test]
    fn a_success_resets_the_failure_streak() {
        let h = health(1, 3);
        let inst = instance(&h);
        inst.record_probe_success();
        inst.record_probe_failure();
        inst.record_probe_failure();
        inst.record_probe_success(); // resets the streak
        inst.record_probe_failure();
        inst.record_probe_failure();
        assert!(inst.is_healthy(), "non-consecutive failures must not eject");
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
            .pick_excluding(&a)
            .expect("a different healthy instance exists");
        assert!(
            Arc::ptr_eq(&other, &group.instances[1]),
            "pick_excluding skips the excluded instance"
        );

        // eject instance[1] (unhealthy_threshold = 3) → `a` is the only healthy one left.
        for _ in 0..3 {
            group.instances[1].record_probe_failure();
        }
        assert!(!group.instances[1].is_healthy(), "instance[1] is ejected");
        assert!(
            group.pick_excluding(&a).is_none(),
            "the only healthy instance can't be retried around"
        );
    }

    #[test]
    fn passive_failure_demotes_a_healthy_instance() {
        // ADR 000017: a real request's connect failure feeds the SAME state machine and demotes.
        let h = health(1, 2);
        let inst = instance(&h);
        inst.record_probe_success();
        assert!(inst.is_healthy());
        inst.record_passive_failure();
        inst.record_passive_failure();
        assert!(
            !inst.is_healthy(),
            "passive failures eject like probe failures"
        );
    }

    #[test]
    fn round_robin_distributes_over_healthy_only() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();

        assert!(
            g.pick().is_none(),
            "all pessimistic → no pick (fail-closed)"
        );

        // make a and c healthy, leave b unhealthy
        g.instances[0].record_probe_success();
        g.instances[2].record_probe_success();

        let mut seen = HashSet::new();
        for _ in 0..6 {
            seen.insert(g.pick().unwrap().address().to_string());
        }
        assert_eq!(
            seen,
            HashSet::from(["a:1".to_string(), "c:3".to_string()]),
            "round-robin only ever returns the healthy instances"
        );
    }

    #[test]
    fn reconcile_preserves_unchanged_adds_new_drops_removed() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2"], health(1, 3))])
            .unwrap();
        let g0 = reg.group("u").unwrap();
        g0.instances[0].record_probe_success(); // a:1 becomes healthy
        assert!(g0.instances[0].is_healthy());

        // reload: drop b:2, keep a:1, add c:3 — same health policy
        reg.reconcile(&[upstream("u", &["a:1", "c:3"], health(1, 3))])
            .unwrap();
        let g1 = reg.group("u").unwrap();
        assert_eq!(g1.instances.len(), 2);
        assert!(
            g1.instances[0].is_healthy(),
            "the unchanged a:1 keeps its health across reload"
        );
        assert_eq!(g1.instances[1].address(), "c:3");
        assert!(
            !g1.instances[1].is_healthy(),
            "the new c:3 starts pessimistic"
        );
    }

    #[test]
    fn reconcile_changing_health_policy_reprobes_from_pessimistic() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1"], health(1, 3))])
            .unwrap();
        reg.group("u").unwrap().instances[0].record_probe_success();
        assert!(reg.group("u").unwrap().instances[0].is_healthy());

        // same address, different health policy → fresh pessimistic instance, new thresholds apply
        reg.reconcile(&[upstream("u", &["a:1"], health(2, 5))])
            .unwrap();
        assert!(
            !reg.group("u").unwrap().instances[0].is_healthy(),
            "a health-policy change re-probes the instance from pessimistic"
        );
    }

    #[test]
    fn reconcile_rejects_empty_addresses_and_duplicate_names() {
        let reg = UpstreamRegistry::new();
        let empty = reg.reconcile(&[upstream("u", &[], health(1, 1))]);
        assert!(matches!(
            empty,
            Err(ControlError::EmptyUpstreamAddresses(_))
        ));

        let dup = reg.reconcile(&[
            upstream("u", &["a:1"], health(1, 1)),
            upstream("u", &["b:2"], health(1, 1)),
        ]);
        assert!(matches!(dup, Err(ControlError::DuplicateUpstream(_))));
    }

    #[test]
    fn zero_thresholds_are_clamped_to_one() {
        // A manifest typo (`healthy_threshold = 0` / `unhealthy_threshold = 0`) must not become a
        // config-induced DoS. Without the `.max(1)` clamp a 0 healthy_threshold would make a
        // never-yet-healthy instance promote on the cold-start path anyway, but a 0
        // unhealthy_threshold would eject a healthy instance the instant it served — and re-entry
        // could be impossible. Clamping both to >=1 makes "one success promotes, one failure
        // ejects, one success restores" hold, never "never promote" or "instant eject".
        let inst = instance(&health(0, 0));
        assert!(!inst.is_healthy(), "still starts pessimistic");
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success promotes (healthy_threshold clamped to >=1)"
        );
        inst.record_probe_failure();
        assert!(
            !inst.is_healthy(),
            "one real failure ejects — not instant-eject before any failure"
        );
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success restores after an eject (re-entry is possible)"
        );
    }
}
