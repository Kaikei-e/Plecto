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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::ControlError;
use crate::manifest::{HealthConfig, Upstream};

/// Upper bound on the outlier ejection-time exponential backoff (ADR 000032): the window is
/// `base · 2^min(eject_count, cap)`, so the cap bounds it at `base · 2^6` (64×) however many times an
/// instance flaps.
const OUTLIER_BACKOFF_SHIFT_CAP: u32 = 6;

/// Wall-clock milliseconds since the epoch, for outlier-ejection windows (ADR 000032). Non-monotonic,
/// but the windows are coarse (seconds), so a backward clock step merely shortens or lengthens one
/// window — never a panic on untrusted input.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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
    /// Outlier ejection deadline (ms since epoch, `0` = not ejected); the lock-free read surface for
    /// `pick` (ADR 000032). Written by `record_outcome` while holding `counters`. Time-based, so it
    /// auto-expires when the window passes — independent of the `healthy` bit (a separate axis).
    outlier_ejected_until_ms: AtomicU64,
}

#[derive(Debug)]
struct HealthCounters {
    consecutive_ok: u32,
    consecutive_fail: u32,
    /// Whether this instance has EVER been healthy. While `false`, a single successful probe
    /// promotes it (cold-start fast path, ADR 000017); afterwards the full `healthy_threshold`
    /// applies for re-entry after an eject.
    ever_healthy: bool,
    /// Consecutive gateway-class 5xx on live traffic, for outlier detection (ADR 000032). Reset by a
    /// non-failure outcome; reaching the policy threshold ejects the instance.
    consecutive_gw_fail: u32,
    /// How many times this instance has been outlier-ejected, for the exponential ejection-time
    /// backoff (ADR 000032). Reset on a successful outcome.
    outlier_eject_count: u32,
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
                consecutive_gw_fail: 0,
                outlier_eject_count: 0,
            }),
            // a 0 threshold would be a footgun (never promote / instant eject); clamp to >= 1.
            healthy_threshold: health.healthy_threshold.max(1),
            unhealthy_threshold: health.unhealthy_threshold.max(1),
            outlier_ejected_until_ms: AtomicU64::new(0),
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

    /// Whether this instance is currently outlier-ejected at `now_ms` (ADR 000032). Lock-free — the
    /// `pick` hot path. The ejection auto-expires when its window passes (no probe needed); this is a
    /// distinct axis from `is_healthy` (an instance can be probe-healthy yet outlier-ejected).
    pub fn is_outlier_ejected(&self, now_ms: u64) -> bool {
        self.outlier_ejected_until_ms.load(Ordering::Acquire) > now_ms
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
    /// Per-try timeout for ONE forward attempt to this upstream (ADR 000019, reframed as the per-try
    /// bound by ADR 000031); `Duration::ZERO` disables it. Bounds one attempt's time-to-response-
    /// headers, failing closed 504 on overrun. Not part of `health`, so a timeout-only change
    /// rebuilds the group but preserves instance health.
    request_timeout: Duration,
    /// Overall request deadline across the WHOLE transaction — every attempt PLUS the backoff between
    /// them (ADR 000031); `Duration::ZERO` = no overall bound (only the per-try `request_timeout`
    /// applies). The runtime applies the tighter of the two; exceeding it fails closed 504.
    overall_timeout: Duration,
    /// Max retries to a DIFFERENT instance after a retryable forward failure (ADR 000023); `0`
    /// disables retry. Like `request_timeout`, not part of `health`, so a retry-only change rebuilds
    /// the group but preserves instance health.
    max_retries: u64,
    /// Round-robin cursor. `Relaxed` suffices: it only needs to advance, not synchronise memory.
    rr: AtomicUsize,
    /// Circuit-breaker cap (ADR 000028): max concurrent in-flight requests to this upstream; `0` =
    /// unlimited. Rebuilt from the manifest on every reconcile, like `request_timeout`/`max_retries`,
    /// so it is not part of `health` and a breaker-only change preserves instance health.
    max_requests: usize,
    /// Current concurrent in-flight requests (ADR 000028) — held by a [`RequestPermit`] from forward
    /// time until the upstream response headers arrive (or it fails). A (re)built group starts at 0;
    /// in-flight requests of a superseded group decrement that group's own counter via their permit,
    /// so a reload never miscounts.
    in_flight: AtomicUsize,
    /// Outlier-detection policy (ADR 000032), rebuilt from the manifest like the other non-health
    /// knobs (so an outlier-config change preserves instance health): the consecutive gateway-5xx
    /// threshold (`0` = disabled), the base ejection window (× exponential backoff), and the cap on
    /// the fraction of the pool ejectable at once.
    outlier_consecutive: u32,
    outlier_base_ejection: Duration,
    outlier_max_ejection_percent: u32,
}

/// A held slot in an upstream's circuit-breaker cap (ADR 000028). Decrements the group's in-flight
/// count on drop, so the slot is released on EVERY return path of a forward (success, retry
/// exhaustion, or transport error) — RAII, no manual book-keeping that a `?` could leak past.
#[derive(Debug)]
pub struct RequestPermit {
    /// `None` for an unlimited breaker (`max_requests == 0`): a zero-cost no-op permit.
    group: Option<Arc<UpstreamGroup>>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            group.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl UpstreamGroup {
    /// Pick the next healthy instance by round-robin, or `None` when every instance is unhealthy
    /// (the fast path then fails closed with 503 — ADR 000017).
    pub fn pick(&self) -> Option<Arc<UpstreamInstance>> {
        self.pick_inner(None)
    }

    /// Pick the next healthy instance OTHER than `exclude` (round-robin), or `None` when `exclude`
    /// is the only healthy one. Used to retry a failed forward on a different instance (ADR 000023).
    pub fn pick_excluding(&self, exclude: &Arc<UpstreamInstance>) -> Option<Arc<UpstreamInstance>> {
        self.pick_inner(Some(exclude))
    }

    /// Round-robin over the *eligible set* — the instances that are healthy and, for a retry, not
    /// `exclude`. The cursor advances over only that set, so an ejected (or excluded) instance's
    /// slot is never absorbed by its neighbour: degraded distribution stays even instead of skewing
    /// ~1:2 toward each dead instance's successor, which the old forward-scan produced (ADR 000024,
    /// refining ADR 000017). Returns `None` only when nothing is eligible (the fast path then fails
    /// closed — ADR 000017).
    ///
    /// Two allocation-free passes — count the eligible, then index into them — so the hot path still
    /// only reads the lock-free `is_healthy` bit and never allocates. If an instance flips between
    /// the passes we return the last eligible one seen rather than spuriously `None`.
    fn pick_inner(&self, exclude: Option<&Arc<UpstreamInstance>>) -> Option<Arc<UpstreamInstance>> {
        // Outlier detection (ADR 000032) gates `pick` on a time-based ejection window, a separate axis
        // from the health bit. Read the clock once, and only when the policy is enabled, so a disabled
        // policy keeps the pre-000032 cost (a single lock-free `is_healthy` read).
        let check_outlier = self.outlier_enabled();
        let now_ms = if check_outlier { now_millis() } else { 0 };
        let is_eligible = |inst: &Arc<UpstreamInstance>| {
            inst.is_healthy()
                && (!check_outlier || !inst.is_outlier_ejected(now_ms))
                && match exclude {
                    Some(ex) => !Arc::ptr_eq(inst, ex),
                    None => true,
                }
        };
        let eligible = self.instances.iter().filter(|&i| is_eligible(i)).count();
        if eligible == 0 {
            return None;
        }
        let target = self.rr.fetch_add(1, Ordering::Relaxed) % eligible;
        let mut seen = 0;
        let mut last = None;
        for inst in &self.instances {
            if is_eligible(inst) {
                last = Some(inst);
                if seen == target {
                    return Some(inst.clone());
                }
                seen += 1;
            }
        }
        last.cloned()
    }

    /// The PER-TRY timeout the fast path applies to one forward attempt (ADR 000019, per-try by ADR
    /// 000031). `Duration::ZERO` means no per-try bound (e.g. a streaming / long-poll backend);
    /// otherwise one attempt is bounded and overrun fails closed 504.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The OVERALL request deadline across all attempts + backoff (ADR 000031); `Duration::ZERO`
    /// means no overall bound (only the per-try `request_timeout` applies). Exceeding it fails
    /// closed 504 `request-timeout` with no further retry.
    pub fn overall_timeout(&self) -> Duration {
        self.overall_timeout
    }

    /// The max number of retries to a different instance on a retryable forward failure (ADR
    /// 000023); `0` disables retry.
    pub fn max_retries(&self) -> u64 {
        self.max_retries
    }

    /// Whether outlier detection is enabled for this upstream (ADR 000032).
    fn outlier_enabled(&self) -> bool {
        self.outlier_consecutive > 0
    }

    /// Record one forward's outcome against `instance` for outlier detection (ADR 000032).
    /// `gateway_failure` is `true` only for a gateway-class 5xx (502/503/504) the upstream actually
    /// RETURNED — never a circuit-breaker shed or a per-try timeout (those are other axes). Returns
    /// `true` iff this call ejected the instance (the caller bumps the ejection metric). A success
    /// resets the failure streak and ejection backoff; consecutive failures past the threshold eject
    /// the instance for a backing-off window — unless that would push the pool past
    /// `max_ejection_percent`, in which case it stays in rotation (fail-closed must not self-DoS).
    pub fn record_outcome(&self, instance: &Arc<UpstreamInstance>, gateway_failure: bool) -> bool {
        if !self.outlier_enabled() {
            return false;
        }
        // a poisoned lock means a thread panicked mid-transition; fail safe (no ejection).
        let Ok(mut c) = instance.counters.lock() else {
            return false;
        };
        if !gateway_failure {
            c.consecutive_gw_fail = 0;
            c.outlier_eject_count = 0;
            return false;
        }
        c.consecutive_gw_fail = c.consecutive_gw_fail.saturating_add(1);
        if c.consecutive_gw_fail < self.outlier_consecutive {
            return false;
        }

        // Threshold reached. Honour the ejection cap: never eject so many that the pool drops below
        // its working minimum (`100 - max_ejection_percent`). Integer math, no float.
        let now_ms = now_millis();
        let already_ejected = self
            .instances
            .iter()
            .filter(|i| i.is_outlier_ejected(now_ms))
            .count();
        if (already_ejected + 1) * 100
            > self.outlier_max_ejection_percent as usize * self.instances.len()
        {
            // Cap reached — keep this instance in rotation, but reset its streak so it gets a fresh
            // threshold's worth of chances rather than re-tripping on the very next failure.
            c.consecutive_gw_fail = 0;
            return false;
        }

        // Eject for `base · 2^min(eject_count, cap)` — exponential backoff, bounded.
        let shift = c.outlier_eject_count.min(OUTLIER_BACKOFF_SHIFT_CAP);
        let window = self.outlier_base_ejection.saturating_mul(1u32 << shift);
        instance.outlier_ejected_until_ms.store(
            now_ms.saturating_add(window.as_millis() as u64),
            Ordering::Release,
        );
        c.outlier_eject_count = c.outlier_eject_count.saturating_add(1);
        c.consecutive_gw_fail = 0;
        true
    }

    /// Try to take an in-flight slot under the circuit-breaker cap (ADR 000028). `None` means the
    /// upstream is at `max_requests` and the fast path should fail closed (503). An unlimited breaker
    /// (`max_requests == 0`, the default) always succeeds with a zero-cost no-op permit. Lock-free:
    /// an optimistic increment that backs out if it crossed the cap, so concurrent callers never
    /// hold more than `max_requests` permits at once.
    pub fn try_acquire(self: &Arc<Self>) -> Option<RequestPermit> {
        if self.max_requests == 0 {
            return Some(RequestPermit { group: None });
        }
        // `fetch_add` returns the PRIOR value: `prev >= max` means the cap was already full, so this
        // would be the (max+1)th in flight — back the increment out and reject. `Relaxed` suffices
        // (a bare counter, like `rr`; it guards no other memory).
        let prev = self.in_flight.fetch_add(1, Ordering::Relaxed);
        if prev >= self.max_requests {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(RequestPermit {
            group: Some(self.clone()),
        })
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
            let prev_any = groups.get(&up.name);
            // reuse the prior group's instances only if the health policy is identical; a policy
            // change re-probes the upstream from pessimistic (so new thresholds actually apply).
            let prev = prev_any.filter(|g| g.health == up.health);
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
            // carry the round-robin cursor across the reload (independent of which instances or the
            // health policy changed — it is only a rotation counter) so the first post-reload pick
            // continues the rotation instead of restarting at the eligible set's head (ADR 000024).
            let rr = prev_any.map(|g| g.rr.load(Ordering::Relaxed)).unwrap_or(0);
            next.insert(
                up.name.clone(),
                Arc::new(UpstreamGroup {
                    name: up.name.clone(),
                    health: up.health.clone(),
                    instances,
                    request_timeout: Duration::from_millis(up.request_timeout_ms),
                    overall_timeout: Duration::from_millis(up.overall_timeout_ms),
                    max_retries: up.max_retries,
                    rr: AtomicUsize::new(rr),
                    max_requests: up.circuit_breaker.max_requests as usize,
                    in_flight: AtomicUsize::new(0),
                    outlier_consecutive: up.outlier_detection.consecutive_gateway_failures,
                    outlier_base_ejection: Duration::from_millis(
                        up.outlier_detection.base_ejection_time_ms,
                    ),
                    outlier_max_ejection_percent: up.outlier_detection.max_ejection_percent,
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
    use crate::manifest::{CircuitBreaker, HealthConfig, OutlierDetection};

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
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
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
            match g.pick().unwrap().address() {
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
        assert_eq!(g0.pick().unwrap().address(), "a:1");
        assert_eq!(g0.pick().unwrap().address(), "b:2");

        // reload with the SAME upstream + health policy → instances and health are preserved
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 3))])
            .unwrap();
        let g1 = reg.group("u").unwrap();
        assert!(
            g1.instances.iter().all(|i| i.is_healthy()),
            "health survives an unchanged-policy reload (ADR 000017)"
        );
        assert_eq!(
            g1.pick().unwrap().address(),
            "c:3",
            "the cursor carried across reload (would be a:1 if reset to 0)"
        );
    }

    #[test]
    fn circuit_breaker_caps_concurrent_in_flight_and_releases_on_drop() {
        // ADR 000028: `max_requests` bounds concurrent in-flight forwards to an upstream. At the cap
        // `try_acquire` returns None (the fast path fails closed 503); dropping a permit frees a slot.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses: vec!["a:1".to_string()],
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker { max_requests: 2 },
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        let g = reg.group("u").unwrap();

        let p1 = g.try_acquire().expect("1st slot is under the cap");
        let _p2 = g.try_acquire().expect("2nd slot is under the cap");
        assert!(
            g.try_acquire().is_none(),
            "the 3rd concurrent request is over the cap → rejected"
        );

        drop(p1);
        let _p3 = g.try_acquire().expect("a freed slot is reusable");
        assert!(
            g.try_acquire().is_none(),
            "still capped at 2 after reusing the freed slot"
        );
    }

    #[test]
    fn circuit_breaker_zero_is_unlimited() {
        // The default (`max_requests == 0`) never rejects — a zero-cost no-op permit, no cap. The
        // `upstream` helper leaves the breaker at its default, so this also covers the common config.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();
        let permits: Vec<_> = (0..1000)
            .map(|_| g.try_acquire().expect("an unlimited breaker never rejects"))
            .collect();
        assert_eq!(permits.len(), 1000);
    }

    /// Build a healthy group with outlier detection configured (ADR 000032).
    fn outlier_group(
        addrs: &[&str],
        consecutive: u32,
        base_ms: u64,
        max_pct: u32,
    ) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection {
                consecutive_gateway_failures: consecutive,
                base_ejection_time_ms: base_ms,
                max_ejection_percent: max_pct,
            },
        }])
        .unwrap();
        let g = reg.group("u").unwrap();
        for inst in &g.instances {
            inst.record_probe_success(); // cold-start: all healthy
        }
        g
    }

    #[test]
    fn outlier_ejects_after_consecutive_gateway_failures_and_success_resets() {
        let g = outlier_group(&["a:1", "b:2"], 2, 60_000, 100);
        let a = g.instances[0].clone();
        assert!(
            !g.record_outcome(&a, true),
            "1st failure is below the threshold"
        );
        // a success between failures resets the streak.
        assert!(!g.record_outcome(&a, false));
        assert!(
            !g.record_outcome(&a, true),
            "streak reset → this is the 1st again"
        );
        assert!(
            g.record_outcome(&a, true),
            "2nd consecutive failure ejects (returns true)"
        );
        assert!(a.is_outlier_ejected(now_millis()), "ejected from rotation");
        assert!(
            a.is_healthy(),
            "but the health bit is untouched — outlier detection is a separate axis (ADR 000032)"
        );
    }

    #[test]
    fn outlier_ejection_window_expires() {
        let g = outlier_group(&["a:1", "b:2"], 1, 1000, 100);
        let a = g.instances[0].clone();
        assert!(
            g.record_outcome(&a, true),
            "threshold 1 → one failure ejects"
        );
        let now = now_millis();
        assert!(a.is_outlier_ejected(now), "ejected at `now`");
        assert!(
            !a.is_outlier_ejected(now + 2000),
            "the 1s window has expired 2s later — auto-return, no probe needed"
        );
    }

    #[test]
    fn outlier_max_ejection_percent_keeps_some_in_rotation() {
        // 3 instances, 50% cap → at most 1 may be ejected; the rest stay in rotation even while
        // failing, so fail-closed never becomes a self-inflicted total outage.
        let g = outlier_group(&["a:1", "b:2", "c:3"], 1, 60_000, 50);
        let a = g.instances[0].clone();
        let b = g.instances[1].clone();
        assert!(g.record_outcome(&a, true), "a ejects (1/3 within 50%)");
        assert!(
            !g.record_outcome(&b, true),
            "b is NOT ejected — a 2nd ejection (2/3) would exceed the 50% cap"
        );
        assert!(!b.is_outlier_ejected(now_millis()), "b stays in rotation");
    }

    #[test]
    fn outlier_disabled_never_ejects() {
        let g = outlier_group(&["a:1"], 0, 60_000, 100); // consecutive 0 = disabled
        let a = g.instances[0].clone();
        for _ in 0..100 {
            assert!(
                !g.record_outcome(&a, true),
                "a disabled policy never ejects"
            );
        }
        assert!(!a.is_outlier_ejected(now_millis()));
    }

    #[test]
    fn outlier_ejected_instance_is_skipped_by_pick() {
        let g = outlier_group(&["a:1", "b:2"], 1, 60_000, 100);
        let a = g.instances[0].clone();
        assert!(g.record_outcome(&a, true), "eject a");
        for _ in 0..6 {
            assert_eq!(
                g.pick().unwrap().address(),
                "b:2",
                "round-robin skips the outlier-ejected (but still healthy) instance"
            );
        }
    }
}
