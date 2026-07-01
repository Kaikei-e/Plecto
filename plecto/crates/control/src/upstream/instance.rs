//! Per-instance active-health-check state machine (ADR 000017).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::manifest::HealthConfig;

/// One backend instance (`host:port`) of an upstream, with its health state (ADR 000017).
///
/// The hot path (`pick` → [`UpstreamInstance::is_healthy`]) reads a lock-free `AtomicBool`. State
/// transitions take a small per-instance `Mutex` so "increment a counter, compare the threshold,
/// flip the bit, reset" is race-free — but the mutex is touched only on a probe (cold, every
/// interval) or a passive connect failure (rare), never on the success hot path.
#[derive(Debug)]
pub struct UpstreamInstance {
    address: String,
    /// Load-balancing weight (ADR 000035): biases the least-request comparison and the Maglev table
    /// share toward higher-capacity instances. `1` for a bare address. Immutable for the instance's
    /// life; a weight change builds a fresh instance on reconcile (like a health-policy change).
    weight: u32,
    /// The lock-free read surface for `pick`. Written only while holding `counters`.
    healthy: AtomicBool,
    /// Active forwarded-request count to THIS instance (ADR 000035), the least-request load signal.
    /// Incremented when an attempt selects this instance and decremented when the attempt ends (RAII,
    /// across retries). Distinct from the per-group circuit-breaker in-flight (ADR 000028): that caps
    /// the upstream's saturation, this drives per-instance selection. Only touched under
    /// `least_request`; round-robin / maglev leave it at 0.
    pub(super) in_flight: AtomicUsize,
    pub(super) counters: Mutex<HealthCounters>,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    /// Outlier ejection deadline (ms since epoch, `0` = not ejected); the lock-free read surface for
    /// `pick` (ADR 000032). Written by `record_outcome` while holding `counters`. Time-based, so it
    /// auto-expires when the window passes — independent of the `healthy` bit (a separate axis).
    pub(super) outlier_ejected_until_ms: AtomicU64,
}

#[derive(Debug)]
pub(super) struct HealthCounters {
    pub(super) consecutive_ok: u32,
    pub(super) consecutive_fail: u32,
    /// Whether this instance has EVER been healthy. While `false`, a single successful probe
    /// promotes it (cold-start fast path, ADR 000017); afterwards the full `healthy_threshold`
    /// applies for re-entry after an eject.
    pub(super) ever_healthy: bool,
    /// Consecutive gateway-class 5xx on live traffic, for outlier detection (ADR 000032). Reset by a
    /// non-failure outcome; reaching the policy threshold ejects the instance.
    pub(super) consecutive_gw_fail: u32,
    /// How many times this instance has been outlier-ejected, for the exponential ejection-time
    /// backoff (ADR 000032). Reset on a successful outcome.
    pub(super) outlier_eject_count: u32,
}

impl UpstreamInstance {
    pub(super) fn new(address: String, weight: u32, health: &HealthConfig) -> Self {
        Self {
            address,
            // a 0 weight would divide by zero in the least-request ratio; validation rejects it, but
            // clamp to >= 1 as defence in depth (data-plane no-panic).
            weight: weight.max(1),
            // pessimistic: a fresh instance is out of rotation until a probe passes (ADR 000017).
            healthy: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
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

    /// This instance's load-balancing weight (ADR 000035), `>= 1`.
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// Current active forwarded-request count to this instance (ADR 000035) — the least-request load
    /// signal. Lock-free read.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
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
            tracing::info!(address = %self.address, "upstream instance became healthy");
        }
    }

    /// Record a failed active probe (non-2xx, timeout, or connect error).
    pub fn record_probe_failure(&self) {
        self.record_failure("active probe");
    }

    /// Record a *passive* failure — a real forwarded request that could not even connect to this
    /// instance (ADR 000017). It demotes exactly like a probe failure, but can only ever demote: an
    /// ejected instance receives no traffic, so only the active prober restores it.
    pub fn record_passive_failure(&self) {
        self.record_failure("passive request");
    }

    fn record_failure(&self, source: &'static str) {
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.consecutive_ok = 0;
        c.consecutive_fail = c.consecutive_fail.saturating_add(1);
        if self.healthy.load(Ordering::Acquire) && c.consecutive_fail >= self.unhealthy_threshold {
            c.consecutive_fail = 0;
            self.healthy.store(false, Ordering::Release);
            tracing::warn!(
                address = %self.address,
                source,
                "upstream instance became unhealthy"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn instance(h: &HealthConfig) -> UpstreamInstance {
        UpstreamInstance::new("127.0.0.1:9000".to_string(), 1, h)
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
