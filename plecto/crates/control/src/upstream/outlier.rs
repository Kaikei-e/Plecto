//! Outlier detection (ADR 000032): eject an instance from rotation when it MISBEHAVES on live
//! traffic (consecutive gateway-class 5xx), a third resilience axis distinct from active health
//! ("is it reachable?") and the circuit breaker ("is it saturated?").

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::instance::UpstreamInstance;
use super::{UpstreamGroup, now_millis};

/// Upper bound on the outlier ejection-time exponential backoff (ADR 000032): the window is
/// `base · 2^min(eject_count, cap)`, so the cap bounds it at `base · 2^6` (64×) however many times an
/// instance flaps.
const OUTLIER_BACKOFF_SHIFT_CAP: u32 = 6;

impl UpstreamGroup {
    /// Whether outlier detection is enabled for this upstream (ADR 000032).
    pub(super) fn outlier_enabled(&self) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        AddressSpec, CircuitBreaker, HealthConfig, LbAlgorithm, OutlierDetection, Upstream,
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
            addresses: addrs
                .iter()
                .map(|s| AddressSpec::Bare(s.to_string()))
                .collect(),
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
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
                g.pick(None).unwrap().address(),
                "b:2",
                "round-robin skips the outlier-ejected (but still healthy) instance"
            );
        }
    }
}
