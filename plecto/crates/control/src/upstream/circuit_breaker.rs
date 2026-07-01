//! The per-upstream circuit breaker (ADR 000028): a concurrent in-flight cap distinct from health
//! — health ejects *failing* instances, this caps concurrent work on *healthy* ones so a saturated
//! backend sheds load fast instead of queueing unbounded.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::UpstreamGroup;

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

#[cfg(test)]
mod tests {
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

    #[test]
    fn circuit_breaker_caps_concurrent_in_flight_and_releases_on_drop() {
        // ADR 000028: `max_requests` bounds concurrent in-flight forwards to an upstream. At the cap
        // `try_acquire` returns None (the fast path fails closed 503); dropping a permit frees a slot.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses: vec![AddressSpec::Bare("a:1".to_string())],
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
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
}
