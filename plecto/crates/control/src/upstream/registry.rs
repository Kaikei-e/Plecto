//! The live registry of upstream groups (ADR 000017), owned by `Control` OUTSIDE the swapped
//! `ActiveConfig` so health state survives a reload.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::ControlError;
use crate::manifest::{HashKeyKind, LbAlgorithm, Upstream};

use super::UpstreamGroup;
use super::instance::UpstreamInstance;
use super::lb::{HashKeySource, LbState};
use crate::maglev::MaglevTable;

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
    /// addresses, and the LB config — ADR 000035) runs FIRST against the whole list, so a bad
    /// manifest leaves the running set untouched (all-or-nothing, like the rest of a reload). Then,
    /// per upstream: build a new group whose instances reuse the existing `Arc<UpstreamInstance>` for
    /// any unchanged `(name, address, weight)` *when the health policy is unchanged* (preserving
    /// health), create a fresh pessimistic instance otherwise, build the LB state (a Maglev upstream
    /// recomputes its table from the instance set), and drop upstreams no longer present.
    pub fn reconcile(&self, upstreams: &[Upstream]) -> Result<(), ControlError> {
        let mut seen = HashSet::new();
        for up in upstreams {
            if up.addresses.is_empty() {
                return Err(ControlError::EmptyUpstreamAddresses(up.name.clone()));
            }
            if !seen.insert(up.name.as_str()) {
                return Err(ControlError::DuplicateUpstream(up.name.clone()));
            }
            up.validate_lb()
                .map_err(|reason| ControlError::InvalidUpstreamLb {
                    name: up.name.clone(),
                    reason,
                })?;
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
            let instances: Vec<Arc<UpstreamInstance>> = up
                .addresses
                .iter()
                .map(|spec| {
                    let addr = spec.address();
                    let weight = spec.weight();
                    // reuse only when address AND weight are unchanged; a weight edit (LB capacity)
                    // builds a fresh instance, like a health-policy change.
                    prev.and_then(|g| {
                        g.instances
                            .iter()
                            .find(|i| i.address() == addr && i.weight() == weight)
                            .cloned()
                    })
                    .unwrap_or_else(|| {
                        Arc::new(UpstreamInstance::new(addr.to_string(), weight, &up.health))
                    })
                })
                .collect();
            // carry the round-robin cursor across the reload (independent of which instances or the
            // health policy changed — it is only a rotation counter) so the first post-reload pick
            // continues the rotation instead of restarting at the eligible set's head (ADR 000024).
            let rr = prev_any.map(|g| g.rr.load(Ordering::Relaxed)).unwrap_or(0);
            // Build the LB state from the manifest (ADR 000035). Maglev recomputes its lookup table
            // from the instance set + weights; validation above guaranteed a hash block and a valid
            // (prime, in-range) table size.
            let lb = match up.lb_algorithm {
                LbAlgorithm::RoundRobin => LbState::RoundRobin,
                LbAlgorithm::LeastRequest => LbState::LeastRequest,
                LbAlgorithm::Maglev => {
                    let entries: Vec<(&str, u32)> = instances
                        .iter()
                        .map(|i| (i.address(), i.weight()))
                        .collect();
                    let m = up.hash.as_ref().map(|h| h.table_size).unwrap_or(65537) as usize;
                    LbState::Maglev(MaglevTable::build(&entries, m))
                }
            };
            let hash_key = up.hash.as_ref().map(|h| match h.key {
                HashKeyKind::Header => {
                    HashKeySource::Header(h.header.clone().unwrap_or_default().to_ascii_lowercase())
                }
                HashKeyKind::SourceIp => HashKeySource::SourceIp,
            });
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
                    lb,
                    hash_key,
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
    use crate::manifest::{AddressSpec, CircuitBreaker, HealthConfig, OutlierDetection};

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
}
