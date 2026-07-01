//! `Control`'s observability surface (ADR 000009 Stage A): the host-aggregated filter-execution
//! metrics snapshot and the operator-configured admin/access-log settings the fast path reads.

use plecto_host::MetricsSnapshot;

use crate::Control;

impl Control {
    /// A snapshot of the host-aggregated filter-execution metrics (ADR 000009): the tally the
    /// `MetricsSink` wired at construction has accumulated. The fast path's admin `/metrics`
    /// endpoint renders this alongside its native RED metrics.
    pub fn filter_metrics(&self) -> MetricsSnapshot {
        self.filter_metrics.snapshot()
    }

    /// The admin endpoint bind address (`[observability] admin_addr`), or `None` when no admin
    /// listener is configured (the default). The fast path binds a separate listener there for
    /// `/metrics` + liveness/readiness (ADR 000009 Stage A).
    pub fn admin_addr(&self) -> Option<&str> {
        self.observability.admin_addr.as_deref()
    }

    /// Whether the structured access log is enabled (`[observability] access_log`, ADR 000009).
    pub fn access_log_enabled(&self) -> bool {
        self.observability.access_log
    }
}
