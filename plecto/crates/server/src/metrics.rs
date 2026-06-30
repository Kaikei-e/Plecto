//! Native data-plane metrics for the fast path (Stage A observability, ADR 000009). Plecto stays
//! dependency-free here: a handful of atomics tally the RED signals (Rate / Errors / Duration) plus
//! a fixed-bucket latency histogram, rendered to the Prometheus text exposition format (v0.0.4) by
//! hand and served on the admin endpoint (`crate::admin`). The host-aggregated filter-execution
//! metrics (`MetricsSink`, ADR 000009) are folded in at render time, so one scrape covers both the
//! data plane and the extension plane. Recording is lock-free and cheap enough to run on every
//! request unconditionally; rendering is a cold path (an admin scrape).

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use plecto_control::MetricsSnapshot;

/// Upper bounds (seconds) of the request-latency histogram buckets. Prometheus convention: each
/// `_bucket{le=...}` is cumulative and a final `+Inf` bucket equals `_count`. The spread (1 ms…10 s)
/// covers a proxy's working range so p50/p90/p99 are recoverable via `histogram_quantile`.
const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A lock-free latency histogram: per-bucket counts (non-cumulative; summed at render), the total
/// observation count, and the running sum in microseconds (an integer atomic, no float CAS).
struct Histogram {
    buckets: Vec<AtomicU64>,
    count: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: DURATION_BUCKETS.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    /// Record one observation. The float→int cast saturates (Rust semantics: NaN→0, negative→0,
    /// overflow→`u64::MAX`), so a pathological duration never panics or wraps (data-plane discipline).
    fn observe(&self, seconds: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        let micros = (seconds * 1_000_000.0) as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
        for (bound, slot) in DURATION_BUCKETS.iter().zip(self.buckets.iter()) {
            if seconds <= *bound {
                slot.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // Above the last finite bound: counted only in `+Inf` (== count), no per-bucket slot.
    }
}

/// The fast path's native request metrics (Stage A, ADR 000009). Counters are monotonic; the gauge
/// tracks in-flight requests. One instance lives on `ServerState`, shared across all transports.
pub(crate) struct ServerMetrics {
    /// Requests completed, indexed by response status class: `[1xx, 2xx, 3xx, 4xx, 5xx]`.
    status_class: [AtomicU64; 5],
    /// Requests currently being served (incremented at entry, decremented at exit).
    in_flight: AtomicI64,
    /// Upstream retries onto another instance (ADR 000023).
    retries: AtomicU64,
    /// Requests shed by an upstream circuit breaker (ADR 000028) — a fast-fail 503 at the cap.
    circuit_open: AtomicU64,
    /// Instances ejected from rotation by outlier detection (ADR 000032).
    outlier_ejections: AtomicU64,
    duration: Histogram,
}

impl ServerMetrics {
    pub(crate) fn new() -> Self {
        Self {
            status_class: std::array::from_fn(|_| AtomicU64::new(0)),
            in_flight: AtomicI64::new(0),
            retries: AtomicU64::new(0),
            circuit_open: AtomicU64::new(0),
            outlier_ejections: AtomicU64::new(0),
            duration: Histogram::new(),
        }
    }

    pub(crate) fn inc_in_flight(&self) {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn dec_in_flight(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_retries(&self) {
        self.retries.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_circuit_open(&self) {
        self.circuit_open.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_outlier_ejection(&self) {
        self.outlier_ejections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one completed request: tally its status class and observe its total duration. The
    /// class index is clamped into `[1,5]` then offset, and the read is bounds-checked, so an
    /// out-of-range status (a hostile filter could synthesise any `u16`) never panics.
    pub(crate) fn record_request(&self, status: u16, elapsed: Duration) {
        let idx = (status / 100).clamp(1, 5) as usize - 1;
        if let Some(slot) = self.status_class.get(idx) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
        self.duration.observe(elapsed.as_secs_f64());
    }

    /// Render the Prometheus text exposition format: the native RED metrics plus the host-aggregated
    /// filter-execution metrics (ADR 000009). Built by `format!` + `join` (no `write!` Result to
    /// swallow); a cold path, so the allocation is immaterial.
    pub(crate) fn render(&self, filter: &MetricsSnapshot) -> String {
        const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
        let mut out: Vec<String> = Vec::new();

        out.push(
            "# HELP plecto_requests_total Total client requests handled, by response status class."
                .to_string(),
        );
        out.push("# TYPE plecto_requests_total counter".to_string());
        for (class, slot) in CLASSES.iter().zip(self.status_class.iter()) {
            out.push(format!(
                "plecto_requests_total{{status_class=\"{class}\"}} {}",
                slot.load(Ordering::Relaxed)
            ));
        }

        out.push("# HELP plecto_requests_in_flight Requests currently being served.".to_string());
        out.push("# TYPE plecto_requests_in_flight gauge".to_string());
        out.push(format!(
            "plecto_requests_in_flight {}",
            self.in_flight.load(Ordering::Relaxed).max(0)
        ));

        out.push("# HELP plecto_request_duration_seconds Request duration in seconds.".to_string());
        out.push("# TYPE plecto_request_duration_seconds histogram".to_string());
        let mut cumulative = 0u64;
        for (bound, slot) in DURATION_BUCKETS.iter().zip(self.duration.buckets.iter()) {
            cumulative += slot.load(Ordering::Relaxed);
            out.push(format!(
                "plecto_request_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}"
            ));
        }
        let count = self.duration.count.load(Ordering::Relaxed);
        out.push(format!(
            "plecto_request_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        ));
        let sum_seconds = self.duration.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        out.push(format!("plecto_request_duration_seconds_sum {sum_seconds}"));
        out.push(format!("plecto_request_duration_seconds_count {count}"));

        out.push(
            "# HELP plecto_upstream_retries_total Upstream request retries onto another instance."
                .to_string(),
        );
        out.push("# TYPE plecto_upstream_retries_total counter".to_string());
        out.push(format!(
            "plecto_upstream_retries_total {}",
            self.retries.load(Ordering::Relaxed)
        ));

        out.push(
            "# HELP plecto_circuit_open_total Requests shed by an upstream circuit breaker (ADR 000028)."
                .to_string(),
        );
        out.push("# TYPE plecto_circuit_open_total counter".to_string());
        out.push(format!(
            "plecto_circuit_open_total {}",
            self.circuit_open.load(Ordering::Relaxed)
        ));

        out.push(
            "# HELP plecto_outlier_ejections_total Instances ejected from rotation by outlier detection (ADR 000032)."
                .to_string(),
        );
        out.push("# TYPE plecto_outlier_ejections_total counter".to_string());
        out.push(format!(
            "plecto_outlier_ejections_total {}",
            self.outlier_ejections.load(Ordering::Relaxed)
        ));

        // --- extension plane: host-aggregated filter-execution metrics (ADR 000009) ---
        out.push(
            "# HELP plecto_filter_executions_total Filter hook executions (host-aggregated)."
                .to_string(),
        );
        out.push("# TYPE plecto_filter_executions_total counter".to_string());
        out.push(format!("plecto_filter_executions_total {}", filter.total));

        out.push(
            "# HELP plecto_filter_errors_total Filter executions that faulted (trap/deadline/instantiate/unavailable)."
                .to_string(),
        );
        out.push("# TYPE plecto_filter_errors_total counter".to_string());
        out.push(format!("plecto_filter_errors_total {}", filter.errors));

        out.push(
            "# HELP plecto_filter_short_circuits_total Filter executions that short-circuited the chain."
                .to_string(),
        );
        out.push("# TYPE plecto_filter_short_circuits_total counter".to_string());
        out.push(format!(
            "plecto_filter_short_circuits_total {}",
            filter.short_circuits
        ));

        out.push(
            "# HELP plecto_filter_duration_seconds_total Total filter execution time in seconds."
                .to_string(),
        );
        out.push("# TYPE plecto_filter_duration_seconds_total counter".to_string());
        out.push(format!(
            "plecto_filter_duration_seconds_total {}",
            filter.total_duration.as_secs_f64()
        ));

        let mut text = out.join("\n");
        text.push('\n');
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(total: u64, errors: u64, short_circuits: u64) -> MetricsSnapshot {
        MetricsSnapshot {
            total,
            errors,
            short_circuits,
            total_duration: Duration::from_millis(0),
        }
    }

    #[test]
    fn records_status_classes_and_renders_prometheus_exposition() {
        let m = ServerMetrics::new();
        m.record_request(200, Duration::from_millis(3));
        m.record_request(204, Duration::from_millis(7));
        m.record_request(404, Duration::from_millis(1));
        m.record_request(503, Duration::from_millis(50));

        let text = m.render(&snap(0, 0, 0));
        assert!(text.contains("plecto_requests_total{status_class=\"2xx\"} 2"));
        assert!(text.contains("plecto_requests_total{status_class=\"4xx\"} 1"));
        assert!(text.contains("plecto_requests_total{status_class=\"5xx\"} 1"));
        assert!(text.contains("plecto_requests_total{status_class=\"3xx\"} 0"));
        assert!(text.contains("plecto_request_duration_seconds_count 4"));
        assert!(text.contains("# TYPE plecto_request_duration_seconds histogram"));
    }

    #[test]
    fn out_of_range_status_does_not_panic() {
        // A hostile filter can synthesise any u16 status; the metric must absorb it, never panic.
        let m = ServerMetrics::new();
        for status in [0u16, 99, 600, 999, u16::MAX] {
            m.record_request(status, Duration::from_millis(1));
        }
        // all five clamp into 1xx or 5xx — the point is simply that none panicked.
        assert!(
            m.render(&snap(0, 0, 0))
                .contains("plecto_request_duration_seconds_count 5")
        );
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_end_at_total_count() {
        let m = ServerMetrics::new();
        for ms in [2u64, 8, 30, 300] {
            m.record_request(200, Duration::from_millis(ms));
        }
        let text = m.render(&snap(0, 0, 0));
        let counts: Vec<u64> = text
            .lines()
            .filter(|l| l.starts_with("plecto_request_duration_seconds_bucket"))
            .filter_map(|l| l.rsplit(' ').next())
            .filter_map(|n| n.parse::<u64>().ok())
            .collect();
        assert!(
            counts.windows(2).all(|w| w[0] <= w[1]),
            "buckets must be cumulative / non-decreasing: {counts:?}"
        );
        assert_eq!(
            counts.last().copied(),
            Some(4),
            "the +Inf bucket equals the total observation count"
        );
    }

    #[test]
    fn in_flight_gauge_tracks_the_balance() {
        let m = ServerMetrics::new();
        m.inc_in_flight();
        m.inc_in_flight();
        m.dec_in_flight();
        assert!(
            m.render(&snap(0, 0, 0))
                .contains("plecto_requests_in_flight 1")
        );
    }

    #[test]
    fn folds_in_host_filter_metrics() {
        let m = ServerMetrics::new();
        let text = m.render(&snap(5, 2, 1));
        assert!(text.contains("plecto_filter_executions_total 5"));
        assert!(text.contains("plecto_filter_errors_total 2"));
        assert!(text.contains("plecto_filter_short_circuits_total 1"));
    }
}
