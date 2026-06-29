//! Active health checks (ADR 000017).
//!
//! One supervisor task drives ALL upstream instances. Each loop it reads the current upstream groups
//! from Control — so a reload's reconciled add/remove is picked up automatically, with no per-
//! instance task lifecycle to manage — and probes every instance whose `interval_ms` has elapsed. A
//! brand-new instance (not yet seen) is probed immediately: that cold-start fast probe, with the
//! first-success-promotes rule (ADR 000017), shrinks the pessimistic startup window to ~one probe
//! RTT. Probes run on plain HTTP/1.1 (upstream TLS is deferred); each runs on its own task so a slow
//! or timing-out probe never stalls the others.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use plecto_control::{Control, HealthConfig, UpstreamInstance};

use crate::upstream_connector;

/// Run the health-check supervisor until the server stops (ADR 000017). Drives `GET {health.path}`
/// to each upstream instance on its configured interval and feeds the result into the instance's
/// shared health state, which `proxy_core`'s round-robin then reads.
pub(crate) async fn serve_health_checks(control: Arc<Control>) {
    // a dedicated plain-HTTP/1.1 client for probes (empty body), separate from the request path.
    let client: Client<HttpConnector, Empty<Bytes>> =
        Client::builder(TokioExecutor::new()).build(upstream_connector());
    // per-(upstream, address) last-probe instant, so each instance is probed on ITS interval even
    // though one task drives them all. An instance not yet in the map is probed now (cold start).
    let mut last: HashMap<(String, String), Instant> = HashMap::new();
    loop {
        let groups = control.upstream_groups();
        let now = Instant::now();
        let mut live: HashSet<(String, String)> = HashSet::new();
        // wake at the shortest configured interval; idle a few seconds when there are no upstreams.
        let mut period = Duration::from_secs(5);
        for g in &groups {
            let interval = Duration::from_millis(g.health.interval_ms.max(1));
            period = period.min(interval);
            for inst in &g.instances {
                let key = (g.name.clone(), inst.address().to_string());
                let due = last
                    .get(&key)
                    .is_none_or(|t| now.duration_since(*t) >= interval);
                if due {
                    last.insert(key.clone(), now);
                    let client = client.clone();
                    let inst = inst.clone();
                    let health = g.health.clone();
                    tokio::spawn(async move { probe_once(&client, &health, &inst).await });
                }
                live.insert(key);
            }
        }
        // forget bookkeeping for instances that vanished on a reload.
        last.retain(|k, _| live.contains(k));
        tokio::time::sleep(period.max(Duration::from_millis(20))).await;
    }
}

/// Probe one instance once: `GET {health.path}` bounded by `timeout_ms`. A 2xx is a success; a
/// non-2xx, a timeout, or a connect/transport error is a failure. Never panics (data-plane
/// discipline) — a malformed address/path is simply a failed probe.
async fn probe_once(
    client: &Client<HttpConnector, Empty<Bytes>>,
    health: &HealthConfig,
    inst: &UpstreamInstance,
) {
    let uri = format!("http://{}{}", inst.address(), health.path);
    let req = match Request::builder()
        .method("GET")
        .uri(&uri)
        .body(Empty::<Bytes>::new())
    {
        Ok(req) => req,
        Err(_) => {
            inst.record_probe_failure();
            return;
        }
    };
    let timeout = Duration::from_millis(health.timeout_ms.max(1));
    match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(resp)) if resp.status().is_success() => inst.record_probe_success(),
        _ => inst.record_probe_failure(),
    }
}
