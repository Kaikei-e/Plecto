//! E2E for native L7 rate limiting (ADR 000033): a per-route token-bucket baseline the fast path
//! consults BEFORE the filter chain, fast-failing over the cap with **429** + `Retry-After` (distinct
//! from the breaker's 503). A `rate = 1, burst = 1` bucket lets one request through, then sheds the
//! next; the admin `/metrics` (ADR 000009) shows the rejected count. Per-IP isolation across distinct
//! source addresses is unit-tested in `plecto-control` (loopback gives one peer); here both `route`
//! and `client-ip` keying are exercised end-to-end for a single client.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use plecto_control::{Control, ControlError, Manifest};
use plecto_server::serve;

/// An upstream that answers everything (health probe + traffic) immediately with `ok`.
async fn svc(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::from_static(b"ok")))
        .unwrap())
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(svc))
                    .await;
            });
        }
    });
    addr
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// GET → (status, Retry-After header if any, body).
async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    addr: SocketAddr,
    path: &str,
) -> (StatusCode, Option<String>, String) {
    let resp = client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{addr}{path}"))
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("request");
    let (parts, body) = resp.into_parts();
    let retry_after = parts
        .headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        retry_after,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Poll until the upstream is healthy (the proxy stops returning 503 no-healthy). A 429 here (the
/// limiter already drained by a probe) also counts as "ready" — anything but 503.
async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..150 {
        let (status, _, _) = get(client, proxy, "/").await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy");
}

async fn scrape_rate_limited(
    client: &Client<HttpConnector, Empty<Bytes>>,
    admin: SocketAddr,
) -> u64 {
    let (status, _, metrics) = get(client, admin, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    metrics
        .lines()
        .find(|l| l.starts_with("plecto_rate_limited_total "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
        .expect("the rate-limited counter is exposed")
}

/// Drive a `rate = 1, burst = 1` route to its cap and back. Shared by the `route` and `client-ip`
/// keying variants — for a single loopback client they behave identically (one peer = one bucket).
async fn run_limit_test(key: &str) {
    let upstream = spawn_upstream().await;
    let admin = free_addr().await;
    let toml = format!(
        r#"
[observability]
admin_addr = "{admin}"

[[upstream]]
name = "u"
addresses = ["{upstream}"]
[upstream.health]
path = "/healthz"
interval_ms = 50

[[route]]
path_prefix = "/"
upstream = "u"
[route.rate_limit]
rate = 1
burst = 1
key = "{key}"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let control = Arc::new(Control::from_manifest(&manifest, Path::new(".")).unwrap());

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data = data_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, data_listener).await;
    });

    let client = client();
    wait_ready(&client, data).await;

    // Readiness probing may have drained the single token; wait one whole refill interval so the
    // bucket is back to full (burst = 1) and the drain below is deterministic.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // The one token is spent here → forwarded, upstream answers `ok`.
    let (s1, _, b1) = get(&client, data, "/").await;
    assert_eq!(
        s1,
        StatusCode::OK,
        "the first request within burst is forwarded"
    );
    assert_eq!(b1, "ok");

    // The very next request (sub-millisecond later, no refill) is over the cap → fast-fail 429.
    let (s2, retry_after, b2) = get(&client, data, "/").await;
    assert_eq!(
        s2,
        StatusCode::TOO_MANY_REQUESTS,
        "a request over the rate cap is shed with 429 (not the breaker's 503)"
    );
    assert_eq!(b2, "rate limit exceeded", "the rate-limit fast-fail body");
    assert_eq!(
        retry_after.as_deref(),
        Some("1"),
        "429 carries a Retry-After hint (one refill interval)"
    );

    // The rejection is observable on the admin endpoint (ADR 000009 + 000033).
    assert!(
        scrape_rate_limited(&client, admin).await >= 1,
        "the shed request is counted in plecto_rate_limited_total"
    );
}

#[tokio::test]
async fn route_keyed_rate_limit_sheds_over_the_cap() {
    run_limit_test("route").await;
}

#[tokio::test]
async fn client_ip_keyed_rate_limit_sheds_over_the_cap() {
    run_limit_test("client-ip").await;
}

#[test]
fn zero_rate_or_burst_is_rejected_fail_closed_at_build() {
    // A `rate = 0` bucket never refills and a `burst = 0` holds nothing — a config typo, rejected at
    // build (like the per-filter limiter validation) so it never reaches the limiter arithmetic.
    for (rate, burst) in [(0u64, 1u64), (1, 0)] {
        let toml = format!(
            r#"
[[upstream]]
name = "u"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/healthz"

[[route]]
path_prefix = "/"
upstream = "u"
[route.rate_limit]
rate = {rate}
burst = {burst}
"#
        );
        let manifest = Manifest::from_toml(&toml).unwrap();
        let result = Control::from_manifest(&manifest, Path::new("."));
        assert!(
            matches!(result, Err(ControlError::InvalidRouteRateLimit { .. })),
            "rate={rate} burst={burst} must be rejected fail-closed at build"
        );
    }
}
