//! E2E (tdd-workflow Phase 0) for the upstream end-to-end timeout (ADR 000019 / review f000005
//! P2#4): drive a real HTTP/1.1 request through `plecto-server` to an upstream that answers its
//! health probe promptly but stalls on the real request. With a short `request_timeout_ms` the
//! fast path must fail closed with **504** (`x-plecto-fault: upstream-timeout`) instead of hanging
//! on the slow backend — and a healthy-but-fast upstream is unaffected.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use plecto_control::{Control, Host, Manifest, MemoryStore};
use plecto_host::test_support::TestSigner;
use plecto_server::serve;

/// A fake upstream that answers `/healthz` IMMEDIATELY (so the instance becomes healthy) but stalls
/// `delay` before responding to anything else (so the real request hits the proxy's timeout).
async fn spawn_slow_upstream(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<hyper::body::Incoming>| async move {
                            // health probe is fast → instance goes healthy; real paths stall.
                            if req.uri().path() != "/healthz" {
                                tokio::time::sleep(delay).await;
                            }
                            Ok::<Response<Full<Bytes>>, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("x-from", "upstream")
                                    .body(Full::new(Bytes::from_static(b"slow-ok")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

async fn spawn_proxy(control: Arc<Control>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, listener).await;
    });
    addr
}

/// A filter-less `/api` route to a single upstream with a short `request_timeout_ms`.
fn control_for(upstream_addr: SocketAddr, request_timeout_ms: u64) -> Arc<Control> {
    let signer = TestSigner::new().unwrap();
    let toml = format!(
        r#"
[[upstream]]
name = "slow"
addresses = ["{upstream_addr}"]
request_timeout_ms = {request_timeout_ms}
[upstream.health]
path = "/healthz"
interval_ms = 50
timeout_ms = 200

[[route]]
path_prefix = "/api"
upstream = "slow"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(MemoryStore::new())).unwrap())
}

/// A filter-less `/api` route to a single `pool` upstream over several instances, with a short
/// `request_timeout_ms` and an explicit `max_retries` (ADR 000023).
fn control_for_pool(
    addresses: &[SocketAddr],
    request_timeout_ms: u64,
    max_retries: u64,
) -> Arc<Control> {
    let signer = TestSigner::new().unwrap();
    let addrs = addresses
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
[[upstream]]
name = "pool"
addresses = [{addrs}]
request_timeout_ms = {request_timeout_ms}
max_retries = {max_retries}
[upstream.health]
path = "/healthz"
interval_ms = 50
timeout_ms = 200

[[route]]
path_prefix = "/api"
upstream = "pool"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(MemoryStore::new())).unwrap())
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    proxy: SocketAddr,
) -> (StatusCode, Option<String>) {
    let resp = client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{proxy}/api/x"))
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("proxy request");
    let fault = resp
        .headers()
        .get("x-plecto-fault")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), fault)
}

/// Poll a forwarding path until the upstream's first health probe lands (no longer 503). The probe
/// is fast even on the slow upstream, so this returns once the instance is healthy.
async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..200 {
        if get(client, proxy).await.0 != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy within the readiness window");
}

#[tokio::test]
async fn slow_upstream_fails_closed_with_504() {
    // The upstream stalls ~400ms on the real request; the route's timeout is 50ms → 504.
    let upstream = spawn_slow_upstream(Duration::from_millis(400)).await;
    let proxy = spawn_proxy(control_for(upstream, 50)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let (status, fault) = get(&client, proxy).await;
    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "an upstream that misses the timeout must fail closed with 504"
    );
    assert_eq!(
        fault.as_deref(),
        Some("upstream-timeout"),
        "the 504 carries the upstream-timeout fault marker"
    );
}

#[tokio::test]
async fn fast_upstream_within_timeout_succeeds() {
    // A control: the same wiring with a generous timeout and no artificial delay forwards 200, so
    // the 504 above is genuinely the timeout firing — not the route being broken.
    let upstream = spawn_slow_upstream(Duration::from_millis(0)).await;
    let proxy = spawn_proxy(control_for(upstream, 5_000)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let (status, _fault) = get(&client, proxy).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a prompt upstream within the timeout forwards normally"
    );
}

#[tokio::test]
async fn timeout_retries_to_a_healthy_instance() {
    // pool = [slow, fast]: the slow instance answers /healthz promptly (so it joins the rotation)
    // but stalls 500ms on the real path, far past the 80ms timeout. With max_retries = 1, every
    // request the round-robin sends to the slow instance must time out and be RE-SENT to the fast
    // instance — so a GET (bodyless, idempotent) only ever sees 200, never a 504 (ADR 000023).
    let slow = spawn_slow_upstream(Duration::from_millis(500)).await;
    let fast = spawn_slow_upstream(Duration::from_millis(0)).await;
    let proxy = spawn_proxy(control_for_pool(&[slow, fast], 80, 1)).await;
    let client = client();
    wait_ready(&client, proxy).await;
    // let both instances pass a probe so the round-robin actually visits the slow one.
    tokio::time::sleep(Duration::from_millis(200)).await;

    for _ in 0..24 {
        let (status, _fault) = get(&client, proxy).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a slow-instance pick must be retried onto the fast instance, never a 504"
        );
    }
}

#[tokio::test]
async fn max_retries_zero_disables_retry() {
    // Same pool, but max_retries = 0: a request the round-robin sends to the slow instance now fails
    // closed with 504 (no retry), while a fast-instance pick still succeeds — over a run we see
    // BOTH, proving retry is genuinely off, not that every request happened to hit fast (ADR 000023).
    let slow = spawn_slow_upstream(Duration::from_millis(500)).await;
    let fast = spawn_slow_upstream(Duration::from_millis(0)).await;
    let proxy = spawn_proxy(control_for_pool(&[slow, fast], 80, 0)).await;
    let client = client();
    wait_ready(&client, proxy).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut saw_ok = false;
    let mut saw_timeout = false;
    for _ in 0..24 {
        match get(&client, proxy).await {
            (StatusCode::OK, _) => saw_ok = true,
            (StatusCode::GATEWAY_TIMEOUT, fault) => {
                assert_eq!(fault.as_deref(), Some("upstream-timeout"));
                saw_timeout = true;
            }
            (other, _) => panic!("unexpected status {other}"),
        }
    }
    assert!(saw_ok, "a fast-instance pick still succeeds");
    assert!(
        saw_timeout,
        "a slow-instance pick fails closed with 504 when retry is disabled"
    );
}
