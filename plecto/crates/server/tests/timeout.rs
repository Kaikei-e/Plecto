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
