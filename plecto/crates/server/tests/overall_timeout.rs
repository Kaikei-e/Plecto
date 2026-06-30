//! E2E for the overall request timeout (ADR 000031): the per-try timeout bounds ONE attempt, while
//! the overall timeout bounds the WHOLE transaction across retries + backoff. With two slow
//! instances and a generous retry budget, the per-try timeout keeps retrying — but the overall
//! deadline ends the transaction with a 504 `request-timeout` (distinct from a per-try
//! `upstream-timeout`), instead of letting retries run to exhaustion.

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

use plecto_control::{Control, Manifest};
use plecto_server::serve;

/// An upstream that answers `/healthz` immediately (so it joins the rotation) but sleeps a long time
/// on every real path — so every forward attempt hits the per-try timeout.
async fn slow(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if !req.uri().path().starts_with("/healthz") {
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::from_static(b"ok")))
        .unwrap())
}

async fn spawn_slow_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(slow))
                    .await;
            });
        }
    });
    addr
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    addr: SocketAddr,
    path: &str,
) -> (StatusCode, String) {
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
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn overall_timeout_caps_the_retry_sequence_with_504_request_timeout() {
    let a = spawn_slow_upstream().await;
    let b = spawn_slow_upstream().await;
    // per-try 50ms, overall 200ms, a generous retry budget (20): the per-try keeps firing and
    // retrying, but the overall deadline ends the transaction well before the budget is spent.
    let toml = format!(
        r#"
[[upstream]]
name = "u"
addresses = ["{a}", "{b}"]
request_timeout_ms = 50
overall_timeout_ms = 200
max_retries = 20
[upstream.health]
path = "/healthz"
interval_ms = 30

[[route]]
path_prefix = "/"
upstream = "u"
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
    // Readiness: a real request is 503 (no-healthy) until a health probe passes, then 504 (the
    // upstream is healthy but slow). Poll until it stops being 503.
    let mut ready = false;
    for _ in 0..100 {
        let (status, _) = get(&client, data, "/probe").await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready, "upstreams never became healthy");

    // The transaction is capped by the overall deadline: 504 with the overall fault, NOT the per-try
    // `upstream-timeout` and NOT a hang until the retry budget is spent.
    let started = std::time::Instant::now();
    let (status, body) = get(&client, data, "/slow").await;
    let elapsed = started.elapsed();

    assert_eq!(
        status,
        StatusCode::GATEWAY_TIMEOUT,
        "overall deadline → 504"
    );
    assert_eq!(
        body, "request timeout",
        "the overall-timeout fault body, distinct from the per-try `upstream timeout`"
    );
    assert!(
        elapsed < Duration::from_millis(900),
        "the overall deadline (200ms) bounds the transaction well before 20 × 50ms of retries (got {elapsed:?})"
    );
}
