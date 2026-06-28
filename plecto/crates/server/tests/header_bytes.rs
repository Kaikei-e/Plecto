//! E2E (tdd-workflow Phase 0) for **header byte-equivalence pass-through** (P3#6). The filter
//! contract carries header values as a lossy-UTF-8 `string`, so before this fix a value holding
//! non-UTF-8 bytes was re-encoded from its `U+FFFD`-mangled form (or dropped) on the way to the
//! upstream — even for a route whose chain never touched it. The contract round-trip happens for
//! EVERY proxied request (the upstream request is rebuilt from the chain's header view), so a
//! filterless route is enough to exercise it; the precise filter-touched / removed / replaced
//! semantics are covered by the `copy_headers_preserving` unit tests.
//!
//! The fake upstream reflects the inbound `x-blob` header bytes into its response BODY, so what the
//! upstream actually received is observable byte-for-byte from the client side.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use plecto_control::{Control, Host, Manifest, MemoryStore};
use plecto_host::test_support::TestSigner;
use plecto_server::serve;

/// Reflects the inbound `x-blob` header's RAW bytes into the response body (so the test sees exactly
/// what the proxy forwarded), and answers `/healthz` and everything else 200 so the instance is
/// healthy. A request without `x-blob` (the readiness probe) answers with `ready`.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = req
        .headers()
        .get("x-blob")
        .map(|v| Bytes::copy_from_slice(v.as_bytes()))
        .unwrap_or_else(|| Bytes::from_static(b"ready"));
    Ok(Response::builder()
        .status(200)
        .body(Full::new(body))
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
                    .serve_connection(TokioIo::new(stream), service_fn(echo))
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

/// A filterless `/api` route (strip `/api`) → the given upstream. No `[[filter]]` is loaded, so no
/// signing is needed; the trust policy is present only because `Host` requires one.
fn control_for(upstream_addr: SocketAddr) -> Arc<Control> {
    let toml = format!(
        r#"
[[upstream]]
name = "backend"
addresses = ["{upstream_addr}"]
[upstream.health]
path = "/healthz"
interval_ms = 50

[[route]]
path_prefix = "/api"
upstream = "backend"
strip_prefix = "/api"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let signer = TestSigner::new().unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(MemoryStore::new())).unwrap())
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Send a GET through the proxy carrying an optional raw `x-blob` header; return (status, body bytes).
async fn get_blob(
    client: &Client<HttpConnector, Empty<Bytes>>,
    proxy: SocketAddr,
    path: &str,
    blob: Option<&[u8]>,
) -> (StatusCode, Bytes) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy}{path}"));
    if let Some(bytes) = blob {
        builder = builder.header(
            HeaderName::from_static("x-blob"),
            HeaderValue::from_bytes(bytes).unwrap(),
        );
    }
    let resp = client
        .request(builder.body(Empty::<Bytes>::new()).unwrap())
        .await
        .expect("proxy request");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, bytes)
}

async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..100 {
        let (status, _) = get_blob(client, proxy, "/api/__ready", None).await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy within the readiness window");
}

#[tokio::test]
async fn non_utf8_header_passes_through_byte_for_byte() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    // An `x-blob` value that is NOT valid UTF-8 (a truncated 2-byte sequence). The lossy `string`
    // the contract would carry is `U+FFFD '('` = bytes EF BF BD 28 — the upstream must NOT see that.
    let raw: &[u8] = &[0xC3, 0x28];
    let (status, seen) = get_blob(&client, proxy, "/api/x", Some(raw)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        seen.as_ref(),
        raw,
        "the upstream received the original header bytes, not the U+FFFD re-encoding"
    );
}

#[tokio::test]
async fn ordinary_header_still_forwards() {
    // Sanity: a normal ASCII value (the overwhelmingly common case) is unaffected by the fix.
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let (status, seen) = get_blob(&client, proxy, "/api/x", Some(b"plain-ascii")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(seen.as_ref(), b"plain-ascii");
}
