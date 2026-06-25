//! E2E (tdd-workflow Phase 0) for the M2 fast path (ADR 000013): drive real HTTP/1.1 requests
//! through a running `plecto-server` and assert the client-visible behaviour — routing by host +
//! path prefix, the route's filter chain (continue / short-circuit / response-edit), host-native
//! prefix strip on the forwarded path, and a 404 when no route matches. A fake hyper upstream
//! echoes the path it received so the strip is observable; filter-hello supplies the chain.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use plecto_control::{Control, Host, Manifest, MemoryStore, ResolvedArtifact};
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use plecto_server::serve;

/// A fake upstream: returns 200 with the path it received (`x-upstream-path`), an `x-from:
/// upstream` marker, an `x-plecto-respedit` header (so the response chain has something to act
/// on), and a fixed body. Lets a test prove the request reached the upstream and on what path.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    // Reflect the inbound `traceparent` so a test can prove the proxy continued the caller's trace
    // (review f000005 P1#2) rather than minting a fresh root.
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Reflect the forwarding headers the proxy set, so a test can prove edge-model overwrite
    // (review f000005 P2#3): the upstream sees Plecto's values, not the client's spoof.
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xfp = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // `X-Real-IP` is re-issued by Plecto (nginx convention); `CF-Connecting-IP` is part of the
    // stripped client-IP family but NOT re-issued — so a test can prove both halves of the edge
    // model (ADR 000022): the re-issued header carries the real peer, the dropped one is empty.
    let xrealip = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let cfip = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    Ok(Response::builder()
        .status(200)
        .header("x-upstream-path", path)
        .header("x-upstream-traceparent", traceparent)
        .header("x-upstream-xff", xff)
        .header("x-upstream-xfproto", xfp)
        .header("x-upstream-xrealip", xrealip)
        .header("x-upstream-cfip", cfip)
        .header("x-from", "upstream")
        .header("x-plecto-respedit", "1")
        .body(Full::new(Bytes::from_static(b"upstream-ok")))
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

/// Build a control plane: filter-hello signed + loaded as a trusted filter, a route `/api`
/// (strip `/api`) → that chain → the given upstream address.
fn control_for(upstream_addr: SocketAddr) -> Arc<Control> {
    let component = filter_hello_component();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom).unwrap();
    let mut store = MemoryStore::new();
    let digest = store.insert(
        "fh",
        ResolvedArtifact {
            component,
            component_signature,
            sbom,
            sbom_signature,
        },
    );
    let toml = format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "trusted"

[[upstream]]
name = "echo"
addresses = ["{upstream_addr}"]
[upstream.health]
path = "/healthz"
interval_ms = 50

[[route]]
path_prefix = "/api"
filters = ["fh"]
upstream = "echo"
strip_prefix = "/api"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(store)).unwrap())
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Send a GET through the proxy; return (status, response headers, body string).
async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    proxy: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, hyper::HeaderMap, String) {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy}{path}"));
    for (n, v) in headers {
        builder = builder.header(*n, *v);
    }
    let resp = client
        .request(builder.body(Empty::<Bytes>::new()).unwrap())
        .await
        .expect("proxy request");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Wait until the upstream's first health probe lands (ADR 000017): instances start pessimistic, so
/// a forward returns 503 until a probe passes. Poll a forwarding path until it stops being 503.
async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..100 {
        let (status, _, _) = get(client, proxy, "/api/__ready", &[]).await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy within the readiness window");
}

#[tokio::test]
async fn routes_runs_chain_strips_prefix_and_forwards() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let (status, headers, body) = get(&client, proxy, "/api/hello", &[]).await;

    assert_eq!(status, StatusCode::OK, "an unblocked request forwards 200");
    assert_eq!(body, "upstream-ok", "the upstream body streams through");
    assert_eq!(
        headers.get("x-from").and_then(|v| v.to_str().ok()),
        Some("upstream"),
        "the response came from the upstream (the chain continued)"
    );
    assert_eq!(
        headers.get("x-upstream-path").and_then(|v| v.to_str().ok()),
        Some("/hello"),
        "host-native strip_prefix removed /api before forwarding"
    );
    assert!(
        headers.contains_key("x-plecto-respadded"),
        "the response-side chain ran and applied the filter's response edit"
    );
}

#[tokio::test]
async fn short_circuit_never_reaches_upstream() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();

    let (status, headers, body) =
        get(&client, proxy, "/api/hello", &[("x-plecto-block", "1")]).await;

    assert_eq!(status, StatusCode::FORBIDDEN, "a blocked request gets 403");
    assert_eq!(
        body, "blocked by filter-hello",
        "the filter synthesised the body"
    );
    assert!(
        !headers.contains_key("x-from"),
        "a short-circuit must not reach the upstream"
    );
}

#[tokio::test]
async fn unmatched_route_is_404() {
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();

    let (status, headers, _body) = get(&client, proxy, "/nope", &[]).await;

    assert_eq!(status, StatusCode::NOT_FOUND, "no matching route → 404");
    assert_eq!(
        headers.get("x-plecto-fault").and_then(|v| v.to_str().ok()),
        Some("no-route"),
    );
}

#[tokio::test]
async fn continues_inbound_trace_context() {
    // review f000005 P1#2 / ADR 000009: a request carrying a W3C `traceparent` must have its trace
    // CONTINUED through Plecto — the traceparent forwarded upstream keeps the same trace-id, not a
    // freshly-minted root. (Before the fix `proxy_core` always called `snapshot()` = a new root.)
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let (status, headers, _body) =
        get(&client, proxy, "/api/hello", &[("traceparent", inbound)]).await;

    assert_eq!(status, StatusCode::OK);
    let forwarded = headers
        .get("x-upstream-traceparent")
        .and_then(|v| v.to_str().ok())
        .expect("the upstream received a traceparent");
    let trace_id = forwarded.split('-').nth(1).unwrap_or("");
    assert_eq!(
        trace_id, "4bf92f3577b34da6a3ce929d0e0e4736",
        "the inbound trace-id is preserved (the caller's trace continues, not a new root)"
    );
}

#[tokio::test]
async fn overwrites_spoofed_forwarded_headers_with_the_real_peer() {
    // review f000005 P2#3 / ADR 000018 + 000022: a client cannot forge its source IP. The whole
    // de-facto client-IP family is stripped — `X-Forwarded-For` AND `X-Real-IP` AND CDN headers
    // like `CF-Connecting-IP` — then `X-Forwarded-For` / `X-Real-IP` are re-issued from the real
    // connection peer (loopback in a test) and `X-Forwarded-Proto` from the wire scheme. So the
    // upstream (and any IP-based filter) sees Plecto's authoritative values, never the client's.
    let upstream = spawn_upstream().await;
    let proxy = spawn_proxy(control_for(upstream)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let (status, headers, _body) = get(
        &client,
        proxy,
        "/api/hello",
        &[
            ("x-forwarded-for", "9.9.9.9"),
            ("x-real-ip", "9.9.9.9"),
            ("cf-connecting-ip", "8.8.8.8"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get("x-upstream-xff").and_then(|v| v.to_str().ok()),
        Some("127.0.0.1"),
        "the spoofed X-Forwarded-For is replaced by the real loopback peer"
    );
    assert_eq!(
        headers
            .get("x-upstream-xrealip")
            .and_then(|v| v.to_str().ok()),
        Some("127.0.0.1"),
        "the spoofed X-Real-IP is replaced by the real loopback peer"
    );
    assert_eq!(
        headers.get("x-upstream-cfip").and_then(|v| v.to_str().ok()),
        Some(""),
        "a spoofed CF-Connecting-IP is stripped and not re-issued"
    );
    assert_eq!(
        headers
            .get("x-upstream-xfproto")
            .and_then(|v| v.to_str().ok()),
        Some("http"),
        "X-Forwarded-Proto reflects the plaintext connection"
    );
}
