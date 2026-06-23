//! plecto-server — the M2 fast path (ADR 000013, TLS 000014, HTTP/2 000015).
//!
//! A tokio + hyper listener that turns Plecto from a library into an actual reverse proxy. It
//! serves HTTP/1.1, or HTTP/2 when TLS-ALPN negotiates `h2` (h2c is not supported — ADR 000015).
//! Per request it: builds a header-only `HttpRequest`, asks the control plane which route
//! matches (host + path prefix), runs that route's filter chain, and either responds now (a
//! filter short-circuited / failed closed) or forwards the request to the route's upstream and
//! runs the response side of the chain on the way back.
//!
//! **sync↔async bridge (the §6.3 prerequisite).** Filter execution is synchronous and runs on a
//! wasmtime `Store` that is `!Send`, so it cannot cross an `.await`. Each chain dispatch is moved
//! to tokio's blocking pool via `spawn_blocking`; the M1 trusted instance pool handles instance
//! reuse and saturation there. Route matching is pure config lookup and stays on the async thread.
//!
//! **Bodies are opaque (header-only contract, ADR 000010 / §6.7).** Filters never see the body;
//! the request body streams straight to the upstream and the response body streams straight back.
//! The chain only edits headers / status (and may synthesise a short-circuit body of its own).

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use plecto_control::{ChainOutcome, Control, Header, HttpRequest, HttpResponse};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The response body the service yields: either a synthesised buffer (`Full`, for a short-circuit
/// or a fail-closed 5xx) or the upstream's streamed body (`Incoming`), unified behind one boxed
/// type so the service has a single return shape.
type ResponseBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// The pooling upstream client (hyper-util legacy): connection reuse to each upstream for free.
/// Plain HTTP/1.1, the inbound body streamed straight through (`Incoming` as the request body).
type UpstreamClient = Client<HttpConnector, Incoming>;

/// Hop-by-hop headers a proxy must not forward (RFC 9110 §7.6.1). Stripped both ways so the
/// upstream's framing (`transfer-encoding`) and connection management never collide with the
/// fresh framing hyper computes for the leg we send.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Shared per-server state: the control plane (filters, routes, reload) and the upstream client.
struct ServerState {
    control: Arc<Control>,
    client: UpstreamClient,
}

/// Per-connection cap on concurrent HTTP/2 streams (ADR 000015). A fixed, conservative bound (not
/// yet manifest-configurable): it stops a single h2 connection from monopolising the fixed-capacity
/// M1 instance pool (ADR 000012) with concurrent chain dispatches, and is defence-in-depth against
/// stream-flooding DoS (the h2 crate already mitigates Rapid Reset, CVE-2023-44487). 100 is the
/// RFC 9113 recommended floor; hyper's own default is version-dependent and not API-stable, so we
/// pin it explicitly.
const MAX_CONCURRENT_STREAMS: u32 = 100;

/// Serve the fast path on an already-bound `listener` until it errors unrecoverably. Each accepted
/// connection is handled on its own task; the protocol is HTTP/1.1, or HTTP/2 when TLS-ALPN
/// negotiates `h2` (ADR 000015). A per-connection error is logged, not fatal. Bind with
/// `TcpListener::bind` (the caller picks the addr, so a test can use an ephemeral `127.0.0.1:0`
/// and read `local_addr`).
pub async fn serve(control: Arc<Control>, listener: TcpListener) -> anyhow::Result<()> {
    let state = Arc::new(ServerState {
        control,
        client: Client::builder(TokioExecutor::new()).build_http(),
    });

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            // a transient accept error (e.g. fd exhaustion) must not kill the listener.
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let state = state.clone();
        // The TLS config is read PER accept (ADR 000014): a reload's new certs apply to new
        // connections, while in-flight ones keep the cert they negotiated with. `None` → plain.
        let tls = state.control.tls_config();
        tokio::spawn(async move {
            match tls {
                Some(cfg) => match TlsAcceptor::from(cfg).accept(stream).await {
                    Ok(tls_stream) => {
                        // ALPN picks the protocol: `h2` → HTTP/2, anything else (`http/1.1`, or no
                        // ALPN) → HTTP/1.1 (ADR 000015 — h2 over TLS+ALPN only). The connection
                        // terminated TLS, so the chain sees `https`.
                        let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_ref());
                        serve_conn(state, TokioIo::new(tls_stream), "https", h2).await;
                    }
                    // a failed TLS handshake (incl. ALPN mismatch) just drops the connection
                    // (fail-closed; nothing is forwarded), it is not a server error.
                    Err(e) => tracing::debug!(error = %e, "TLS handshake failed"),
                },
                // plaintext: HTTP/1.1 only — no h2c / prior-knowledge (ADR 000015). `http` scheme.
                None => serve_conn(state, TokioIo::new(stream), "http", false).await,
            }
        });
    }
}

/// Serve one connection: HTTP/2 when `h2` (the ALPN result), HTTP/1.1 otherwise. `scheme` is the
/// connection's wire scheme, passed through to the chain. Request handling (route → chain →
/// forward) is identical across protocols; only the wire framing differs — for h2 the multiplexed
/// streams each become one transaction, capped at `MAX_CONCURRENT_STREAMS` (ADR 000015).
async fn serve_conn<I>(state: Arc<ServerState>, io: I, scheme: &'static str, h2: bool)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle(state.clone(), scheme, req));
    let result = if h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .serve_connection(io, service)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await
    };
    if let Err(e) = result {
        tracing::debug!(error = %e, "connection closed with error");
    }
}

/// The hyper service entry: never fails the connection (a proxy synthesises an error response
/// instead of dropping the socket), so the request handling's errors are mapped to a 502. `scheme`
/// is the connection's wire scheme (`"https"` if TLS-terminated, else `"http"`), surfaced to the
/// chain (ADR 000015).
async fn handle(
    state: Arc<ServerState>,
    scheme: &'static str,
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    Ok(match route_and_proxy(state, scheme, req).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "fast-path error");
            synth(StatusCode::BAD_GATEWAY, "upstream", b"upstream error")
        }
    })
}

/// Route → chain (request side) → forward → chain (response side). Returns the client-visible
/// response. Errors here are upstream/transport failures the caller maps to a 502.
async fn route_and_proxy(
    state: Arc<ServerState>,
    scheme: &'static str,
    req: Request<Incoming>,
) -> anyhow::Result<Response<ResponseBody>> {
    let (parts, body) = req.into_parts();
    let http_req = to_http_request(&parts, scheme);

    // One snapshot pins config + trace for the whole transaction (a concurrent reload cannot
    // desync the request and response halves); cloning it is a cheap Arc + trace-id clone.
    let snapshot = state.control.snapshot();
    let Some(route) = snapshot.find_route(&http_req.authority, &http_req.path) else {
        return Ok(synth(StatusCode::NOT_FOUND, "no-route", b"no route"));
    };
    let idx = route.index;

    // --- request side: the route's chain on the blocking pool (sync wasmtime, !Send Store) ---
    let snap_req = snapshot.clone();
    let forward = match tokio::task::spawn_blocking(move || {
        snap_req.dispatch_request(idx, http_req)
    })
    .await?
    {
        ChainOutcome::Respond(resp) => return Ok(http_response(resp)),
        ChainOutcome::Forward(req) => req,
    };

    // --- forward to the upstream, streaming the original request body opaquely ---
    let upstream_path = route.rewrite_path(&forward.path);
    let uri = format!("http://{}{}", route.upstream_address, upstream_path);
    let mut builder = Request::builder().method(forward.method.as_str()).uri(uri);
    copy_headers(builder.headers_mut(), &forward.headers);
    // continue the trace into the upstream (ADR 000009 W3C propagation).
    if let Some(h) = builder.headers_mut()
        && let Ok(v) = HeaderValue::from_str(&snapshot.traceparent())
    {
        h.insert("traceparent", v);
    }
    let upstream_resp = state.client.request(builder.body(body)?).await?;

    // --- response side: the route's chain in reverse (status / headers only) ---
    let (uparts, ubody) = upstream_resp.into_parts();
    let http_resp = HttpResponse {
        status: uparts.status.as_u16(),
        headers: headers_to_vec(&uparts.headers),
        body: Vec::new(), // header-only: filters never see the streamed body
    };
    let snap_resp = snapshot.clone();
    let edited =
        tokio::task::spawn_blocking(move || snap_resp.dispatch_response(idx, http_resp)).await?;

    // A response filter that trapped fail-closed yields a synthetic 5xx WITH a body; only then is
    // `body` non-empty (a normal response-edit can set status/headers but not a body). So: a
    // non-empty body means "use the synthetic response, drop the upstream stream"; an empty body
    // means "send the edited status + headers and stream the upstream body through".
    if edited.body.is_empty() {
        Ok(stream_response(edited.status, &edited.headers, ubody))
    } else {
        Ok(http_response(edited))
    }
}

/// Build a header-only `HttpRequest` (the chain's view) from the inbound request parts. The body
/// is handled separately (streamed), so it is absent here — the v0.1 contract is header-only.
///
/// `scheme` is the connection-level truth (`"https"` when the fast path terminated TLS on this
/// connection, `"http"` for plaintext) — not the request URI's scheme, which a client can spoof.
fn to_http_request(parts: &hyper::http::request::Parts, scheme: &str) -> HttpRequest {
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // authority: for HTTP/2 the `:authority` pseudo-header lands in the URI; for HTTP/1.1 it is the
    // Host header. Prefer the URI authority (h2), falling back to Host, then to empty.
    let authority = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            parts
                .headers
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    HttpRequest {
        method: parts.method.as_str().to_string(),
        path,
        authority,
        scheme: scheme.to_string(),
        headers: headers_to_vec(&parts.headers),
    }
}

/// Convert a hyper `HeaderMap` to the contract's `Vec<Header>`, lossily decoding values (HTTP
/// permits non-UTF-8 bytes; the contract is `string`). Hop-by-hop headers are dropped.
fn headers_to_vec(map: &hyper::HeaderMap) -> Vec<Header> {
    map.iter()
        .filter(|(name, _)| !is_hop_by_hop(name.as_str()))
        .map(|(name, value)| Header {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

/// Copy contract headers into a hyper `HeaderMap`, skipping hop-by-hop and any that fail hyper's
/// validation (a malformed name/value is dropped, never panics — data-plane no-panic).
fn copy_headers(dst: Option<&mut hyper::HeaderMap>, headers: &[Header]) {
    let Some(dst) = dst else { return };
    for h in headers {
        if is_hop_by_hop(&h.name) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_str(&h.value),
        ) {
            dst.append(name, value);
        }
    }
}

/// A synthesised response (short-circuit / fail-closed) → a hyper `Response` with a buffered body.
fn http_response(resp: HttpResponse) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    copy_headers(builder.headers_mut(), &resp.headers);
    builder.body(full(resp.body)).unwrap_or_else(|_| {
        // builder only errors on an invalid status/header already guarded above; stay total.
        Response::new(full(b"response build error".to_vec()))
    })
}

/// A forwarded response: the chain-edited status + headers, with the upstream body streamed.
fn stream_response(status: u16, headers: &[Header], body: Incoming) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    copy_headers(builder.headers_mut(), headers);
    builder
        .body(stream(body))
        .unwrap_or_else(|_| Response::new(full(b"response build error".to_vec())))
}

/// A small fail-closed response with an `x-plecto-fault` marker (404 no-route, 502 upstream).
fn synth(status: StatusCode, fault: &str, body: &'static [u8]) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("x-plecto-fault", fault)
        .body(full(body.to_vec()))
        .expect("static synth response is always valid")
}

/// A buffered body boxed into `ResponseBody` (its `Infallible` error widened to the boxed type).
fn full(bytes: Vec<u8>) -> ResponseBody {
    Full::new(Bytes::from(bytes))
        .map_err(|e: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match e {} })
        .boxed()
}

/// The upstream's streamed body boxed into `ResponseBody`.
fn stream(body: Incoming) -> ResponseBody {
    body.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(authority_in_uri: bool) -> hyper::http::request::Parts {
        let uri = if authority_in_uri {
            "https://h2.example/api/x"
        } else {
            "/api/x"
        };
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "h1.example")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn scheme_reflects_tls_termination_not_a_hardcoded_value() {
        // A TLS-terminated connection must surface `https` to the chain; plaintext surfaces `http`.
        // (The scheme is connection truth — what the fast path terminated — so a filter that, say,
        // redirects http→https can trust it.)
        assert_eq!(to_http_request(&parts(false), "https").scheme, "https");
        assert_eq!(to_http_request(&parts(false), "http").scheme, "http");
    }

    #[test]
    fn authority_prefers_h2_uri_authority_then_falls_back_to_host() {
        // HTTP/2 carries the host in the URI (`:authority`); HTTP/1.1 carries it in the Host header.
        assert_eq!(
            to_http_request(&parts(true), "https").authority,
            "h2.example"
        );
        assert_eq!(
            to_http_request(&parts(false), "http").authority,
            "h1.example"
        );
    }
}
