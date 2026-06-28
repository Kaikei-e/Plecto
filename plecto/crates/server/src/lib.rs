//! plecto-server — the M2 fast path (ADR 000013, TLS 000014, HTTP/2 000015, HTTP/3 000016).
//!
//! A tokio listener that turns Plecto from a library into an actual reverse proxy. It serves
//! HTTP/1.1 and HTTP/2 over TCP (hyper, ALPN-negotiated — ADR 000015) and HTTP/3 over QUIC (quinn +
//! the h3 crate, an independent UDP listener advertised via `Alt-Svc` — ADR 000016). All three
//! transports feed the same transaction core (`proxy_core`); only the body adapters differ.
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

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use plecto_control::{
    ChainOutcome, Control, Header, HealthConfig, HttpRequest, HttpResponse, RequestBodyOutcome,
    RequestTrace, UpstreamInstance,
};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

/// A boxed, `Send` error — the unified error type for the boxed request/response bodies.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The response body the service yields: either a synthesised buffer (`Full`, for a short-circuit
/// or a fail-closed 5xx) or the upstream's streamed body (`Incoming`), unified behind one boxed
/// type so the service has a single return shape.
type ResponseBody = BoxBody<Bytes, BoxError>;

/// The request body forwarded to the upstream, boxed so one type covers every inbound transport:
/// the hyper `Incoming` (HTTP/1.1 + HTTP/2) and the QUIC/h3 recv stream (HTTP/3, ADR 000016). The
/// body streams straight through opaquely (header-only contract, ADR 000010) regardless of source.
type ReqBody = BoxBody<Bytes, BoxError>;

/// The pooling upstream client (hyper-util legacy): connection reuse to each upstream for free.
/// Plain HTTP/1.1 to the upstream; the inbound body (any transport) is boxed into `ReqBody`.
type UpstreamClient = Client<HttpConnector, ReqBody>;

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
    // Proxy-scoped credentials/challenges are hop-by-hop (RFC 9110 §11.7.1/§11.7.2): a
    // client's `Proxy-Authorization` must not leak to the upstream, nor an upstream's
    // `Proxy-Authenticate` back to the client.
    "proxy-authorization",
    "proxy-authenticate",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// The cap on a request body buffered for the `on-request-body` hook (ADR 000025). Buffer-then-
/// decide must bound memory: an unbounded buffer is a trivial OOM DoS, so a body larger than this
/// fails closed (413) rather than being read into RAM. A per-route override is a follow-up; the
/// constant keeps v1 safe. Header-only / bodyless requests never reach this path.
const MAX_REQUEST_BODY_BUFFER: usize = 16 << 20; // 16 MiB

/// Global cap on concurrently-served connections across all transports (CWE-770). A permit
/// is acquired BEFORE each accept, so at saturation the listener stops pulling new connections off
/// the OS backlog (natural backpressure) instead of spawning per-connection tasks unboundedly.
const MAX_CONNECTIONS: usize = 10_000;
/// Cap on request bodies buffered concurrently for the `on-request-body` hook. Bounds total
/// buffered memory at `MAX_INFLIGHT_BODY_BUFFERS × MAX_REQUEST_BODY_BUFFER`.
const MAX_INFLIGHT_BODY_BUFFERS: usize = 64;
/// Explicit cap on inbound request header lines. hyper's http1 default (~100) is documented
/// as not API-stable, so pin it — as `MAX_CONCURRENT_STREAMS` already does for h2.
const MAX_HEADERS: usize = 100;
/// How long a connection may take to send its request headers before it is dropped (slowloris on
/// headers). hyper enforces a header-read timeout ONLY when a timer is configured, so the
/// server sets both the timer and this value rather than relying on the (timer-less, inert) default.
const INBOUND_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the server spends reading a buffered request body before failing closed 408 (slow-body
/// slowloris): the body hook buffers, and an un-timed read would await trickled frames forever.
const INBOUND_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The set of header names DYNAMICALLY designated hop-by-hop by `Connection` (RFC 9110 §7.6.1):
/// `Connection: X-Foo, close` marks `X-Foo` connection-specific, so a proxy must not forward it.
/// Forwarding such a header is a request-smuggling / header-leak primitive, so we strip these too
/// — not just the static `HOP_BY_HOP` set (review f000005 P2#5). Tokens are lower-cased for the
/// case-insensitive name compare; `close` / `keep-alive` are inert (no such header to drop).
fn connection_named(map: &hyper::HeaderMap) -> HashSet<String> {
    let mut named = HashSet::new();
    for value in map.get_all(hyper::header::CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    named.insert(token.to_ascii_lowercase());
                }
            }
        }
    }
    named
}

/// Forwarding / client-IP headers a client could spoof: RFC 7239 `Forwarded`, the de-facto
/// `X-Forwarded-*`, and the de-facto client-IP family that many backends and CDNs trust (nginx's
/// `X-Real-IP`, Akamai/Cloudflare `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`,
/// `X-Client-IP`, `X-Cluster-Client-IP`). As an EDGE proxy Plecto strips this whole family on
/// ingress and sets its own (review f000005 P2#3 / ADR 000018 + 000022), so an untrusted client
/// cannot forge its source IP / scheme for an IP-based filter or the upstream — stripping `XFF`
/// alone would leave a spoofed `X-Real-IP` to fool a backend that reads it instead.
const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
];

/// Edge-proxy client-IP propagation: drop any client-supplied forwarding / client-IP headers
/// (`FORWARDED_HEADERS`), then set `X-Forwarded-For` and `X-Real-IP` (the real connection peer) and
/// `X-Forwarded-Proto` (the wire scheme) afresh. `X-Real-IP` is re-issued — not just stripped — so a
/// backend reading the nginx convention rather than `XFF` still gets Plecto's authoritative peer
/// (ADR 000022 widens ADR 000018's "issue For+Proto only"). The chain (so IP-based rate-limit / auth
/// filters can trust them) and the upstream then see only Plecto's values, never the client's claim.
/// A trusted-proxy *append* mode (Plecto behind another LB) is a manifest knob deferred to a later
/// slice; overwrite is the safe default.
fn set_forwarded(headers: &mut Vec<Header>, peer: IpAddr, scheme: &str) {
    headers.retain(|h| {
        !FORWARDED_HEADERS
            .iter()
            .any(|f| h.name.eq_ignore_ascii_case(f))
    });
    // An IPv4 client on a dual-stack ([::]) listener arrives as an IPv4-mapped IPv6 address
    // (`::ffff:a.b.c.d`); normalise it to dotted IPv4 so backends/filters that all-list on the IPv4
    // form match, and the value matches what nginx/Envoy would emit. A genuine IPv6 peer is kept
    // verbatim (no brackets — XFF carries a bare address).
    let client_ip = match peer {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    };
    headers.push(Header {
        name: "x-forwarded-for".to_string(),
        value: client_ip.clone(),
    });
    headers.push(Header {
        name: "x-real-ip".to_string(),
        value: client_ip,
    });
    headers.push(Header {
        name: "x-forwarded-proto".to_string(),
        value: scheme.to_string(),
    });
}

/// Shared per-server state: the control plane (filters, routes, reload), the upstream client, and
/// the `Alt-Svc` header value advertising HTTP/3 (ADR 000016) — `Some` only when a QUIC listener is
/// bound, and added to TCP (HTTP/1.1 + HTTP/2) responses to steer capable clients to h3.
struct ServerState {
    control: Arc<Control>,
    client: UpstreamClient,
    alt_svc: Option<HeaderValue>,
    /// Global connection cap across TCP + QUIC: a permit is held for each connection's
    /// lifetime, so the server never serves more than `MAX_CONNECTIONS` at once.
    conn_limit: Arc<Semaphore>,
    /// Cap on concurrently-buffered request bodies for the `on-request-body` hook, bounding
    /// total buffered memory.
    body_buffer_limit: Arc<Semaphore>,
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
    let tcp_addr = listener.local_addr()?;

    // HTTP/3 (ADR 000016): when QUIC TLS is configured (i.e. there is `[[tls]]`), bind an
    // independent QUIC/UDP listener on the SAME port number as the TCP one and advertise it via
    // `Alt-Svc` on TCP responses. No TLS → no h3 (QUIC requires TLS), and no `Alt-Svc`.
    let quic_cfg = control.quic_tls_config();
    let alt_svc = quic_cfg.as_ref().and_then(|_| {
        HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", tcp_addr.port())).ok()
    });

    let state = Arc::new(ServerState {
        control,
        client: Client::builder(TokioExecutor::new()).build(upstream_connector()),
        alt_svc,
        conn_limit: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        body_buffer_limit: Arc::new(Semaphore::new(MAX_INFLIGHT_BODY_BUFFERS)),
    });

    // Active health checks (ADR 000017): a background supervisor probes each upstream instance and
    // flips its healthy/unhealthy state, so the round-robin in `proxy_core` only ever picks live
    // instances. Spawned like the reload loop — the server owns the task, Control owns the state.
    tokio::spawn(serve_health_checks(state.control.clone()));

    if let Some(cfg) = quic_cfg {
        match build_h3_endpoint(cfg, tcp_addr) {
            Ok(endpoint) => {
                tracing::info!(port = tcp_addr.port(), "HTTP/3 (QUIC) listener bound");
                tokio::spawn(serve_h3(state.clone(), endpoint));
            }
            // a QUIC bind failure must not take down the TCP fast path; log and serve TCP only.
            Err(e) => {
                tracing::error!(error = %e, "failed to bind HTTP/3 listener; serving TCP only")
            }
        }
    }

    loop {
        // Acquire a connection permit BEFORE accepting: at saturation we stop pulling
        // connections off the backlog (backpressure) rather than spawning tasks without bound. The
        // permit is moved into the connection task and released when it ends.
        let permit = match state.conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Ok(()), // semaphore closed → stop serving
        };
        let (stream, peer) = match listener.accept().await {
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
            let _permit = permit; // released when this connection task ends
            match tls {
                Some(cfg) => match TlsAcceptor::from(cfg).accept(stream).await {
                    Ok(tls_stream) => {
                        // ALPN picks the protocol: `h2` → HTTP/2, anything else (`http/1.1`, or no
                        // ALPN) → HTTP/1.1 (ADR 000015 — h2 over TLS+ALPN only). The connection
                        // terminated TLS, so the chain sees `https`.
                        let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_ref());
                        serve_conn(state, TokioIo::new(tls_stream), "https", h2, peer).await;
                    }
                    // a failed TLS handshake (incl. ALPN mismatch) just drops the connection
                    // (fail-closed; nothing is forwarded), it is not a server error.
                    Err(e) => tracing::debug!(error = %e, "TLS handshake failed"),
                },
                // plaintext: HTTP/1.1 only — no h2c / prior-knowledge (ADR 000015). `http` scheme.
                None => serve_conn(state, TokioIo::new(stream), "http", false, peer).await,
            }
        });
    }
}

/// Serve one connection: HTTP/2 when `h2` (the ALPN result), HTTP/1.1 otherwise. `scheme` is the
/// connection's wire scheme, passed through to the chain. Request handling (route → chain →
/// forward) is identical across protocols; only the wire framing differs — for h2 the multiplexed
/// streams each become one transaction, capped at `MAX_CONCURRENT_STREAMS` (ADR 000015).
async fn serve_conn<I>(
    state: Arc<ServerState>,
    io: I,
    scheme: &'static str,
    h2: bool,
    peer: SocketAddr,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle(state.clone(), scheme, peer, req));
    let result = if h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .serve_connection(io, service)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            // enforce a header-read timeout (slowloris on headers) and an explicit
            // header-count cap. The header-read timeout only fires with a timer configured, so set
            // both rather than relying on hyper's timer-less (inert) default.
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(INBOUND_HEADER_READ_TIMEOUT)
            .max_headers(MAX_HEADERS)
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
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    // adapt the hyper inbound body (HTTP/1.1 + HTTP/2) into the transport-agnostic `ReqBody`.
    let (parts, incoming) = req.into_parts();
    let mut resp =
        match proxy_core(state.clone(), scheme, peer, parts, box_incoming(incoming)).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(error = %e, "fast-path error");
                synth(StatusCode::BAD_GATEWAY, "upstream", b"upstream error")
            }
        };
    // Advertise HTTP/3 on TCP responses (ADR 000016); h3 responses are not tagged (already h3).
    if let Some(av) = &state.alt_svc {
        resp.headers_mut()
            .insert(hyper::header::ALT_SVC, av.clone());
    }
    Ok(resp)
}

/// A retryable upstream failure (ADR 000023). A timeout may already have been acted on by the
/// upstream; a connect failure never reached it.
#[derive(Clone, Copy)]
enum Failure {
    Timeout,
    Connect,
}

/// RFC 9110 §9.2.2 idempotent methods — safe to retry on a timeout. Matched case-sensitively
/// (standard methods are uppercase tokens); any other token is treated as non-idempotent.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// Whether a failed forward MAY be retried on another instance (ADR 000023) — independent of whether
/// a different instance is actually available (the caller checks that). A retry needs remaining
/// budget and a replayable (bodyless) body; a timeout additionally needs an idempotent method, while
/// a connect failure is safe for any method (the upstream never received the request).
fn may_retry(failure: Failure, method: &str, bodyless: bool, tries_left: u64) -> bool {
    bodyless
        && tries_left > 0
        && match failure {
            Failure::Timeout => is_idempotent(method),
            Failure::Connect => true,
        }
}

/// The transport-agnostic transaction core: route → chain (request side) → forward → chain
/// (response side). Takes the request head + a boxed body (so HTTP/1.1, HTTP/2 and HTTP/3 all share
/// it) and returns the client-visible response. Errors here are upstream/transport failures the
/// caller maps to a 502.
async fn proxy_core(
    state: Arc<ServerState>,
    scheme: &'static str,
    peer: SocketAddr,
    parts: hyper::http::request::Parts,
    body: ReqBody,
) -> anyhow::Result<Response<ResponseBody>> {
    let mut http_req = to_http_request(&parts, scheme);

    // Normalize the request path once at ingress (CWE-22 Path Traversal / CWE-436
    // Interpretation Conflict): route selection, the filter chain, and the forwarded path then all
    // use the SAME normalized path, so the upstream cannot re-derive a stricter path than the
    // (possibly laxer, unfiltered) route we selected — closing the per-route-filter bypass. An
    // ambiguous (encoded-separator) or root-escaping path is rejected fail-closed.
    match plecto_control::normalize_path(&http_req.path) {
        Some(path) => http_req.path = path,
        None => {
            return Ok(synth(
                StatusCode::BAD_REQUEST,
                "bad-path",
                b"bad request path",
            ));
        }
    }

    // Client-IP propagation, edge model (ADR 000018 / review f000005 P2#3): strip any inbound
    // `X-Forwarded-*` / `Forwarded` (which an untrusted client can forge) and set them afresh from
    // the connection's real peer + scheme. Done BEFORE the chain so an IP-based rate-limit / auth
    // filter sees a value it can trust; the corrected headers then forward to the upstream.
    set_forwarded(&mut http_req.headers, peer.ip(), scheme);

    // Continue an inbound distributed trace (ADR 000009): if the caller sent a W3C `traceparent`,
    // parse it and pin the transaction to it so Plecto's filter spans JOIN the caller's trace
    // (and the traceparent forwarded upstream keeps the same trace-id) instead of starting a fresh
    // root. Fail-soft — a missing / malformed header falls back to a new root, never a panic on
    // untrusted input (review f000005 P1#2; `from_traceparent` is the fail-soft parser).
    let trace = parts
        .headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(RequestTrace::from_traceparent)
        .unwrap_or_else(RequestTrace::root);

    // One snapshot pins config + trace for the whole transaction (a concurrent reload cannot
    // desync the request and response halves); cloning it is a cheap Arc + trace-id clone.
    let snapshot = state.control.snapshot_with_trace(trace);
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

    // --- forward to a healthy instance, with bounded retry onto ANOTHER instance on a retryable
    // failure (ADR 000019 timeout / 000023 retry). The per-attempt invariants are computed once. ---
    let upstream_path = route.rewrite_path(&forward.path);
    let timeout = route.upstream.request_timeout();
    // Only a bodyless request can be retried without buffering: the opaque streamed body
    // (ADR 000013) can't be replayed. `exact() == Some(0)` is hyper's framing-accurate "no body".
    let bodyless = body.size_hint().exact() == Some(0);
    let mut real_body = Some(body);
    let mut tries_left = route.upstream.max_retries();

    // --- request-side body hook (ADR 000025): for a filtered route carrying a body, buffer it
    // (bounded), run the chain's `on-request-body`, and forward the possibly-transformed body — or
    // short-circuit before upstream. Header-only routes and bodyless requests skip this, keeping the
    // zero-copy streaming path. The chain runs on the blocking pool (sync wasmtime, !Send Store),
    // like the header chain. (v1 buffers; a header-only zero-copy bypass is a follow-up.)
    if route.has_filters
        && !bodyless
        && let Some(b) = real_body.take()
    {
        // Bound concurrent buffered-body memory and the time spent reading one body
        // (slow-body slowloris): hold a buffer permit and read under a deadline. Over the
        // size cap → 413, over the time budget → 408 — both fail closed (never an unbounded buffer).
        let _buf_permit = state.body_buffer_limit.clone().acquire_owned().await.ok();
        let buffered = match tokio::time::timeout(
            INBOUND_BODY_READ_TIMEOUT,
            buffer_request_body(b, MAX_REQUEST_BODY_BUFFER),
        )
        .await
        {
            Ok(Some(buf)) => buf,
            Ok(None) => {
                return Ok(synth(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body-too-large",
                    b"request body too large",
                ));
            }
            Err(_) => {
                return Ok(synth(
                    StatusCode::REQUEST_TIMEOUT,
                    "body-timeout",
                    b"request body read timeout",
                ));
            }
        };
        let snap_body = snapshot.clone();
        match tokio::task::spawn_blocking(move || snap_body.dispatch_request_body(idx, buffered))
            .await?
        {
            RequestBodyOutcome::Respond(resp) => return Ok(http_response(resp)),
            RequestBodyOutcome::Forward(edited) => real_body = Some(req_full(edited)),
        }
    }

    // First pick by round-robin; fail closed (503) if no instance is healthy (ADR 000017).
    let Some(mut instance) = route.upstream.pick() else {
        return Ok(synth(
            StatusCode::SERVICE_UNAVAILABLE,
            "no-healthy-upstream",
            b"no healthy upstream",
        ));
    };

    let upstream_resp = loop {
        // Build this attempt. A bodyless request re-sends an empty body to each instance; a bodied
        // one moves its single streamed body and (since `may_retry` is false for it) is sent once.
        let attempt_body = if bodyless {
            empty_req()
        } else {
            real_body.take().unwrap_or_else(empty_req)
        };
        let uri = format!("http://{}{}", instance.address(), upstream_path);
        let mut builder = Request::builder().method(forward.method.as_str()).uri(uri);
        // Forward the chain's headers, restoring byte-equivalence for any the filters left untouched
        // (P3#6): the contract's `string` values are lossy, but the original inbound bytes are still
        // here in `parts.headers`, so a pass-through header reaches the upstream byte-for-byte.
        copy_headers_preserving(builder.headers_mut(), &forward.headers, &parts.headers);
        // continue the trace into the upstream (ADR 000009 W3C propagation).
        if let Some(h) = builder.headers_mut()
            && let Ok(v) = HeaderValue::from_str(&snapshot.traceparent())
        {
            h.insert("traceparent", v);
        }
        let upstream_req = builder.body(attempt_body)?;

        // The timeout (ADR 000019) bounds time-to-response-headers; `Duration::ZERO` opts out. The
        // body then streams without a deadline, so streaming responses are unaffected.
        let send = state.client.request(upstream_req);
        let outcome = if timeout.is_zero() {
            Some(send.await)
        } else {
            tokio::time::timeout(timeout, send).await.ok()
        };

        match outcome {
            Some(Ok(resp)) => break resp,
            // The deadline elapsed before response headers. Not a health signal (ADR 000019) — leave
            // liveness to the active prober. Retry onto a DIFFERENT instance if policy allows and one
            // is available (idempotent-only, ADR 000023), else fail closed 504.
            None => {
                if may_retry(
                    Failure::Timeout,
                    forward.method.as_str(),
                    bodyless,
                    tries_left,
                ) && let Some(next) = route.upstream.pick_excluding(&instance)
                {
                    tries_left -= 1;
                    instance = next;
                    continue;
                }
                return Ok(synth(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream-timeout",
                    b"upstream timeout",
                ));
            }
            Some(Err(e)) => {
                // A connect failure passively ejects (ADR 000017) and is safe to retry for ANY method
                // (the upstream never received the request, ADR 000023). A non-connect transport
                // fault is neither a health signal nor retried — only the active prober governs
                // health then; the request fails closed (the caller maps the error to 502).
                if e.is_connect() {
                    instance.record_passive_failure();
                    if may_retry(
                        Failure::Connect,
                        forward.method.as_str(),
                        bodyless,
                        tries_left,
                    ) && let Some(next) = route.upstream.pick_excluding(&instance)
                    {
                        tries_left -= 1;
                        instance = next;
                        continue;
                    }
                }
                return Err(e.into());
            }
        }
    };

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
        Ok(stream_response(
            edited.status,
            &edited.headers,
            &uparts.headers,
            ubody,
        ))
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
/// permits non-UTF-8 bytes; the contract is `string`). Both the static hop-by-hop set AND any
/// header dynamically named by `Connection` are dropped (RFC 9110 §7.6.1) — this is the single
/// ingress point for both the request (from `parts`) and the response (from the upstream parts),
/// so a connection-specific header can never be carried into the contract and forwarded.
fn headers_to_vec(map: &hyper::HeaderMap) -> Vec<Header> {
    let named = connection_named(map);
    map.iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name.as_str()) && !named.contains(&name.as_str().to_ascii_lowercase())
        })
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

/// Like [`copy_headers`], but restores byte-equivalence for headers a filter never touched (P3#6).
/// The contract carries each header value as a lossy-UTF-8 `string`, so a value holding non-UTF-8
/// bytes (HTTP permits them) reaches the chain `U+FFFD`-mangled and would be re-encoded from that
/// mangled form — or dropped entirely by `HeaderValue::from_str`. For every contract header whose
/// `(name, value)` still matches an `original` inbound header's lossy projection (i.e. the filter
/// passed it through unchanged), the ORIGINAL bytes are forwarded verbatim; a value a filter set or
/// changed no longer matches and is encoded from the contract string exactly as `copy_headers` does.
/// This keeps pass-through headers byte-exact WITHOUT widening the WIT contract — the typed
/// `wasi:http` byte distinction is the eventual M3-convergence form (ADR 000020); this is the
/// host-side interim that needs no contract churn. It can only forward bytes the peer actually sent
/// under that name, and never resurrects a header the chain removed or replaced (we iterate the
/// chain's output), so it carries no smuggling/spoofing regression over `copy_headers`.
fn copy_headers_preserving(
    dst: Option<&mut hyper::HeaderMap>,
    headers: &[Header],
    original: &hyper::HeaderMap,
) {
    let Some(dst) = dst else { return };
    for h in headers {
        if is_hop_by_hop(&h.name) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(h.name.as_bytes()) else {
            continue;
        };
        // Prefer the original bytes when the chain left this header untouched: find an inbound value
        // under the same name whose lossy decoding equals the contract string. A match means the
        // filter passed it through, so forward the bytes verbatim; otherwise the filter set or
        // changed it and we encode from the contract string (dropping a value hyper rejects).
        let preserved = original
            .get_all(&name)
            .iter()
            .find(|v| String::from_utf8_lossy(v.as_bytes()) == h.value)
            .cloned();
        match preserved {
            Some(value) => {
                dst.append(name, value);
            }
            None => {
                if let Ok(value) = HeaderValue::from_str(&h.value) {
                    dst.append(name, value);
                }
            }
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
/// `original` is the upstream's inbound header map, so headers a response filter left untouched
/// stream back to the client byte-for-byte (P3#6), not via a lossy `string` round-trip.
fn stream_response(
    status: u16,
    headers: &[Header],
    original: &hyper::HeaderMap,
    body: Incoming,
) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    copy_headers_preserving(builder.headers_mut(), headers, original);
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
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}

/// The upstream's streamed body boxed into `ResponseBody`.
fn stream(body: Incoming) -> ResponseBody {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

/// Box a hyper `Incoming` inbound body into the transport-agnostic `ReqBody`.
fn box_incoming(body: Incoming) -> ReqBody {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

/// An empty `ReqBody` — used to re-send a bodyless request to another instance on retry (ADR
/// 000023), since the opaque streamed body (ADR 000013) cannot be replayed.
fn empty_req() -> ReqBody {
    Empty::<Bytes>::new()
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}

/// Buffer a request body for the `on-request-body` hook (ADR 000025), capped at `max` bytes.
/// Streams frame-by-frame so an over-cap body is rejected without first reading it all into memory;
/// returns `None` on over-cap OR a body read fault, so the caller fails closed (413) rather than
/// holding an unbounded buffer (data-plane no-panic / DoS-aware, bp-rust).
async fn buffer_request_body(mut body: ReqBody, max: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > max {
                return None;
            }
            buf.extend_from_slice(&data);
        }
    }
    Some(buf)
}

/// An upstream HTTP connector with `TCP_NODELAY` set. A proxy must disable Nagle on its upstream
/// sockets: with Nagle on, a streamed request body sent in several writes stalls ~40 ms on the
/// peer's delayed-ACK timer (surfaced by the body benchmark as a p99 cliff on large streamed
/// bodies). Disabling Nagle on proxy/upstream sockets is standard practice across mature L7 proxies.
/// Both the forwarding client and the health prober use it.
fn upstream_connector() -> HttpConnector {
    let mut c = HttpConnector::new();
    c.set_nodelay(true);
    c
}

/// A buffered request body (post `on-request-body` hook, ADR 000025) boxed into `ReqBody` — the
/// transformed body the fast path forwards in place of the original stream.
fn req_full(bytes: Vec<u8>) -> ReqBody {
    Full::new(Bytes::from(bytes))
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}

// ===== HTTP/3 (ADR 000016) =====
//
// An independent QUIC/UDP listener terminates HTTP/3, then feeds each request into the SAME
// `proxy_core` as the TCP path — only the wire transport and the body adapters differ. The request
// body (the h3 recv stream) is wrapped as an `http_body::Body` so it streams to the upstream, and
// the response body streams back out over the h3 send stream. RFC 9114 forbids connection-specific
// headers in HTTP/3 messages; `headers_to_vec`/`copy_headers` already strip the hop-by-hop set both
// ways, so what we send over h3 is compliant.

/// Build the QUIC `Endpoint` for HTTP/3 from control's QUIC TLS config, bound on the same port
/// number as the TCP listener (UDP). Caps concurrent request streams (see below).
fn build_h3_endpoint(
    quic_cfg: Arc<plecto_control::TlsServerConfig>,
    tcp_addr: SocketAddr,
) -> anyhow::Result<quinn::Endpoint> {
    let crypto = QuicServerConfig::try_from(quic_cfg)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    // Cap concurrent request streams per connection (mirrors ADR 000015's h2 cap): each h3 request
    // is one bidi stream → one chain dispatch, so this bounds one connection's draw on the M1 pool
    // and is defence-in-depth against stream-flood DoS. uni streams (h3 control / QPACK) keep
    // quinn's default. quinn itself enforces QUIC's 3x anti-amplification limit (RFC 9000 §8/§21),
    // so the endpoint can't be turned into a UDP reflector with a spoofed source address.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into());
    server_config.transport_config(Arc::new(transport));
    // Same port as the TCP listener, but UDP — an independent protocol namespace.
    let udp_addr = SocketAddr::new(tcp_addr.ip(), tcp_addr.port());
    Ok(quinn::Endpoint::server(server_config, udp_addr)?)
}

/// Accept QUIC connections, set up an h3 connection on each, and drive every request stream through
/// `handle_h3_request`. A per-connection / per-request error is logged, never fatal.
async fn serve_h3(state: Arc<ServerState>, endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        // Count a QUIC connection against the same global cap as TCP.
        let permit = match state.conn_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed → stop accepting
        };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when this connection task ends
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "QUIC connection failed");
                    return;
                }
            };
            // the client's address, captured before `conn` is moved into the h3 wrapper — fed to
            // `proxy_core` for X-Forwarded-For (ADR 000018), same as the TCP `accept()` peer.
            let peer = conn.remote_address();
            let mut h3conn = match h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
                h3_quinn::Connection::new(conn),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "h3 connection setup failed");
                    return;
                }
            };
            loop {
                match h3conn.accept().await {
                    Ok(Some(resolver)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_request(state, peer, resolver).await {
                                tracing::debug!(error = %e, "h3 request failed");
                            }
                        });
                    }
                    // graceful close (the client sent GOAWAY / closed the connection).
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "h3 accept failed");
                        break;
                    }
                }
            }
        });
    }
}

/// Handle one HTTP/3 request: split the bidi stream, wrap the recv half as the request body, run
/// the shared `proxy_core` (scheme is always `https` — h3 is always over TLS), then stream the
/// response head + body back over the send half.
async fn handle_h3_request(
    state: Arc<ServerState>,
    peer: SocketAddr,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> anyhow::Result<()> {
    let (req, stream) = resolver.resolve_request().await?;
    let (mut send, recv) = stream.split();
    let (parts, ()) = req.into_parts();
    let body = H3ReqBody { recv }.boxed();

    let resp = match proxy_core(state, "https", peer, parts, body).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "h3 fast-path error");
            synth(StatusCode::BAD_GATEWAY, "upstream", b"upstream error")
        }
    };

    let (rparts, mut rbody) = resp.into_parts();
    send.send_response(Response::from_parts(rparts, ())).await?;
    while let Some(frame) = rbody.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    send.send_data(data).await?;
                }
            }
            Err(e) => {
                // a mid-stream upstream body error: stop here and finish the stream.
                tracing::debug!(error = %e, "h3 response body error");
                break;
            }
        }
    }
    send.finish().await?;
    Ok(())
}

/// Adapts an HTTP/3 request's recv stream into an `http_body::Body`, so the request body streams to
/// the upstream like any other inbound body. One copy per chunk into `Bytes` (the recv buffer's
/// own type is opaque); the body is otherwise opaque pass-through.
struct H3ReqBody {
    recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl Body for H3ReqBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match this.recv.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut buf))) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== Active health checks (ADR 000017) =====
//
// One supervisor task drives ALL upstream instances. Each loop it reads the current upstream groups
// from Control — so a reload's reconciled add/remove is picked up automatically, with no per-
// instance task lifecycle to manage — and probes every instance whose `interval_ms` has elapsed. A
// brand-new instance (not yet seen) is probed immediately: that cold-start fast probe, with the
// first-success-promotes rule (ADR 000017), shrinks the pessimistic startup window to ~one probe
// RTT. Probes run on plain HTTP/1.1 (upstream TLS is deferred); each runs on its own task so a slow
// or timing-out probe never stalls the others.

/// Run the health-check supervisor until the server stops (ADR 000017). Drives `GET {health.path}`
/// to each upstream instance on its configured interval and feeds the result into the instance's
/// shared health state, which `proxy_core`'s round-robin then reads.
async fn serve_health_checks(control: Arc<Control>) {
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

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn hop_by_hop_set_is_recognised_case_insensitively() {
        // The exact RFC 9110 §7.6.1 connection-management set a proxy must never forward, plus
        // `transfer-encoding` — forwarding a client's `Transfer-Encoding`/`Connection` next to the
        // fresh framing hyper computes is the classic request-smuggling primitive (CWE-444).
        for h in [
            "connection",
            "Keep-Alive",
            "PROXY-CONNECTION",
            "Transfer-Encoding",
            "te",
            "Trailer",
            "upgrade",
            "Proxy-Authorization",
            "Proxy-Authenticate",
        ] {
            assert!(is_hop_by_hop(h), "{h} must be treated as hop-by-hop");
        }
        // a normal end-to-end header is not hop-by-hop.
        assert!(!is_hop_by_hop("x-api-key"));
        assert!(!is_hop_by_hop("content-type"));
    }

    #[test]
    fn headers_to_vec_strips_hop_by_hop_on_ingress() {
        // What the chain (and ultimately the upstream) sees must already be free of connection-
        // management headers: stripping them on the way in is half the smuggling defence (the
        // other half is `copy_headers` on the way out).
        let mut map = hyper::HeaderMap::new();
        map.insert("x-keep", HeaderValue::from_static("1"));
        map.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        map.insert(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        map.insert(hyper::header::TE, HeaderValue::from_static("trailers"));

        let out = headers_to_vec(&map);
        assert!(
            out.iter().all(|h| !is_hop_by_hop(&h.name)),
            "no hop-by-hop header may survive the ingress conversion"
        );
        assert!(
            out.iter().any(|h| h.name == "x-keep"),
            "an end-to-end header is preserved"
        );
    }

    #[test]
    fn headers_to_vec_strips_connection_named_headers() {
        // RFC 9110 §7.6.1 (review f000005 P2#5): a header NAMED by `Connection` is connection-
        // specific and must not be forwarded. A client using `Connection: x-secret` to smuggle
        // `x-secret` past the proxy is defeated; inert tokens (`close`) are ignored.
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("X-Secret, close"),
        );
        map.append("x-secret", HeaderValue::from_static("leak"));
        map.insert("x-keep", HeaderValue::from_static("1"));

        let out = headers_to_vec(&map);
        assert!(
            !out.iter().any(|h| h.name.eq_ignore_ascii_case("x-secret")),
            "a Connection-named header must be stripped"
        );
        assert!(
            !out.iter()
                .any(|h| h.name.eq_ignore_ascii_case("connection")),
            "Connection itself is hop-by-hop"
        );
        assert!(
            out.iter().any(|h| h.name == "x-keep"),
            "an unrelated end-to-end header survives"
        );
    }

    #[test]
    fn copy_headers_preserving_keeps_untouched_non_utf8_bytes() {
        // P3#6: a header value with non-UTF-8 bytes reaches the chain as a lossy `string`. When the
        // filter passes it through unchanged, the upstream must still receive the ORIGINAL bytes —
        // not the `U+FFFD`-mangled re-encoding, and not a drop (which is what `from_str` would do).
        let raw: &[u8] = &[0xC3, 0x28]; // invalid UTF-8
        let mut original = hyper::HeaderMap::new();
        original.insert("x-blob", HeaderValue::from_bytes(raw).unwrap());

        // the chain's view of that header == the lossy projection `headers_to_vec` produced.
        let contract = vec![header("x-blob", &String::from_utf8_lossy(raw))];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert_eq!(
            dst.get("x-blob").map(|v| v.as_bytes()),
            Some(raw),
            "an untouched header forwards byte-for-byte, not via the lossy string"
        );
    }

    #[test]
    fn copy_headers_preserving_uses_the_filter_value_when_changed() {
        // A header the filter REWROTE no longer matches the original's lossy projection, so the
        // chain's new value must win — preservation must never shadow an intentional edit.
        let mut original = hyper::HeaderMap::new();
        original.insert("x-user", HeaderValue::from_static("client-claim"));
        let contract = vec![header("x-user", "real-user")];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert_eq!(
            dst.get("x-user").and_then(|v| v.to_str().ok()),
            Some("real-user"),
            "a rewritten header forwards the chain's value, not the original"
        );
    }

    #[test]
    fn copy_headers_preserving_does_not_resurrect_a_removed_header() {
        // A header the chain dropped is absent from its output, so it must not reappear from
        // `original` — the reconciliation iterates the chain's output, never the original map.
        let mut original = hyper::HeaderMap::new();
        original.insert("x-secret", HeaderValue::from_static("leak"));
        let contract: Vec<Header> = vec![]; // filter removed it

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert!(
            !dst.contains_key("x-secret"),
            "a removed header is never resurrected from the original map"
        );
    }

    #[test]
    fn copy_headers_preserving_still_skips_hop_by_hop() {
        // The smuggling defence in `copy_headers` (CWE-444) must hold on this path too.
        let original = hyper::HeaderMap::new();
        let contract = vec![header("connection", "keep-alive"), header("x-keep", "1")];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert!(!dst.contains_key("connection"), "hop-by-hop is dropped");
        assert!(dst.contains_key("x-keep"), "an end-to-end header survives");
    }

    #[test]
    fn set_forwarded_overwrites_spoofed_client_headers() {
        // Edge model (review f000005 P2#3 / ADR 000018 + 000022): the whole de-facto client-IP
        // family — X-Forwarded-For / Forwarded / X-Real-IP / CDN headers — is STRIPPED and the
        // peer's value re-issued, never appended-to or trusted, so an untrusted client cannot forge
        // its source IP. X-Forwarded-For and X-Real-IP carry the real peer; X-Forwarded-Proto the
        // wire scheme; a stripped CDN header (CF-Connecting-IP) is NOT re-issued.
        let mut headers = vec![
            header("X-Forwarded-For", "9.9.9.9"),
            header("forwarded", "for=10.0.0.1"),
            header("X-Real-IP", "9.9.9.9"),
            header("cf-connecting-ip", "8.8.8.8"),
            header("x-keep", "1"),
        ];
        set_forwarded(&mut headers, "203.0.113.5".parse().unwrap(), "https");

        let xff: Vec<&str> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            xff,
            vec!["203.0.113.5"],
            "the spoofed XFF is replaced by the real peer (one value, not appended)"
        );
        let xrealip: Vec<&str> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("x-real-ip"))
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            xrealip,
            vec!["203.0.113.5"],
            "the spoofed X-Real-IP is replaced by the real peer (one value, re-issued)"
        );
        assert!(
            !headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("forwarded")),
            "a spoofed Forwarded header is stripped"
        );
        assert!(
            !headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("cf-connecting-ip")),
            "a spoofed CDN client-IP header is stripped and not re-issued"
        );
        assert_eq!(
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("x-forwarded-proto"))
                .map(|h| h.value.as_str()),
            Some("https"),
            "X-Forwarded-Proto reflects the connection scheme"
        );
        assert!(
            headers.iter().any(|h| h.name == "x-keep"),
            "an unrelated header is left intact"
        );
    }

    #[test]
    fn set_forwarded_normalises_ipv4_mapped_peer() {
        // An IPv4 client on a dual-stack ([::]) listener arrives as an IPv4-mapped IPv6 peer
        // (`::ffff:a.b.c.d`); X-Forwarded-For / X-Real-IP must carry the dotted IPv4 form so a
        // backend all-listing on the IPv4 address matches (ADR 000022).
        let mut headers = vec![];
        set_forwarded(&mut headers, "::ffff:203.0.113.5".parse().unwrap(), "https");
        for name in ["x-forwarded-for", "x-real-ip"] {
            assert_eq!(
                headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(name))
                    .map(|h| h.value.as_str()),
                Some("203.0.113.5"),
                "an IPv4-mapped peer normalises to dotted IPv4 in {name}"
            );
        }

        // A genuine IPv6 peer is preserved verbatim (no brackets in XFF).
        let mut headers = vec![];
        set_forwarded(&mut headers, "2001:db8::1".parse().unwrap(), "https");
        assert_eq!(
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("x-forwarded-for"))
                .map(|h| h.value.as_str()),
            Some("2001:db8::1"),
            "a real IPv6 peer is kept as-is"
        );
    }

    #[test]
    fn copy_headers_drops_hop_by_hop_crlf_and_malformed_names() {
        // Egress side: a filter (or a buggy/hostile one) must not be able to smuggle framing or
        // inject a header via an embedded CRLF (CWE-113) or a malformed name. `copy_headers` drops
        // each silently and never panics (data-plane discipline) — and the rest still copies.
        let mut dst = hyper::HeaderMap::new();
        copy_headers(
            Some(&mut dst),
            &[
                header("x-ok", "fine"),
                header("transfer-encoding", "chunked"), // hop-by-hop → dropped
                header("x-evil", "a\r\nInjected: pwned"), // CRLF in value → dropped
                header("bad name", "x"),                // space in name → invalid → dropped
                header("", "x"),                        // empty name → invalid → dropped
            ],
        );

        assert_eq!(
            dst.get("x-ok").and_then(|v| v.to_str().ok()),
            Some("fine"),
            "a valid end-to-end header is copied"
        );
        assert!(
            !dst.contains_key("transfer-encoding"),
            "a filter cannot re-introduce a hop-by-hop header"
        );
        assert!(
            !dst.contains_key("x-evil") && !dst.contains_key("injected"),
            "a CRLF-bearing value is rejected, not split into a second header"
        );
        assert_eq!(dst.len(), 1, "only the one valid header survives");
    }

    #[test]
    fn http_response_clamps_invalid_status_and_drops_invalid_headers_without_panicking() {
        // A short-circuit / fail-closed response carries a filter-supplied `u16` status and
        // arbitrary headers. An out-of-range status must clamp to 502 (never panic), and an
        // invalid header value must be dropped — the data plane must survive hostile filter output.
        for bad_status in [0u16, 99, 1000] {
            let resp = http_response(HttpResponse {
                status: bad_status,
                headers: vec![],
                body: Vec::new(),
            });
            assert_eq!(
                resp.status(),
                StatusCode::BAD_GATEWAY,
                "an out-of-range status ({bad_status}) clamps to 502"
            );
        }

        // a valid status is preserved; a CRLF-bearing header is dropped, a clean one kept.
        let resp = http_response(HttpResponse {
            status: 403,
            headers: vec![header("x-clean", "ok"), header("x-evil", "a\r\nb")],
            body: b"denied".to_vec(),
        });
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().contains_key("x-clean"));
        assert!(
            !resp.headers().contains_key("x-evil"),
            "an invalid header value is dropped from a synthesised response"
        );
    }

    #[test]
    fn idempotent_methods_per_rfc_9110() {
        for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert!(is_idempotent(m), "{m} is idempotent (RFC 9110 §9.2.2)");
        }
        for m in ["POST", "PATCH", "CONNECT", "get", ""] {
            assert!(!is_idempotent(m), "{m} is not idempotent");
        }
    }

    #[test]
    fn may_retry_gates_on_failure_method_body_and_budget() {
        // A timeout retries only for an idempotent method (the upstream may have acted).
        assert!(may_retry(Failure::Timeout, "GET", true, 1));
        assert!(!may_retry(Failure::Timeout, "POST", true, 1));
        // A connect failure never reached the upstream → safe for ANY method.
        assert!(may_retry(Failure::Connect, "POST", true, 1));
        assert!(may_retry(Failure::Connect, "GET", true, 1));
        // A bodied request can't be replayed (no buffering) → never retried, either failure.
        assert!(!may_retry(Failure::Timeout, "GET", false, 1));
        assert!(!may_retry(Failure::Connect, "POST", false, 1));
        // Exhausted budget → no retry.
        assert!(!may_retry(Failure::Timeout, "GET", true, 0));
        assert!(!may_retry(Failure::Connect, "GET", true, 0));
    }
}
