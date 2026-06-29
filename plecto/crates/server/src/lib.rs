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

mod access_log;
mod admin;
mod body;
mod h3;
mod headers;
mod health;
mod listener;
mod metrics;
mod proxy;
mod respond;

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::header::HeaderValue;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use plecto_control::Control;
use tokio::sync::Semaphore;

use crate::metrics::ServerMetrics;

pub use listener::serve;

/// A boxed, `Send` error — the unified error type for the boxed request/response bodies.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The response body the service yields: either a synthesised buffer (`Full`, for a short-circuit
/// or a fail-closed 5xx) or the upstream's streamed body (`Incoming`), unified behind one boxed
/// type so the service has a single return shape.
pub(crate) type ResponseBody = BoxBody<Bytes, BoxError>;

/// The request body forwarded to the upstream, boxed so one type covers every inbound transport:
/// the hyper `Incoming` (HTTP/1.1 + HTTP/2) and the QUIC/h3 recv stream (HTTP/3, ADR 000016). The
/// body streams straight through opaquely (header-only contract, ADR 000010) regardless of source.
pub(crate) type ReqBody = BoxBody<Bytes, BoxError>;

/// The pooling upstream client (hyper-util legacy): connection reuse to each upstream for free.
/// Plain HTTP/1.1 to the upstream; the inbound body (any transport) is boxed into `ReqBody`.
pub(crate) type UpstreamClient = Client<HttpConnector, ReqBody>;

/// Global cap on concurrently-served connections across all transports (CWE-770). A permit
/// is acquired BEFORE each accept, so at saturation the listener stops pulling new connections off
/// the OS backlog (natural backpressure) instead of spawning per-connection tasks unboundedly.
pub(crate) const MAX_CONNECTIONS: usize = 10_000;

/// Per-connection cap on concurrent HTTP/2 streams (ADR 000015). A fixed, conservative bound (not
/// yet manifest-configurable): it stops a single h2 connection from monopolising the fixed-capacity
/// M1 instance pool (ADR 000012) with concurrent chain dispatches, and is defence-in-depth against
/// stream-flooding DoS (the h2 crate already mitigates Rapid Reset, CVE-2023-44487). 100 is the
/// RFC 9113 recommended floor; hyper's own default is version-dependent and not API-stable, so we
/// pin it explicitly.
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 100;

/// Shared per-server state: the control plane (filters, routes, reload), the upstream client, and
/// the `Alt-Svc` header value advertising HTTP/3 (ADR 000016) — `Some` only when a QUIC listener is
/// bound, and added to TCP (HTTP/1.1 + HTTP/2) responses to steer capable clients to h3.
pub(crate) struct ServerState {
    control: Arc<Control>,
    client: UpstreamClient,
    alt_svc: Option<HeaderValue>,
    /// Global connection cap across TCP + QUIC: a permit is held for each connection's
    /// lifetime, so the server never serves more than `MAX_CONNECTIONS` at once.
    conn_limit: Arc<Semaphore>,
    /// Cap on concurrently-buffered request bodies for the `on-request-body` hook, bounding
    /// total buffered memory.
    body_buffer_limit: Arc<Semaphore>,
    /// Native data-plane metrics (Stage A observability, ADR 000009): RED signals tallied per
    /// request and served on the admin endpoint. Always recorded (cheap atomics); whether anyone
    /// can scrape them is gated by `[observability] admin_addr`.
    metrics: Arc<ServerMetrics>,
}

/// An upstream HTTP connector with `TCP_NODELAY` set. A proxy must disable Nagle on its upstream
/// sockets: with Nagle on, a streamed request body sent in several writes stalls ~40 ms on the
/// peer's delayed-ACK timer (surfaced by the body benchmark as a p99 cliff on large streamed
/// bodies). Disabling Nagle on proxy/upstream sockets is standard practice across mature L7 proxies.
/// Both the forwarding client and the health prober use it.
pub(crate) fn upstream_connector() -> HttpConnector {
    let mut c = HttpConnector::new();
    c.set_nodelay(true);
    c
}
