//! The fast-path listener: bind, spawn the health supervisor + the HTTP/3 endpoint, and run the
//! TCP accept loop. Each connection is HTTP/1.1, or HTTP/2 when TLS-ALPN negotiates `h2` (ADR
//! 000015); the per-request handling (route → chain → forward) is shared with all transports via
//! `proxy_core`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use plecto_control::Control;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::body::{MAX_INFLIGHT_BODY_BUFFERS, box_incoming};
use crate::h3::{build_h3_endpoint, serve_h3};
use crate::health::serve_health_checks;
use crate::metrics::ServerMetrics;
use crate::proxy::proxy_core;
use crate::respond::synth;
use crate::{
    MAX_CONCURRENT_STREAMS, MAX_CONNECTIONS, ResponseBody, ServerState, admin, upstream_connector,
};

/// Explicit cap on inbound request header lines. hyper's http1 default (~100) is documented
/// as not API-stable, so pin it — as `MAX_CONCURRENT_STREAMS` already does for h2.
const MAX_HEADERS: usize = 100;
/// How long a connection may take to send its request headers before it is dropped (slowloris on
/// headers). hyper enforces a header-read timeout ONLY when a timer is configured, so the
/// server sets both the timer and this value rather than relying on the (timer-less, inert) default.
const INBOUND_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

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
        metrics: Arc::new(ServerMetrics::new()),
    });

    // Admin endpoint (Stage A observability, ADR 000009): a SEPARATE listener for `/metrics` +
    // liveness/readiness, bound only when `[observability] admin_addr` is set. A bad address disables
    // it (logged) without affecting the data plane — observability never fails serving closed.
    if let Some(admin_addr) = state.control.admin_addr() {
        match admin_addr.parse::<SocketAddr>() {
            Ok(addr) => {
                tokio::spawn(admin::serve_admin(state.clone(), addr));
            }
            Err(e) => {
                tracing::error!(addr = admin_addr, error = %e, "invalid observability.admin_addr; admin endpoint disabled");
            }
        }
    }

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
