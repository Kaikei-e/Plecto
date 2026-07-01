//! The fast-path listener: bind, spawn the health supervisor + the HTTP/3 endpoint, and run the
//! TCP accept loop. Each connection is HTTP/1.1, or HTTP/2 when TLS-ALPN negotiates `h2` (ADR
//! 000015); the per-request handling (route → chain → forward) is shared with all transports via
//! `proxy_core`. Graceful shutdown (ADR 000039): when the caller's shutdown future resolves, the
//! accept loops stop, every connection is told to finish its in-flight work and close (HTTP/1.1
//! stops keep-alive, HTTP/2 sends GOAWAY, HTTP/3 connections close), and connections still open
//! at the drain deadline are cut.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::header::HeaderValue;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use plecto_control::Control;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::body::MAX_INFLIGHT_BODY_BUFFERS;
use crate::dispatch::handle;
use crate::error::ServerError;
use crate::h3::{build_h3_endpoint, serve_h3};
use crate::health::serve_health_checks;
use crate::metrics::ServerMetrics;
use crate::upstream_client::HyperUpstreamClient;
use crate::{MAX_CONCURRENT_STREAMS, MAX_CONNECTIONS, ServerState, admin, upstream_connector};

/// Explicit cap on inbound request header lines. hyper's http1 default (~100) is documented
/// as not API-stable, so pin it — as `MAX_CONCURRENT_STREAMS` already does for h2.
const MAX_HEADERS: usize = 100;
/// How long a connection may take to send its request headers before it is dropped (slowloris on
/// headers). hyper enforces a header-read timeout ONLY when a timer is configured, so the
/// server sets both the timer and this value rather than relying on the (timer-less, inert) default.
const INBOUND_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Default drain window for graceful shutdown (ADR 000039), used by the shipped binary: generous
/// enough for normal in-flight requests (the default per-try upstream timeout is 30 s too) and
/// aligned with the common 30 s termination grace of process supervisors.
pub const DEFAULT_DRAIN_DEADLINE: Duration = Duration::from_secs(30);

/// Serve the fast path on an already-bound `listener` until it errors unrecoverably. Each accepted
/// connection is handled on its own task; the protocol is HTTP/1.1, or HTTP/2 when TLS-ALPN
/// negotiates `h2` (ADR 000015). A per-connection error is logged, not fatal. Bind with
/// `TcpListener::bind` (the caller picks the addr, so a test can use an ephemeral `127.0.0.1:0`
/// and read `local_addr`).
///
/// Public boundary stays `anyhow::Result` (bp-rust: typed errors are a library-internal
/// convention, not a public-API commitment) — the internal `ServerError` is `pub(crate)`, so a
/// caller in another crate could not even name it. `serve_inner` does the typed work.
pub async fn serve(control: Arc<Control>, listener: TcpListener) -> anyhow::Result<()> {
    serve_inner(
        control,
        listener,
        std::future::pending::<()>(),
        DEFAULT_DRAIN_DEADLINE,
    )
    .await
    .map_err(Into::into)
}

/// Serve like [`serve`], but stop accepting when `shutdown` resolves, drain in-flight
/// connections up to `drain_deadline`, then return `Ok` (ADR 000039). Connections still open at
/// the deadline are cut.
pub async fn serve_with_shutdown(
    control: Arc<Control>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    drain_deadline: Duration,
) -> anyhow::Result<()> {
    serve_inner(control, listener, shutdown, drain_deadline)
        .await
        .map_err(Into::into)
}

async fn serve_inner(
    control: Arc<Control>,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send,
    drain_deadline: Duration,
) -> Result<(), ServerError> {
    let tcp_addr = listener.local_addr().map_err(ServerError::Bind)?;

    // HTTP/3 (ADR 000016): when QUIC TLS is configured (i.e. there is `[[tls]]`), bind an
    // independent QUIC/UDP listener on the SAME port number as the TCP one and advertise it via
    // `Alt-Svc` on TCP responses. No TLS → no h3 (QUIC requires TLS), and no `Alt-Svc`.
    let quic_cfg = control.quic_tls_config();
    let alt_svc = quic_cfg.as_ref().and_then(|_| {
        HeaderValue::from_str(&format!("h3=\":{}\"; ma=86400", tcp_addr.port())).ok()
    });

    let state = Arc::new(ServerState {
        control,
        client: HyperUpstreamClient::new(
            Client::builder(TokioExecutor::new()).build(upstream_connector()),
        ),
        alt_svc,
        conn_limit: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        body_buffer_limit: Arc::new(Semaphore::new(MAX_INFLIGHT_BODY_BUFFERS)),
        metrics: Arc::new(ServerMetrics::new()),
    });

    // The drain flag (ADR 000039): flipped to `true` exactly once, at shutdown. Every connection
    // task holds a receiver and gracefully closes its connection when it flips; the h3 loops stop
    // accepting. `false` for the entire serving lifetime.
    let (drain_tx, drain_rx) = watch::channel(false);

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
                tokio::spawn(serve_h3(state.clone(), endpoint, drain_rx.clone()));
            }
            // a QUIC bind failure must not take down the TCP fast path; log and serve TCP only.
            Err(e) => {
                tracing::error!(error = %e, "failed to bind HTTP/3 listener; serving TCP only")
            }
        }
    }

    // Connection tasks live in a JoinSet so the drain deadline can cut the stragglers
    // (`abort_all`). Finished tasks are reaped opportunistically in the accept loop below.
    let mut conns = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        // Acquire a connection permit BEFORE accepting: at saturation we stop pulling
        // connections off the backlog (backpressure) rather than spawning tasks without bound. The
        // permit is moved into the connection task and released when it ends.
        let permit = tokio::select! {
            _ = &mut shutdown => break,
            // reap finished connection tasks so the JoinSet does not grow unboundedly
            Some(_) = conns.join_next() => continue,
            permit = state.conn_limit.clone().acquire_owned() => match permit {
                Ok(p) => p,
                Err(_) => return Ok(()), // semaphore closed → stop serving
            },
        };
        let (stream, peer) = tokio::select! {
            _ = &mut shutdown => break,
            Some(_) = conns.join_next() => continue, // the permit is re-acquired next iteration
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                // a transient accept error (e.g. fd exhaustion) must not kill the listener.
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };
        let state = state.clone();
        // The TLS config is read PER accept (ADR 000014): a reload's new certs apply to new
        // connections, while in-flight ones keep the cert they negotiated with. `None` → plain.
        let tls = state.control.tls_config();
        let drain = drain_rx.clone();
        conns.spawn(async move {
            let _permit = permit; // released when this connection task ends
            match tls {
                Some(cfg) => match TlsAcceptor::from(cfg).accept(stream).await {
                    Ok(tls_stream) => {
                        // ALPN picks the protocol: `h2` → HTTP/2, anything else (`http/1.1`, or no
                        // ALPN) → HTTP/1.1 (ADR 000015 — h2 over TLS+ALPN only). The connection
                        // terminated TLS, so the chain sees `https`.
                        let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_ref());
                        serve_conn(state, TokioIo::new(tls_stream), "https", h2, peer, drain).await;
                    }
                    // a failed TLS handshake (incl. ALPN mismatch) just drops the connection
                    // (fail-closed; nothing is forwarded), it is not a server error.
                    Err(e) => tracing::debug!(error = %e, "TLS handshake failed"),
                },
                // plaintext: HTTP/1.1 only — no h2c / prior-knowledge (ADR 000015). `http` scheme.
                None => serve_conn(state, TokioIo::new(stream), "http", false, peer, drain).await,
            }
        });
    }

    // Graceful shutdown (ADR 000039): stop accepting (drop the listener), flip the drain flag so
    // every connection finishes its in-flight work and closes, then wait for ALL connection
    // permits (TCP + QUIC share `conn_limit`) to come home — bounded by the drain deadline, after
    // which the stragglers are cut.
    drop(listener);
    let _ = drain_tx.send(true);
    let all_drained = state.conn_limit.acquire_many(MAX_CONNECTIONS as u32);
    if tokio::time::timeout(drain_deadline, all_drained)
        .await
        .is_ok()
    {
        tracing::info!("graceful shutdown: all connections drained");
    } else {
        tracing::warn!(
            deadline_ms = drain_deadline.as_millis() as u64,
            "graceful shutdown: drain deadline expired; cutting remaining connections"
        );
        conns.abort_all();
    }
    Ok(())
}

/// Resolve when the drain flag flips to `true` — or when the sender is gone (serve returned),
/// which closes the same way. A helper rather than an inline `wait_for` in `select!` arms:
/// `wait_for` yields a `watch::Ref` (a lock guard, not `Send`), and dropping it INSIDE this fn
/// keeps the surrounding connection future `Send` (spawnable).
pub(crate) async fn drained(drain: &mut watch::Receiver<bool>) {
    let _ = drain.wait_for(|d| *d).await;
}

/// Serve one connection: HTTP/2 when `h2` (the ALPN result), HTTP/1.1 otherwise. `scheme` is the
/// connection's wire scheme, passed through to the chain. Request handling (route → chain →
/// forward) is identical across protocols; only the wire framing differs — for h2 the multiplexed
/// streams each become one transaction, capped at `MAX_CONCURRENT_STREAMS` (ADR 000015). When the
/// drain flag flips (ADR 000039), the connection finishes its in-flight requests and closes —
/// hyper's `graceful_shutdown` disables HTTP/1.1 keep-alive (an idle connection closes at once)
/// and sends the HTTP/2 GOAWAY.
async fn serve_conn<I>(
    state: Arc<ServerState>,
    io: I,
    scheme: &'static str,
    h2: bool,
    peer: SocketAddr,
    mut drain: watch::Receiver<bool>,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle(state.clone(), scheme, peer, req));
    let result = if h2 {
        let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .serve_connection(io, service);
        tokio::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            // `wait_for` also completes when the sender is gone (serve returned) — same close.
            _ = drained(&mut drain) => {
                conn.as_mut().graceful_shutdown();
                conn.await
            }
        }
    } else {
        let conn = hyper::server::conn::http1::Builder::new()
            // enforce a header-read timeout (slowloris on headers) and an explicit
            // header-count cap. The header-read timeout only fires with a timer configured, so set
            // both rather than relying on hyper's timer-less (inert) default.
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(INBOUND_HEADER_READ_TIMEOUT)
            .max_headers(MAX_HEADERS)
            .serve_connection(io, service);
        tokio::pin!(conn);
        tokio::select! {
            res = conn.as_mut() => res,
            _ = drained(&mut drain) => {
                conn.as_mut().graceful_shutdown();
                conn.await
            }
        }
    };
    if let Err(e) = result {
        tracing::debug!(error = %e, "connection closed with error");
    }
}
