//! The admin endpoint (Stage A observability, ADR 000009): a small, SEPARATE HTTP/1.1 listener —
//! never the data-plane port — exposing Prometheus metrics and liveness/readiness. Bound only when
//! `[observability] admin_addr` is set (off by default), so proxied routes never collide with it and
//! the metrics surface is never reachable by data-plane clients (an Envoy-style admin interface).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::ServerState;

/// Bind `addr` and serve `/metrics`, `/healthz`, `/readyz` until the listener errors. A bind
/// failure disables the admin endpoint (logged) WITHOUT taking down the data plane — observability
/// is best-effort and never a reason to fail closed on serving traffic.
pub(crate) async fn serve_admin(state: Arc<ServerState>, addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(%addr, error = %e, "failed to bind admin endpoint; observability disabled");
            return;
        }
    };
    tracing::info!(%addr, "admin endpoint listening (/metrics /healthz /readyz)");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| admin_handle(state.clone(), req));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "admin connection closed with error");
            }
        });
    }
}

/// Route an admin request: `/metrics` renders the Prometheus exposition (native + filter-plane),
/// `/healthz` is liveness (the process is up), `/readyz` is readiness (it is serving). Anything
/// else is 404. The response builder is total (a fallback body on the impossible build error), so
/// the admin path never panics either.
async fn admin_handle(
    state: Arc<ServerState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (status, content_type, body) = match req.uri().path() {
        "/metrics" => (
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            state.metrics.render(&state.control.filter_metrics()),
        ),
        "/healthz" => (
            StatusCode::OK,
            "text/plain; charset=utf-8",
            "ok\n".to_string(),
        ),
        "/readyz" => (
            StatusCode::OK,
            "text/plain; charset=utf-8",
            "ready\n".to_string(),
        ),
        _ => (
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };
    let response = Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"admin error\n"))));
    Ok(response)
}
