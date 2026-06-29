//! Structured access logging (Stage A observability, ADR 000009). Opt-in via `[observability]
//! access_log`; one `tracing` event per request on the `plecto::access` target — never `println!`
//! (bp-rust DECREE 8) — so the binary's JSON subscriber renders it as a structured line and an
//! operator can route the `plecto::access` target wherever they like. Disabled by default; the
//! per-request fields are only captured when it is on, so a disabled log costs nothing.

use std::net::SocketAddr;
use std::time::Duration;

/// The request fields captured (in `crate::proxy`) BEFORE the transaction core consumes the request
/// parts. Held only while the access log is enabled.
pub(crate) struct Access {
    pub(crate) method: String,
    pub(crate) authority: String,
    pub(crate) path: String,
}

/// Emit one access-log event. Deliberately carries no secrets (no Authorization / Cookie value, and
/// the path without its query string — bp-rust): only method, authority, path, status, duration,
/// client IP and the connection scheme.
pub(crate) fn record(
    scheme: &str,
    peer: SocketAddr,
    access: &Access,
    status: u16,
    elapsed: Duration,
) {
    tracing::info!(
        target: "plecto::access",
        client = %peer.ip(),
        scheme = scheme,
        method = %access.method,
        authority = %access.authority,
        path = %access.path,
        status = status,
        duration_ms = elapsed.as_millis() as u64,
        "access"
    );
}
