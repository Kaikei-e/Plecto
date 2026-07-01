//! plecto — the fast-path binary (ADR 000013). Loads a declarative manifest, builds the control
//! plane (filters, routes, upstreams), and serves the fast path until terminated: HTTP/1.1 and
//! HTTP/2 over TCP, plus HTTP/3 over QUIC on the same port (UDP) when `[[tls]]` is configured.
//!
//! Usage: `plecto <manifest.toml> [listen_addr]` (listen defaults to `127.0.0.1:8080`).

use std::path::Path;
use std::sync::Arc;

use plecto_control::Control;
use plecto_server::serve;
use tokio::net::TcpListener;

fn main() -> anyhow::Result<()> {
    // Cap glibc malloc arenas BEFORE the runtime spawns worker threads (M_ARENA_MAX only gates new
    // arenas, so it must precede them) — a manual runtime build instead of `#[tokio::main]` is what
    // gives us that ordering. Bounds RSS on many-core hosts (docs/servey body-tax).
    plecto_server::cap_malloc_arenas();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    // JSON structured logging for the binary (Stage A observability, ADR 000009): the access log
    // (`plecto::access`) and the host diagnostics render as machine-parseable lines. `try_init` is
    // idempotent — a failure means a global subscriber is already installed (e.g. a test harness),
    // which we intentionally keep.
    let _logging = tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .try_init();

    let mut args = std::env::args().skip(1);
    let manifest = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: plecto <manifest.toml> [listen_addr]"))?;
    let listen = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());

    let control = Arc::new(Control::from_manifest_path(Path::new(&manifest))?);
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(%listen, version = %control.config_version(), "plecto fast path listening");
    serve(control, listener).await
}
