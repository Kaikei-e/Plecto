//! plecto — the fast-path binary (ADR 000013). Loads a declarative manifest, builds the control
//! plane (filters, routes, upstreams), and serves the fast path: HTTP/1.1 and HTTP/2 over TCP,
//! plus HTTP/3 over QUIC on the same port (UDP) when `[[tls]]` is configured. SIGHUP re-reads the
//! manifest and swaps it in without downtime (ADR 000008 / 000039); SIGTERM / SIGINT stop
//! accepting, drain in-flight connections, and exit cleanly (ADR 000039).
//!
//! Usage: `plecto <manifest.toml> [listen_addr]` (listen defaults to `127.0.0.1:8080`).

use std::path::Path;
use std::sync::Arc;

use plecto_control::Control;
use plecto_server::{DEFAULT_DRAIN_DEADLINE, serve_with_shutdown};
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

    // The SIGHUP reload loop (ADR 000008 / 000039): `from_manifest_path` remembers the path, so
    // each SIGHUP re-reads the on-disk manifest and swaps it in atomically, fail-closed (a bad
    // edit keeps the current set live). `serve_reloads` is a blocking loop, so it runs on its own
    // thread beside the async data plane. Signals are a unix concept; elsewhere the config is
    // static for the process lifetime.
    #[cfg(unix)]
    {
        let control = control.clone();
        std::thread::spawn(move || match plecto_control::SignalReloadSource::sighup() {
            Ok(mut source) => plecto_control::serve_reloads(&control, &mut source),
            Err(e) => {
                tracing::error!(error = %e, "cannot register SIGHUP handler; hot reload disabled")
            }
        });
    }

    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(%listen, version = %control.config_version(), "plecto fast path listening");
    serve_with_shutdown(control, listener, shutdown_signal(), DEFAULT_DRAIN_DEADLINE).await?;
    tracing::info!("plecto fast path stopped");
    Ok(())
}

/// Resolves on the operator's "stop serving" signal — SIGTERM (process supervisors) or SIGINT
/// (ctrl-c) — triggering graceful shutdown (ADR 000039): accept stops, in-flight connections
/// drain up to `DEFAULT_DRAIN_DEADLINE`, then the process exits 0.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot register SIGTERM handler; ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
