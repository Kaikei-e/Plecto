//! upstream — a standalone HTTP/1.1 backend for the memory-matrix bench (mem-matrix.sh).
//!
//! The other harnesses spawn their upstream in-process (same PID as the proxy), which is fine for
//! throughput but fatal for a MEMORY investigation: the proxy's RSS then also holds the upstream's
//! request-body drain buffers and response buffers, so you cannot attribute a byte. This runs the
//! upstream as its OWN process (pin it to its own cores), so `/proc/<proxy_pid>/smaps_rollup`
//! measures the proxy alone.
//!
//! It drains the request body (so POST bodies + keep-alive work), optionally sleeps
//! `BACKEND_LATENCY_MS`, then returns a `RESP_BYTES`-sized body. Bind address from `UPSTREAM_ADDR`
//! (default 127.0.0.1:28090).

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::time::Duration;
use tokio::net::TcpListener;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::var("UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:28090".to_string());
    let resp_bytes = env_u64("RESP_BYTES", 16) as usize;
    let latency_ms = env_u64("BACKEND_LATENCY_MS", 0);

    let listener = TcpListener::bind(&addr).await?;
    let local = listener.local_addr()?;
    let body = Bytes::from(vec![b'x'; resp_bytes]);
    println!(
        "upstream listening on http://{local} (resp_bytes={resp_bytes}, latency={latency_ms}ms)"
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let body = body.clone();
                async move {
                    // Drain the request body so the connection stays reusable and we model an
                    // upstream that actually consumes what the body hook forwarded.
                    let _ = req.into_body().collect().await;
                    if latency_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(latency_ms)).await;
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("x-from", "backend")
                            .body(Full::new(body))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}
