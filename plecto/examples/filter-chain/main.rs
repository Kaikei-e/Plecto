//! Plecto demo — **the filter chain** (the WASM extension plane).
//!
//! Run it:  `cargo run -p plecto-server --example filter-chain`
//!
//! Focuses on what a `plecto:filter` component does to a request as it passes through: the typed
//! `decision` (continue / modify / short-circuit) and host-native rate limiting. The bundled
//! `filter-hello` reacts to a few request headers:
//!   * (none)              -> continue; the request is forwarded, the response gains a header
//!   * x-plecto-addheader  -> modify; the filter adds `x-plecto-added: 1` (the upstream echoes it)
//!   * x-plecto-block      -> short-circuit 403; the upstream is never reached
//!   * x-plecto-ratelimit  -> consult a host-native token bucket (capacity 2): 200, 200, 429
//!
//! Plain HTTP/1.1 (no TLS) so the focus stays on the filter, not the transport. It still wires the
//! production load path: the filter is signed, bundled as an offline OCI layout, and loaded
//! fail-closed through `Control::from_manifest_path`. Temp dir, cleaned up on exit.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use plecto_control::oci::write_layout;
use plecto_control::{Control, ResolvedArtifact};
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use plecto_server::serve;

const PROXY_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let base = dir.path();

    let signer = TestSigner::new()?;
    std::fs::write(base.join("trust.pem"), signer.public_key_pem())?;
    let component = filter_hello_component();
    let component_signature = signer.sign(&component)?;
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom)?;
    let digest = write_layout(
        &base.join("filters/hello"),
        &ResolvedArtifact {
            component,
            component_signature,
            sbom,
            sbom_signature,
        },
    )?;

    let upstream = spawn_upstream().await?;
    let manifest_path = base.join("plecto.toml");
    std::fs::write(&manifest_path, manifest_toml(&digest, upstream))?;

    let control = Arc::new(Control::from_manifest_path(&manifest_path)?);

    let listener = TcpListener::bind(PROXY_ADDR).await?;
    let proxy = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = serve(control, listener).await {
            eprintln!("proxy stopped: {e}");
        }
    });

    print_banner(proxy);
    tokio::signal::ctrl_c().await?;
    println!("\nshutting down — temp dir cleaned up.");
    Ok(())
}

/// The echo upstream: echoes the path and any `x-plecto-added` the filter set, so a request-side
/// modify is observable, and sends `x-plecto-respedit` so the response-side chain has something to act on.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    let added = req
        .headers()
        .get("x-plecto-added")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("(none)")
        .to_string();
    let body = format!("upstream received: {path}\nx-plecto-added: {added}\n");
    Ok(Response::builder()
        .status(200)
        .header("x-from", "filter-chain-upstream")
        .header("x-plecto-respedit", "1")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn spawn_upstream() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(echo))
                    .await;
            });
        }
    });
    Ok(addr)
}

fn manifest_toml(digest: &str, upstream: SocketAddr) -> String {
    format!(
        r#"# Plecto demo manifest (generated) — one signed filter on a /api route, plain HTTP/1.1.
[trust]
keys = ["trust.pem"]

[[filter]]
id = "hello"
source = "filters/hello"
digest = "{digest}"
isolation = "trusted"
# Host-side token bucket for this filter (ADR 000026): capacity 2, no meaningful refill — so the
# `x-plecto-ratelimit` demo shows 200, 200, 429. Without it the host fails closed (deny) and the
# first request is already 429.
ratelimit = {{ capacity = 2, refill_tokens = 1, refill_interval_ms = 60000 }}

[[upstream]]
name = "app"
addresses = ["{upstream}"]
[upstream.health]
path = "/"

[[route]]
path_prefix = "/api"
filters = ["hello"]
upstream = "app"
strip_prefix = "/api"
"#
    )
}

fn print_banner(proxy: SocketAddr) {
    let p = proxy.port();
    println!("\n  Plecto demo — the filter chain (WASM extension plane)\n");
    println!("  proxy : http://localhost:{p}   (plain HTTP/1.1 — no -k needed)");
    println!("\n  Try it (Ctrl-C to stop):\n");
    println!("    curl -i http://localhost:{p}/api/hello");
    println!("        -> continue; /api stripped; forwarded; response gains x-plecto-respadded");
    println!("    curl -i -H 'x-plecto-addheader: 1' http://localhost:{p}/api/hello");
    println!("        -> modify; the upstream echoes  x-plecto-added: 1");
    println!("    curl -i -H 'x-plecto-block: 1' http://localhost:{p}/api/hello");
    println!("        -> short-circuit 403 (the upstream is never reached)");
    println!(
        "    for i in 1 2 3; do curl -s -o /dev/null -w '%{{http_code}}\\n' \
         -H 'x-plecto-ratelimit: 1' http://localhost:{p}/api/hello; done"
    );
    println!("        -> host-native token bucket (capacity 2): 200, 200, 429\n");
}
