//! A runnable Plecto demo — a real reverse proxy, end to end.
//!
//! Run it:  `cargo run -p plecto-server --example demo`
//!
//! It wires the **production load path** (nothing is faked): it signs the bundled `filter-hello`
//! component, packages it as an offline OCI image-layout, generates a self-signed TLS cert, writes
//! a declarative manifest, and builds the control plane with `Control::from_manifest_path` — the
//! same entrypoint the `plecto` binary uses. Then it starts a tiny echo upstream and serves the
//! fast path over **HTTPS**, routing `/api/*` through the signed filter to the upstream.
//!
//! The signing here uses the host's throwaway test signer (a fresh key each run) — convenient for
//! a demo, NOT production provenance. Everything lives in a temp dir that is cleaned up on exit.

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

/// Where the HTTPS proxy listens. Plain `127.0.0.1` so the demo never exposes a public port.
const PROXY_ADDR: &str = "127.0.0.1:8443";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let base = dir.path();

    // 1. trust root + signer: write the public key the manifest trusts, keep the signer to sign.
    let signer = TestSigner::new()?;
    std::fs::write(base.join("trust.pem"), signer.public_key_pem())?;

    // 2. sign filter-hello and bundle it as an offline OCI image-layout (ADR 000006 / 000007).
    let component = filter_hello_component();
    let component_signature = signer.sign(&component)?;
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom)?;
    let artifact = ResolvedArtifact {
        component,
        component_signature,
        sbom,
        sbom_signature,
    };
    let digest = write_layout(&base.join("filters/hello"), &artifact)?;

    // 3. a fresh self-signed TLS cert for `localhost` (ADR 000014).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    std::fs::create_dir_all(base.join("tls"))?;
    std::fs::write(base.join("tls/cert.pem"), cert.cert.pem())?;
    std::fs::write(base.join("tls/key.pem"), cert.key_pair.serialize_pem())?;

    // 4. a tiny upstream that echoes what it received (so the route + prefix strip are visible).
    let upstream = spawn_upstream().await?;

    // 5. the declarative manifest — exactly what an operator would write.
    let manifest_path = base.join("plecto.toml");
    std::fs::write(&manifest_path, manifest_toml(&digest, upstream))?;

    // 6. build the control plane through the real ops entrypoint (reads keys, OCI layout, certs;
    //    verifies the signature + SBOM; loads the filter; builds the TLS config — all fail-closed).
    let control = Arc::new(Control::from_manifest_path(&manifest_path)?);

    // 7. serve the fast path. The manifest has `[[tls]]`, so this is HTTPS.
    let listener = TcpListener::bind(PROXY_ADDR).await?;
    let proxy = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(e) = serve(control, listener).await {
            eprintln!("proxy stopped: {e}");
        }
    });

    print_banner(proxy, upstream, &manifest_path);
    tokio::signal::ctrl_c().await?;
    println!("\nshutting down — temp dir cleaned up.");
    Ok(())
}

/// The echo upstream: returns what it received so the stripped path and any filter-added header
/// are observable, and sends `x-plecto-respedit` so the response-side chain has something to do.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
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
    let body = format!("demo upstream received: {method} {path}\nx-plecto-added: {added}\n");
    Ok(Response::builder()
        .status(200)
        .header("x-from", "demo-upstream")
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
        r#"# Plecto demo manifest (generated). Trust root, one signed filter, one route, TLS.
[trust]
keys = ["trust.pem"]

[[filter]]
id = "hello"
source = "filters/hello"
digest = "{digest}"
isolation = "trusted"

[[upstream]]
name = "demo-upstream"
address = "{upstream}"

[[route]]
path_prefix = "/api"
filters = ["hello"]
upstream = "demo-upstream"
strip_prefix = "/api"

[[tls]]
cert_path = "tls/cert.pem"
key_path = "tls/key.pem"
"#
    )
}

fn print_banner(proxy: SocketAddr, upstream: SocketAddr, manifest: &std::path::Path) {
    let p = proxy.port();
    println!("\n  Plecto demo — a real reverse proxy (signed WASM filter + TLS + routing)\n");
    println!("  HTTPS proxy : https://localhost:{p}   (self-signed cert — use curl -k)");
    println!("  upstream    : http://{upstream}  (echoes what it received)");
    println!("  manifest    : {}", manifest.display());
    println!("\n  Try it (Ctrl-C to stop):\n");
    println!("    curl -k https://localhost:{p}/api/hello");
    println!("        -> routed; /api stripped; forwarded (upstream sees /hello);");
    println!("           the response gains x-plecto-respadded from the response-side chain");
    println!("    curl -k -H 'x-plecto-addheader: 1' https://localhost:{p}/api/hello");
    println!("        -> the filter rewrites the request; upstream echoes x-plecto-added: 1");
    println!("    curl -k -H 'x-plecto-block: 1' https://localhost:{p}/api/hello");
    println!("        -> the filter short-circuits 403 (never reaches the upstream)");
    println!(
        "    for i in 1 2 3; do curl -k -s -o /dev/null -w '%{{http_code}}\\n' \
         -H 'x-plecto-ratelimit: 1' https://localhost:{p}/api/hello; done"
    );
    println!("        -> host-native token bucket (capacity 2): 200, 200, 429");
    println!("    curl -k https://localhost:{p}/nope");
    println!("        -> no matching route -> 404\n");
}
