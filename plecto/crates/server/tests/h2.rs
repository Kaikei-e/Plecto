//! E2E (tdd-workflow Phase 0) for HTTP/2 termination (ADR 000015): drive a real **HTTP/2** request
//! through `plecto-server` over TLS, negotiated via ALPN. Asserts the handshake selects `h2`, then
//! a multiplexed h2 request routes, runs the chain, and forwards to the (HTTP/1.1) upstream — the
//! request processing path is identical to slice 1, only the wire protocol differs.
//!
//! A fresh self-signed cert (rcgen) backs the listener; a rustls client offers `h2` in its ALPN
//! list (alone, or alongside `http/1.1` to pin the server's h2-first preference) and drives an
//! `hyper` HTTP/2 client connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::ring};

use plecto_control::{Control, Host, Manifest, MemoryStore, ResolvedArtifact};
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use plecto_server::serve;

/// A fresh self-signed cert for `localhost`, written to a temp dir. Returns the dir (kept alive),
/// the cert + key paths for the manifest, and the cert DER for the client's trust store.
struct TestCert {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
    cert_der: CertificateDer<'static>,
}

fn make_cert() -> TestCert {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.key_pair.serialize_pem()).unwrap();
    TestCert {
        cert_der: generated.cert.der().clone(),
        cert_path: cert_path.to_str().unwrap().to_string(),
        key_path: key_path.to_str().unwrap().to_string(),
        _dir: dir,
    }
}

/// An HTTP/1.1 upstream that echoes a fixed body — Plecto terminates h2 on the client side but
/// forwards to the upstream over HTTP/1.1 (ADR 000015: upstream stays HTTP/1.1).
async fn echo(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(200)
        .header("x-from", "upstream")
        .body(Full::new(Bytes::from_static(b"upstream-ok")))
        .unwrap())
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(echo))
                    .await;
            });
        }
    });
    addr
}

/// A manifest declaring filter-hello, a `/api`→echo route, and a default (host-less) `[[tls]]` cert.
fn manifest_toml(upstream: SocketAddr, digest: &str, cert: &TestCert) -> String {
    format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "trusted"

[[upstream]]
name = "echo"
address = "{upstream}"

[[route]]
path_prefix = "/api"
filters = ["fh"]
upstream = "echo"
strip_prefix = "/api"

[[tls]]
cert_path = "{cert_path}"
key_path = "{key_path}"
"#,
        cert_path = cert.cert_path,
        key_path = cert.key_path,
    )
}

fn loaded_control(toml: &str) -> Control {
    let component = filter_hello_component();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom).unwrap();
    let mut store = MemoryStore::new();
    let digest = store.insert(
        "fh",
        ResolvedArtifact {
            component,
            component_signature,
            sbom,
            sbom_signature,
        },
    );
    let toml = toml.replace("{digest}", &digest);
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Control::load(host, &manifest, Box::new(store)).unwrap()
}

async fn spawn_proxy(control: Arc<Control>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, listener).await;
    });
    addr
}

/// What the client got: the ALPN protocol the handshake selected, plus the (status, body) of one
/// HTTP/2 GET `/api/hello` driven over the negotiated connection.
struct H2Result {
    negotiated_alpn: Option<Vec<u8>>,
    status: StatusCode,
    body: String,
}

/// Connect to `proxy` trusting `root`, offering `alpn_offer` in the ClientHello, then drive one
/// HTTP/2 request and report what came back.
async fn drive_h2(
    proxy: SocketAddr,
    root: CertificateDer<'static>,
    alpn_offer: &[&[u8]],
) -> H2Result {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_offer.iter().map(|p| p.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect(proxy).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let negotiated_alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("/api/hello")
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    H2Result {
        negotiated_alpn,
        status: parts.status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

#[tokio::test]
async fn negotiates_h2_then_routes_and_forwards() {
    let cert = make_cert();
    let upstream = spawn_upstream().await;
    let control = loaded_control(&manifest_toml(upstream, "{digest}", &cert));
    let proxy = spawn_proxy(Arc::new(control)).await;

    // A client that advertises ONLY h2.
    let r = drive_h2(proxy, cert.cert_der.clone(), &[b"h2"]).await;

    assert_eq!(
        r.negotiated_alpn.as_deref(),
        Some(b"h2".as_ref()),
        "ALPN must negotiate h2 when the client offers it"
    );
    assert_eq!(
        r.status,
        StatusCode::OK,
        "the h2 request routes + forwards 200"
    );
    assert_eq!(
        r.body, "upstream-ok",
        "the upstream body streams back over h2"
    );
}

#[tokio::test]
async fn prefers_h2_when_client_offers_both() {
    let cert = make_cert();
    let upstream = spawn_upstream().await;
    let control = loaded_control(&manifest_toml(upstream, "{digest}", &cert));
    let proxy = spawn_proxy(Arc::new(control)).await;

    // A client offering BOTH: the server's preference order (h2 first, ADR 000015) must win.
    let r = drive_h2(proxy, cert.cert_der.clone(), &[b"h2", b"http/1.1"]).await;

    assert_eq!(
        r.negotiated_alpn.as_deref(),
        Some(b"h2".as_ref()),
        "with both offered, the server prefers h2"
    );
    assert_eq!(r.status, StatusCode::OK);
}
