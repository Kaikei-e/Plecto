//! E2E (tdd-workflow Phase 0) for graceful shutdown (ADR 000039): `serve_with_shutdown` must stop
//! accepting when the shutdown future resolves, drain in-flight requests up to the drain deadline,
//! cut connections that outlive it, and not let idle keep-alive connections hold the drain open.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use plecto_control::{Control, Host, Manifest, MemoryStore, ResolvedArtifact};
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use plecto_server::serve_with_shutdown;

/// A fake upstream that answers instantly EXCEPT on `/slow`, where it sleeps `delay` before
/// responding — so a test can hold a request in flight across the shutdown trigger while health
/// probes (`/healthz`) and readiness polls stay fast.
async fn spawn_upstream(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |req: Request<Incoming>| async move {
                            if req.uri().path() == "/slow" {
                                tokio::time::sleep(delay).await;
                            }
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(200)
                                    .body(Full::new(Bytes::from_static(b"upstream-ok")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

/// Build a control plane: filter-hello signed + loaded as a trusted filter, a route `/api`
/// (strip `/api`) → that chain → the given upstream address (same shape as `tests/e2e.rs`).
fn control_for(upstream_addr: SocketAddr) -> Arc<Control> {
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
    let toml = format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "trusted"

[[upstream]]
name = "echo"
addresses = ["{upstream_addr}"]
[upstream.health]
path = "/healthz"
interval_ms = 50

[[route]]
filters = ["fh"]
upstream = "echo"
strip_prefix = "/api"
[route.match]
path_prefix = "/api"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(store)).unwrap())
}

/// Spawn the proxy under test on an ephemeral port with a oneshot-triggered shutdown and the
/// given drain deadline. Returns the bound addr, the trigger, and the serve task's handle.
async fn spawn_proxy(
    control: Arc<Control>,
    drain_deadline: Duration,
) -> (
    SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<anyhow::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(serve_with_shutdown(
        control,
        listener,
        async move {
            let _ = rx.await;
        },
        drain_deadline,
    ));
    (addr, tx, handle)
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// Send a GET through the proxy; `Err` when the connection was refused or cut mid-response.
async fn try_get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    proxy: SocketAddr,
    path: &str,
) -> anyhow::Result<(StatusCode, String)> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy}{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = client.request(req).await?;
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await?.to_bytes();
    Ok((parts.status, String::from_utf8_lossy(&bytes).into_owned()))
}

/// Wait until the upstream's first health probe lands (instances start pessimistic, ADR 000017).
async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..100 {
        if let Ok((status, _)) = try_get(client, proxy, "/api/__ready").await
            && status != StatusCode::SERVICE_UNAVAILABLE
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy within the readiness window");
}

#[tokio::test]
async fn graceful_shutdown_drains_inflight_and_stops_accepting() {
    let upstream = spawn_upstream(Duration::from_millis(400)).await;
    let (proxy, shutdown, server) =
        spawn_proxy(control_for(upstream), Duration::from_secs(5)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    // Hold a request in flight (the upstream sleeps 400 ms on /slow), then trigger shutdown.
    let inflight = {
        let client = client.clone();
        tokio::spawn(async move { try_get(&client, proxy, "/api/slow").await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.send(()).unwrap();

    let (status, body) = inflight
        .await
        .unwrap()
        .expect("the in-flight request must complete during the drain window");
    assert_eq!(status, StatusCode::OK, "drained response is the real one");
    assert_eq!(body, "upstream-ok");

    let served = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("serve must return once in-flight connections drained")
        .unwrap();
    served.expect("a drained shutdown is a clean (Ok) exit");

    // Accept stopped: a fresh TCP connect must be refused after shutdown.
    assert!(
        tokio::net::TcpStream::connect(proxy).await.is_err(),
        "the listener must be closed after shutdown"
    );
}

#[tokio::test]
async fn drain_deadline_cuts_off_connections_that_outlive_it() {
    // The upstream would hold /slow for 10 s, far beyond the 200 ms drain deadline.
    let upstream = spawn_upstream(Duration::from_secs(10)).await;
    let (proxy, shutdown, server) =
        spawn_proxy(control_for(upstream), Duration::from_millis(200)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    let inflight = {
        let client = client.clone();
        tokio::spawn(async move { try_get(&client, proxy, "/api/slow").await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.send(()).unwrap();

    // The deadline bounds shutdown: serve returns in ~200 ms, NOT after the upstream's 10 s.
    let served = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("serve must return once the drain deadline expires")
        .unwrap();
    served.expect("a deadline-bounded shutdown is still a clean (Ok) exit");

    assert!(
        inflight.await.unwrap().is_err(),
        "a request that outlives the drain deadline is cut, not answered"
    );
}

#[tokio::test]
async fn idle_keepalive_connections_do_not_hold_the_drain_open() {
    let upstream = spawn_upstream(Duration::ZERO).await;
    // Generous deadline: if idle connections were WAITED on instead of closed, serve would sit
    // here for 10 s and the timeout below would trip.
    let (proxy, shutdown, server) =
        spawn_proxy(control_for(upstream), Duration::from_secs(10)).await;
    let client = client();
    wait_ready(&client, proxy).await;

    // A completed request leaves an idle pooled keep-alive connection to the proxy.
    let (status, _) = try_get(&client, proxy, "/api/hello").await.unwrap();
    assert_eq!(status, StatusCode::OK);

    shutdown.send(()).unwrap();

    let served = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("idle keep-alive connections must be closed, not drained until the deadline")
        .unwrap();
    served.expect("shutdown with only idle connections is a clean (Ok) exit");
}
