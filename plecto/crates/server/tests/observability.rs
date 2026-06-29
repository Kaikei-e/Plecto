//! E2E for Stage A observability (ADR 000009): drive real traffic through the proxy, then scrape
//! the SEPARATE admin endpoint and assert the Prometheus metrics + liveness/readiness reflect it.
//! A no-filter manifest (so no signing infra is needed) routes `/` to a fake upstream; the admin
//! endpoint binds a distinct port (`[observability] admin_addr`), never the data-plane port.

use std::convert::Infallible;
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

use plecto_control::{Control, Manifest};
use plecto_server::serve;

/// A trivial upstream: 200 with a fixed body for any path (so the health probe to `/healthz` passes
/// and a forwarded `/` returns 200).
async fn echo(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(200)
        .body(Full::new(Bytes::from_static(b"ok")))
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

/// Grab a free port for the admin endpoint by binding `:0`, reading the addr, then releasing it so
/// the server can re-bind it. (A tiny TOCTOU window, fine for a loopback test.)
async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    addr: SocketAddr,
    path: &str,
) -> (StatusCode, String) {
    let resp = client
        .request(
            Request::builder()
                .method("GET")
                .uri(format!("http://{addr}{path}"))
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .expect("request");
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Poll a forwarding path until the upstream's first health probe lands (instances start
/// pessimistic, so a forward is 503 until a probe passes).
async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..150 {
        let (status, _) = get(client, proxy, "/").await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstream never became healthy within the readiness window");
}

/// Poll the admin endpoint until it is bound (it comes up on its own task inside `serve`).
async fn wait_admin(client: &Client<HttpConnector, Empty<Bytes>>, admin: SocketAddr) {
    for _ in 0..150 {
        let req = Request::builder()
            .uri(format!("http://{admin}/healthz"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        if let Ok(resp) = client.request(req).await
            && resp.status() == StatusCode::OK
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("admin endpoint never came up within the window");
}

#[tokio::test]
async fn admin_endpoint_exposes_prometheus_metrics_and_health_after_traffic() {
    let upstream = spawn_upstream().await;
    let admin = free_addr().await;

    let toml = format!(
        r#"
[observability]
admin_addr = "{admin}"

[[upstream]]
name = "echo"
addresses = ["{upstream}"]
[upstream.health]
path = "/healthz"
interval_ms = 50

[[route]]
path_prefix = "/"
upstream = "echo"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let control = Arc::new(Control::from_manifest(&manifest, std::path::Path::new(".")).unwrap());

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, data_listener).await;
    });

    let client = client();
    wait_ready(&client, data_addr).await;

    // Drive a couple of successful requests through the data plane.
    let (status, body) = get(&client, data_addr, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
    let _ = get(&client, data_addr, "/").await;

    wait_admin(&client, admin).await;

    // /healthz (liveness) and /readyz (readiness) on the admin endpoint.
    let (hstatus, hbody) = get(&client, admin, "/healthz").await;
    assert_eq!(hstatus, StatusCode::OK);
    assert_eq!(hbody, "ok\n");
    let (rstatus, rbody) = get(&client, admin, "/readyz").await;
    assert_eq!(rstatus, StatusCode::OK);
    assert_eq!(rbody, "ready\n");

    // /metrics reflects the served traffic in Prometheus exposition form.
    let (mstatus, metrics) = get(&client, admin, "/metrics").await;
    assert_eq!(mstatus, StatusCode::OK);
    assert!(
        metrics.contains("# TYPE plecto_requests_total counter"),
        "exposition has TYPE lines:\n{metrics}"
    );
    assert!(
        metrics.contains("plecto_request_duration_seconds_count"),
        "the latency histogram is present:\n{metrics}"
    );
    let twoxx = metrics
        .lines()
        .find(|l| l.starts_with("plecto_requests_total{status_class=\"2xx\"}"))
        .expect("a 2xx counter line is present");
    let count: u64 = twoxx
        .rsplit(' ')
        .next()
        .and_then(|n| n.parse().ok())
        .expect("the counter line ends in a number");
    assert!(
        count >= 2,
        "at least the two driven requests are counted as 2xx, got: {twoxx}"
    );

    // An unknown admin path is 404 (the admin endpoint is not a catch-all).
    let (nstatus, _) = get(&client, admin, "/nope").await;
    assert_eq!(nstatus, StatusCode::NOT_FOUND);
}
