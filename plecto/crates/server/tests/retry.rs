//! E2E for retry hardening (ADR 000030): a retriable gateway-class 5xx (503) from one upstream
//! instance is retried — with backoff — onto another healthy instance, so an idempotent request is
//! rescued instead of surfacing the 5xx. A 503 is NOT a health signal (the bad instance stays in
//! rotation), so over many requests every GET still succeeds and the retry counter climbs.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
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

/// An upstream that answers `/healthz` with 200 (so it stays in rotation) and every other path with
/// `non_health_status` — a 503 instance is healthy to the prober but fails real requests, which is
/// exactly what exercises retry-on-5xx without demotion.
async fn spawn_upstream(non_health_status: u16) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let status = if req.uri().path().starts_with("/healthz") {
                        200u16
                    } else {
                        non_health_status
                    };
                    async move {
                        Ok::<Response<Full<Bytes>>, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from_static(b"x")))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    addr
}

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

#[tokio::test]
async fn retriable_5xx_is_retried_onto_a_healthy_instance() {
    let bad = spawn_upstream(503).await; // healthy to the prober, 503 on real requests
    let good = spawn_upstream(200).await;
    let admin = free_addr().await;
    let toml = format!(
        r#"
[observability]
admin_addr = "{admin}"

[[upstream]]
name = "u"
addresses = ["{bad}", "{good}"]
[upstream.health]
path = "/healthz"
interval_ms = 30

[[route]]
path_prefix = "/"
upstream = "u"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let control = Arc::new(Control::from_manifest(&manifest, Path::new(".")).unwrap());

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data = data_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, data_listener).await;
    });

    let client = client();
    // Wait until BOTH instances have passed a health probe (so round-robin reaches the 503 one and
    // retry-on-5xx actually fires). Poll past the first success, then give a couple more intervals.
    for _ in 0..150 {
        let (status, _) = get(&client, data, "/probe").await;
        if status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Every GET succeeds: when round-robin lands on the 503 instance, the request is retried onto
    // the 200 instance instead of surfacing the 503.
    for i in 0..12 {
        let (status, body) = get(&client, data, &format!("/r{i}")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET #{i} was rescued by retry-on-5xx (got {status})"
        );
        assert_eq!(body, "x");
    }

    // The retries are observable: at least one request hit the 503 instance and was retried.
    let (mstatus, metrics) = get(&client, admin, "/metrics").await;
    assert_eq!(mstatus, StatusCode::OK);
    let retries = metrics
        .lines()
        .find(|l| l.starts_with("plecto_upstream_retries_total "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
        .expect("the retries counter is exposed");
    assert!(
        retries >= 1,
        "retry-on-5xx must have fired at least once over 12 round-robined requests, got {retries}"
    );
}
