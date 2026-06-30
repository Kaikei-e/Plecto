//! E2E for outlier detection (ADR 000032): an instance that returns gateway-class 5xx on live
//! traffic is ejected from rotation after the consecutive-failure threshold — a THIRD resilience
//! axis, separate from active health (the bad instance still passes its `/healthz` probe) and from
//! the circuit breaker. Once ejected, traffic flows only to the healthy instance; the ejection is
//! observable on the admin `/metrics`.

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

/// An upstream that is healthy to the prober (`/healthz` → 200) but returns `non_health_status` on
/// every real path — a 503 instance stays probe-healthy while misbehaving, which is exactly what
/// outlier detection (not health) must catch.
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

async fn wait_ready(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr) {
    for _ in 0..150 {
        let (status, _) = get(client, proxy, "/probe").await;
        if status != StatusCode::SERVICE_UNAVAILABLE {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("upstreams never became healthy");
}

#[tokio::test]
async fn instance_returning_5xx_is_ejected_then_traffic_avoids_it() {
    let bad = spawn_upstream(503).await; // probe-healthy, but 503 on real traffic
    let good = spawn_upstream(200).await;
    let admin = free_addr().await;
    let toml = format!(
        r#"
[observability]
admin_addr = "{admin}"

[[upstream]]
name = "u"
addresses = ["{bad}", "{good}"]
max_retries = 1
[upstream.health]
path = "/healthz"
interval_ms = 30
[upstream.outlier_detection]
consecutive_gateway_failures = 2
base_ejection_time_ms = 60000
max_ejection_percent = 50

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
    wait_ready(&client, data).await;
    tokio::time::sleep(Duration::from_millis(80)).await; // let both pass a probe → both in rotation

    // Drive enough requests that round-robin lands on the 503 instance twice (the eject threshold).
    // Every request still succeeds: while the bad instance is in rotation a 503 is rescued by
    // retry-on-5xx, and once it is ejected only the good instance is picked.
    for i in 0..16 {
        let (status, body) = get(&client, data, &format!("/r{i}")).await;
        assert_eq!(status, StatusCode::OK, "GET #{i} succeeds (got {status})");
        assert_eq!(body, "x");
    }

    // The ejection is observable, and the bad instance was removed from rotation (ADR 000032 + 000009).
    let (mstatus, metrics) = get(&client, admin, "/metrics").await;
    assert_eq!(mstatus, StatusCode::OK);
    let ejections = metrics
        .lines()
        .find(|l| l.starts_with("plecto_outlier_ejections_total "))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
        .expect("the outlier-ejections counter is exposed");
    assert!(
        ejections >= 1,
        "the misbehaving instance was ejected at least once, got {ejections}"
    );
}
