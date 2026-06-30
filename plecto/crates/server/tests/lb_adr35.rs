//! E2E (tdd-workflow Phase 0) for the ADR 000035 load-balancing algorithms: drive real HTTP/1.1
//! requests through a running `plecto-server` and assert the client-visible behaviour of
//! `least_request` (power-of-two-choices) and `maglev` (consistent hashing). This proves the WIRING
//! the unit tests can't: the manifest's `lb_algorithm` / `[upstream.hash]` reach the group, and the
//! fast path projects the hash key from a real request (a header value or the peer IP). Each fake
//! upstream tags its 200 with `x-instance: {label}` so the distribution / affinity is observable.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

use plecto_control::{Control, Host, Manifest, MemoryStore};
use plecto_host::test_support::TestSigner;
use plecto_server::serve;

async fn spawn_labeled_upstream(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req| async move {
                            Ok::<Response<Full<Bytes>>, Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("x-instance", label)
                                    .body(Full::new(Bytes::from_static(b"ok")))
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

async fn spawn_proxy(control: Arc<Control>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(control, listener).await;
    });
    addr
}

/// A control plane with one `pool` upstream over `addresses`, an `lb` config block (the
/// `lb_algorithm` + optional `[upstream.hash]`), and a filter-less `/api` route to it.
fn control_for(addresses: &[SocketAddr], lb: &str) -> Arc<Control> {
    let signer = TestSigner::new().unwrap();
    let addrs = addresses
        .iter()
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
[[upstream]]
name = "pool"
addresses = [{addrs}]
{lb}
[upstream.health]
path = "/healthz"
interval_ms = 50
timeout_ms = 100

[[route]]
upstream = "pool"
[route.match]
path_prefix = "/api"
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    Arc::new(Control::load(host, &manifest, Box::new(MemoryStore::new())).unwrap())
}

fn client() -> Client<HttpConnector, Empty<Bytes>> {
    Client::builder(TokioExecutor::new()).build_http()
}

/// One GET through the proxy with an optional `x-user` header → (status, `x-instance` value).
async fn get(
    client: &Client<HttpConnector, Empty<Bytes>>,
    proxy: SocketAddr,
    user: Option<&str>,
) -> (StatusCode, Option<String>) {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("http://{proxy}/api/x"));
    if let Some(u) = user {
        req = req.header("x-user", u);
    }
    let resp = client
        .request(req.body(Empty::<Bytes>::new()).unwrap())
        .await
        .expect("proxy request");
    let instance = resp
        .headers()
        .get("x-instance")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    (resp.status(), instance)
}

/// Drive traffic (rotating the `x-user` key so a hashing upstream spreads) until every instance has
/// served at least once — i.e. all instances passed cold-start and are healthy.
async fn warm_up(client: &Client<HttpConnector, Empty<Bytes>>, proxy: SocketAddr, n: usize) {
    let mut seen = HashSet::new();
    for i in 0..400 {
        let (status, instance) = get(client, proxy, Some(&format!("warm-{i}"))).await;
        if status == StatusCode::OK
            && let Some(label) = instance
        {
            seen.insert(label);
        }
        if seen.len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("only {}/{n} instances became healthy in time", seen.len());
}

#[tokio::test]
async fn least_request_forwards_and_spreads_under_concurrency() {
    // Two facts end to end: (1) a `least_request` upstream forwards correctly (the per-instance
    // metering path does not break forwarding), and (2) under genuinely concurrent in-flight load it
    // spreads across the healthy set — P2C routes the second concurrent request away from the busy
    // first. (Idle SEQUENTIAL traffic legitimately pins to one instance, since there is never any
    // in-flight load to balance; that selection logic is covered precisely by the unit tests.)
    let a = spawn_labeled_upstream("a").await;
    let b = spawn_labeled_upstream("b").await;
    let proxy = spawn_proxy(control_for(&[a, b], "lb_algorithm = \"least_request\"")).await;
    let client = client();

    // Readiness: wait until the proxy serves a 200 (instances pass cold-start via the prober,
    // independent of which one least-request happens to route an idle request to).
    for _ in 0..400 {
        if get(&client, proxy, None).await.0 == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    // Fire concurrent batches so in-flight accumulates; P2C then distributes. Retry a few rounds to
    // absorb cold-start / scheduling jitter before asserting both instances were hit.
    let mut seen = HashSet::new();
    for _ in 0..20 {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let c = client.clone();
                tokio::spawn(async move { get(&c, proxy, None).await })
            })
            .collect();
        for h in handles {
            let (status, instance) = h.await.unwrap();
            assert_eq!(status, StatusCode::OK, "least-request forwards a 200");
            if let Some(label) = instance {
                seen.insert(label);
            }
        }
        if seen.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        seen,
        HashSet::from(["a".to_string(), "b".to_string()]),
        "under concurrent load least-request spreads across both healthy instances"
    );
}

#[tokio::test]
async fn maglev_header_key_pins_each_user_to_one_instance() {
    // The affinity guarantee through the proxy: a request's `x-user` header is hashed (ADR 000035),
    // so the same user always lands on the same instance, while distinct users spread across the
    // pool. This exercises the fast path's header→hash-key projection.
    let a = spawn_labeled_upstream("a").await;
    let b = spawn_labeled_upstream("b").await;
    let c = spawn_labeled_upstream("c").await;
    let lb = "lb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"header\"\nheader = \"x-user\"\ntable_size = 97";
    let proxy = spawn_proxy(control_for(&[a, b, c], lb)).await;
    let client = client();
    warm_up(&client, proxy, 3).await;

    // Map each user to the instance it first hits, then assert stability over many repeats.
    let users = ["alice", "bob", "carol", "dave", "erin", "frank"];
    let mut pinned: HashMap<&str, String> = HashMap::new();
    for u in users {
        let (status, instance) = get(&client, proxy, Some(u)).await;
        assert_eq!(status, StatusCode::OK);
        pinned.insert(u, instance.expect("a labeled instance served"));
    }
    for _ in 0..5 {
        for u in users {
            let (_, instance) = get(&client, proxy, Some(u)).await;
            assert_eq!(
                instance.as_deref(),
                Some(pinned[u].as_str()),
                "user {u} must always reach its pinned instance (affinity)"
            );
        }
    }
    let distinct: HashSet<&String> = pinned.values().collect();
    assert!(
        distinct.len() >= 2,
        "distinct users must spread across the pool, got {pinned:?}"
    );
}

#[tokio::test]
async fn maglev_falls_back_when_the_header_is_absent() {
    // No `x-user` header → no hash key → the maglev upstream falls back to round-robin (never 503
    // while an instance is up). Proves the absent-key fallback path end to end.
    let a = spawn_labeled_upstream("a").await;
    let b = spawn_labeled_upstream("b").await;
    let lb = "lb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"header\"\nheader = \"x-user\"\ntable_size = 97";
    let proxy = spawn_proxy(control_for(&[a, b], lb)).await;
    let client = client();
    warm_up(&client, proxy, 2).await;

    let mut seen = HashSet::new();
    for _ in 0..40 {
        let (status, instance) = get(&client, proxy, None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "keyless maglev still serves (no 503)"
        );
        if let Some(label) = instance {
            seen.insert(label);
        }
    }
    assert_eq!(
        seen.len(),
        2,
        "without a hash key maglev round-robins across the pool"
    );
}
