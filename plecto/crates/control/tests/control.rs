//! E2E (tdd-workflow Phase 0) for the control plane: a TOML manifest declares a chain of
//! real `plecto:filter` components (filter-hello), resolved through an `ArtifactStore` and
//! loaded through the ADR 000006 provenance gate; the chain dispatcher drives requests; and
//! `reload` swaps the active set atomically. Uses the in-memory store so these tests need no
//! OCI layout (the offline OCI store is covered separately).

use std::sync::Arc;

use plecto_control::{
    ChainOutcome, Control, ControlError, Host, HttpRequest, HttpResponse, InMemorySink, Manifest,
    MemoryStore, ResolvedArtifact,
};
use plecto_host::Header;
use plecto_host::test_support::{
    TestSigner, bound_sbom, filter_hello_component, filter_quickstart_component,
};

fn req(headers: &[(&str, &str)]) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        path: "/".to_string(),
        authority: "example.test".to_string(),
        scheme: "https".to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| Header {
                name: (*n).to_string(),
                value: (*v).to_string(),
            })
            .collect(),
    }
}

/// filter-hello, signed with a fresh ephemeral key (the returned signer trusts it).
fn signed_filter_hello() -> (TestSigner, ResolvedArtifact) {
    let component = filter_hello_component();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom).unwrap();
    let artifact = ResolvedArtifact {
        component,
        component_signature,
        sbom,
        sbom_signature,
    };
    (signer, artifact)
}

/// A manifest declaring one filter `fh` pinned at `digest`, with the given chain order.
fn manifest_toml(digest: &str, chain: &[&str]) -> String {
    let chain_list = chain
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "untrusted"

[chain]
filters = [{chain_list}]
"#
    )
}

/// Sign arbitrary component bytes into a self-consistent `ResolvedArtifact` (bytes + bound SBOM +
/// both DER signatures) with `signer`.
fn signed(component: Vec<u8>, signer: &TestSigner) -> ResolvedArtifact {
    let component_signature = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom).unwrap();
    ResolvedArtifact {
        component,
        component_signature,
        sbom,
        sbom_signature,
    }
}

/// A GET request at `path` (route matching reads the path prefix; headers are irrelevant here).
fn req_path(path: &str) -> HttpRequest {
    let mut r = req(&[]);
    r.path = path.to_string();
    r
}

#[test]
fn route_reads_body_only_when_a_filter_exports_the_body_hook() {
    // ADR 000038: a route buffers the request body IFF one of its filters actually reads it (exports
    // `on-request-body`). filter-hello (world `filter-body`) does; filter-quickstart (header-only)
    // does not. This pins the control-side aggregation and the `RouteInfo.reads_body` the fast path
    // reads to decide whether to buffer — the seam that turns the export-presence signal into a
    // zero-copy streaming passthrough.
    let signer = TestSigner::new().unwrap();
    let mut store = MemoryStore::new();
    let body_digest = store.insert("body", signed(filter_hello_component(), &signer));
    let hdr_digest = store.insert("hdr", signed(filter_quickstart_component(), &signer));
    let manifest_toml = format!(
        r#"
[[filter]]
id = "body"
source = "body"
digest = "{body_digest}"
isolation = "untrusted"

[[filter]]
id = "hdr"
source = "hdr"
digest = "{hdr_digest}"
isolation = "untrusted"

[[upstream]]
name = "be"
addresses = ["127.0.0.1:9"]
[upstream.health]
path = "/"

[[route]]
filters = ["body"]
upstream = "be"
[route.match]
path_prefix = "/body"

[[route]]
filters = ["hdr"]
upstream = "be"
[route.match]
path_prefix = "/headers"
"#
    );
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let manifest = Manifest::from_toml(&manifest_toml).unwrap();
    let control = Control::load(host, &manifest, Box::new(store)).unwrap();
    let snap = control.snapshot();

    let body_route = snap
        .find_route(&req_path("/body/x"))
        .expect("the /body route must match");
    assert!(
        body_route.reads_body,
        "a route with a body-reading filter must set reads_body (host buffers the body)"
    );

    let hdr_route = snap
        .find_route(&req_path("/headers/x"))
        .expect("the /headers route must match");
    assert!(
        !hdr_route.reads_body,
        "a route of only header-only filters must NOT buffer the body (zero-copy passthrough)"
    );
}

/// A control plane with filter-hello loaded and the given chain order.
fn signed_control(chain: &[&str]) -> Control {
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let manifest = Manifest::from_toml(&manifest_toml(&digest, chain)).unwrap();
    Control::load(host, &manifest, Box::new(store)).unwrap()
}

#[test]
fn chain_forwards_unblocked_and_short_circuits_blocked() {
    let control = signed_control(&["fh"]);

    match control.on_request(req(&[])) {
        ChainOutcome::Forward(_) => {}
        ChainOutcome::Respond(_) => panic!("an unblocked request should forward upstream"),
    }

    match control.on_request(req(&[("x-plecto-block", "1")])) {
        ChainOutcome::Respond(resp) => assert_eq!(resp.status, 403, "blocked request → 403"),
        ChainOutcome::Forward(_) => panic!("a blocked request must short-circuit"),
    }
}

#[test]
fn chain_applies_modified_edit_before_forwarding() {
    // The filter returns `modified` (add a header); the dispatcher must APPLY the edit so the
    // forwarded request (and any later filter / upstream) sees it (ADR 000007).
    let control = signed_control(&["fh"]);

    match control.on_request(req(&[("x-plecto-addheader", "1")])) {
        ChainOutcome::Forward(forwarded) => assert!(
            forwarded
                .headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("x-plecto-added")),
            "the host must apply the filter's modified edit before forwarding"
        ),
        ChainOutcome::Respond(_) => panic!("a modified (not short-circuit) request should forward"),
    }
}

#[test]
fn response_chain_applies_edit() {
    let control = signed_control(&["fh"]);

    let resp = plecto_host::HttpResponse {
        status: 200,
        headers: vec![Header {
            name: "x-plecto-respedit".to_string(),
            value: "1".to_string(),
        }],
        body: vec![],
    };
    let out = control.on_response(resp);
    assert!(
        out.headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-plecto-respadded")),
        "the response-side chain must apply the filter's response edit"
    );
}

#[test]
fn reload_swaps_chain_atomically() {
    // ADR 000007 hot-reload: build a new set and switch in one atomic store. v1 has the filter
    // in the chain (blocks); v2 drops it from the chain (forwards). The SAME host is reused.
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();

    let v1 = Manifest::from_toml(&manifest_toml(&digest, &["fh"])).unwrap();
    let control = Control::load(host, &v1, Box::new(store)).unwrap();
    assert!(
        matches!(control.on_request(req(&[("x-plecto-block", "1")])), ChainOutcome::Respond(r) if r.status == 403),
        "v1 chain blocks"
    );

    let v2 = Manifest::from_toml(&manifest_toml(&digest, &[])).unwrap();
    control.reload(&v2).unwrap();
    assert!(
        matches!(
            control.on_request(req(&[("x-plecto-block", "1")])),
            ChainOutcome::Forward(_)
        ),
        "after reload the chain is empty → the same request now forwards"
    );
}

#[test]
fn control_load_rejects_untrusted_signature() {
    // The ADR 000006 gate flows through the control plane: a filter signed by a key the host
    // does not trust fails to load (fail-closed), and the failure is typed.
    let (_signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let other = TestSigner::new().unwrap(); // host trusts a DIFFERENT key
    let host = Host::new(other.trust_policy().unwrap()).unwrap();
    let manifest = Manifest::from_toml(&manifest_toml(&digest, &["fh"])).unwrap();

    match Control::load(host, &manifest, Box::new(store)) {
        Ok(_) => panic!("a filter signed by an untrusted key must not load"),
        Err(e) => assert!(matches!(e, ControlError::Load { .. }), "got {e}"),
    }
}

#[test]
fn control_load_rejects_digest_mismatch() {
    // ADR 000007 content pinning: if the artifact's digest does not equal the manifest pin,
    // the filter is rejected before it is ever loaded.
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let _real_digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let wrong = format!("sha256:{}", "0".repeat(64));
    let manifest = Manifest::from_toml(&manifest_toml(&wrong, &["fh"])).unwrap();

    match Control::load(host, &manifest, Box::new(store)) {
        Ok(_) => panic!("a wrong pinned digest must be rejected"),
        Err(e) => assert!(matches!(e, ControlError::DigestMismatch { .. }), "got {e}"),
    }
}

#[test]
fn request_and_response_spans_share_one_trace_via_snapshot() {
    // ADR 000009: a request transaction takes ONE snapshot; both halves run under its trace, so
    // the request-side and response-side filter spans belong to the same trace and share a
    // parent (the request span). The host emits them to its injected sink as the chain runs.
    let sink = Arc::new(InMemorySink::new());
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap())
        .unwrap()
        .with_telemetry_sink(sink.clone());
    let manifest = Manifest::from_toml(&manifest_toml(&digest, &["fh"])).unwrap();
    let control = Control::load(host, &manifest, Box::new(store)).unwrap();

    let snap = control.snapshot();
    let _ = snap.on_request(req(&[]));
    let _ = snap.on_response(HttpResponse {
        status: 200,
        headers: vec![],
        body: vec![],
    });

    let spans = sink.spans();
    assert_eq!(spans.len(), 2, "one request span + one response span");
    assert_eq!(
        spans[0].trace_id, spans[1].trace_id,
        "both halves of one transaction share a trace"
    );
    assert_eq!(
        spans[0].parent_span_id, spans[1].parent_span_id,
        "both filter spans are children of the request span"
    );
}

#[test]
fn duplicate_filter_id_is_rejected() {
    // f000004 #6 / the host flagged filter-id uniqueness as the caller's job — control is that
    // caller. Two `[[filter]]` sharing an id is a config error, caught before a half-built set
    // could go live.
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let toml = format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"

[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"

[chain]
filters = ["fh"]
"#
    );
    let manifest = Manifest::from_toml(&toml).unwrap();

    match Control::load(host, &manifest, Box::new(store)) {
        Ok(_) => panic!("duplicate filter ids must be rejected"),
        Err(e) => assert!(matches!(e, ControlError::DuplicateFilterId(_)), "got {e}"),
    }
}

#[test]
fn chain_referencing_unknown_filter_is_rejected() {
    // A manifest whose chain names a filter that is not declared is a config error.
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let manifest = Manifest::from_toml(&manifest_toml(&digest, &["fh", "ghost"])).unwrap();

    match Control::load(host, &manifest, Box::new(store)) {
        Ok(_) => panic!("a chain referencing an undeclared filter must be rejected"),
        Err(e) => assert!(matches!(e, ControlError::UnknownChainFilter(_)), "got {e}"),
    }
}
