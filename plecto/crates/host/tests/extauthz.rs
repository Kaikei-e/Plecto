//! End-to-end behaviour of the outbound HTTP capability (ADR 000036) through the real
//! `filter-extauthz` wasm guest. Compiled only with the `outbound-http` feature (OFF by default).
//!
//! The guest calls an external authorization endpoint (URL from the `x-authz-url` header) over
//! `wasi:http/outgoing-handler`; the host gates every call by the operator allowlist + the SSRF
//! guard, and the guest fails closed (403) on any error. These tests pin the two gates end-to-end:
//!   - a destination NOT on the allowlist is denied before any DNS/socket (`HttpRequestDenied`);
//!   - an allowlisted NAME that resolves to a blocked IP (loopback) is denied on the resolved
//!     address (`DestinationIpProhibited`), even with a live server listening there — the DNS
//!     rebinding defense, proven through a real guest.
#![cfg(feature = "outbound-http")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};

use plecto_host::test_support::{TestSigner, bound_sbom, filter_extauthz_component};
use plecto_host::{
    AllowEntry, Header, Host, HttpRequest, LoadOptions, LoadedFilter, RequestDecision,
    RequestTrace, Scheme, SignedArtifact,
};

/// A raw HTTP/1.1 server on loopback that answers every connection `200 OK`. Used to prove the SSRF
/// guard blocks an allowlisted name that resolves here *despite* a real listener.
fn spawn_ok_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        }
    });
    addr
}

/// Sign + load filter-extauthz with the given outbound policy. The `Host` owns the epoch ticker and
/// the outbound tokio runtime, so it must outlive the filter — returned alongside.
fn signed_load(opts: LoadOptions) -> (Host, LoadedFilter) {
    let bytes = filter_extauthz_component();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&bytes).unwrap();
    let sbom = bound_sbom(&bytes);
    let sbom_signature = signer.sign(&sbom).unwrap();
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    let artifact = SignedArtifact {
        component_bytes: &bytes,
        component_signature: &component_signature,
        sbom: &sbom,
        sbom_signature: &sbom_signature,
    };
    let filter = host
        .load("filter-extauthz", &artifact, opts)
        .expect("load filter-extauthz");
    (host, filter)
}

fn request(authz_url: &str) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        path: "/protected".to_string(),
        authority: "gateway.test".to_string(),
        scheme: "https".to_string(),
        headers: vec![Header {
            name: "x-authz-url".to_string(),
            value: authz_url.to_string(),
        }],
    }
}

fn outbound_opts(allow: Vec<AllowEntry>) -> LoadOptions {
    LoadOptions::untrusted().with_outbound(
        allow,
        vec![],
        Some(2_000),
        Some(5_000),
        Some(64 * 1024),
        Some(8),
    )
}

fn short_circuit_body(f: &LoadedFilter, r: &HttpRequest) -> (u16, String) {
    let (decision, _logs) = f
        .on_request(r, &RequestTrace::root())
        .expect("run on_request");
    match decision {
        RequestDecision::ShortCircuit(resp) => (
            resp.status,
            String::from_utf8_lossy(&resp.body).into_owned(),
        ),
        other => panic!("expected a fail-closed short-circuit, got {other:?}"),
    }
}

#[test]
fn unlisted_destination_is_denied_before_any_connection() {
    // The allowlist names one host; the guest tries a different one → deny-by-default, no DNS/socket.
    let opts = outbound_opts(vec![AllowEntry {
        scheme: Scheme::Https,
        host: "authz.allowed.test".to_string(),
        port: 443,
    }]);
    let (_host, filter) = signed_load(opts);

    let (status, body) = short_circuit_body(&filter, &request("https://evil.example.test/authz"));
    assert_eq!(status, 403, "an unlisted destination must fail closed");
    assert!(
        body.contains("HttpRequestDenied"),
        "the allowlist gate denies it (body: {body:?})"
    );
}

#[test]
fn allowlisted_name_resolving_to_loopback_is_ssrf_blocked() {
    // The SSRF/rebinding defense end-to-end: allowlist `localhost:PORT`, run a real server there, but
    // the guard rejects the resolved 127.0.0.1 — the guest never reaches the listener.
    let addr = spawn_ok_server();
    let opts = outbound_opts(vec![AllowEntry {
        scheme: Scheme::Http,
        host: "localhost".to_string(),
        port: addr.port(),
    }]);
    let (_host, filter) = signed_load(opts);

    let url = format!("http://localhost:{}/authz", addr.port());
    let (status, body) = short_circuit_body(&filter, &request(&url));
    assert_eq!(status, 403, "a loopback-resolving target must fail closed");
    assert!(
        body.contains("DestinationIpProhibited"),
        "the SSRF guard blocks the resolved loopback address (body: {body:?})"
    );
}

#[test]
fn no_authz_url_fails_closed() {
    // Defensive: a request the filter can't authorize (no target) must not be allowed through.
    let opts = outbound_opts(vec![AllowEntry {
        scheme: Scheme::Https,
        host: "authz.allowed.test".to_string(),
        port: 443,
    }]);
    let (_host, filter) = signed_load(opts);

    let req = HttpRequest {
        method: "GET".to_string(),
        path: "/protected".to_string(),
        authority: "gateway.test".to_string(),
        scheme: "https".to_string(),
        headers: vec![],
    };
    let (status, _body) = short_circuit_body(&filter, &req);
    assert_eq!(status, 403);
}
