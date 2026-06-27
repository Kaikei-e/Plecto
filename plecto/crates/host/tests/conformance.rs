//! WIT-conformance (tdd-workflow Phase 1) + the ADR 000006 provenance gate.
//!
//! Loading a component type-checks it against the `plecto:filter@0.1.0` world (`InstancePre`
//! resolves every import/export) — Plecto's consumer-driven contract test. ADR 000006 now
//! ALSO requires, before instantiation, a verified keyed cosign signature over the component
//! plus a signed SBOM: `Host::load` is fail-closed. These tests pin both the contract and the
//! provenance gate. Deny-by-default (the `Linker` lends only the plecto host-API, no WASI /
//! network / filesystem / sockets) remains structural — a filter can reach nothing it was not
//! lent, and now cannot even load unless a trusted key signed it.

use plecto_host::test_support::{TestSigner, bound_sbom};
use plecto_host::{
    Host, HttpResponse, Isolation, LoadOptions, RequestBodyDecision, RequestTrace,
    ResponseDecision, SignedArtifact, TrustPolicy,
};

fn component_bytes() -> Vec<u8> {
    std::fs::read(env!("FILTER_HELLO_COMPONENT")).expect("read filter-hello component")
}

/// A freshly-signed filter-hello: the ephemeral signer (whose key a matching `TrustPolicy`
/// trusts), the component bytes, an SBOM bound to that component, and DER signatures over
/// both (review f000003 #1: the SBOM's subject digest is sha256(component)).
struct Fixture {
    signer: TestSigner,
    bytes: Vec<u8>,
    component_signature: Vec<u8>,
    sbom: Vec<u8>,
    sbom_signature: Vec<u8>,
}

fn fixture() -> Fixture {
    let bytes = component_bytes();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&bytes).unwrap();
    let sbom = bound_sbom(&bytes);
    let sbom_signature = signer.sign(&sbom).unwrap();
    Fixture {
        signer,
        bytes,
        component_signature,
        sbom,
        sbom_signature,
    }
}

impl Fixture {
    fn artifact(&self) -> SignedArtifact<'_> {
        SignedArtifact {
            component_bytes: &self.bytes,
            component_signature: &self.component_signature,
            sbom: &self.sbom,
            sbom_signature: &self.sbom_signature,
        }
    }

    /// A host that trusts exactly this fixture's signing key.
    fn host(&self) -> Host {
        Host::new(self.signer.trust_policy().unwrap()).unwrap()
    }
}

#[test]
fn component_satisfies_plecto_filter_world() {
    // Resolving imports proves the host provides the full lent surface (incl. the ADR 000004
    // host-counter / host-ratelimit). Loading also exercises the ADR 000006 provenance gate.
    let fx = fixture();
    fx.host()
        .load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
        .expect("filter-hello must satisfy plecto:filter@0.1.0 and pass the provenance gate");
}

#[test]
fn component_loads_under_both_isolation_modes() {
    // Both engines (pooling for trusted, on-demand for untrusted) must instantiate the
    // contract. Isolation is the caller's explicit choice — a valid signature does not pick it.
    let fx = fixture();
    let host = fx.host();
    let trusted = host
        .load("filter-hello", &fx.artifact(), LoadOptions::trusted())
        .expect("pooling (trusted) engine must instantiate the component");
    assert_eq!(trusted.isolation(), Isolation::Trusted);

    let untrusted = host
        .load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
        .expect("on-demand (untrusted) engine must instantiate the component");
    assert_eq!(untrusted.isolation(), Isolation::Untrusted);
}

#[test]
fn response_hook_is_honoured() {
    let fx = fixture();
    let filter = fx
        .host()
        .load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
        .unwrap();

    let resp = HttpResponse {
        status: 200,
        headers: vec![],
        body: vec![],
    };
    let (decision, _logs) = filter.on_response(&resp, &RequestTrace::root()).unwrap();
    assert!(matches!(decision, ResponseDecision::Continue));
}

// --- ADR 000006 provenance gate: load is fail-closed on a bad/missing signature or SBOM ---
// (`LoadedFilter` is not `Debug`, so rejections assert via `is_err()` / `match`, not expect_err.)

#[test]
fn load_rejects_signature_from_untrusted_key() {
    // Signed by a real key, but the host trusts a DIFFERENT key → no trusted key verifies →
    // reject. A valid signature from a third party is not enough; the signer must be trusted.
    let fx = fixture();
    let other_key = TestSigner::new().unwrap();
    let host = Host::new(other_key.trust_policy().unwrap()).unwrap();
    match host.load("filter-hello", &fx.artifact(), LoadOptions::untrusted()) {
        Ok(_) => panic!("a signature from an untrusted key must be rejected (fail-closed)"),
        Err(e) => assert!(
            e.to_string().contains("component signature"),
            "rejection reason should name the component signature, got: {e}"
        ),
    }
}

#[test]
fn load_rejects_tampered_component() {
    // The signature is valid over the ORIGINAL bytes; flipping one byte invalidates it, so the
    // host must reject BEFORE handing the bytes to wasmtime.
    let fx = fixture();
    let host = fx.host();
    let mut tampered = fx.bytes.clone();
    *tampered.last_mut().unwrap() ^= 0xff;
    let artifact = SignedArtifact {
        component_bytes: &tampered,
        component_signature: &fx.component_signature,
        sbom: &fx.sbom,
        sbom_signature: &fx.sbom_signature,
    };
    assert!(
        host.load("filter-hello", &artifact, LoadOptions::untrusted())
            .is_err(),
        "tampered component bytes must fail signature verification (fail-closed)"
    );
}

#[test]
fn load_rejects_missing_sbom() {
    // ADR 000006 requires a signed SBOM to be present. An empty SBOM is rejected outright —
    // even with an otherwise-valid (over-empty) signature.
    let fx = fixture();
    let host = fx.host();
    let empty_sbom_sig = fx.signer.sign(b"").unwrap();
    let artifact = SignedArtifact {
        component_bytes: &fx.bytes,
        component_signature: &fx.component_signature,
        sbom: b"",
        sbom_signature: &empty_sbom_sig,
    };
    match host.load("filter-hello", &artifact, LoadOptions::untrusted()) {
        Ok(_) => panic!("a missing SBOM must be rejected (fail-closed)"),
        Err(e) => assert!(
            e.to_string().contains("SBOM"),
            "rejection reason should name the SBOM, got: {e}"
        ),
    }
}

#[test]
fn load_rejects_bad_sbom_signature() {
    // The component signature is fine, but the SBOM signature is from the wrong key → reject.
    let fx = fixture();
    let other = TestSigner::new().unwrap();
    let bad_sbom_sig = other.sign(&fx.sbom).unwrap();
    let host = fx.host();
    let artifact = SignedArtifact {
        component_bytes: &fx.bytes,
        component_signature: &fx.component_signature,
        sbom: &fx.sbom,
        sbom_signature: &bad_sbom_sig,
    };
    match host.load("filter-hello", &artifact, LoadOptions::untrusted()) {
        Ok(_) => panic!("an SBOM signature from an untrusted key must be rejected"),
        Err(e) => assert!(
            e.to_string().contains("SBOM signature"),
            "rejection reason should name the SBOM signature, got: {e}"
        ),
    }
}

#[test]
fn load_rejects_sbom_for_other_component() {
    // review f000003 #1: the SBOM is validly signed by a TRUSTED key, but it attests a
    // DIFFERENT component (its subject digest != sha256(this component)). Mixing a legitimate
    // component with a legitimate-but-unrelated SBOM must be rejected — fail-closed.
    let fx = fixture();
    let other_component = b"a different component".to_vec();
    let other_sbom = bound_sbom(&other_component);
    let other_sbom_sig = fx.signer.sign(&other_sbom).unwrap();
    let artifact = SignedArtifact {
        component_bytes: &fx.bytes,
        component_signature: &fx.component_signature,
        sbom: &other_sbom,
        sbom_signature: &other_sbom_sig,
    };
    match fx
        .host()
        .load("filter-hello", &artifact, LoadOptions::untrusted())
    {
        Ok(_) => panic!("an SBOM attesting a different component must be rejected"),
        Err(e) => assert!(
            e.to_string().contains("does not attest this component"),
            "rejection reason should name the binding failure, got: {e}"
        ),
    }
}

#[test]
fn empty_trust_policy_loads_nothing() {
    // The fail-closed default: a host that trusts no keys cannot load even a validly-signed
    // filter. There is deliberately no "allow unsigned" escape hatch.
    let fx = fixture();
    let host = Host::new(TrustPolicy::empty()).unwrap();
    assert!(
        host.load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
            .is_err(),
        "an empty trust policy must load nothing (deny-by-default)"
    );
}

// --- ADR 000011: the host-assigned filter id is the KV-namespace root; load validates it ---

#[test]
fn load_rejects_empty_filter_id() {
    // An empty id would namespace to just the delimiter — a degenerate root. Rejected even for a
    // perfectly-signed component (the provenance gate passing does not waive id validation).
    let fx = fixture();
    match fx.host().load("", &fx.artifact(), LoadOptions::untrusted()) {
        Ok(_) => panic!("an empty filter id must be rejected"),
        Err(e) => assert!(
            e.to_string().contains("filter id"),
            "rejection should name the filter id, got: {e}"
        ),
    }
}

#[test]
fn load_rejects_filter_id_with_namespace_delimiter() {
    // The KV key prefix is `{filter_id}\u{1f}`; a filter id that itself embeds that delimiter
    // could forge the boundary between two filters' keyspaces (ADR 000011 capability isolation),
    // so it is rejected at load — a filter can never choose an id that escapes its own namespace.
    let fx = fixture();
    let evil_id = format!("a{}b", '\u{1f}');
    match fx
        .host()
        .load(&evil_id, &fx.artifact(), LoadOptions::untrusted())
    {
        Ok(_) => panic!("a filter id containing the KV namespace delimiter must be rejected"),
        Err(e) => assert!(
            e.to_string().contains("delimiter"),
            "rejection should name the delimiter, got: {e}"
        ),
    }
}

// --- ADR 000025: the request-side body hook (buffer-then-decide, v1 list<u8>) ---

#[test]
fn request_body_hook_transforms_then_continues() {
    // buffer-then-decide: the host hands the filter the whole body; filter-hello uppercases it and
    // continues. The transformed bytes round-trip through the host's `on_request_body`.
    let fx = fixture();
    let filter = fx
        .host()
        .load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
        .unwrap();

    let (decision, _logs) = filter
        .on_request_body(b"hello world", &RequestTrace::root())
        .unwrap();
    match decision {
        RequestBodyDecision::Continue(body) => assert_eq!(body, b"HELLO WORLD".to_vec()),
        RequestBodyDecision::ShortCircuit(_) => panic!("expected continue with transformed body"),
    }
}

#[test]
fn request_body_hook_short_circuits_before_upstream() {
    // A body carrying the marker is blocked 403 — and because the host applies the decision before
    // forwarding (buffer-then-decide), the short-circuit never reaches upstream.
    let fx = fixture();
    let filter = fx
        .host()
        .load("filter-hello", &fx.artifact(), LoadOptions::untrusted())
        .unwrap();

    let (decision, _logs) = filter
        .on_request_body(b"please deny-body now", &RequestTrace::root())
        .unwrap();
    match decision {
        RequestBodyDecision::ShortCircuit(resp) => assert_eq!(resp.status, 403),
        RequestBodyDecision::Continue(_) => panic!("expected short-circuit 403 on the marker body"),
    }
}
