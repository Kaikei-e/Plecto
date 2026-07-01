//! WASM extension-plane micro-benchmarks (criterion): the in-process cost of running a filter,
//! isolated from the network so it complements the end-to-end WASM cost-ladder macro scenario
//! (micro-cost × calls-per-request should roughly explain the macro delta).
//!
//! - `filter_load`: cold load — verify component + SBOM signatures, instantiate, run `init` once.
//! - `on_request/trusted_pooled`: per-request cost on a reused pooled instance (dispatch + call;
//!   `init` amortized).
//! - `on_request/untrusted_fresh`: per-request cost with a fresh instance every request (dispatch +
//!   instantiate + `init` + call). The trusted↔untrusted delta is the per-request instantiation cost
//!   — what the pool buys (ADR 000012).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use plecto_host::{Header, Host, HttpRequest, LoadOptions, RequestTrace, SignedArtifact};

/// A signed filter-hello artifact plus the key that signed it (so a `Host` can trust exactly it).
struct Fixture {
    component: Vec<u8>,
    component_sig: Vec<u8>,
    sbom: Vec<u8>,
    sbom_sig: Vec<u8>,
    signer: TestSigner,
}

fn fixture() -> Fixture {
    let component = filter_hello_component();
    let signer = TestSigner::new().unwrap();
    let component_sig = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_sig = signer.sign(&sbom).unwrap();
    Fixture {
        component,
        component_sig,
        sbom,
        sbom_sig,
        signer,
    }
}

impl Fixture {
    fn artifact(&self) -> SignedArtifact<'_> {
        SignedArtifact {
            component_bytes: &self.component,
            component_signature: &self.component_sig,
            sbom: &self.sbom,
            sbom_signature: &self.sbom_sig,
        }
    }
    fn host(&self) -> Host {
        Host::new(self.signer.trust_policy().unwrap()).unwrap()
    }
}

fn request() -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        path: "/api/data".to_string(),
        authority: "example.test".to_string(),
        scheme: "https".to_string(),
        headers: vec![Header {
            name: "x-req".to_string(),
            value: "1".to_string(),
        }],
    }
}

fn bench_load(c: &mut Criterion) {
    let fx = fixture();
    let host = fx.host(); // Host construction (epoch ticker) is outside the timed loop.
    c.bench_function("filter_load/trusted_cold", |b| {
        b.iter(|| {
            let loaded = host
                .load("bench", &fx.artifact(), LoadOptions::trusted())
                .unwrap();
            black_box(loaded);
        })
    });
}

fn bench_on_request(c: &mut Criterion) {
    let fx = fixture();
    let req = request();
    let trace = RequestTrace::root();

    let host_t = fx.host();
    let trusted = host_t
        .load("bench-t", &fx.artifact(), LoadOptions::trusted())
        .unwrap();
    let _ = trusted.on_request(&req, &trace); // warm the pooled instance

    let host_u = fx.host();
    let untrusted = host_u
        .load("bench-u", &fx.artifact(), LoadOptions::untrusted())
        .unwrap();

    let mut g = c.benchmark_group("on_request");
    g.bench_function("trusted_pooled", |b| {
        b.iter(|| black_box(trusted.on_request(black_box(&req), &trace)))
    });
    g.bench_function("untrusted_fresh", |b| {
        b.iter(|| black_box(untrusted.on_request(black_box(&req), &trace)))
    });
    g.finish();
}

criterion_group!(benches, bench_load, bench_on_request);
criterion_main!(benches);
