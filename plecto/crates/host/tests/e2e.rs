//! E2E (tdd-workflow Phase 0): drive requests through the host + a real `plecto:filter`
//! component (filter-hello) and assert the client-visible outcome — the taken `decision`,
//! the synthesised response, and the lifecycle effect ADR 000004 promises (init-once for
//! trusted filters, fresh-per-request for untrusted ones).

use plecto_host::test_support::{TestSigner, bound_sbom};
use plecto_host::{
    Header, Host, HttpRequest, LoadOptions, LoadedFilter, LogLine, RequestDecision, RequestTrace,
    RunError, SignedArtifact,
};

/// Run the request hook under a fresh per-request trace (ADR 000009). These tests assert on
/// the returned decision + logs (telemetry shape is covered in `observe.rs` / the sink tests),
/// so a throwaway root trace per call is fine.
fn on_req(f: &LoadedFilter, r: &HttpRequest) -> Result<(RequestDecision, Vec<LogLine>), RunError> {
    f.on_request(r, &RequestTrace::root())
}

fn component_bytes() -> Vec<u8> {
    std::fs::read(env!("FILTER_HELLO_COMPONENT")).expect("read filter-hello component")
}

/// Sign filter-hello (and a component-bound SBOM) with a fresh ephemeral key, build a `Host`
/// that trusts exactly that key, and load it. Returns the `Host` too: it owns the epoch ticker,
/// so it must outlive the filter for deadlines to keep firing. This is the real provenance path
/// (ADR 000006) — every load here goes through signature + SBOM-binding verification.
fn signed_load(opts: LoadOptions) -> (Host, LoadedFilter) {
    let bytes = component_bytes();
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
    let filter = host.load("filter-hello", &artifact, opts).unwrap();
    (host, filter)
}

fn request(headers: &[(&str, &str)]) -> HttpRequest {
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

/// The filter logs `init-calls=N` each request; recover N to observe the lifecycle.
fn init_calls(logs: &[LogLine]) -> u64 {
    logs.iter()
        .find_map(|l| {
            l.message
                .strip_prefix("init-calls=")
                .and_then(|n| n.parse().ok())
        })
        .expect("filter-hello logs init-calls=N every request")
}

/// The filter logs `local-state=N` each request: guest LINEAR-MEMORY state (a function-local
/// static), distinct from host-side `init-calls`. Used to falsify zeroization (ADR 000006).
fn local_state(logs: &[LogLine]) -> u32 {
    logs.iter()
        .find_map(|l| {
            l.message
                .strip_prefix("local-state=")
                .and_then(|n| n.parse().ok())
        })
        .expect("filter-hello logs local-state=N every request")
}

#[test]
fn continues_when_request_is_not_blocked() {
    let (_host, filter) = signed_load(LoadOptions::untrusted());

    let (decision, logs) = on_req(&filter, &request(&[])).unwrap();

    assert!(
        matches!(decision, RequestDecision::Continue),
        "an unblocked request should continue down the chain"
    );
    assert!(logs.iter().any(|l| l.message.contains("on-request")));
}

#[test]
fn short_circuits_when_block_header_present() {
    let (_host, filter) = signed_load(LoadOptions::untrusted());

    let (decision, _logs) = on_req(&filter, &request(&[("x-plecto-block", "1")])).unwrap();

    match decision {
        RequestDecision::ShortCircuit(resp) => {
            assert_eq!(resp.status, 403, "blocked request must get 403");
            assert!(
                resp.headers
                    .iter()
                    .any(|h| h.name == "x-plecto" && h.value == "blocked"),
                "short-circuit response must carry the filter's header"
            );
        }
        _ => panic!("expected short-circuit for a blocked request"),
    }
}

#[test]
fn trusted_filter_runs_init_once_across_requests() {
    // Tenet 4 effect (ADR 000004 / 000011): a trusted filter's init runs exactly once;
    // the persistent instance is reused, so the host counter stays at 1.
    let (_host, filter) = signed_load(LoadOptions::trusted());

    for _ in 0..3 {
        let (_decision, logs) = on_req(&filter, &request(&[])).unwrap();
        assert_eq!(init_calls(&logs), 1, "trusted init must run exactly once");
    }
}

#[test]
fn untrusted_filter_reinitializes_each_request() {
    // The isolation trade (ADR 000011): a fresh instance per request re-runs init, so the
    // host counter climbs with each request.
    let (_host, filter) = signed_load(LoadOptions::untrusted());

    let mut seen = Vec::new();
    for _ in 0..3 {
        let (_decision, logs) = on_req(&filter, &request(&[])).unwrap();
        seen.push(init_calls(&logs));
    }
    assert_eq!(seen, vec![1, 2, 3], "untrusted init must run every request");
}

#[test]
fn rate_limit_short_circuits_after_capacity() {
    // Host-native token bucket (ADR 000005): capacity 2 → first two pass, third is denied
    // with a synthesised 429. State lives host-side, so it persists across requests. The spec is
    // host-configured (ADR 000026), not filter-supplied.
    let (_host, filter) = signed_load(LoadOptions::trusted().with_ratelimit_bucket(2, 1, 60_000));

    let limited = request(&[("x-plecto-ratelimit", "1")]);

    for n in 1..=2 {
        let (decision, _logs) = on_req(&filter, &limited).unwrap();
        assert!(
            matches!(decision, RequestDecision::Continue),
            "request {n} within capacity should continue"
        );
    }

    let (decision, _logs) = on_req(&filter, &limited).unwrap();
    match decision {
        RequestDecision::ShortCircuit(resp) => {
            assert_eq!(resp.status, 429, "exhausted bucket must get 429");
            assert!(
                resp.headers.iter().any(|h| h.name == "retry-after-ms"),
                "429 must advertise a retry-after"
            );
        }
        _ => panic!("expected short-circuit once the bucket is empty"),
    }
}

#[test]
fn rate_limit_counting_is_host_native_across_fresh_untrusted_instances() {
    // ADR 000005 conformance (mechanism 3: super-hot paths go host-native). The token
    // bucket's refill + counting live host-side and never cross the WASM boundary, so the
    // count is NOT held in a filter's linear memory. This test makes that claim falsifiable:
    // run under `untrusted`, where every request gets a FRESH instance with fresh linear
    // memory (init re-runs, so `init-calls` climbs 1→2→3). If counting lived in WASM memory
    // it would reset each request and the bucket would never drain; because it is host-native,
    // the same capacity-2 bucket still drains across those fresh instances and the third
    // request is denied 429. The spec (capacity 2) is now HOST-configured (ADR 000026), not
    // filter-supplied — the filter only passes (key, cost), so it cannot widen its own limit.
    let (_host, filter) = signed_load(LoadOptions::untrusted().with_ratelimit_bucket(2, 1, 60_000));

    let limited = request(&[("x-plecto-ratelimit", "1")]);

    for n in 1..=2 {
        let (decision, logs) = on_req(&filter, &limited).unwrap();
        assert_eq!(
            init_calls(&logs),
            n,
            "untrusted instance must be fresh each request (init re-runs)"
        );
        assert!(
            matches!(decision, RequestDecision::Continue),
            "request {n} within capacity should continue even on a fresh instance"
        );
    }

    let (decision, logs) = on_req(&filter, &limited).unwrap();
    assert_eq!(
        init_calls(&logs),
        3,
        "third request is still a fresh instance"
    );
    assert!(
        matches!(decision, RequestDecision::ShortCircuit(resp) if resp.status == 429),
        "host-native bucket drains across fresh instances → third request denied 429"
    );
}

#[test]
fn ratelimit_without_a_host_bucket_fails_closed() {
    // ADR 000026: the bucket spec is host-configured per filter; a filter with NO configured
    // bucket cannot get a free pass. Loaded without `with_ratelimit_bucket`, the filter's
    // `try-acquire` denies — so an untrusted filter cannot bypass rate limiting by simply lacking
    // a host limit. The first request that consults the limiter is short-circuited 429.
    let (_host, filter) = signed_load(LoadOptions::untrusted());

    let (decision, _logs) = on_req(&filter, &request(&[("x-plecto-ratelimit", "1")])).unwrap();
    assert!(
        matches!(decision, RequestDecision::ShortCircuit(resp) if resp.status == 429),
        "a filter with no host-configured bucket must fail closed (denied), not bypass the limiter"
    );
}

// --- ADR 000006: data-plane metering (epoch deadline + Store memory cap) is fail-closed ---

#[test]
fn runaway_filter_is_interrupted_by_epoch_deadline() {
    // A filter stuck in an infinite loop must be trapped by the epoch deadline and surfaced
    // as a typed, fail-closed `RunError::Deadline` — it must NOT hang the calling thread.
    // (If epoch interruption were absent this test would never return.)
    let (_host, filter) = signed_load(LoadOptions::untrusted().with_request_deadline_ms(50));

    let result = on_req(&filter, &request(&[("x-plecto-spin", "1")]));
    assert!(
        matches!(result, Err(RunError::Deadline)),
        "a runaway filter must trap as Deadline (fail-closed)"
    );
}

#[test]
fn trusted_filter_recovers_after_trap() {
    // Trap recovery (ADR 000006): a trusted PERSISTENT instance whose call traps is discarded
    // and rebuilt (re-instantiate + re-init) on the next request — it self-heals instead of
    // staying broken. A trap leaves linear memory undefined, so reuse is not safe.
    let (_host, filter) = signed_load(LoadOptions::trusted().with_request_deadline_ms(50));

    let trapped = on_req(&filter, &request(&[("x-plecto-spin", "1")]));
    assert!(
        matches!(trapped, Err(RunError::Deadline)),
        "the runaway request must trap the persistent instance"
    );

    // the very next normal request still succeeds: the instance was rebuilt and re-inited.
    let (decision, logs) =
        on_req(&filter, &request(&[])).expect("trusted filter must self-heal after a trap");
    assert!(matches!(decision, RequestDecision::Continue));
    assert!(logs.iter().any(|l| l.message.contains("on-request")));
}

#[test]
fn trusted_trap_storm_opens_circuit_breaker() {
    // review f000003 #5: a trusted filter that traps deterministically must not force a
    // rebuild + re-init every request forever. The first few traps self-heal (surface as
    // Deadline); after the threshold the breaker opens and subsequent calls fail closed
    // CHEAPLY (Unavailable) WITHOUT re-instantiating — even a benign request is rejected while
    // the circuit is open.
    let (_host, filter) = signed_load(LoadOptions::trusted().with_request_deadline_ms(50));
    let spin = request(&[("x-plecto-spin", "1")]);

    for _ in 0..3 {
        assert!(
            matches!(on_req(&filter, &spin), Err(RunError::Deadline)),
            "consecutive traps self-heal and surface as Deadline until the breaker opens"
        );
    }

    assert!(
        matches!(on_req(&filter, &request(&[])), Err(RunError::Unavailable)),
        "once the breaker is open, even a benign request fails closed cheaply (no rebuild)"
    );
}

#[test]
fn memory_limit_traps_runaway_allocation() {
    // A filter allocating past its Store memory cap must trap (the guest allocator aborts on
    // the denied linear-memory grow) and surface as a fail-closed error. Critically, the HOST
    // process must survive — the cap bounds the guest, it does not OOM the host.
    let (_host, filter) = signed_load(LoadOptions::untrusted().with_max_memory_bytes(16 << 20));

    let result = on_req(&filter, &request(&[("x-plecto-balloon", "1")]));
    assert!(
        matches!(result, Err(RunError::Trap(_))),
        "over-allocation past the memory cap must trap (fail-closed), not OOM the host"
    );

    // the host is still alive and serves a normal request afterwards.
    let (decision, _logs) = on_req(&filter, &request(&[])).expect("host survives the guest trap");
    assert!(matches!(decision, RequestDecision::Continue));
}

// --- ADR 000006 / 000011: zeroization made falsifiable via guest linear-memory state ---

#[test]
fn untrusted_guest_memory_is_fresh_each_request() {
    // `local-state` is guest LINEAR-MEMORY state (a function-local static), NOT host KV. Under
    // `untrusted`, every request gets a fresh instance with fresh memory, so it must stay 1 —
    // no carry-over, no stale-heap leak between requests (the zeroization property).
    let (_host, filter) = signed_load(LoadOptions::untrusted());

    for _ in 0..3 {
        let (_decision, logs) = on_req(&filter, &request(&[])).unwrap();
        assert_eq!(
            local_state(&logs),
            1,
            "untrusted guest memory must be fresh each request (no carry-over)"
        );
    }
}

#[test]
fn trusted_guest_memory_persists_across_requests() {
    // The contrast that proves the test above measures *real* memory persistence: a trusted
    // (reused) instance is NOT zeroized between requests — same trust domain (ADR 000011) — so
    // its guest-local state climbs 1→2→3. Statelessness is honored by trust here, not enforced;
    // only `untrusted`'s fresh-per-request memory enforces it structurally.
    let (_host, filter) = signed_load(LoadOptions::trusted());

    let mut seen = Vec::new();
    for _ in 0..3 {
        let (_decision, logs) = on_req(&filter, &request(&[])).unwrap();
        seen.push(local_state(&logs));
    }
    assert_eq!(
        seen,
        vec![1, 2, 3],
        "trusted guest memory persists across reused-instance requests"
    );
}
