//! E2E (tdd-workflow Phase 0) for the ADR 000009 observability stage: drive a real
//! `plecto:filter` component (filter-hello) through the host and assert the host emits one
//! span per execution to its `TelemetrySink` — parented by the request trace, carrying the
//! outcome and the filter's host-log lines as events, and recording faults (trap/deadline).

use std::sync::Arc;

use plecto_host::test_support::{TestSigner, bound_sbom};
use plecto_host::{
    Header, Host, HttpRequest, InMemorySink, LoadOptions, LoadedFilter, RequestDecision,
    RequestTrace, SignedArtifact, SpanOutcome,
};

fn component_bytes() -> Vec<u8> {
    std::fs::read(env!("FILTER_HELLO_COMPONENT")).expect("read filter-hello component")
}

/// Load filter-hello into a host whose telemetry sink is `sink` (so spans are observable).
fn load_with_sink(opts: LoadOptions, sink: Arc<InMemorySink>) -> (Host, LoadedFilter) {
    let bytes = component_bytes();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&bytes).unwrap();
    let sbom = bound_sbom(&bytes);
    let sbom_signature = signer.sign(&sbom).unwrap();
    let host = Host::new(signer.trust_policy().unwrap())
        .unwrap()
        .with_telemetry_sink(sink);
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

#[test]
fn on_request_emits_a_span_parented_by_the_trace_with_log_events() {
    let sink = Arc::new(InMemorySink::new());
    let (_host, filter) = load_with_sink(LoadOptions::untrusted(), sink.clone());
    let trace = RequestTrace::root();

    let (decision, _logs) = filter.on_request(&request(&[]), &trace).unwrap();
    assert!(matches!(decision, RequestDecision::Continue));

    let spans = sink.spans();
    assert_eq!(spans.len(), 1, "exactly one span per filter execution");
    let span = &spans[0];
    assert_eq!(span.name, "filter-hello", "span name is the filter id");
    assert_eq!(span.outcome, SpanOutcome::Continue);
    assert_eq!(
        span.trace_id,
        trace.trace_id(),
        "the span belongs to the request trace"
    );
    assert_eq!(
        span.parent_span_id,
        trace.request_span_id(),
        "the filter span is a child of the request span"
    );
    assert!(
        !span.events.is_empty(),
        "the filter's host-log lines are recorded as span events (no longer dropped)"
    );
}

#[test]
fn short_circuit_is_recorded_as_a_span_outcome() {
    let sink = Arc::new(InMemorySink::new());
    let (_host, filter) = load_with_sink(LoadOptions::untrusted(), sink.clone());

    let _ = filter
        .on_request(&request(&[("x-plecto-block", "1")]), &RequestTrace::root())
        .unwrap();

    assert_eq!(
        sink.spans()[0].outcome,
        SpanOutcome::ShortCircuit,
        "a blocking filter is recorded as short-circuit (a decision, not a fault)"
    );
}

#[test]
fn a_deadline_trap_still_emits_a_fault_span() {
    // Even when the filter never returns a decision (it runs away and is interrupted), the host
    // records the execution as a fault span — observability must not have a blind spot on faults.
    let sink = Arc::new(InMemorySink::new());
    let (_host, filter) = load_with_sink(
        LoadOptions::untrusted().with_request_deadline_ms(50),
        sink.clone(),
    );

    let result = filter.on_request(&request(&[("x-plecto-spin", "1")]), &RequestTrace::root());
    assert!(result.is_err(), "a runaway filter fails closed");

    let spans = sink.spans();
    assert_eq!(spans.len(), 1, "the fault still produced a span");
    assert_eq!(spans[0].outcome, SpanOutcome::Deadline);
}
