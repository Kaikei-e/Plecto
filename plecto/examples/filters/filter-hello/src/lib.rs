//! filter-hello — a minimal `plecto:filter` exercising the ADR 000004 host runtime.
//!
//! Doubles as the hand-written conformance fixture the host's E2E/conformance tests load
//! (tdd-workflow Phase 0/1). It imports — and calls — every lent capability so loading it
//! proves the whole host-API surface resolves (consumer-driven contract). Behaviour:
//!   - init: bump the host counter `init-calls`. Observing this from on-request lets a
//!     test see init-ONCE for trusted filters vs init-per-request for untrusted ones
//!     (ADR 000011 / Tenet 4).
//!   - on-request:
//!       * log how many times init has run so far (reads the `init-calls` counter);
//!       * if `x-plecto-ratelimit` is present, consult a tiny host-native token bucket
//!         and short-circuit 429 when empty (ADR 000005);
//!       * if `x-plecto-block` is present, short-circuit 403;
//!       * otherwise continue.
//!   - on-response: continue.

// wit-bindgen flattens records into many core-wasm ABI args, so generated FFI shims trip
// clippy::too_many_arguments. This allow scopes ONLY to generated code.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    path: "../../../wit",
    world: "filter",
});

use crate::plecto::filter::host_counter;
use crate::plecto::filter::host_log;
use crate::plecto::filter::host_ratelimit::{self, Bucket};
use crate::plecto::filter::types::{Header, RequestEdit, ResponseEdit};

struct FilterHello;

fn has_header(req: &HttpRequest, name: &str) -> bool {
    req.headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case(name))
}

impl Guest for FilterHello {
    fn init() {
        // Heavy-init marker: how many times has init run for this filter identity?
        host_counter::increment("init-calls", 1);
    }

    fn on_request(req: HttpRequest) -> RequestDecision {
        host_log::log(host_log::Level::Info, "filter-hello: on-request");
        // observable init-once signal: stays 1 for a reused (trusted) instance, grows for
        // a fresh-per-request (untrusted) one.
        let inits = host_counter::get("init-calls");
        host_log::log(host_log::Level::Info, &format!("init-calls={inits}"));

        // Guest-LOCAL linear-memory state (NOT host KV): a function-local `static` that
        // persists across calls on a reused (trusted) instance and resets on a fresh-per-
        // request (untrusted) one. This makes zeroization falsifiable (ADR 000006 / 000011):
        // under `untrusted`, memory is fresh by construction, so `local-state` must stay 1.
        static LOCAL_HITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        let local = LOCAL_HITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) + 1;
        host_log::log(host_log::Level::Info, &format!("local-state={local}"));

        // Deliberately runaway: the host's epoch deadline (ADR 000006) must interrupt this
        // and fail-closed, not hang the calling thread.
        if has_header(&req, "x-plecto-spin") {
            let mut n: u64 = 0;
            loop {
                n = n.wrapping_add(1);
                core::hint::black_box(n);
            }
        }

        // Deliberately over-allocate past the Store memory limit (ADR 000006). The linear-
        // memory grow fails, the guest allocator aborts, and the host observes a trap — the
        // host process itself must survive.
        if has_header(&req, "x-plecto-balloon") {
            let big: Vec<u8> = Vec::with_capacity(256 << 20);
            core::hint::black_box(&big);
        }

        // A BOUNDED busy loop (no trap): burn `x-plecto-busy` iterations of cheap work, then
        // continue normally. Unlike `x-plecto-spin` (which runs forever and must hit the epoch
        // deadline), this returns on its own — so the host's pool keeps this instance CHECKED
        // OUT for the duration. The trusted-pool tests use it to hold an instance long enough
        // to observe saturation (fail-closed under contention) and real concurrency (the pool
        // builds a second instance while the first is busy), deterministically and without a
        // guest sleep capability (none is lent). Iteration count comes from the header so a
        // test can tune the hold; keep the per-request deadline generous when using it.
        if let Some(h) = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("x-plecto-busy"))
        {
            let iters: u64 = h.value.parse().unwrap_or(0);
            let mut acc: u64 = 0;
            let mut i: u64 = 0;
            while i < iters {
                acc = acc.wrapping_add(i);
                core::hint::black_box(acc);
                i += 1;
            }
            core::hint::black_box(acc);
        }

        // Ask the host to rewrite the request and continue (chain-dispatch edit application,
        // ADR 000007). The next filter / upstream sees the added header.
        if has_header(&req, "x-plecto-addheader") {
            return RequestDecision::Modified(RequestEdit {
                set_headers: vec![Header {
                    name: "x-plecto-added".to_string(),
                    value: "1".to_string(),
                }],
                remove_headers: vec![],
            });
        }

        if has_header(&req, "x-plecto-ratelimit") {
            let outcome = host_ratelimit::try_acquire(
                "default",
                1,
                Bucket {
                    capacity: 2,
                    refill_tokens: 1,
                    refill_interval_ms: 60_000,
                },
            );
            if !outcome.allowed {
                return RequestDecision::ShortCircuit(HttpResponse {
                    status: 429,
                    headers: vec![Header {
                        name: "retry-after-ms".to_string(),
                        value: outcome.retry_after_ms.to_string(),
                    }],
                    body: b"rate limited by filter-hello".to_vec(),
                });
            }
        }

        if has_header(&req, "x-plecto-block") {
            RequestDecision::ShortCircuit(HttpResponse {
                status: 403,
                headers: vec![Header {
                    name: "x-plecto".to_string(),
                    value: "blocked".to_string(),
                }],
                body: b"blocked by filter-hello".to_vec(),
            })
        } else {
            RequestDecision::Continue
        }
    }

    fn on_request_body(body: Vec<u8>) -> RequestBodyDecision {
        // buffer-then-decide (ADR 000025): the host buffered the whole body and handed it over.
        // Short-circuit on a marker (exercises the SC path), otherwise transform (uppercase) and
        // continue — both before upstream is reached, so a short-circuit is always clean.
        host_log::log(host_log::Level::Info, "filter-hello: on-request-body");
        if body
            .windows(9)
            .any(|w| w.eq_ignore_ascii_case(b"deny-body"))
        {
            RequestBodyDecision::ShortCircuit(HttpResponse {
                status: 403,
                headers: vec![Header {
                    name: "x-plecto".to_string(),
                    value: "blocked-body".to_string(),
                }],
                body: b"blocked body by filter-hello".to_vec(),
            })
        } else {
            RequestBodyDecision::Continue(body.to_ascii_uppercase())
        }
    }

    fn on_response(resp: HttpResponse) -> ResponseDecision {
        // Opt-in response rewrite (gated on a header so default responses still `continue`):
        // exercises the response-side chain dispatch + edit application (ADR 000007).
        if resp
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-plecto-respedit"))
        {
            return ResponseDecision::Modified(ResponseEdit {
                set_status: None,
                set_headers: vec![Header {
                    name: "x-plecto-respadded".to_string(),
                    value: "1".to_string(),
                }],
                remove_headers: vec![],
            });
        }
        ResponseDecision::Continue
    }
}

export!(FilterHello);
