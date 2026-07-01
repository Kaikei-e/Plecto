//! filter-noop — the leanest possible `plecto:filter`: it makes NO host-API calls and returns
//! `continue` on every hook.
//!
//! It is the benchmark's "pure WASM no-op" rung of the cost ladder (ADR 000005 / 000012). The
//! delta between the native `/baseline` route and a route running this filter isolates the
//! irreducible extension-plane per-request cost — chain dispatch + instance acquisition + one empty
//! host↔guest crossing — with none of the host-KV / header / body work a real filter adds. Running
//! it pooled (trusted) vs fresh-per-request (untrusted) then isolates the instantiation cost the
//! pool amortizes. Built for wasm32-unknown-unknown (ADR 000010).

// wit-bindgen flattens records into many core-wasm ABI args; the generated FFI shims trip
// clippy::too_many_arguments. Scope the allow to this crate's generated code only.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    path: "../../../plecto/wit",
    world: "filter-body",
});

struct FilterNoop;

impl Guest for FilterNoop {
    fn init() {}

    fn on_request(_req: HttpRequest) -> RequestDecision {
        RequestDecision::Continue
    }

    fn on_request_body(body: Vec<u8>) -> RequestBodyDecision {
        // Pass the body through untouched (only invoked for a route with a body; the no-op ladder
        // scenario drives bodyless GETs, so this stays off the measured path).
        RequestBodyDecision::Continue(body)
    }

    fn on_response(_resp: HttpResponse) -> ResponseDecision {
        ResponseDecision::Continue
    }
}

export!(FilterNoop);
