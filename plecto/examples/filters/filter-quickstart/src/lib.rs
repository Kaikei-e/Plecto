//! filter-quickstart — the simplest useful `plecto:filter`: it stamps one header on every response.
//!
//! This is the "hello, world" of the extension plane, for `examples/quickstart`. It shows the whole
//! shape of a filter — the generated `Guest` trait, the four hooks, the typed `decision` — with the
//! least possible logic: `on-response` returns `modified` to add `x-plecto: hello-from-wasm`, so a
//! single `curl -i` proves a sandboxed WASM component touched your response. Everything else is a
//! pass-through. When you're ready to do real work, read `filter-apikey` (auth) next, or scaffold
//! your own from `examples/filters/filter-template`. Built for wasm32-unknown-unknown (ADR 000010).

// wit-bindgen flattens records into many core-wasm ABI args; the generated FFI shims trip
// clippy::too_many_arguments. Scope the allow to this crate's generated code only.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    path: "../../../wit",
    world: "filter",
});

use crate::plecto::filter::types::{Header, ResponseEdit};

struct FilterQuickstart;

impl Guest for FilterQuickstart {
    fn init() {}

    fn on_request(_req: HttpRequest) -> RequestDecision {
        RequestDecision::Continue
    }

    fn on_response(_resp: HttpResponse) -> ResponseDecision {
        // The one visible thing this filter does: stamp a header so `curl -i` shows a WASM filter
        // touched the response.
        ResponseDecision::Modified(ResponseEdit {
            set_status: None,
            set_headers: vec![Header {
                name: "x-plecto".to_string(),
                value: "hello-from-wasm".to_string(),
            }],
            remove_headers: vec![],
        })
    }
}

export!(FilterQuickstart);
