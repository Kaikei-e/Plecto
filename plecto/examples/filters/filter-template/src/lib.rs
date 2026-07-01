//! A starter `plecto:filter`. Copy this crate, rename it, and put your policy in `on_request`.
//!
//! It implements the whole `filter` world: `init` plus the request / request-body / response
//! hooks. The default behaviour passes everything through, except it short-circuits with `403`
//! when a request carries an `x-block` header — replace that with your own decision.
//!
//! A filter is stateless: anything it must remember (a counter, a rate-limit bucket, a cached
//! value) lives in host state, reached through the capabilities the host lent it (here, only
//! `host-log`). See docs/writing-a-filter.md.

// wit-bindgen flattens records into many core-wasm ABI args, so the generated FFI shims trip
// clippy::too_many_arguments. This allow scopes ONLY to generated code.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    path: "wit",
    world: "filter",
});

use crate::plecto::filter::host_log;

struct MyFilter;

impl Guest for MyFilter {
    fn init() {
        // Heavy, once-per-instance setup goes here (regex compile, schema build). Empty for now.
    }

    fn on_request(req: HttpRequest) -> RequestDecision {
        host_log::log(host_log::Level::Info, "my-filter: on-request");

        // Example policy: reject any request carrying `x-block`. Replace with your own.
        if req
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-block"))
        {
            return RequestDecision::ShortCircuit(HttpResponse {
                status: 403,
                headers: vec![],
                body: b"blocked by my-filter".to_vec(),
            });
        }

        RequestDecision::Continue
    }

    // This starter is header-only (world `filter`): it never reads the request body, so the host
    // streams the body straight through (zero-copy). To inspect or transform the body, target world
    // `filter-body` in the `generate!` above and add `fn on_request_body(body: Vec<u8>) ->
    // RequestBodyDecision` — its presence is what makes the host buffer the body (ADR 000038).

    fn on_response(_resp: HttpResponse) -> ResponseDecision {
        ResponseDecision::Continue
    }
}

export!(MyFilter);
