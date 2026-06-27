//! filter-apikey — a real-world `plecto:filter`: an **API-key authentication gate**.
//!
//! This is the kind of per-request *decision* Plecto pushes into a sandboxed WASM component
//! instead of the native data path. It shows the whole story in one small filter:
//!   - **typed decision** — `short-circuit` 401 for a missing/invalid key, `modified` to stamp the
//!     caller's identity, `continue` otherwise. Never an ambiguous flag.
//!   - **filters are stateless; state lives in host KV** (Tenet 4) — `init` seeds the key→user map
//!     into the host KV (namespaced to this filter, ADR 000011); the hot path only *reads* it, so
//!     the filter pools and hot-swaps cleanly.
//!   - **host-native counters** — each authenticated request bumps a per-user counter.
//!   - **deny-by-default capability** — it imports only `host-kv` / `host-counter` / `host-log`;
//!     it has no network, no filesystem, no clock unless lent. The sandbox enforces it.
//!
//! In production the key→user map would be seeded from a secret store at deploy time rather than
//! hard-coded; here `init` seeds a couple of demo keys so the example is self-contained.

// wit-bindgen flattens records into many core-wasm ABI args; the generated FFI shims trip
// clippy::too_many_arguments. Scope the allow to this crate's generated code only.
#![allow(clippy::too_many_arguments)]

wit_bindgen::generate!({
    path: "../../../wit",
    world: "filter",
});

use crate::plecto::filter::host_counter;
use crate::plecto::filter::host_kv;
use crate::plecto::filter::host_log;
use crate::plecto::filter::types::{Header, RequestEdit};

struct FilterApiKey;

/// Demo key→user map seeded into host KV at init. (Production: load from a secret store.)
const DEMO_KEYS: &[(&str, &str)] = &[("alice-secret", "alice"), ("bob-secret", "bob")];

/// The header carrying the caller's API key.
const API_KEY_HEADER: &str = "x-api-key";

fn kv_key(api_key: &str) -> String {
    format!("key:{api_key}")
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn unauthorized(reason: &str) -> RequestDecision {
    RequestDecision::ShortCircuit(HttpResponse {
        status: 401,
        headers: vec![
            Header {
                name: "www-authenticate".to_string(),
                value: "ApiKey".to_string(),
            },
            Header {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
        ],
        body: format!("{{\"error\":\"{reason}\"}}").into_bytes(),
    })
}

impl Guest for FilterApiKey {
    fn init() {
        // Seed the key→user map into the filter's own KV namespace. Idempotent across reloads:
        // the same `id` keeps its namespace, so re-seeding just rewrites the same entries.
        for (key, user) in DEMO_KEYS {
            host_kv::set(&kv_key(key), user.as_bytes());
        }
        host_log::log(
            host_log::Level::Info,
            "filter-apikey: init seeded demo keys",
        );
    }

    fn on_request(req: HttpRequest) -> RequestDecision {
        let Some(api_key) = header(&req, API_KEY_HEADER) else {
            host_log::log(host_log::Level::Info, "filter-apikey: missing API key");
            return unauthorized("missing API key");
        };

        // Look the key up in host KV (seeded at init). Absent → reject.
        let Some(user_bytes) = host_kv::get(&kv_key(api_key)) else {
            host_log::log(host_log::Level::Info, "filter-apikey: invalid API key");
            return unauthorized("invalid API key");
        };
        let Ok(user) = String::from_utf8(user_bytes) else {
            // a corrupt KV value is a server-side fault, not the caller's — fail closed.
            return unauthorized("invalid API key");
        };

        // Authenticated: count the call per user (host-native counter) and stamp the identity so
        // the upstream — and any later filter — sees who the caller is.
        let total = host_counter::increment(&format!("requests:{user}"), 1);
        host_log::log(
            host_log::Level::Info,
            &format!("filter-apikey: authenticated user={user} (request #{total})"),
        );
        // `set` REPLACES case-insensitively (it is not an append), so this also overwrites any
        // `x-authenticated-user` a client tried to spoof inbound — no separate remove needed.
        RequestDecision::Modified(RequestEdit {
            set_headers: vec![Header {
                name: "x-authenticated-user".to_string(),
                value: user,
            }],
            remove_headers: vec![],
        })
    }

    fn on_request_body(body: Vec<u8>) -> RequestBodyDecision {
        // An auth gate doesn't touch the body — pass it through unchanged (buffer-then-decide,
        // ADR 000025). Until the export-presence-based bypass (ADR 000005 mechanism 2) lands, a
        // header-only filter still implements a trivial pass-through.
        RequestBodyDecision::Continue(body)
    }

    fn on_response(_resp: HttpResponse) -> ResponseDecision {
        ResponseDecision::Continue
    }
}

export!(FilterApiKey);
