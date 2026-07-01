//! filter-extauthz — an ext_authz-style `plecto:filter` that calls an external authorization
//! endpoint over the lent outbound HTTP capability (ADR 000036) and decides:
//!   - a 2xx from the authz endpoint → `continue`,
//!   - any other status, or ANY outbound error (allowlist deny / SSRF block / timeout / protocol) →
//!     short-circuit 403. A failed or blocked authz check is NEVER treated as "allow" (fail-closed).
//!
//! The target URL is taken from the `x-authz-url` request header so a test can point it at different
//! destinations; in production it would be fixed in the filter. Built for wasm32-wasip2 — unlike the
//! header-only filters it imports `wasi:http/outgoing-handler` (via the `wasi` crate). The host still
//! gates every call by the operator allowlist + SSRF guard; this guest cannot widen that.
#![allow(clippy::all)]

wit_bindgen::generate!({
    path: "../../../wit",
    world: "filter",
});

use crate::plecto::filter::host_log;
use crate::plecto::filter::types::Header;

use wasi::http::outgoing_handler;
use wasi::http::types::{Fields, Method, OutgoingRequest, Scheme};

struct FilterExtAuthz;

const AUTHZ_URL_HEADER: &str = "x-authz-url";

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn forbid(reason: &str) -> RequestDecision {
    RequestDecision::ShortCircuit(HttpResponse {
        status: 403,
        headers: vec![Header {
            name: "content-type".to_string(),
            value: "text/plain".to_string(),
        }],
        body: format!("ext_authz denied: {reason}").into_bytes(),
    })
}

/// Split `scheme://authority/path?query` into its parts (no url crate — keep the guest tiny).
fn parse_url(url: &str) -> Option<(Scheme, String, String)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return None;
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    if authority.is_empty() {
        return None;
    }
    Some((scheme, authority, path))
}

/// Call the authz endpoint. `Ok(status)` on a completed HTTP response; `Err(reason)` on any failure —
/// the caller treats `Err` as deny (fail-closed). `reason` carries the wasi `error-code` so a test
/// can distinguish an allowlist deny from an SSRF block.
fn authorize(url: &str) -> Result<u16, String> {
    let (scheme, authority, path) = parse_url(url).ok_or_else(|| "bad url".to_string())?;

    let req = OutgoingRequest::new(Fields::new());
    req.set_method(&Method::Get).map_err(|_| "method".to_string())?;
    req.set_scheme(Some(&scheme))
        .map_err(|_| "scheme".to_string())?;
    req.set_authority(Some(&authority))
        .map_err(|_| "authority".to_string())?;
    req.set_path_with_query(Some(&path))
        .map_err(|_| "path".to_string())?;

    let future = outgoing_handler::handle(req, None).map_err(|e| format!("{e:?}"))?;
    let pollable = future.subscribe();
    loop {
        match future.get() {
            Some(result) => {
                let inner = result.map_err(|_| "future already consumed".to_string())?;
                let response = inner.map_err(|e| format!("{e:?}"))?;
                return Ok(response.status());
            }
            None => pollable.block(),
        }
    }
}

impl Guest for FilterExtAuthz {
    fn init() {
        host_log::log(host_log::Level::Info, "filter-extauthz: init");
    }

    fn on_request(req: HttpRequest) -> RequestDecision {
        let Some(url) = header(&req, AUTHZ_URL_HEADER) else {
            return forbid("no authz url");
        };
        match authorize(url) {
            Ok(status) if (200..300).contains(&status) => RequestDecision::Continue,
            Ok(status) => forbid(&format!("authz status {status}")),
            Err(reason) => forbid(&reason),
        }
    }

    fn on_response(_resp: HttpResponse) -> ResponseDecision {
        ResponseDecision::Continue
    }
}

export!(FilterExtAuthz);
