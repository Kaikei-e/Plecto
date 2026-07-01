//! `ConfigSnapshot` — a pinned view of one `ActiveConfig` for the span of a single request
//! transaction (f000004 #2). `Control::on_request` and `on_response` each load the active
//! config independently, so a reload landing *between* a request's two halves would run the
//! request side against config A and the response side against config B — only the in-flight
//! request at the reload instant, but asymmetric filtering nonetheless.
//!
//! A snapshot closes that: the fast-path server takes one snapshot per request and drives both
//! halves through it. The snapshot holds its `Arc<ActiveConfig>` until dropped, so a concurrent
//! reload swaps the *live* set without disturbing any transaction already in flight. Taking one
//! is cheap — a single atomic `Arc` clone.

use std::sync::Arc;

use plecto_host::{HttpRequest, HttpResponse, RequestTrace};

use crate::ActiveConfig;
use crate::chain::{self, ChainOutcome, RequestBodyOutcome};
use crate::route::{self, RouteInfo};

/// A configuration pinned for one request transaction. Obtain via [`crate::Control::snapshot`];
/// run `on_request` then (later) `on_response` against the *same* snapshot so a reload cannot
/// desync the two halves.
///
/// The snapshot also carries the request's [`RequestTrace`] (ADR 000009): both halves run
/// under one trace context, so the request-side and response-side filter spans belong to the
/// same trace. The host emits those spans to its sink as the chain runs.
///
/// `Clone` is cheap (an `Arc` clone + the trace ids) and yields the **same** pinned config and
/// trace — the fast-path server clones one snapshot to run the request and response halves on
/// separate `spawn_blocking` tasks while keeping them in one transaction (ADR 000013).
#[derive(Clone)]
pub struct ConfigSnapshot {
    config: Arc<ActiveConfig>,
    trace: RequestTrace,
}

impl ConfigSnapshot {
    pub(crate) fn new(config: Arc<ActiveConfig>, trace: RequestTrace) -> Self {
        Self { config, trace }
    }

    /// Drive a request through the **default** `[chain]` (the chain-only convenience). The
    /// fast-path server uses [`ConfigSnapshot::find_route`] + [`ConfigSnapshot::dispatch_request`].
    pub fn on_request(&self, request: HttpRequest) -> ChainOutcome {
        chain::dispatch_request(&self.config, &self.config.chain, request, &self.trace)
    }

    /// Drive a response back through the default `[chain]` in reverse.
    pub fn on_response(&self, response: HttpResponse) -> HttpResponse {
        chain::dispatch_response(&self.config, &self.config.chain, response, &self.trace)
    }

    /// Match a request to a route by its `[route.match]` dimensions — host, path prefix, method,
    /// headers, query (ADR 000013 / 000034) — or `None` when no route matches (the server responds
    /// 404). The most specific match wins (see [`route::select`]). Pure config lookup — cheap and
    /// non-blocking, so it runs on the async thread; only the returned route's chain dispatch is
    /// blocking work. Reads only borrowed request fields, so matching is allocation-free.
    pub fn find_route(&self, request: &HttpRequest) -> Option<RouteInfo> {
        let parts = route::RequestParts {
            authority: &request.authority,
            path: &request.path,
            method: &request.method,
            headers: &request.headers,
        };
        let index = route::select(&self.config.routes, &parts)?;
        let r = &self.config.routes[index];
        Some(RouteInfo {
            index,
            backends: r.backends.clone(),
            strip_prefix: r.strip_prefix.clone(),
            has_filters: !r.filters.is_empty(),
            reads_body: r.reads_body,
            rate_limit: r.rate_limit.clone(),
        })
    }

    /// Drive a request through a matched route's chain (request side). `route` is the index from
    /// [`ConfigSnapshot::find_route`] on this same snapshot. Returns forward-or-respond just like
    /// `on_request`. Out-of-range (a stale index from another snapshot) responds with a
    /// fail-closed 404 rather than panicking (data-plane no-panic, bp-rust).
    pub fn dispatch_request(&self, route: usize, request: HttpRequest) -> ChainOutcome {
        match self.config.routes.get(route) {
            Some(r) => chain::dispatch_request(&self.config, &r.filters, request, &self.trace),
            None => ChainOutcome::Respond(no_route_response()),
        }
    }

    /// Drive a buffered request body through a matched route's `on-request-body` chain (ADR 000025).
    /// Same `route` index as the request side, on the same snapshot. The server calls this only for a
    /// route with filters and a non-empty body; a stale index forwards the body unchanged.
    pub fn dispatch_request_body(&self, route: usize, body: Vec<u8>) -> RequestBodyOutcome {
        match self.config.routes.get(route) {
            Some(r) => chain::dispatch_request_body(&self.config, &r.filters, body, &self.trace),
            None => RequestBodyOutcome::Forward(body),
        }
    }

    /// Drive a response back through a matched route's chain in reverse. Same `route` index as
    /// the request side, on the same (cloned) snapshot, so both halves run one route's chain.
    pub fn dispatch_response(&self, route: usize, response: HttpResponse) -> HttpResponse {
        match self.config.routes.get(route) {
            Some(r) => chain::dispatch_response(&self.config, &r.filters, response, &self.trace),
            None => response,
        }
    }

    /// The `config version` (manifest content hash) this transaction is pinned to.
    pub fn config_version(&self) -> &str {
        &self.config.hash
    }

    /// The W3C `traceparent` for this transaction — pass downstream so the upstream request
    /// continues the same trace (ADR 000009 propagation).
    pub fn traceparent(&self) -> String {
        self.trace.to_traceparent()
    }
}

/// A minimal fail-closed 404 for a `dispatch_*` called with a route index this snapshot does not
/// have (only reachable by misuse — a stale index from a different snapshot). The fast-path
/// server builds its own 404 for the ordinary "no route matched" case (`find_route` → `None`).
fn no_route_response() -> HttpResponse {
    HttpResponse {
        status: 404,
        headers: vec![plecto_host::Header {
            name: "x-plecto-fault".to_string(),
            value: "no-route".to_string(),
        }],
        body: b"no route".to_vec(),
    }
}
