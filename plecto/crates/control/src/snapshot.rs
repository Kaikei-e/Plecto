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
use crate::chain::{self, ChainOutcome};

/// A configuration pinned for one request transaction. Obtain via [`crate::Control::snapshot`];
/// run `on_request` then (later) `on_response` against the *same* snapshot so a reload cannot
/// desync the two halves.
///
/// The snapshot also carries the request's [`RequestTrace`] (ADR 000009): both halves run
/// under one trace context, so the request-side and response-side filter spans belong to the
/// same trace. The host emits those spans to its sink as the chain runs.
pub struct ConfigSnapshot {
    config: Arc<ActiveConfig>,
    trace: RequestTrace,
}

impl ConfigSnapshot {
    pub(crate) fn new(config: Arc<ActiveConfig>, trace: RequestTrace) -> Self {
        Self { config, trace }
    }

    /// Drive a request through the pinned chain (forward, or respond on short-circuit /
    /// fail-closed).
    pub fn on_request(&self, request: HttpRequest) -> ChainOutcome {
        chain::dispatch_request(&self.config, request, &self.trace)
    }

    /// Drive a response back through the pinned chain in reverse.
    pub fn on_response(&self, response: HttpResponse) -> HttpResponse {
        chain::dispatch_response(&self.config, response, &self.trace)
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
