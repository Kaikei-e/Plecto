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

use plecto_host::{HttpRequest, HttpResponse};

use crate::ActiveConfig;
use crate::chain::{self, ChainOutcome};

/// A configuration pinned for one request transaction. Obtain via [`crate::Control::snapshot`];
/// run `on_request` then (later) `on_response` against the *same* snapshot so a reload cannot
/// desync the two halves.
pub struct ConfigSnapshot {
    config: Arc<ActiveConfig>,
}

impl ConfigSnapshot {
    pub(crate) fn new(config: Arc<ActiveConfig>) -> Self {
        Self { config }
    }

    /// Drive a request through the pinned chain (forward, or respond on short-circuit /
    /// fail-closed).
    pub fn on_request(&self, request: HttpRequest) -> ChainOutcome {
        chain::dispatch_request(&self.config, request)
    }

    /// Drive a response back through the pinned chain in reverse.
    pub fn on_response(&self, response: HttpResponse) -> HttpResponse {
        chain::dispatch_response(&self.config, response)
    }

    /// The `config version` (manifest content hash) this transaction is pinned to.
    pub fn config_version(&self) -> &str {
        &self.config.hash
    }
}
