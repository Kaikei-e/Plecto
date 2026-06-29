//! The transport-agnostic transaction core: route → chain (request side) → forward → chain
//! (response side). HTTP/1.1, HTTP/2 and HTTP/3 all funnel through `proxy_core`; only the body
//! adapters differ. Bounded retry onto another instance (ADR 000023) and the `on-request-body`
//! hook (ADR 000025) live here.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::body::Body;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use plecto_control::{ChainOutcome, HttpResponse, RequestBodyOutcome, RequestTrace};

use crate::body::{
    INBOUND_BODY_READ_TIMEOUT, MAX_REQUEST_BODY_BUFFER, buffer_request_body, empty_req, req_full,
};
use crate::headers::{copy_headers_preserving, headers_to_vec, set_forwarded, to_http_request};
use crate::respond::{http_response, stream_response, synth};
use crate::{ReqBody, ResponseBody, ServerState, access_log};

/// A retryable upstream failure (ADR 000023). A timeout may already have been acted on by the
/// upstream; a connect failure never reached it.
#[derive(Clone, Copy)]
enum Failure {
    Timeout,
    Connect,
}

/// RFC 9110 §9.2.2 idempotent methods — safe to retry on a timeout. Matched case-sensitively
/// (standard methods are uppercase tokens); any other token is treated as non-idempotent.
fn is_idempotent(method: &str) -> bool {
    matches!(
        method,
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

/// Whether a failed forward MAY be retried on another instance (ADR 000023) — independent of whether
/// a different instance is actually available (the caller checks that). A retry needs remaining
/// budget and a replayable (bodyless) body; a timeout additionally needs an idempotent method, while
/// a connect failure is safe for any method (the upstream never received the request).
fn may_retry(failure: Failure, method: &str, bodyless: bool, tries_left: u64) -> bool {
    bodyless
        && tries_left > 0
        && match failure {
            Failure::Timeout => is_idempotent(method),
            Failure::Connect => true,
        }
}

/// The transport-agnostic transaction core (Stage A observability wrapper, ADR 000009). Every
/// transport funnels through here, so it is the one place to tally per-request metrics and emit the
/// access log: it times `proxy_core_inner`, records the RED signals, and — when enabled — logs the
/// request, then returns the inner result unchanged.
pub(crate) async fn proxy_core(
    state: Arc<ServerState>,
    scheme: &'static str,
    peer: SocketAddr,
    parts: hyper::http::request::Parts,
    body: ReqBody,
) -> anyhow::Result<Response<ResponseBody>> {
    let start = Instant::now();
    state.metrics.inc_in_flight();

    // Capture the access-log fields BEFORE the core consumes `parts`, and only when logging is on —
    // a disabled access log allocates nothing on the hot path.
    let access = state
        .control
        .access_log_enabled()
        .then(|| access_log::Access {
            method: parts.method.as_str().to_string(),
            authority: parts
                .uri
                .authority()
                .map(|a| a.to_string())
                .or_else(|| {
                    parts
                        .headers
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string)
                })
                .unwrap_or_default(),
            path: parts.uri.path().to_string(),
        });

    let result = proxy_core_inner(state.clone(), scheme, peer, parts, body).await;

    state.metrics.dec_in_flight();
    let status = match &result {
        Ok(resp) => resp.status().as_u16(),
        // an inner error is mapped to 502 by the caller (`handle`), so record it as such here.
        Err(_) => StatusCode::BAD_GATEWAY.as_u16(),
    };
    let elapsed = start.elapsed();
    state.metrics.record_request(status, elapsed);
    if let Some(access) = access {
        access_log::record(scheme, peer, &access, status, elapsed);
    }
    result
}

/// The transaction core proper: route → chain (request side) → forward → chain (response side).
/// Takes the request head + a boxed body (so HTTP/1.1, HTTP/2 and HTTP/3 all share it) and returns
/// the client-visible response. Errors here are upstream/transport failures the caller maps to 502.
async fn proxy_core_inner(
    state: Arc<ServerState>,
    scheme: &'static str,
    peer: SocketAddr,
    parts: hyper::http::request::Parts,
    body: ReqBody,
) -> anyhow::Result<Response<ResponseBody>> {
    let mut http_req = to_http_request(&parts, scheme);

    // Normalize the request path once at ingress (CWE-22 Path Traversal / CWE-436
    // Interpretation Conflict): route selection, the filter chain, and the forwarded path then all
    // use the SAME normalized path, so the upstream cannot re-derive a stricter path than the
    // (possibly laxer, unfiltered) route we selected — closing the per-route-filter bypass. An
    // ambiguous (encoded-separator) or root-escaping path is rejected fail-closed.
    match plecto_control::normalize_path(&http_req.path) {
        Some(path) => http_req.path = path,
        None => {
            return Ok(synth(
                StatusCode::BAD_REQUEST,
                "bad-path",
                b"bad request path",
            ));
        }
    }

    // Client-IP propagation, edge model (ADR 000018 / review f000005 P2#3): strip any inbound
    // `X-Forwarded-*` / `Forwarded` (which an untrusted client can forge) and set them afresh from
    // the connection's real peer + scheme. Done BEFORE the chain so an IP-based rate-limit / auth
    // filter sees a value it can trust; the corrected headers then forward to the upstream.
    set_forwarded(&mut http_req.headers, peer.ip(), scheme);

    // Continue an inbound distributed trace (ADR 000009): if the caller sent a W3C `traceparent`,
    // parse it and pin the transaction to it so Plecto's filter spans JOIN the caller's trace
    // (and the traceparent forwarded upstream keeps the same trace-id) instead of starting a fresh
    // root. Fail-soft — a missing / malformed header falls back to a new root, never a panic on
    // untrusted input (review f000005 P1#2; `from_traceparent` is the fail-soft parser).
    let trace = parts
        .headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(RequestTrace::from_traceparent)
        .unwrap_or_else(RequestTrace::root);

    // One snapshot pins config + trace for the whole transaction (a concurrent reload cannot
    // desync the request and response halves); cloning it is a cheap Arc + trace-id clone.
    let snapshot = state.control.snapshot_with_trace(trace);
    let Some(route) = snapshot.find_route(&http_req.authority, &http_req.path) else {
        return Ok(synth(StatusCode::NOT_FOUND, "no-route", b"no route"));
    };
    let idx = route.index;

    // --- request side: the route's chain on the blocking pool (sync wasmtime, !Send Store) ---
    let snap_req = snapshot.clone();
    let forward = match tokio::task::spawn_blocking(move || {
        snap_req.dispatch_request(idx, http_req)
    })
    .await?
    {
        ChainOutcome::Respond(resp) => return Ok(http_response(resp)),
        ChainOutcome::Forward(req) => req,
    };

    // --- forward to a healthy instance, with bounded retry onto ANOTHER instance on a retryable
    // failure (ADR 000019 timeout / 000023 retry). The per-attempt invariants are computed once. ---
    let upstream_path = route.rewrite_path(&forward.path);
    let timeout = route.upstream.request_timeout();
    // Only a bodyless request can be retried without buffering: the opaque streamed body
    // (ADR 000013) can't be replayed. `exact() == Some(0)` is hyper's framing-accurate "no body".
    let bodyless = body.size_hint().exact() == Some(0);
    let mut real_body = Some(body);
    let mut tries_left = route.upstream.max_retries();

    // --- request-side body hook (ADR 000025): for a filtered route carrying a body, buffer it
    // (bounded), run the chain's `on-request-body`, and forward the possibly-transformed body — or
    // short-circuit before upstream. Header-only routes and bodyless requests skip this, keeping the
    // zero-copy streaming path. The chain runs on the blocking pool (sync wasmtime, !Send Store),
    // like the header chain. (v1 buffers; a header-only zero-copy bypass is a follow-up.)
    if route.has_filters
        && !bodyless
        && let Some(b) = real_body.take()
    {
        // Bound concurrent buffered-body memory and the time spent reading one body
        // (slow-body slowloris): hold a buffer permit and read under a deadline. Over the
        // size cap → 413, over the time budget → 408 — both fail closed (never an unbounded buffer).
        let _buf_permit = state.body_buffer_limit.clone().acquire_owned().await.ok();
        let buffered = match tokio::time::timeout(
            INBOUND_BODY_READ_TIMEOUT,
            buffer_request_body(b, MAX_REQUEST_BODY_BUFFER),
        )
        .await
        {
            Ok(Some(buf)) => buf,
            Ok(None) => {
                return Ok(synth(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "body-too-large",
                    b"request body too large",
                ));
            }
            Err(_) => {
                return Ok(synth(
                    StatusCode::REQUEST_TIMEOUT,
                    "body-timeout",
                    b"request body read timeout",
                ));
            }
        };
        let snap_body = snapshot.clone();
        match tokio::task::spawn_blocking(move || snap_body.dispatch_request_body(idx, buffered))
            .await?
        {
            RequestBodyOutcome::Respond(resp) => return Ok(http_response(resp)),
            RequestBodyOutcome::Forward(edited) => real_body = Some(req_full(edited)),
        }
    }

    // First pick by round-robin; fail closed (503) if no instance is healthy (ADR 000017).
    let Some(mut instance) = route.upstream.pick() else {
        return Ok(synth(
            StatusCode::SERVICE_UNAVAILABLE,
            "no-healthy-upstream",
            b"no healthy upstream",
        ));
    };

    let upstream_resp = loop {
        // Build this attempt. A bodyless request re-sends an empty body to each instance; a bodied
        // one moves its single streamed body and (since `may_retry` is false for it) is sent once.
        let attempt_body = if bodyless {
            empty_req()
        } else {
            real_body.take().unwrap_or_else(empty_req)
        };
        let uri = format!("http://{}{}", instance.address(), upstream_path);
        let mut builder = Request::builder().method(forward.method.as_str()).uri(uri);
        // Forward the chain's headers, restoring byte-equivalence for any the filters left untouched
        // (P3#6): the contract's `string` values are lossy, but the original inbound bytes are still
        // here in `parts.headers`, so a pass-through header reaches the upstream byte-for-byte.
        copy_headers_preserving(builder.headers_mut(), &forward.headers, &parts.headers);
        // continue the trace into the upstream (ADR 000009 W3C propagation).
        if let Some(h) = builder.headers_mut()
            && let Ok(v) = HeaderValue::from_str(&snapshot.traceparent())
        {
            h.insert("traceparent", v);
        }
        let upstream_req = builder.body(attempt_body)?;

        // The timeout (ADR 000019) bounds time-to-response-headers; `Duration::ZERO` opts out. The
        // body then streams without a deadline, so streaming responses are unaffected.
        let send = state.client.request(upstream_req);
        let outcome = if timeout.is_zero() {
            Some(send.await)
        } else {
            tokio::time::timeout(timeout, send).await.ok()
        };

        match outcome {
            Some(Ok(resp)) => break resp,
            // The deadline elapsed before response headers. Not a health signal (ADR 000019) — leave
            // liveness to the active prober. Retry onto a DIFFERENT instance if policy allows and one
            // is available (idempotent-only, ADR 000023), else fail closed 504.
            None => {
                if may_retry(
                    Failure::Timeout,
                    forward.method.as_str(),
                    bodyless,
                    tries_left,
                ) && let Some(next) = route.upstream.pick_excluding(&instance)
                {
                    state.metrics.inc_retries();
                    tries_left -= 1;
                    instance = next;
                    continue;
                }
                return Ok(synth(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream-timeout",
                    b"upstream timeout",
                ));
            }
            Some(Err(e)) => {
                // A connect failure passively ejects (ADR 000017) and is safe to retry for ANY method
                // (the upstream never received the request, ADR 000023). A non-connect transport
                // fault is neither a health signal nor retried — only the active prober governs
                // health then; the request fails closed (the caller maps the error to 502).
                if e.is_connect() {
                    instance.record_passive_failure();
                    if may_retry(
                        Failure::Connect,
                        forward.method.as_str(),
                        bodyless,
                        tries_left,
                    ) && let Some(next) = route.upstream.pick_excluding(&instance)
                    {
                        state.metrics.inc_retries();
                        tries_left -= 1;
                        instance = next;
                        continue;
                    }
                }
                return Err(e.into());
            }
        }
    };

    // --- response side: the route's chain in reverse (status / headers only) ---
    let (uparts, ubody) = upstream_resp.into_parts();
    let http_resp = HttpResponse {
        status: uparts.status.as_u16(),
        headers: headers_to_vec(&uparts.headers),
        body: Vec::new(), // header-only: filters never see the streamed body
    };
    let snap_resp = snapshot.clone();
    let edited =
        tokio::task::spawn_blocking(move || snap_resp.dispatch_response(idx, http_resp)).await?;

    // A response filter that trapped fail-closed yields a synthetic 5xx WITH a body; only then is
    // `body` non-empty (a normal response-edit can set status/headers but not a body). So: a
    // non-empty body means "use the synthetic response, drop the upstream stream"; an empty body
    // means "send the edited status + headers and stream the upstream body through".
    if edited.body.is_empty() {
        Ok(stream_response(
            edited.status,
            &edited.headers,
            &uparts.headers,
            ubody,
        ))
    } else {
        Ok(http_response(edited))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_methods_per_rfc_9110() {
        for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert!(is_idempotent(m), "{m} is idempotent (RFC 9110 §9.2.2)");
        }
        for m in ["POST", "PATCH", "CONNECT", "get", ""] {
            assert!(!is_idempotent(m), "{m} is not idempotent");
        }
    }

    #[test]
    fn may_retry_gates_on_failure_method_body_and_budget() {
        // A timeout retries only for an idempotent method (the upstream may have acted).
        assert!(may_retry(Failure::Timeout, "GET", true, 1));
        assert!(!may_retry(Failure::Timeout, "POST", true, 1));
        // A connect failure never reached the upstream → safe for ANY method.
        assert!(may_retry(Failure::Connect, "POST", true, 1));
        assert!(may_retry(Failure::Connect, "GET", true, 1));
        // A bodied request can't be replayed (no buffering) → never retried, either failure.
        assert!(!may_retry(Failure::Timeout, "GET", false, 1));
        assert!(!may_retry(Failure::Connect, "POST", false, 1));
        // Exhausted budget → no retry.
        assert!(!may_retry(Failure::Timeout, "GET", true, 0));
        assert!(!may_retry(Failure::Connect, "GET", true, 0));
    }
}
