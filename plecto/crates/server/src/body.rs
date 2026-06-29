//! Body adapters and the request-body buffering for the `on-request-body` hook (ADR 000025). The
//! fast path boxes every inbound body into `ReqBody` and every response body into `ResponseBody` so
//! one type covers all three transports; the buffering bounds memory and time for the body hook.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;

use crate::{BoxError, ReqBody, ResponseBody};

/// The cap on a request body buffered for the `on-request-body` hook (ADR 000025). Buffer-then-
/// decide must bound memory: an unbounded buffer is a trivial OOM DoS, so a body larger than this
/// fails closed (413) rather than being read into RAM. A per-route override is a follow-up; the
/// constant keeps v1 safe. Header-only / bodyless requests never reach this path.
pub(crate) const MAX_REQUEST_BODY_BUFFER: usize = 16 << 20; // 16 MiB

/// Cap on request bodies buffered concurrently for the `on-request-body` hook. Bounds total
/// buffered memory at `MAX_INFLIGHT_BODY_BUFFERS × MAX_REQUEST_BODY_BUFFER`.
pub(crate) const MAX_INFLIGHT_BODY_BUFFERS: usize = 64;

/// How long the server spends reading a buffered request body before failing closed 408 (slow-body
/// slowloris): the body hook buffers, and an un-timed read would await trickled frames forever.
pub(crate) const INBOUND_BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A buffered body boxed into `ResponseBody` (its `Infallible` error widened to the boxed type).
pub(crate) fn full(bytes: Vec<u8>) -> ResponseBody {
    Full::new(Bytes::from(bytes))
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}

/// The upstream's streamed body boxed into `ResponseBody`.
pub(crate) fn stream(body: Incoming) -> ResponseBody {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

/// Box a hyper `Incoming` inbound body into the transport-agnostic `ReqBody`.
pub(crate) fn box_incoming(body: Incoming) -> ReqBody {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

/// An empty `ReqBody` — used to re-send a bodyless request to another instance on retry (ADR
/// 000023), since the opaque streamed body (ADR 000013) cannot be replayed.
pub(crate) fn empty_req() -> ReqBody {
    Empty::<Bytes>::new()
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}

/// Buffer a request body for the `on-request-body` hook (ADR 000025), capped at `max` bytes.
/// Streams frame-by-frame so an over-cap body is rejected without first reading it all into memory;
/// returns `None` on over-cap OR a body read fault, so the caller fails closed (413) rather than
/// holding an unbounded buffer (data-plane no-panic / DoS-aware, bp-rust).
pub(crate) async fn buffer_request_body(mut body: ReqBody, max: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            if buf.len() + data.len() > max {
                return None;
            }
            buf.extend_from_slice(&data);
        }
    }
    Some(buf)
}

/// A buffered request body (post `on-request-body` hook, ADR 000025) boxed into `ReqBody` — the
/// transformed body the fast path forwards in place of the original stream.
pub(crate) fn req_full(bytes: Vec<u8>) -> ReqBody {
    Full::new(Bytes::from(bytes))
        .map_err(|e: Infallible| -> BoxError { match e {} })
        .boxed()
}
