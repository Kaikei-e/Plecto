//! Response construction: synthesised short-circuit / fail-closed responses (buffered) and the
//! forwarded response that streams the upstream body back. All three stay total — a hostile filter
//! status / header can never panic the data plane.

use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use plecto_control::{Header, HttpResponse};

use crate::ResponseBody;
use crate::body::{full, stream};
use crate::headers::{copy_headers, copy_headers_preserving};

/// A synthesised response (short-circuit / fail-closed) → a hyper `Response` with a buffered body.
pub(crate) fn http_response(resp: HttpResponse) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    copy_headers(builder.headers_mut(), &resp.headers);
    builder.body(full(resp.body)).unwrap_or_else(|_| {
        // builder only errors on an invalid status/header already guarded above; stay total.
        Response::new(full(b"response build error".to_vec()))
    })
}

/// A forwarded response: the chain-edited status + headers, with the upstream body streamed.
/// `original` is the upstream's inbound header map, so headers a response filter left untouched
/// stream back to the client byte-for-byte (P3#6), not via a lossy `string` round-trip.
pub(crate) fn stream_response(
    status: u16,
    headers: &[Header],
    original: &hyper::HeaderMap,
    body: Incoming,
) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    copy_headers_preserving(builder.headers_mut(), headers, original);
    builder
        .body(stream(body))
        .unwrap_or_else(|_| Response::new(full(b"response build error".to_vec())))
}

/// A small fail-closed response with an `x-plecto-fault` marker (404 no-route, 502 upstream).
pub(crate) fn synth(
    status: StatusCode,
    fault: &str,
    body: &'static [u8],
) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("x-plecto-fault", fault)
        .body(full(body.to_vec()))
        .expect("static synth response is always valid")
}

/// Like [`synth`] but also carries a `Retry-After` (seconds) hint — for the native rate-limit 429
/// (ADR 000033), where the limiter knows when a token next frees up. The value is a decimal integer,
/// always a valid header value, so the builder still cannot fail.
pub(crate) fn synth_retry_after(
    status: StatusCode,
    fault: &str,
    body: &'static [u8],
    retry_after_secs: u64,
) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("x-plecto-fault", fault)
        .header("retry-after", retry_after_secs.to_string())
        .body(full(body.to_vec()))
        .expect("static synth response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn http_response_clamps_invalid_status_and_drops_invalid_headers_without_panicking() {
        // A short-circuit / fail-closed response carries a filter-supplied `u16` status and
        // arbitrary headers. An out-of-range status must clamp to 502 (never panic), and an
        // invalid header value must be dropped — the data plane must survive hostile filter output.
        for bad_status in [0u16, 99, 1000] {
            let resp = http_response(HttpResponse {
                status: bad_status,
                headers: vec![],
                body: Vec::new(),
            });
            assert_eq!(
                resp.status(),
                StatusCode::BAD_GATEWAY,
                "an out-of-range status ({bad_status}) clamps to 502"
            );
        }

        // a valid status is preserved; a CRLF-bearing header is dropped, a clean one kept.
        let resp = http_response(HttpResponse {
            status: 403,
            headers: vec![header("x-clean", "ok"), header("x-evil", "a\r\nb")],
            body: b"denied".to_vec(),
        });
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().contains_key("x-clean"));
        assert!(
            !resp.headers().contains_key("x-evil"),
            "an invalid header value is dropped from a synthesised response"
        );
    }
}
