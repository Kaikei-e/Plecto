//! The chain dispatcher (ADR 000007): drive a request through the loaded filters in order,
//! honouring `decision` and applying `modified` edits; drive the response back in reverse.
//! Fail-closed — a trapped / timed-out filter (`RunError`) never falls through to upstream.

use plecto_host::{
    Header, HttpRequest, HttpResponse, RequestDecision, RequestEdit, RequestTrace,
    ResponseDecision, ResponseEdit,
};

use crate::ActiveConfig;

/// The result of driving a request through the chain.
pub enum ChainOutcome {
    /// Respond now without reaching upstream: a filter short-circuited, or the chain failed
    /// closed on a trap / deadline (the synthetic 5xx from `RunError::fail_closed_response`).
    Respond(HttpResponse),
    /// The chain passed: forward this (possibly edited) request upstream.
    Forward(HttpRequest),
}

pub(crate) fn dispatch_request(
    active: &ActiveConfig,
    mut request: HttpRequest,
    trace: &RequestTrace,
) -> ChainOutcome {
    for id in &active.chain {
        // `build_active` validates chain ⊆ filters, so this is always `Some`; staying total
        // (no indexing panic) honours the data-plane no-panic discipline (bp-rust).
        let Some(filter) = active.filters.get(id) else {
            continue;
        };
        // `trace` parents each filter span (ADR 000009): the host times the call and emits the
        // span to its sink; we drive only the decision here.
        match filter.on_request(&request, trace) {
            Ok((RequestDecision::Continue, _logs)) => {}
            Ok((RequestDecision::Modified(edit), _logs)) => apply_request_edit(&mut request, edit),
            Ok((RequestDecision::ShortCircuit(response), _logs)) => {
                return ChainOutcome::Respond(response);
            }
            // fail-closed: a trapped / timed-out filter must not reach upstream.
            Err(err) => return ChainOutcome::Respond(err.fail_closed_response()),
        }
    }
    ChainOutcome::Forward(request)
}

pub(crate) fn dispatch_response(
    active: &ActiveConfig,
    mut response: HttpResponse,
    trace: &RequestTrace,
) -> HttpResponse {
    // The response side runs the chain in reverse (CONTEXT: request/response are symmetric).
    // `response-decision` has no short-circuit, so the chain only continues or rewrites. The
    // same `trace` as the request side, so request + response spans share one trace (ADR 000009).
    for id in active.chain.iter().rev() {
        let Some(filter) = active.filters.get(id) else {
            continue;
        };
        match filter.on_response(&response, trace) {
            Ok((ResponseDecision::Continue, _logs)) => {}
            Ok((ResponseDecision::Modified(edit), _logs)) => {
                apply_response_edit(&mut response, edit)
            }
            Err(err) => return err.fail_closed_response(),
        }
    }
    response
}

/// Apply a request rewrite: remove the named headers, then set (replace-or-add) the given
/// ones. Header names match case-insensitively (HTTP semantics).
fn apply_request_edit(request: &mut HttpRequest, edit: RequestEdit) {
    remove_headers(&mut request.headers, &edit.remove_headers);
    set_headers(&mut request.headers, edit.set_headers);
}

fn apply_response_edit(response: &mut HttpResponse, edit: ResponseEdit) {
    if let Some(status) = edit.set_status {
        response.status = status;
    }
    remove_headers(&mut response.headers, &edit.remove_headers);
    set_headers(&mut response.headers, edit.set_headers);
}

fn remove_headers(headers: &mut Vec<Header>, names: &[String]) {
    for name in names {
        headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }
}

fn set_headers(headers: &mut Vec<Header>, set: Vec<Header>) {
    for header in set {
        headers.retain(|existing| !existing.name.eq_ignore_ascii_case(&header.name));
        headers.push(header);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn request_edit_sets_replaces_and_removes_case_insensitively() {
        let mut request = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            authority: "a".to_string(),
            scheme: "https".to_string(),
            headers: vec![h("X-Keep", "1"), h("X-Drop", "old"), h("X-Replace", "old")],
        };
        apply_request_edit(
            &mut request,
            RequestEdit {
                set_headers: vec![h("x-replace", "new"), h("X-Add", "1")],
                remove_headers: vec!["x-drop".to_string()],
            },
        );

        assert!(
            !request
                .headers
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case("x-drop")),
            "removed header gone"
        );
        let replaced: Vec<_> = request
            .headers
            .iter()
            .filter(|x| x.name.eq_ignore_ascii_case("x-replace"))
            .collect();
        assert_eq!(replaced.len(), 1, "set replaces, not duplicates");
        assert_eq!(replaced[0].value, "new");
        assert!(
            request
                .headers
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case("x-add"))
        );
        assert!(request.headers.iter().any(|x| x.name == "X-Keep"));
    }

    #[test]
    fn response_edit_sets_status_and_headers() {
        let mut response = HttpResponse {
            status: 200,
            headers: vec![h("X-Old", "1")],
            body: vec![],
        };
        apply_response_edit(
            &mut response,
            ResponseEdit {
                set_status: Some(503),
                set_headers: vec![h("X-New", "1")],
                remove_headers: vec!["x-old".to_string()],
            },
        );

        assert_eq!(response.status, 503);
        assert!(response.headers.iter().any(|x| x.name == "X-New"));
        assert!(
            !response
                .headers
                .iter()
                .any(|x| x.name.eq_ignore_ascii_case("x-old"))
        );
    }
}
