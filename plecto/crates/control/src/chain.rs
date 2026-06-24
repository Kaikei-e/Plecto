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
    chain: &[String],
    mut request: HttpRequest,
    trace: &RequestTrace,
) -> ChainOutcome {
    for id in chain {
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
    chain: &[String],
    mut response: HttpResponse,
    trace: &RequestTrace,
) -> HttpResponse {
    // The response side runs the chain in reverse (CONTEXT: request/response are symmetric).
    // `response-decision` has no short-circuit, so the chain only continues or rewrites. The
    // same `trace` as the request side, so request + response spans share one trace (ADR 000009).
    for id in chain.iter().rev() {
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
        // Repeatable headers (Set-Cookie) APPEND: each field line is independent, so collapsing
        // them on `set` would drop all but the last cookie (review f000005 P3#7). Every other
        // header REPLACES — the semantics a filter relies on to AUTHORITATIVELY overwrite a value
        // (e.g. a spoofed `x-authenticated-user`), so this carve-out is for repeatables only.
        if !is_repeatable(&header.name) {
            headers.retain(|existing| !existing.name.eq_ignore_ascii_case(&header.name));
        }
        headers.push(header);
    }
}

/// Headers that may legitimately appear multiple times and must not be collapsed by `set`.
/// `Set-Cookie` is the canonical case (RFC 6265: one cookie per field line).
fn is_repeatable(name: &str) -> bool {
    name.eq_ignore_ascii_case("set-cookie")
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

    #[test]
    fn response_edit_appends_repeatable_set_cookie_but_replaces_others() {
        // review f000005 P3#7: two Set-Cookie in one edit must BOTH survive (append), not collapse
        // to the last — otherwise a filter setting a session + a flag cookie silently loses one.
        // A non-repeatable header still replaces (the `set replaces` contract is unchanged for it).
        let mut response = HttpResponse {
            status: 200,
            headers: vec![h("x-keep", "1")],
            body: vec![],
        };
        apply_response_edit(
            &mut response,
            ResponseEdit {
                set_status: None,
                set_headers: vec![
                    h("set-cookie", "session=abc"),
                    h("set-cookie", "flag=1"),
                    h("x-keep", "2"),
                ],
                remove_headers: vec![],
            },
        );

        let cookies: Vec<&str> = response
            .headers
            .iter()
            .filter(|x| x.name.eq_ignore_ascii_case("set-cookie"))
            .map(|x| x.value.as_str())
            .collect();
        assert_eq!(
            cookies,
            vec!["session=abc", "flag=1"],
            "both Set-Cookie field lines must survive (append, not collapse)"
        );
        let keep: Vec<&Header> = response
            .headers
            .iter()
            .filter(|x| x.name.eq_ignore_ascii_case("x-keep"))
            .collect();
        assert_eq!(keep.len(), 1, "a non-repeatable header still replaces");
        assert_eq!(keep[0].value, "2");
    }
}
