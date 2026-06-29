//! Header handling for the fast path: the hop-by-hop strip (RFC 9110 §7.6.1), edge client-IP
//! propagation (X-Forwarded-* / Forwarded), the header-only request projection, and the
//! contract↔hyper conversions (including the byte-preserving pass-through, P3#6).

use std::collections::HashSet;
use std::net::IpAddr;

use hyper::header::{HeaderName, HeaderValue};
use plecto_control::{Header, HttpRequest};

/// Hop-by-hop headers a proxy must not forward (RFC 9110 §7.6.1). Stripped both ways so the
/// upstream's framing (`transfer-encoding`) and connection management never collide with the
/// fresh framing hyper computes for the leg we send.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    // Proxy-scoped credentials/challenges are hop-by-hop (RFC 9110 §11.7.1/§11.7.2): a
    // client's `Proxy-Authorization` must not leak to the upstream, nor an upstream's
    // `Proxy-Authenticate` back to the client.
    "proxy-authorization",
    "proxy-authenticate",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// The set of header names DYNAMICALLY designated hop-by-hop by `Connection` (RFC 9110 §7.6.1):
/// `Connection: X-Foo, close` marks `X-Foo` connection-specific, so a proxy must not forward it.
/// Forwarding such a header is a request-smuggling / header-leak primitive, so we strip these too
/// — not just the static `HOP_BY_HOP` set (review f000005 P2#5). Tokens are lower-cased for the
/// case-insensitive name compare; `close` / `keep-alive` are inert (no such header to drop).
fn connection_named(map: &hyper::HeaderMap) -> HashSet<String> {
    let mut named = HashSet::new();
    for value in map.get_all(hyper::header::CONNECTION).iter() {
        if let Ok(s) = value.to_str() {
            for token in s.split(',') {
                let token = token.trim();
                if !token.is_empty() {
                    named.insert(token.to_ascii_lowercase());
                }
            }
        }
    }
    named
}

/// Forwarding / client-IP headers a client could spoof: RFC 7239 `Forwarded`, the de-facto
/// `X-Forwarded-*`, and the de-facto client-IP family that many backends and CDNs trust (nginx's
/// `X-Real-IP`, Akamai/Cloudflare `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`,
/// `X-Client-IP`, `X-Cluster-Client-IP`). As an EDGE proxy Plecto strips this whole family on
/// ingress and sets its own (review f000005 P2#3 / ADR 000018 + 000022), so an untrusted client
/// cannot forge its source IP / scheme for an IP-based filter or the upstream — stripping `XFF`
/// alone would leave a spoofed `X-Real-IP` to fool a backend that reads it instead.
const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
];

/// Edge-proxy client-IP propagation: drop any client-supplied forwarding / client-IP headers
/// (`FORWARDED_HEADERS`), then set `X-Forwarded-For` and `X-Real-IP` (the real connection peer) and
/// `X-Forwarded-Proto` (the wire scheme) afresh. `X-Real-IP` is re-issued — not just stripped — so a
/// backend reading the nginx convention rather than `XFF` still gets Plecto's authoritative peer
/// (ADR 000022 widens ADR 000018's "issue For+Proto only"). The chain (so IP-based rate-limit / auth
/// filters can trust them) and the upstream then see only Plecto's values, never the client's claim.
/// A trusted-proxy *append* mode (Plecto behind another LB) is a manifest knob deferred to a later
/// slice; overwrite is the safe default.
pub(crate) fn set_forwarded(headers: &mut Vec<Header>, peer: IpAddr, scheme: &str) {
    headers.retain(|h| {
        !FORWARDED_HEADERS
            .iter()
            .any(|f| h.name.eq_ignore_ascii_case(f))
    });
    // An IPv4 client on a dual-stack ([::]) listener arrives as an IPv4-mapped IPv6 address
    // (`::ffff:a.b.c.d`); normalise it to dotted IPv4 so backends/filters that all-list on the IPv4
    // form match, and the value matches what nginx/Envoy would emit. A genuine IPv6 peer is kept
    // verbatim (no brackets — XFF carries a bare address).
    let client_ip = match peer {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    };
    headers.push(Header {
        name: "x-forwarded-for".to_string(),
        value: client_ip.clone(),
    });
    headers.push(Header {
        name: "x-real-ip".to_string(),
        value: client_ip,
    });
    headers.push(Header {
        name: "x-forwarded-proto".to_string(),
        value: scheme.to_string(),
    });
}

/// Build a header-only `HttpRequest` (the chain's view) from the inbound request parts. The body
/// is handled separately (streamed), so it is absent here — the v0.1 contract is header-only.
///
/// `scheme` is the connection-level truth (`"https"` when the fast path terminated TLS on this
/// connection, `"http"` for plaintext) — not the request URI's scheme, which a client can spoof.
pub(crate) fn to_http_request(parts: &hyper::http::request::Parts, scheme: &str) -> HttpRequest {
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // authority: for HTTP/2 the `:authority` pseudo-header lands in the URI; for HTTP/1.1 it is the
    // Host header. Prefer the URI authority (h2), falling back to Host, then to empty.
    let authority = parts
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
        .unwrap_or_default();
    HttpRequest {
        method: parts.method.as_str().to_string(),
        path,
        authority,
        scheme: scheme.to_string(),
        headers: headers_to_vec(&parts.headers),
    }
}

/// Convert a hyper `HeaderMap` to the contract's `Vec<Header>`, lossily decoding values (HTTP
/// permits non-UTF-8 bytes; the contract is `string`). Both the static hop-by-hop set AND any
/// header dynamically named by `Connection` are dropped (RFC 9110 §7.6.1) — this is the single
/// ingress point for both the request (from `parts`) and the response (from the upstream parts),
/// so a connection-specific header can never be carried into the contract and forwarded.
pub(crate) fn headers_to_vec(map: &hyper::HeaderMap) -> Vec<Header> {
    let named = connection_named(map);
    map.iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name.as_str()) && !named.contains(&name.as_str().to_ascii_lowercase())
        })
        .map(|(name, value)| Header {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

/// Copy contract headers into a hyper `HeaderMap`, skipping hop-by-hop and any that fail hyper's
/// validation (a malformed name/value is dropped, never panics — data-plane no-panic).
pub(crate) fn copy_headers(dst: Option<&mut hyper::HeaderMap>, headers: &[Header]) {
    let Some(dst) = dst else { return };
    for h in headers {
        if is_hop_by_hop(&h.name) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(h.name.as_bytes()),
            HeaderValue::from_str(&h.value),
        ) {
            dst.append(name, value);
        }
    }
}

/// Like [`copy_headers`], but restores byte-equivalence for headers a filter never touched (P3#6).
/// The contract carries each header value as a lossy-UTF-8 `string`, so a value holding non-UTF-8
/// bytes (HTTP permits them) reaches the chain `U+FFFD`-mangled and would be re-encoded from that
/// mangled form — or dropped entirely by `HeaderValue::from_str`. For every contract header whose
/// `(name, value)` still matches an `original` inbound header's lossy projection (i.e. the filter
/// passed it through unchanged), the ORIGINAL bytes are forwarded verbatim; a value a filter set or
/// changed no longer matches and is encoded from the contract string exactly as `copy_headers` does.
/// This keeps pass-through headers byte-exact WITHOUT widening the WIT contract — the typed
/// `wasi:http` byte distinction is the eventual M3-convergence form (ADR 000020); this is the
/// host-side interim that needs no contract churn. It can only forward bytes the peer actually sent
/// under that name, and never resurrects a header the chain removed or replaced (we iterate the
/// chain's output), so it carries no smuggling/spoofing regression over `copy_headers`.
pub(crate) fn copy_headers_preserving(
    dst: Option<&mut hyper::HeaderMap>,
    headers: &[Header],
    original: &hyper::HeaderMap,
) {
    let Some(dst) = dst else { return };
    for h in headers {
        if is_hop_by_hop(&h.name) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(h.name.as_bytes()) else {
            continue;
        };
        // Prefer the original bytes when the chain left this header untouched: find an inbound value
        // under the same name whose lossy decoding equals the contract string. A match means the
        // filter passed it through, so forward the bytes verbatim; otherwise the filter set or
        // changed it and we encode from the contract string (dropping a value hyper rejects).
        let preserved = original
            .get_all(&name)
            .iter()
            .find(|v| String::from_utf8_lossy(v.as_bytes()) == h.value)
            .cloned();
        match preserved {
            Some(value) => {
                dst.append(name, value);
            }
            None => {
                if let Ok(value) = HeaderValue::from_str(&h.value) {
                    dst.append(name, value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;

    fn parts(authority_in_uri: bool) -> hyper::http::request::Parts {
        let uri = if authority_in_uri {
            "https://h2.example/api/x"
        } else {
            "/api/x"
        };
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("host", "h1.example")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    #[test]
    fn scheme_reflects_tls_termination_not_a_hardcoded_value() {
        // A TLS-terminated connection must surface `https` to the chain; plaintext surfaces `http`.
        // (The scheme is connection truth — what the fast path terminated — so a filter that, say,
        // redirects http→https can trust it.)
        assert_eq!(to_http_request(&parts(false), "https").scheme, "https");
        assert_eq!(to_http_request(&parts(false), "http").scheme, "http");
    }

    #[test]
    fn authority_prefers_h2_uri_authority_then_falls_back_to_host() {
        // HTTP/2 carries the host in the URI (`:authority`); HTTP/1.1 carries it in the Host header.
        assert_eq!(
            to_http_request(&parts(true), "https").authority,
            "h2.example"
        );
        assert_eq!(
            to_http_request(&parts(false), "http").authority,
            "h1.example"
        );
    }

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn hop_by_hop_set_is_recognised_case_insensitively() {
        // The exact RFC 9110 §7.6.1 connection-management set a proxy must never forward, plus
        // `transfer-encoding` — forwarding a client's `Transfer-Encoding`/`Connection` next to the
        // fresh framing hyper computes is the classic request-smuggling primitive (CWE-444).
        for h in [
            "connection",
            "Keep-Alive",
            "PROXY-CONNECTION",
            "Transfer-Encoding",
            "te",
            "Trailer",
            "upgrade",
            "Proxy-Authorization",
            "Proxy-Authenticate",
        ] {
            assert!(is_hop_by_hop(h), "{h} must be treated as hop-by-hop");
        }
        // a normal end-to-end header is not hop-by-hop.
        assert!(!is_hop_by_hop("x-api-key"));
        assert!(!is_hop_by_hop("content-type"));
    }

    #[test]
    fn headers_to_vec_strips_hop_by_hop_on_ingress() {
        // What the chain (and ultimately the upstream) sees must already be free of connection-
        // management headers: stripping them on the way in is half the smuggling defence (the
        // other half is `copy_headers` on the way out).
        let mut map = hyper::HeaderMap::new();
        map.insert("x-keep", HeaderValue::from_static("1"));
        map.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        map.insert(
            hyper::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        map.insert(hyper::header::TE, HeaderValue::from_static("trailers"));

        let out = headers_to_vec(&map);
        assert!(
            out.iter().all(|h| !is_hop_by_hop(&h.name)),
            "no hop-by-hop header may survive the ingress conversion"
        );
        assert!(
            out.iter().any(|h| h.name == "x-keep"),
            "an end-to-end header is preserved"
        );
    }

    #[test]
    fn headers_to_vec_strips_connection_named_headers() {
        // RFC 9110 §7.6.1 (review f000005 P2#5): a header NAMED by `Connection` is connection-
        // specific and must not be forwarded. A client using `Connection: x-secret` to smuggle
        // `x-secret` past the proxy is defeated; inert tokens (`close`) are ignored.
        let mut map = hyper::HeaderMap::new();
        map.insert(
            hyper::header::CONNECTION,
            HeaderValue::from_static("X-Secret, close"),
        );
        map.append("x-secret", HeaderValue::from_static("leak"));
        map.insert("x-keep", HeaderValue::from_static("1"));

        let out = headers_to_vec(&map);
        assert!(
            !out.iter().any(|h| h.name.eq_ignore_ascii_case("x-secret")),
            "a Connection-named header must be stripped"
        );
        assert!(
            !out.iter()
                .any(|h| h.name.eq_ignore_ascii_case("connection")),
            "Connection itself is hop-by-hop"
        );
        assert!(
            out.iter().any(|h| h.name == "x-keep"),
            "an unrelated end-to-end header survives"
        );
    }

    #[test]
    fn copy_headers_preserving_keeps_untouched_non_utf8_bytes() {
        // P3#6: a header value with non-UTF-8 bytes reaches the chain as a lossy `string`. When the
        // filter passes it through unchanged, the upstream must still receive the ORIGINAL bytes —
        // not the `U+FFFD`-mangled re-encoding, and not a drop (which is what `from_str` would do).
        let raw: &[u8] = &[0xC3, 0x28]; // invalid UTF-8
        let mut original = hyper::HeaderMap::new();
        original.insert("x-blob", HeaderValue::from_bytes(raw).unwrap());

        // the chain's view of that header == the lossy projection `headers_to_vec` produced.
        let contract = vec![header("x-blob", &String::from_utf8_lossy(raw))];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert_eq!(
            dst.get("x-blob").map(|v| v.as_bytes()),
            Some(raw),
            "an untouched header forwards byte-for-byte, not via the lossy string"
        );
    }

    #[test]
    fn copy_headers_preserving_uses_the_filter_value_when_changed() {
        // A header the filter REWROTE no longer matches the original's lossy projection, so the
        // chain's new value must win — preservation must never shadow an intentional edit.
        let mut original = hyper::HeaderMap::new();
        original.insert("x-user", HeaderValue::from_static("client-claim"));
        let contract = vec![header("x-user", "real-user")];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert_eq!(
            dst.get("x-user").and_then(|v| v.to_str().ok()),
            Some("real-user"),
            "a rewritten header forwards the chain's value, not the original"
        );
    }

    #[test]
    fn copy_headers_preserving_does_not_resurrect_a_removed_header() {
        // A header the chain dropped is absent from its output, so it must not reappear from
        // `original` — the reconciliation iterates the chain's output, never the original map.
        let mut original = hyper::HeaderMap::new();
        original.insert("x-secret", HeaderValue::from_static("leak"));
        let contract: Vec<Header> = vec![]; // filter removed it

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert!(
            !dst.contains_key("x-secret"),
            "a removed header is never resurrected from the original map"
        );
    }

    #[test]
    fn copy_headers_preserving_still_skips_hop_by_hop() {
        // The smuggling defence in `copy_headers` (CWE-444) must hold on this path too.
        let original = hyper::HeaderMap::new();
        let contract = vec![header("connection", "keep-alive"), header("x-keep", "1")];

        let mut dst = hyper::HeaderMap::new();
        copy_headers_preserving(Some(&mut dst), &contract, &original);

        assert!(!dst.contains_key("connection"), "hop-by-hop is dropped");
        assert!(dst.contains_key("x-keep"), "an end-to-end header survives");
    }

    #[test]
    fn set_forwarded_overwrites_spoofed_client_headers() {
        // Edge model (review f000005 P2#3 / ADR 000018 + 000022): the whole de-facto client-IP
        // family — X-Forwarded-For / Forwarded / X-Real-IP / CDN headers — is STRIPPED and the
        // peer's value re-issued, never appended-to or trusted, so an untrusted client cannot forge
        // its source IP. X-Forwarded-For and X-Real-IP carry the real peer; X-Forwarded-Proto the
        // wire scheme; a stripped CDN header (CF-Connecting-IP) is NOT re-issued.
        let mut headers = vec![
            header("X-Forwarded-For", "9.9.9.9"),
            header("forwarded", "for=10.0.0.1"),
            header("X-Real-IP", "9.9.9.9"),
            header("cf-connecting-ip", "8.8.8.8"),
            header("x-keep", "1"),
        ];
        set_forwarded(&mut headers, "203.0.113.5".parse().unwrap(), "https");

        let xff: Vec<&str> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            xff,
            vec!["203.0.113.5"],
            "the spoofed XFF is replaced by the real peer (one value, not appended)"
        );
        let xrealip: Vec<&str> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("x-real-ip"))
            .map(|h| h.value.as_str())
            .collect();
        assert_eq!(
            xrealip,
            vec!["203.0.113.5"],
            "the spoofed X-Real-IP is replaced by the real peer (one value, re-issued)"
        );
        assert!(
            !headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("forwarded")),
            "a spoofed Forwarded header is stripped"
        );
        assert!(
            !headers
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case("cf-connecting-ip")),
            "a spoofed CDN client-IP header is stripped and not re-issued"
        );
        assert_eq!(
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("x-forwarded-proto"))
                .map(|h| h.value.as_str()),
            Some("https"),
            "X-Forwarded-Proto reflects the connection scheme"
        );
        assert!(
            headers.iter().any(|h| h.name == "x-keep"),
            "an unrelated header is left intact"
        );
    }

    #[test]
    fn set_forwarded_normalises_ipv4_mapped_peer() {
        // An IPv4 client on a dual-stack ([::]) listener arrives as an IPv4-mapped IPv6 peer
        // (`::ffff:a.b.c.d`); X-Forwarded-For / X-Real-IP must carry the dotted IPv4 form so a
        // backend all-listing on the IPv4 address matches (ADR 000022).
        let mut headers = vec![];
        set_forwarded(&mut headers, "::ffff:203.0.113.5".parse().unwrap(), "https");
        for name in ["x-forwarded-for", "x-real-ip"] {
            assert_eq!(
                headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(name))
                    .map(|h| h.value.as_str()),
                Some("203.0.113.5"),
                "an IPv4-mapped peer normalises to dotted IPv4 in {name}"
            );
        }

        // A genuine IPv6 peer is preserved verbatim (no brackets in XFF).
        let mut headers = vec![];
        set_forwarded(&mut headers, "2001:db8::1".parse().unwrap(), "https");
        assert_eq!(
            headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("x-forwarded-for"))
                .map(|h| h.value.as_str()),
            Some("2001:db8::1"),
            "a real IPv6 peer is kept as-is"
        );
    }

    #[test]
    fn copy_headers_drops_hop_by_hop_crlf_and_malformed_names() {
        // Egress side: a filter (or a buggy/hostile one) must not be able to smuggle framing or
        // inject a header via an embedded CRLF (CWE-113) or a malformed name. `copy_headers` drops
        // each silently and never panics (data-plane discipline) — and the rest still copies.
        let mut dst = hyper::HeaderMap::new();
        copy_headers(
            Some(&mut dst),
            &[
                header("x-ok", "fine"),
                header("transfer-encoding", "chunked"), // hop-by-hop → dropped
                header("x-evil", "a\r\nInjected: pwned"), // CRLF in value → dropped
                header("bad name", "x"),                // space in name → invalid → dropped
                header("", "x"),                        // empty name → invalid → dropped
            ],
        );

        assert_eq!(
            dst.get("x-ok").and_then(|v| v.to_str().ok()),
            Some("fine"),
            "a valid end-to-end header is copied"
        );
        assert!(
            !dst.contains_key("transfer-encoding"),
            "a filter cannot re-introduce a hop-by-hop header"
        );
        assert!(
            !dst.contains_key("x-evil") && !dst.contains_key("injected"),
            "a CRLF-bearing value is rejected, not split into a second header"
        );
        assert_eq!(dst.len(), 1, "only the one valid header survives");
    }
}
