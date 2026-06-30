//! Host-native routing (ADR 000013): match a request to a route by host + path prefix, then
//! the fast-path server runs that route's chain and forwards to its upstream. Pure config logic
//! — no I/O, no wasmtime — so it is unit-tested directly and runs on the async thread (the
//! blocking work is the chain dispatch, not the match).

use std::sync::Arc;

use crate::upstream::UpstreamGroup;

/// A route compiled from a manifest [`crate::Route`] into the live config: the upstream name is
/// resolved to its [`UpstreamGroup`] handle and the host is pre-normalised, so matching is
/// allocation-free. The group is shared (`Arc`) with the upstream registry, so the actual instance
/// is chosen — by round-robin over the healthy set — at forward time, not here (ADR 000017).
#[derive(Debug, Clone)]
pub(crate) struct CompiledRoute {
    /// Lower-cased authority to match, or `None` for any host.
    pub(crate) host: Option<String>,
    pub(crate) path_prefix: String,
    /// This route's inline chain (filter ids, in order).
    pub(crate) filters: Vec<String>,
    /// The upstream group this route forwards to; the fast path calls [`UpstreamGroup::pick`] on it.
    pub(crate) upstream: Arc<UpstreamGroup>,
    pub(crate) strip_prefix: Option<String>,
}

/// What [`crate::ConfigSnapshot::find_route`] hands the fast-path server: which route matched
/// (`index`, used to dispatch its chain) plus the data needed to forward — the upstream group (the
/// server picks a healthy instance from it) and the optional prefix strip. Owned / `Arc`-shared so
/// it survives a move into `spawn_blocking`.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub index: usize,
    pub upstream: Arc<UpstreamGroup>,
    pub strip_prefix: Option<String>,
    /// Whether this route has any filters. The fast path only buffers a request body for the
    /// `on-request-body` hook (ADR 000025) when there is a filter to run; a filterless route keeps
    /// the zero-copy streaming path.
    pub has_filters: bool,
}

impl RouteInfo {
    /// Apply this route's host-native prefix strip to the path the fast-path server forwards to
    /// the upstream. The chain already ran against the original path; this only affects what the
    /// upstream sees. No rule (or a non-matching path) leaves the path unchanged.
    pub fn rewrite_path(&self, path: &str) -> String {
        rewrite_path(path, self.strip_prefix.as_deref())
    }
}

/// Normalise an authority for host matching: drop any `:port`, lower-case. (`example.COM:8443`
/// → `example.com`.) IPv6 literals in brackets keep their colons inside `[...]`.
fn normalize_host(authority: &str) -> String {
    let host = if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:8080` → `[::1]`
        match rest.split_once(']') {
            Some((inner, _)) => &authority[..inner.len() + 2],
            None => authority,
        }
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let lowered = host.to_ascii_lowercase();
    // Absolute-form hosts carry a trailing dot (`example.com.`); strip a single one so they match
    // the canonical `example.com` route and cannot silently slip to a wildcard route (/
    // CWE-644). IPv6 literals (`[...]`) never end in a dot, so this only affects DNS names.
    match lowered.strip_suffix('.') {
        Some(stripped) if !lowered.starts_with('[') => stripped.to_string(),
        _ => lowered,
    }
}

/// Normalize a request target's PATH for routing and forwarding so the proxy and the origin agree
/// on it (CWE-22 Path Traversal / CWE-436 Interpretation Conflict). Per-route filter chains
/// are an access-control boundary, so route selection IS access control: a `..` segment that selects
/// a laxer route here but resolves to a stricter path at the upstream would bypass that route's
/// filters. The fast path normalizes once at ingress and then routes, runs the chain, and forwards
/// on the SAME normalized path, so the origin cannot re-derive a different path.
///
/// Returns the normalized `path[?query]`, or `None` to reject (the server fails closed with 400).
/// Policy: reject control bytes, backslash, and percent-encoded separators/dots (`%2e`/`%2f`/`%5c`,
/// ambiguous between front-end and back-end), then lexically remove `.`/`..` segments; a `..` that
/// escapes the root is rejected. The query string (after `?`) is preserved verbatim.
pub fn normalize_path(target: &str) -> Option<String> {
    let (raw, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    // A non-origin target (asterisk-form, or no leading `/`) cannot fall under a `/`-prefixed
    // route, so it needs no traversal handling — pass it through unchanged.
    if !raw.starts_with('/') {
        return Some(target.to_string());
    }
    // Reject control bytes / backslash and percent-encoded separators or dots: an origin that
    // decodes `%2f`/`%2e`/`%5c` would re-derive a path different from the one we route on and
    // forward, re-opening the front-end/back-end normalization gap.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) || raw.contains('\\') {
        return None;
    }
    if contains_encoded_separator(raw) {
        return None;
    }
    // Lexically resolve `.` / `..` over `/`-separated segments. `out` always holds the leading ""
    // (root); a `..` that would pop past it escapes the root and is rejected (fail-closed).
    let mut out: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "." => {}
            ".." => {
                if out.len() <= 1 {
                    return None;
                }
                out.pop();
            }
            other => out.push(other),
        }
    }
    let mut norm = out.join("/");
    if norm.is_empty() {
        norm.push('/');
    }
    if let Some(q) = query {
        norm.push('?');
        norm.push_str(q);
    }
    Some(norm)
}

/// Does the path contain a percent-encoded separator or dot (`%2e`/`%2f`/`%5c`, any hex case)?
fn contains_encoded_separator(path: &str) -> bool {
    path.as_bytes().windows(3).any(|w| {
        w[0] == b'%'
            && matches!(
                (w[1], w[2]),
                (b'2', b'e' | b'E') | (b'2', b'f' | b'F') | (b'5', b'c' | b'C')
            )
    })
}

/// Does `path` fall under `prefix` on a `/` boundary? `/api` matches `/api` and `/api/x` but not
/// `/apix`; `/` matches everything. A `?query` / `#fragment` acts as a boundary too, so a bare
/// prefix with a query (`/search?q=x` under `/search`) still matches (review f000005 P1#1) — the
/// inbound `path` carries the query (`path_and_query`), but the MATCH decision is over the path
/// only. Rewriting (`rewrite_path`) keeps the query; this is purely the selection predicate.
fn path_under_prefix(prefix: &str, path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    if !path.starts_with(prefix) {
        return false;
    }
    if path.len() == prefix.len() || prefix.ends_with('/') {
        return true;
    }
    path.as_bytes().get(prefix.len()) == Some(&b'/')
}

/// Select the best route for `(authority, path)`: among all that match host + path prefix, the
/// longest prefix wins; ties prefer a host-constrained route over a wildcard one, then the
/// earliest in manifest order. Returns the winner's index, or `None` (no route → the server
/// responds 404).
pub(crate) fn select(routes: &[CompiledRoute], authority: &str, path: &str) -> Option<usize> {
    let host = normalize_host(authority);
    routes
        .iter()
        .enumerate()
        .filter(|(_, r)| match &r.host {
            Some(h) => *h == host,
            None => true,
        })
        .filter(|(_, r)| path_under_prefix(&r.path_prefix, path))
        // best = longest prefix, then host-constrained, then earliest index. `max_by_key` keeps
        // the LAST max on ties, so negate the index to prefer the earliest.
        .max_by_key(|(i, r)| (r.path_prefix.len(), r.host.is_some(), usize::MAX - i))
        .map(|(i, _)| i)
}

/// Apply a route's host-native prefix strip to the forwarded path (the chain already saw the
/// original). Leaves the path unchanged if it does not start with `strip`; always keeps a
/// leading `/`. `/api` stripped from `/api/users` → `/users`; from `/api` → `/`.
pub(crate) fn rewrite_path(path: &str, strip: Option<&str>) -> String {
    let Some(strip) = strip else {
        return path.to_string();
    };
    let Some(rest) = path.strip_prefix(strip) else {
        return path.to_string();
    };
    if rest.is_empty() {
        "/".to_string()
    } else if rest.starts_with('/') {
        rest.to_string()
    } else {
        format!("/{rest}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{CircuitBreaker, HealthConfig, Upstream};
    use crate::upstream::UpstreamRegistry;

    /// A throwaway upstream group named after `upstream` — these tests exercise `select` /
    /// `rewrite_path`, which never touch the group's contents, only its identity.
    fn group(upstream: &str) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: upstream.to_string(),
            addresses: vec!["127.0.0.1:9000".to_string()],
            health: HealthConfig {
                path: "/healthz".to_string(),
                interval_ms: 1000,
                timeout_ms: 500,
                healthy_threshold: 1,
                unhealthy_threshold: 1,
            },
            request_timeout_ms: 30_000,
            max_retries: 1,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
        }])
        .unwrap();
        reg.group(upstream).unwrap()
    }

    fn route(host: Option<&str>, prefix: &str, upstream: &str) -> CompiledRoute {
        CompiledRoute {
            host: host.map(|h| h.to_ascii_lowercase()),
            path_prefix: prefix.to_string(),
            filters: vec![],
            upstream: group(upstream),
            strip_prefix: None,
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let routes = vec![
            route(None, "/", "root"),
            route(None, "/api", "api"),
            route(None, "/api/v2", "v2"),
        ];
        assert_eq!(select(&routes, "h", "/api/v2/x"), Some(2));
        assert_eq!(select(&routes, "h", "/api/users"), Some(1));
        assert_eq!(select(&routes, "h", "/other"), Some(0));
    }

    #[test]
    fn prefix_matches_on_boundary_only() {
        let routes = vec![route(None, "/api", "api")];
        assert_eq!(select(&routes, "h", "/api"), Some(0));
        assert_eq!(select(&routes, "h", "/api/x"), Some(0));
        assert_eq!(select(&routes, "h", "/apix"), None, "no boundary match");
    }

    #[test]
    fn query_or_fragment_acts_as_a_prefix_boundary() {
        // review f000005 P1#1: the inbound path carries the query (`path_and_query`), so a bare
        // prefix followed by `?`/`#` must still match — `/search?q=foo` is under `/search` exactly
        // like `/search` and `/search/x` are. The earlier code treated `?` as path text and 404'd.
        let routes = vec![route(None, "/search", "s")];
        assert_eq!(select(&routes, "h", "/search"), Some(0));
        assert_eq!(
            select(&routes, "h", "/search?q=foo"),
            Some(0),
            "a bare prefix followed by a query must match"
        );
        assert_eq!(select(&routes, "h", "/search/x?q=foo"), Some(0));
        assert_eq!(select(&routes, "h", "/search#frag"), Some(0));
        // the boundary is still a real boundary: `/searching` is not under `/search`.
        assert_eq!(
            select(&routes, "h", "/searching?q=foo"),
            None,
            "a longer word is not a boundary match even with a query"
        );
    }

    #[test]
    fn host_constraint_filters_and_breaks_ties() {
        let routes = vec![
            route(None, "/api", "wild"),
            route(Some("example.com"), "/api", "vhost"),
        ];
        // request to example.com (with a port) prefers the host-constrained route
        assert_eq!(select(&routes, "example.com:8443", "/api/x"), Some(1));
        // a different host falls back to the wildcard
        assert_eq!(select(&routes, "other.test", "/api/x"), Some(0));
    }

    #[test]
    fn no_match_returns_none() {
        let routes = vec![route(Some("a.test"), "/api", "u")];
        assert_eq!(select(&routes, "b.test", "/api"), None);
        let empty: Vec<CompiledRoute> = vec![];
        assert_eq!(select(&empty, "a", "/"), None);
    }

    #[test]
    fn strip_prefix_keeps_leading_slash() {
        assert_eq!(rewrite_path("/api/users", Some("/api")), "/users");
        assert_eq!(rewrite_path("/api", Some("/api")), "/");
        assert_eq!(rewrite_path("/api/", Some("/api")), "/");
        assert_eq!(rewrite_path("/other", Some("/api")), "/other", "no strip");
        assert_eq!(rewrite_path("/api/x", None), "/api/x", "no rule");
    }

    #[test]
    fn normalize_host_drops_port_and_lowercases() {
        // Host matching is case-insensitive and port-insensitive (CWE-644: the routing decision
        // must not be steered by case tricks or a `:port` suffix a client appended).
        assert_eq!(normalize_host("EXAMPLE.com:8443"), "example.com");
        assert_eq!(normalize_host("Example.Com"), "example.com");
        assert_eq!(normalize_host("host:80"), "host");
    }

    #[test]
    fn normalize_host_handles_ipv6_literals() {
        // IPv6 literals keep the colons inside `[...]`; only a trailing `:port` is dropped.
        assert_eq!(normalize_host("[::1]:8080"), "[::1]");
        assert_eq!(normalize_host("[::1]"), "[::1]");
        assert_eq!(normalize_host("[2001:DB8::1]:443"), "[2001:db8::1]");
    }

    #[test]
    fn normalize_host_is_panic_free_on_malformed_authority() {
        // A malformed authority (an unclosed bracket, a lone bracket, an empty string) must not
        // panic the data plane on the bracket-slice arithmetic — it just yields a non-matching
        // host. The fast path normalises EVERY inbound authority, so a single OOB slice here
        // would be a remote DoS.
        assert_eq!(
            normalize_host("[::1"),
            "[::1",
            "unclosed bracket returned as-is"
        );
        assert_eq!(normalize_host("["), "[", "lone bracket does not panic");
        assert_eq!(
            normalize_host("[]"),
            "[]",
            "empty bracket pair does not panic"
        );
        assert_eq!(normalize_host(""), "", "empty authority does not panic");
        assert_eq!(normalize_host("[]:9"), "[]");
    }

    #[test]
    fn normalize_host_strips_trailing_dot() {
        // / CWE-644: an absolute-form host (`example.com.`) must canonicalise to
        // `example.com` so it matches the host-constrained route instead of slipping to a wildcard.
        assert_eq!(normalize_host("example.com."), "example.com");
        assert_eq!(normalize_host("EXAMPLE.COM.:8443"), "example.com");
        assert_eq!(normalize_host("example.com"), "example.com");
        // an IPv6 literal is unaffected (never ends in a dot).
        assert_eq!(normalize_host("[::1]"), "[::1]");
    }

    #[test]
    fn normalize_path_resolves_dot_segments_and_preserves_query() {
        assert_eq!(
            normalize_path("/public/../admin").as_deref(),
            Some("/admin")
        );
        assert_eq!(normalize_path("/a/./b").as_deref(), Some("/a/b"));
        assert_eq!(normalize_path("/a/b/../c").as_deref(), Some("/a/c"));
        assert_eq!(normalize_path("/").as_deref(), Some("/"));
        assert_eq!(normalize_path("/api/").as_deref(), Some("/api/"));
        assert_eq!(normalize_path("/api").as_deref(), Some("/api"));
        // the query is preserved verbatim, dot-resolution applies to the path only.
        assert_eq!(
            normalize_path("/x/../y?a=../b").as_deref(),
            Some("/y?a=../b")
        );
        // a non-origin target (asterisk-form) is passed through.
        assert_eq!(normalize_path("*").as_deref(), Some("*"));
    }

    #[test]
    fn normalize_path_rejects_traversal_and_ambiguous_encodings() {
        // root escape → reject (fail-closed).
        assert_eq!(normalize_path("/.."), None);
        assert_eq!(normalize_path("/a/../.."), None);
        // percent-encoded separators/dots are ambiguous between front-end and back-end → reject.
        assert_eq!(normalize_path("/public/%2e%2e/admin"), None);
        assert_eq!(normalize_path("/x%2fy"), None);
        assert_eq!(normalize_path("/x%2Fy"), None);
        assert_eq!(normalize_path("/x%5cy"), None);
        // backslash and control bytes → reject.
        assert_eq!(normalize_path("/a\\b"), None);
        assert_eq!(normalize_path("/a\nb"), None);
    }

    #[test]
    fn normalize_path_closes_per_route_filter_bypass() {
        // a request crafted to select the laxer `/public` route while resolving to
        // `/public/admin` at the upstream must, after ingress normalization, select the stricter
        // `/public/admin` route (which carries the auth filter) — no bypass.
        let routes = vec![
            route(None, "/public", "pub"),
            route(None, "/public/admin", "admin"),
        ];
        let raw = "/public/x/../admin";
        let norm = normalize_path(raw).expect("normalizes to a clean path");
        assert_eq!(norm, "/public/admin");
        assert_eq!(
            select(&routes, "h", &norm),
            Some(1),
            "the normalized path selects the stricter, filtered route"
        );
        // (the un-normalized path would have selected the laxer route 0 — the bug.)
        assert_eq!(select(&routes, "h", raw), Some(0));
    }
}
