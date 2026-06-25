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
    host.to_ascii_lowercase()
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
    use crate::manifest::{HealthConfig, Upstream};
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
}
