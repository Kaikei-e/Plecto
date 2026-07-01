//! Host-native routing (ADR 000013 / 000034): match a request to a route by its `[route.match]`
//! dimensions (host, path prefix, method, headers, query), then the fast-path server runs that
//! route's chain and forwards to its weighted backends. Pure config logic — no I/O, no wasmtime —
//! so it is unit-tested directly and runs on the async thread (the blocking work is the chain
//! dispatch, not the match). Matching is allocation-free: the compiled dimensions are pre-normalised
//! at build, and per request we only scan and compare borrowed slices.

use std::net::IpAddr;
use std::sync::Arc;

use plecto_host::Header;

use crate::ratelimit::{NativeRateLimit, RateLimitDecision};
use crate::upstream::UpstreamGroup;
use crate::weighted::WeightedBackends;

/// A route compiled from a manifest [`crate::Route`] into the live config: the match dimensions are
/// pre-normalised (host + header names lower-cased, method upper-cased), and the forwarding target —
/// a single upstream or a weighted split — is resolved to a [`WeightedBackends`] whose groups are
/// shared (`Arc`) with the upstream registry, so the actual instance is chosen by round-robin over
/// the healthy set at forward time, not here (ADR 000017 / 000024).
#[derive(Debug, Clone)]
pub(crate) struct CompiledRoute {
    /// Lower-cased authority to match, or `None` for any host.
    pub(crate) host: Option<String>,
    pub(crate) path_prefix: String,
    /// Upper-cased HTTP method to match (exact), or `None` for any method (ADR 000034).
    pub(crate) method: Option<String>,
    /// Header matches (ADR 000034): `(lower-cased name, exact value)`, ANDed. Name is compared
    /// case-insensitively, value byte-/string-exact. A `Vec` (not a map) since it is iterated, small,
    /// and order-stable.
    pub(crate) headers: Vec<(String, String)>,
    /// Query-parameter matches (ADR 000034): `(name, exact value)`, ANDed. Name is case-sensitive
    /// (Gateway-API semantics, asymmetric with headers).
    pub(crate) query: Vec<(String, String)>,
    /// This route's inline chain (filter ids, in order).
    pub(crate) filters: Vec<String>,
    /// Whether any filter on this route reads the request body (exports `on-request-body`, ADR
    /// 000038). Precomputed at build from the loaded filters so per-request buffering is a single
    /// bool check. `false` (all filters header-only) keeps the body on the zero-copy stream path.
    pub(crate) reads_body: bool,
    /// The route's forwarding target: a weighted set of upstream groups (a single `upstream` is a
    /// one-element set). The fast path picks a group via [`WeightedBackends::pick`], then the group
    /// picks a healthy instance. `Arc`-shared so the split cursor persists across a config generation.
    pub(crate) backends: Arc<WeightedBackends>,
    pub(crate) strip_prefix: Option<String>,
    /// This route's native rate limiter (ADR 000033), or `None` for unlimited (the default). Shared
    /// (`Arc`) so every request on the route consults the same token buckets within a config
    /// generation; a reload builds a fresh limiter (the node-local buckets reset).
    pub(crate) rate_limit: Option<Arc<NativeRateLimit>>,
}

/// The request attributes route matching reads (ADR 000034), borrowed so matching stays
/// allocation-free. `path` may carry `?query`; the query is split out only inside `select`.
pub(crate) struct RequestParts<'a> {
    pub(crate) authority: &'a str,
    pub(crate) path: &'a str,
    pub(crate) method: &'a str,
    pub(crate) headers: &'a [Header],
}

/// What [`crate::ConfigSnapshot::find_route`] hands the fast-path server: which route matched
/// (`index`, used to dispatch its chain) plus the data needed to forward — the weighted backends
/// (the server picks a group, then a healthy instance from it) and the optional prefix strip. Owned
/// / `Arc`-shared so it survives a move into `spawn_blocking`.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub index: usize,
    pub(crate) backends: Arc<WeightedBackends>,
    pub strip_prefix: Option<String>,
    /// Whether this route has any filters (drives the header-side chain dispatch).
    pub has_filters: bool,
    /// Whether any filter on this route reads the request body (exports `on-request-body`, ADR
    /// 000038). The fast path buffers the body ONLY when this is `true`; a route of header-only
    /// filters keeps the zero-copy streaming path (the real fix for the body-tax, docs/servey).
    pub reads_body: bool,
    /// This route's native rate limiter (ADR 000033), or `None` for unlimited. `Arc`-shared with the
    /// live config so the per-request `RouteInfo` consults the route's persistent buckets.
    pub(crate) rate_limit: Option<Arc<NativeRateLimit>>,
}

impl RouteInfo {
    /// Pick the upstream group to forward this request to from the route's weighted traffic split
    /// (ADR 000034): the next backend in the split order that has an eligible instance (renormalize
    /// over healthy), or `None` when no backend is eligible (the fast path then fails closed 503,
    /// the same no-healthy fault as a single upstream). Lock-free.
    pub fn pick_upstream(&self) -> Option<Arc<UpstreamGroup>> {
        self.backends.pick()
    }

    /// Apply this route's host-native prefix strip to the path the fast-path server forwards to
    /// the upstream. The chain already ran against the original path; this only affects what the
    /// upstream sees. No rule (or a non-matching path) leaves the path unchanged.
    pub fn rewrite_path(&self, path: &str) -> String {
        rewrite_path(path, self.strip_prefix.as_deref())
    }

    /// Consult this route's native rate limiter (ADR 000033) for one request, keyed on the
    /// connection `peer`. `Allow` when the route has no limiter or a token was available;
    /// `Limit { retry_after_ms }` when the bucket is empty (the fast path fails closed with 429).
    /// Called BEFORE the filter chain so a flood is shed without spending WASM CPU.
    pub fn check_rate_limit(&self, peer: IpAddr) -> RateLimitDecision {
        match &self.rate_limit {
            Some(rl) => rl.check(peer),
            None => RateLimitDecision::Allow,
        }
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

/// Does the request match every dimension this route specifies (ADR 000034)? All specified
/// dimensions are ANDed; an unspecified one is a wildcard. `host` is pre-normalised, `query` is the
/// already-split query string. Header name is matched case-insensitively and value exact; query name
/// is case-sensitive. Byte-/string-exact comparison never panics on untrusted input (no-panic tenet).
fn route_matches(
    r: &CompiledRoute,
    host: &str,
    path: &str,
    method: &str,
    headers: &[Header],
    query: &str,
) -> bool {
    if let Some(h) = &r.host
        && h != host
    {
        return false;
    }
    if !path_under_prefix(&r.path_prefix, path) {
        return false;
    }
    if let Some(m) = &r.method
        && method != m
    {
        return false;
    }
    for (name, value) in &r.headers {
        // Match the FIRST header with this name (case-insensitive name); a later duplicate must not
        // flip the decision (CWE-436): the origin receives every copy and may read a different one,
        // so deciding on the first occurrence keeps our routing aligned with Gateway-API's
        // "first match entry decides" and mirrors the query rule below.
        match headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)) {
            Some(h) if h.value == *value => {}
            _ => return false,
        }
    }
    for (name, value) in &r.query {
        if !query_param_matches(query, name, value) {
            return false;
        }
    }
    true
}

/// Does the query string contain `name=value` exactly (ADR 000034)? Case-sensitive name. The FIRST
/// occurrence of `name` decides (Gateway-API: a repeated key matches its first value); a malformed
/// pair (no `=`) is skipped; an absent name is no-match.
fn query_param_matches(query: &str, name: &str, value: &str) -> bool {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return v == value;
        }
    }
    false
}

/// Select the best route for `req` (ADR 000013 / 000034): among all routes whose every specified
/// match dimension is satisfied, the most specific wins, ordered by host-constrained > longest
/// `path_prefix` > `method` present > more header matches > more query matches, with the earliest
/// manifest index the final stable tie-break (Gateway-API v1.5.0 precedence, adapted). Returns the
/// winner's index, or `None` (no route → the server responds 404).
pub(crate) fn select(routes: &[CompiledRoute], req: &RequestParts) -> Option<usize> {
    let host = normalize_host(req.authority);
    let query = req.path.split_once('?').map(|(_, q)| q).unwrap_or("");
    routes
        .iter()
        .enumerate()
        .filter(|(_, r)| route_matches(r, &host, req.path, req.method, req.headers, query))
        // Specificity key, most-significant first. `max_by_key` keeps the LAST max on ties, so the
        // final `usize::MAX - i` (earliest index largest) makes the earliest manifest route win.
        .max_by_key(|(i, r)| {
            (
                r.host.is_some(),
                r.path_prefix.len(),
                r.method.is_some(),
                r.headers.len(),
                r.query.len(),
                usize::MAX - i,
            )
        })
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
    use crate::manifest::{
        AddressSpec, CircuitBreaker, HealthConfig, LbAlgorithm, OutlierDetection, Upstream,
    };
    use crate::upstream::UpstreamRegistry;

    /// A throwaway upstream group named after `upstream` — these tests exercise `select` /
    /// `rewrite_path`, which never touch the group's contents, only its identity.
    fn group(upstream: &str) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: upstream.to_string(),
            addresses: vec![AddressSpec::Bare("127.0.0.1:9000".to_string())],
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
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
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        reg.group(upstream).unwrap()
    }

    /// A single-upstream weighted set for a route under test.
    fn backends(upstream: &str) -> Arc<WeightedBackends> {
        Arc::new(WeightedBackends::new(vec![(group(upstream), 1)]).unwrap())
    }

    fn route(host: Option<&str>, prefix: &str, upstream: &str) -> CompiledRoute {
        CompiledRoute {
            host: host.map(|h| h.to_ascii_lowercase()),
            path_prefix: prefix.to_string(),
            method: None,
            headers: vec![],
            query: vec![],
            filters: vec![],
            reads_body: false,
            backends: backends(upstream),
            strip_prefix: None,
            rate_limit: None,
        }
    }

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// A GET request with no headers, for the path/host-only tests.
    fn parts<'a>(authority: &'a str, path: &'a str) -> RequestParts<'a> {
        RequestParts {
            authority,
            path,
            method: "GET",
            headers: &[],
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let routes = vec![
            route(None, "/", "root"),
            route(None, "/api", "api"),
            route(None, "/api/v2", "v2"),
        ];
        assert_eq!(select(&routes, &parts("h", "/api/v2/x")), Some(2));
        assert_eq!(select(&routes, &parts("h", "/api/users")), Some(1));
        assert_eq!(select(&routes, &parts("h", "/other")), Some(0));
    }

    #[test]
    fn prefix_matches_on_boundary_only() {
        let routes = vec![route(None, "/api", "api")];
        assert_eq!(select(&routes, &parts("h", "/api")), Some(0));
        assert_eq!(select(&routes, &parts("h", "/api/x")), Some(0));
        assert_eq!(
            select(&routes, &parts("h", "/apix")),
            None,
            "no boundary match"
        );
    }

    #[test]
    fn query_or_fragment_acts_as_a_prefix_boundary() {
        // review f000005 P1#1: the inbound path carries the query (`path_and_query`), so a bare
        // prefix followed by `?`/`#` must still match — `/search?q=foo` is under `/search` exactly
        // like `/search` and `/search/x` are. The earlier code treated `?` as path text and 404'd.
        let routes = vec![route(None, "/search", "s")];
        assert_eq!(select(&routes, &parts("h", "/search")), Some(0));
        assert_eq!(
            select(&routes, &parts("h", "/search?q=foo")),
            Some(0),
            "a bare prefix followed by a query must match"
        );
        assert_eq!(select(&routes, &parts("h", "/search/x?q=foo")), Some(0));
        assert_eq!(select(&routes, &parts("h", "/search#frag")), Some(0));
        // the boundary is still a real boundary: `/searching` is not under `/search`.
        assert_eq!(
            select(&routes, &parts("h", "/searching?q=foo")),
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
        assert_eq!(
            select(&routes, &parts("example.com:8443", "/api/x")),
            Some(1)
        );
        // a different host falls back to the wildcard
        assert_eq!(select(&routes, &parts("other.test", "/api/x")), Some(0));
    }

    #[test]
    fn no_match_returns_none() {
        let routes = vec![route(Some("a.test"), "/api", "u")];
        assert_eq!(select(&routes, &parts("b.test", "/api")), None);
        let empty: Vec<CompiledRoute> = vec![];
        assert_eq!(select(&empty, &parts("a", "/")), None);
    }

    #[test]
    fn method_match_filters_and_outranks_a_bare_path() {
        // Two routes on the same path: one bare, one method-constrained. A POST takes the
        // method-constrained route (more specific); a GET falls to the bare one (ADR 000034).
        let mut post = route(None, "/api", "writes");
        post.method = Some("POST".to_string());
        let routes = vec![route(None, "/api", "reads"), post];

        let mut p = parts("h", "/api/x");
        p.method = "POST";
        assert_eq!(select(&routes, &p), Some(1), "POST takes the method route");
        p.method = "GET";
        assert_eq!(select(&routes, &p), Some(0), "GET falls to the bare route");
    }

    #[test]
    fn header_match_is_case_insensitive_name_exact_value_and_anded() {
        // A header-constrained route matches only when the request carries every named header with
        // the exact value; the header NAME is case-insensitive, the VALUE exact (ADR 000034).
        let mut v2 = route(None, "/api", "v2");
        v2.headers = vec![("x-api-version".to_string(), "2".to_string())];
        let routes = vec![route(None, "/api", "v1"), v2];

        let hdrs = [header("X-Api-Version", "2")];
        let mut p = parts("h", "/api");
        p.headers = &hdrs;
        assert_eq!(
            select(&routes, &p),
            Some(1),
            "a case-different header name still matches, and outranks the bare route"
        );

        let wrong = [header("x-api-version", "3")];
        p.headers = &wrong;
        assert_eq!(
            select(&routes, &p),
            Some(0),
            "a different value does not match"
        );

        p.headers = &[];
        assert_eq!(select(&routes, &p), Some(0), "absent header → bare route");
    }

    #[test]
    fn header_match_decides_on_the_first_duplicate() {
        // A duplicate header must not let a later copy flip the routing decision (CWE-436): the
        // FIRST occurrence of the name decides, like the query rule. Here the first `x-api-version`
        // is `1`, so the header route (which wants `2`) must NOT be selected even though a later
        // copy is `2` — otherwise our routing would disagree with an origin that reads the first.
        let mut v2 = route(None, "/api", "v2");
        v2.headers = vec![("x-api-version".to_string(), "2".to_string())];
        let routes = vec![route(None, "/api", "v1"), v2];

        let hdrs = [header("x-api-version", "1"), header("x-api-version", "2")];
        let mut p = parts("h", "/api");
        p.headers = &hdrs;
        assert_eq!(
            select(&routes, &p),
            Some(0),
            "the first duplicate value (1) decides, so the v2 header route does not match"
        );
    }

    #[test]
    fn query_match_is_case_sensitive_name_first_value_and_handles_malformed() {
        // Query name is case-sensitive (asymmetric with headers); the first occurrence's value
        // decides; a malformed (`=`-less) parameter is skipped (ADR 000034).
        let mut beta = route(None, "/api", "beta");
        beta.query = vec![("flag".to_string(), "on".to_string())];
        let routes = vec![route(None, "/api", "stable"), beta];

        assert_eq!(
            select(&routes, &parts("h", "/api?flag=on")),
            Some(1),
            "exact query value matches"
        );
        assert_eq!(
            select(&routes, &parts("h", "/api?flag=off")),
            Some(0),
            "wrong value → bare route"
        );
        assert_eq!(
            select(&routes, &parts("h", "/api?Flag=on")),
            Some(0),
            "query name is case-sensitive"
        );
        assert_eq!(
            select(&routes, &parts("h", "/api?flag=on&flag=off")),
            Some(1),
            "the first occurrence of a repeated key decides"
        );
        assert_eq!(
            select(&routes, &parts("h", "/api?flag&x=1")),
            Some(0),
            "a malformed (=-less) parameter is skipped, so the constraint is unmet"
        );
    }

    #[test]
    fn precedence_orders_method_above_header_count() {
        // Gateway-API precedence (ADR 000034 1b): method-present outranks a larger header count.
        // Route A: 2 header matches, no method. Route B: 1 header match + a method. A POST that
        // satisfies BOTH must take B (method beats header count), not A.
        let mut a = route(None, "/api", "a");
        a.headers = vec![
            ("h1".to_string(), "1".to_string()),
            ("h2".to_string(), "2".to_string()),
        ];
        let mut b = route(None, "/api", "b");
        b.headers = vec![("h1".to_string(), "1".to_string())];
        b.method = Some("POST".to_string());
        let routes = vec![a, b];

        let hdrs = [header("h1", "1"), header("h2", "2")];
        let mut p = parts("h", "/api");
        p.method = "POST";
        p.headers = &hdrs;
        assert_eq!(
            select(&routes, &p),
            Some(1),
            "method-present outranks the larger header count"
        );
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
            select(&routes, &parts("h", &norm)),
            Some(1),
            "the normalized path selects the stricter, filtered route"
        );
        // (the un-normalized path would have selected the laxer route 0 — the bug.)
        assert_eq!(select(&routes, &parts("h", raw)), Some(0));
    }
}
