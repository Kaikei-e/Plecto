//! The declarative manifest (ADR 000007 / 000008): the single, static source of truth for
//! which filters are loaded, pinned by OCI digest, with which trust roots, in what chain
//! order. TOML (mirrors Cargo; ADR 000008 static config). Routes are deferred until the
//! fast-path server exists; v0.1 has a single chain.

use std::collections::BTreeMap;

use plecto_host::LoadOptions;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ControlError;

/// A parsed manifest. Deserialised from TOML; no I/O happens here (key files and artifacts
/// are resolved by `Control`). `Serialize` exists only to derive the semantic content hash
/// (`content_hash`) — the canonical, representation-independent identity of the config.
///
/// Determinism invariant (f000004 #6): no map fields (`HashMap`). `content_hash` relies on
/// `serde_json` emitting fields and `Vec` elements in a fixed order; a `HashMap` would
/// serialise in nondeterministic order and silently break reload idempotency. If a manifest
/// ever needs a map, use `BTreeMap` (ordered) and keep this invariant.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub trust: Trust,
    /// `[[filter]]` entries.
    #[serde(default, rename = "filter")]
    pub filters: Vec<FilterEntry>,
    /// The default `[chain]` — driven by the chain-only `Control::on_request` convenience and
    /// used by a route that names no filters of its own. The fast-path server uses `[[route]]`.
    #[serde(default)]
    pub chain: Chain,
    /// `[[upstream]]` entries: named backends the fast-path server forwards to (ADR 000013).
    #[serde(default, rename = "upstream")]
    pub upstreams: Vec<Upstream>,
    /// `[[route]]` entries: host + path-prefix → an (inline) chain and an upstream (ADR 000013).
    /// Empty until the fast-path server is configured; matching is the server's job, declared here.
    #[serde(default, rename = "route")]
    pub routes: Vec<Route>,
    /// `[[tls]]` entries: server certificates for TLS termination (ADR 000014). Empty = plain
    /// HTTP/1.1 (the fast path serves TLS only when at least one cert is declared).
    #[serde(default, rename = "tls")]
    pub tls: Vec<TlsCert>,
    /// `[observability]`: operational metrics / access-log / admin-endpoint config (ADR 000009),
    /// captured at construction. `skip_serializing` keeps it OUT of the semantic `content_hash`, so
    /// toggling observability never counts as a config-version change (it is not part of the
    /// filter/route identity, and the admin listener binds once at startup — like `[trust]`).
    #[serde(default, skip_serializing)]
    pub observability: Observability,
}

/// Operational observability config (`[observability]`, ADR 000009 Stage A): a separate admin
/// listener exposing Prometheus metrics + liveness/readiness, and an opt-in structured access log.
/// Off by default — Plecto stays quiet and exposes nothing extra unless asked (operational
/// simplicity). Captured at construction; a reload does not re-bind the admin listener.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    /// `host:port` the admin endpoint binds (e.g. `127.0.0.1:9090`). `None` = no admin listener
    /// (the default). Serves `/metrics`, `/healthz`, `/readyz` — never on the data-plane port, so
    /// proxied routes never collide with it and the metrics surface is not exposed to clients.
    #[serde(default)]
    pub admin_addr: Option<String>,
    /// Emit one structured access-log event per request (the `plecto::access` tracing target,
    /// rendered as JSON by the binary's subscriber). `false` by default.
    #[serde(default)]
    pub access_log: bool,
}

/// One TLS server certificate (ADR 000014). The fast path terminates TLS with rustls and selects
/// a cert by SNI: `host` names the SNI this cert serves (case-insensitive); `None` is the default
/// cert presented when no SNI matches. `cert_path` / `key_path` are manifest-relative PEM files
/// (a cert chain and its private key). Only the **paths** ride the manifest content hash, so a
/// path change reloads but an in-place file edit does not (ADR 000014).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCert {
    /// SNI host this cert serves (case-insensitive). `None` = the default cert.
    #[serde(default)]
    pub host: Option<String>,
    /// Manifest-relative path to the PEM cert chain.
    pub cert_path: String,
    /// Manifest-relative path to the PEM private key.
    pub key_path: String,
}

/// A named upstream the fast-path server forwards a matched request to (ADR 000013 / 000017).
/// One or more `addresses` (plain `host:port`, no scheme; forwarded over plain HTTP/1.1) are the
/// upstream's instances; the fast path balances across the healthy ones per `lb_algorithm`. Every
/// upstream carries an active-health-check policy (`health`) — required, because instances start
/// pessimistic (unhealthy) and only a passing probe puts one into rotation (ADR 000017).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    /// Each backend instance's `host:port` (no scheme; plain HTTP/1.1). Each entry is either a bare
    /// string (`"127.0.0.1:9000"`, weight 1) or a weighted inline table (`{ address = "...",
    /// weight = N }`) for heterogeneous instances (ADR 000035). Must be non-empty (validated at
    /// build). The two forms mix in one list; a bare string and an explicit `weight = 1` are
    /// equivalent (same content hash).
    pub addresses: Vec<AddressSpec>,
    /// Per-upstream load-balancing algorithm (ADR 000035): `round_robin` (default), `least_request`
    /// (power-of-two-choices over per-instance active requests), or `maglev` (consistent hashing for
    /// session affinity). The chosen algorithm selects an instance from the healthy set; default
    /// `round_robin` keeps the pre-000035 behaviour with no per-request cost change.
    #[serde(default)]
    pub lb_algorithm: LbAlgorithm,
    /// Maglev hash config (ADR 000035), `[upstream.hash]`. Required iff `lb_algorithm = "maglev"`
    /// (a `maglev` upstream needs a hash key; any other algorithm must not set it). Absent otherwise.
    #[serde(default)]
    pub hash: Option<HashConfig>,
    /// Active-health-check policy for this upstream's instances (ADR 000017).
    pub health: HealthConfig,
    /// End-to-end timeout (ms) for forwarding a request to this upstream (ADR 000019 / review
    /// f000005 P2#4). Bounds time-to-response-headers; once headers arrive the body streams without
    /// a deadline, so streaming responses are unaffected. Exceeding it fails closed with **504**.
    /// Default 30000; **`0` disables** the timeout (for long-poll / streaming upstreams).
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Maximum times the fast path re-sends this upstream's request to a DIFFERENT healthy instance
    /// after a retryable failure (ADR 000023). A timeout is retried only for an idempotent method
    /// (the upstream may have acted); a connect failure — the upstream never received the request —
    /// is retried for any method. Only bodyless requests are retried (the opaque streamed body,
    /// ADR 000013, can't be replayed). Default 1; **`0` disables** retry.
    #[serde(default = "default_max_retries")]
    pub max_retries: u64,
    /// Overall request timeout (ms) bounding the WHOLE transaction — every attempt PLUS the backoff
    /// between them (ADR 000031) — whereas `request_timeout_ms` bounds a single attempt (per-try).
    /// This is the end-to-end deadline across retries; exceeding it fails closed **504**
    /// (`x-plecto-fault: request-timeout`, distinct from the per-try `upstream-timeout`). Should be
    /// `>= request_timeout_ms`; the runtime applies the tighter of the two regardless. Default `0` =
    /// no overall bound (only the per-try timeout applies — the pre-000031 behaviour).
    #[serde(default)]
    pub overall_timeout_ms: u64,
    /// Per-upstream circuit breaker (ADR 000028): bounds the load the fast path puts on this
    /// upstream. Distinct from health — `health` ejects *failing* instances, this caps concurrent
    /// work on *healthy* ones so a saturated backend sheds load fast instead of queueing unbounded.
    /// Absent = unlimited (the default).
    #[serde(default)]
    pub circuit_breaker: CircuitBreaker,
    /// Per-upstream outlier detection (ADR 000032): eject an instance from rotation when it
    /// MISBEHAVES on live traffic (gateway-class 5xx), a third resilience axis distinct from active
    /// health ("is it reachable?") and the circuit breaker ("is it saturated?"). Absent / threshold
    /// `0` = disabled (the default).
    #[serde(default)]
    pub outlier_detection: OutlierDetection,
}

/// Per-upstream load-balancing algorithm (ADR 000035). `round_robin` is the default and keeps the
/// pre-000035 healthy-set rotation (ADR 000024); the others are opt-in. This selects an INSTANCE
/// within a chosen upstream group — a layer below the route→group weighted split (ADR 000034).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
    /// Healthy-set round-robin (ADR 000017 / 000024) — the default.
    #[default]
    RoundRobin,
    /// Weighted least-request via power-of-two-choices: sample two healthy instances, forward to the
    /// one with the smaller `(active_requests + 1) / weight` (ADR 000035).
    LeastRequest,
    /// Consistent hashing via a (weighted) Maglev lookup table: a request's hash key maps to a
    /// stable instance for session affinity / cache locality (ADR 000035). Needs `[upstream.hash]`.
    Maglev,
}

/// One instance of an upstream (ADR 000035): a bare `host:port` string (weight 1) or a weighted
/// inline table `{ address = "host:port", weight = N }`. The bare form preserves the pre-000035
/// `addresses = ["h:p", ...]` manifest verbatim. A custom `Serialize` canonicalises a `weight = 1`
/// table back to the bare string, so an explicitly-written default weight does not change the
/// content hash (the manifest determinism invariant — same spirit as an explicit `isolation =
/// "untrusted"`).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum AddressSpec {
    /// A bare `host:port` — weight 1.
    Bare(String),
    /// A weighted instance `{ address, weight }`.
    Weighted(WeightedAddress),
}

/// The weighted form of an [`AddressSpec`]: an instance `host:port` plus its integer `weight`
/// (ADR 000035). Weight biases both the least-request comparison and the Maglev table share toward
/// higher-capacity instances; `1` is the default, `0` is rejected at build (drain an instance by
/// removing its address, not by zeroing its weight).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WeightedAddress {
    pub address: String,
    #[serde(default = "default_instance_weight")]
    pub weight: u32,
}

impl AddressSpec {
    /// This instance's `host:port`.
    pub fn address(&self) -> &str {
        match self {
            AddressSpec::Bare(a) => a,
            AddressSpec::Weighted(w) => &w.address,
        }
    }

    /// This instance's load-balancing weight (bare form is 1).
    pub fn weight(&self) -> u32 {
        match self {
            AddressSpec::Bare(_) => default_instance_weight(),
            AddressSpec::Weighted(w) => w.weight,
        }
    }
}

impl Serialize for AddressSpec {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Canonicalise a default `weight = 1` (whether bare or written-out) to the bare-string form
        // so it does not perturb the semantic content hash (manifest determinism invariant, like an
        // explicit `isolation = "untrusted"`). A non-default weight serialises as the table.
        match self {
            AddressSpec::Bare(addr) => serializer.serialize_str(addr),
            AddressSpec::Weighted(w) if w.weight == default_instance_weight() => {
                serializer.serialize_str(&w.address)
            }
            AddressSpec::Weighted(w) => w.serialize(serializer),
        }
    }
}

fn default_instance_weight() -> u32 {
    1
}

/// Upper bound on a per-instance weight (ADR 000035). Keeps the least-request cross-product and the
/// Maglev populate (which interleaves a backend every `max_weight / weight` rounds) bounded; mirrors
/// Google's documented per-instance weight range (0–1000) for weighted Maglev. Drain via address
/// removal, not weight 0, so the floor is 1.
pub(crate) const MAX_INSTANCE_WEIGHT: u32 = 1000;

/// The Maglev consistent-hashing config (ADR 000035), `[upstream.hash]`. Only valid when
/// `lb_algorithm = "maglev"`. Names the request attribute hashed for affinity and the lookup-table
/// size.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HashConfig {
    /// Which request attribute is the hash key.
    pub key: HashKeyKind,
    /// The header name to hash, required iff `key = "header"` (matched case-insensitively). Ignored
    /// for `source_ip`.
    #[serde(default)]
    pub header: Option<String>,
    /// Maglev lookup-table size `M` — must be PRIME (the permutation's `skip` is coprime to `M` only
    /// then) and `>= instance count`. Default 65537. Larger `M` reduces disruption on instance
    /// change at the cost of `M × 2` bytes per upstream; validated prime / in range at build.
    #[serde(default = "default_hash_table_size")]
    pub table_size: u32,
}

/// The request attribute a Maglev upstream hashes for affinity (ADR 000035).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HashKeyKind {
    /// The value of a named request header (requires `header`).
    Header,
    /// The connection peer's IP address (NOT a spoofable forwarding header).
    SourceIp,
}

fn default_hash_table_size() -> u32 {
    65537
}

/// Upper bound on the Maglev `table_size` (ADR 000035), matching Envoy's documented cap. Bounds the
/// per-upstream table memory (`table_size × 2` bytes); the operator must opt into anything this
/// large explicitly. The default (65537) is two orders of magnitude below it.
pub(crate) const MAX_HASH_TABLE_SIZE: u32 = 5_000_011;

impl Upstream {
    /// Validate this upstream's load-balancing config (ADR 000035) fail-closed at build, before the
    /// persistent registry reconciles. Checks per-instance weights, the `lb_algorithm` ↔
    /// `[upstream.hash]` correspondence, and (for Maglev) the hash key and table size. Returns the
    /// reason a caller wraps with the upstream name.
    pub(crate) fn validate_lb(&self) -> Result<(), String> {
        for spec in &self.addresses {
            let w = spec.weight();
            if w == 0 {
                return Err(format!(
                    "instance {:?} has weight 0; drain an instance by removing its address, not by zeroing weight",
                    spec.address()
                ));
            }
            if w > MAX_INSTANCE_WEIGHT {
                return Err(format!(
                    "instance {:?} weight {w} exceeds the maximum {MAX_INSTANCE_WEIGHT}",
                    spec.address()
                ));
            }
        }

        match (self.lb_algorithm, &self.hash) {
            // Maglev needs a hash key; a key with no algorithm to use it is a config mistake.
            (LbAlgorithm::Maglev, None) => {
                return Err(
                    "lb_algorithm = \"maglev\" requires a [upstream.hash] block".to_string()
                );
            }
            (algo, Some(_)) if algo != LbAlgorithm::Maglev => {
                return Err(
                    "[upstream.hash] is only valid with lb_algorithm = \"maglev\"".to_string(),
                );
            }
            _ => {}
        }

        if let Some(hash) = &self.hash {
            if hash.key == HashKeyKind::Header
                && hash
                    .header
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                return Err(
                    "[upstream.hash] key = \"header\" requires a non-empty header name".to_string(),
                );
            }
            let m = hash.table_size;
            if m > MAX_HASH_TABLE_SIZE {
                return Err(format!(
                    "[upstream.hash] table_size {m} exceeds the maximum {MAX_HASH_TABLE_SIZE}"
                ));
            }
            if !is_prime(m) {
                return Err(format!(
                    "[upstream.hash] table_size {m} must be prime (the Maglev permutation needs skip coprime to M)"
                ));
            }
            // Each instance needs at least one table entry, and the table indexes instances with a
            // u16, so the pool must fit both bounds.
            let n = self.addresses.len();
            if n > m as usize {
                return Err(format!(
                    "[upstream.hash] table_size {m} is smaller than the {n} instances"
                ));
            }
            if n > u16::MAX as usize {
                return Err(format!(
                    "maglev supports at most {} instances, got {n}",
                    u16::MAX
                ));
            }
        }
        Ok(())
    }
}

/// Trial-division primality test for the Maglev `table_size` (ADR 000035). Build-time only and `M`
/// is capped at a few million, so trial division to `√M` (~2236 iterations at the cap) is trivial;
/// no need for a probabilistic test or a dependency.
fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut d = 3u64;
    let n = n as u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

/// Per-upstream outlier-detection policy (ADR 000032). A THIRD resilience axis: active health (ADR
/// 000017) asks "is the instance reachable?", the circuit breaker (ADR 000028) "is the upstream
/// saturated?", and this "is the instance misbehaving on live traffic?". An ejected instance leaves
/// the rotation for a (backing-off) ejection window, independent of the health bit; a shed request
/// (circuit breaker) never feeds it, only real upstream 5xx responses do.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutlierDetection {
    /// Consecutive gateway-class 5xx (502/503/504) from live forwards to eject an instance; `0` =
    /// disabled (the default). Counts only real responses — a circuit-breaker 503 or a per-try
    /// timeout is not an instance-misbehaviour signal.
    #[serde(default)]
    pub consecutive_gateway_failures: u32,
    /// Base ejection duration (ms): an ejected instance is out of rotation this long, doubling per
    /// consecutive ejection up to a bounded cap, then auto-returns when the window expires (no probe
    /// needed). Default 30000.
    #[serde(default = "default_base_ejection_time_ms")]
    pub base_ejection_time_ms: u64,
    /// Max % of the pool that may be outlier-ejected at once. The rest stay in rotation even while
    /// failing — fail-closed must not become a self-inflicted total outage (ejecting every instance).
    /// Default 10.
    #[serde(default = "default_max_ejection_percent")]
    pub max_ejection_percent: u32,
}

impl Default for OutlierDetection {
    fn default() -> Self {
        Self {
            consecutive_gateway_failures: 0,
            base_ejection_time_ms: default_base_ejection_time_ms(),
            max_ejection_percent: default_max_ejection_percent(),
        }
    }
}

fn default_base_ejection_time_ms() -> u64 {
    30_000
}

fn default_max_ejection_percent() -> u32 {
    10
}

/// Per-upstream circuit-breaker thresholds (ADR 000028). Overload protection that is deliberately
/// SEPARATE from outlier detection / health (ADR 000017): health answers "is this instance up?",
/// the breaker answers "is this upstream saturated?". A request rejected by the breaker is the
/// upstream shedding load, not an instance failing — so it never demotes an instance.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreaker {
    /// Max concurrent in-flight requests the fast path will forward to this upstream at once. At the
    /// cap a new request fails closed with **503** (`x-plecto-fault: circuit-open`) rather than
    /// piling onto the backend. `0` = unlimited (the default). Counts one slot per request across
    /// the whole retry sequence, released when the upstream response headers arrive (or it fails).
    #[serde(default)]
    pub max_requests: u32,
}

/// Active-health-check policy (ADR 000017). A background prober issues `GET {path}` to each
/// instance every `interval_ms`; a 2xx within `timeout_ms` is a success, anything else (non-2xx,
/// timeout, connect error) a failure. `unhealthy_threshold` consecutive failures eject a healthy
/// instance from the rotation; `healthy_threshold` consecutive successes restore an ejected one.
/// Instances start pessimistic (unhealthy); the FIRST successful probe alone promotes a
/// never-yet-healthy instance (cold-start fast path), after which the full `healthy_threshold`
/// governs re-entry. Only `path` is required; the rest default. `PartialEq` lets a reload detect a
/// changed policy and re-probe the upstream's instances from scratch (ADR 000017 reconcile).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    /// The probe request path, e.g. `/healthz`.
    pub path: String,
    /// Probe period in milliseconds (default 2000).
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    /// Per-probe timeout in milliseconds (default 1000).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Consecutive successes to restore an ejected instance (default 2). The first-ever promotion
    /// of a never-yet-healthy instance needs only one success, regardless of this value.
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// Consecutive failures to eject a healthy instance (default 3).
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_request_timeout_ms() -> u64 {
    30_000
}

fn default_max_retries() -> u64 {
    1
}

fn default_interval_ms() -> u64 {
    2000
}
fn default_timeout_ms() -> u64 {
    1000
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}

/// One routing rule (ADR 000013 / 000034): match a request by the `[route.match]` dimensions, run
/// an inline chain of `filters`, and forward to a single `upstream` (shorthand) or a weighted set of
/// `backends` (traffic split / canary). `strip_prefix` is a **host-native** path rewrite applied to
/// the *forwarded* request only (the chain still sees the original path) — the common reverse-proxy
/// prefix-strip, without a `plecto:filter` contract change. `filters` / `strip_prefix` / `rate_limit`
/// are per-route: they apply identically across every backend (ADR 000034 keeps a backend a pure
/// `{upstream, weight}` pair; a route needing different policy per target uses a separate route).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The match dimensions (`[route.match]`): host / path_prefix / method / headers / query (ADR
    /// 000034). At least `path_prefix` is required; all other dimensions are optional and ANDed.
    #[serde(rename = "match")]
    pub matcher: RouteMatch,
    /// This route's chain: filter ids run in order (may be empty for a pure pass-through route).
    #[serde(default)]
    pub filters: Vec<String>,
    /// Single-upstream shorthand: the `[[upstream]]` `name` to forward a passing request to.
    /// Mutually exclusive with `backends` (exactly one is required; validated at build). A single
    /// `upstream` is normalised to a one-element weighted set (weight 1) at compile time.
    #[serde(default)]
    pub upstream: Option<String>,
    /// Weighted traffic split (ADR 000034): forward to these `{upstream, weight}` backends in
    /// proportion to their weights (canary). Mutually exclusive with `upstream`. Empty unless used.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// If set and the forwarded path starts with it, strip it before forwarding to the upstream
    /// (host-native rewrite; the chain saw the original path). E.g. `/api` + `/api/x` → `/x`.
    #[serde(default)]
    pub strip_prefix: Option<String>,
    /// Native fast-path rate limit (ADR 000033): a coarse token-bucket baseline consulted BEFORE
    /// this route's filter chain. Absent = unlimited (the default). Distinct from the per-filter
    /// `host-ratelimit` capability (ADR 000026): this is the operator's native floor on a route
    /// (or per client-IP), needs no WASM filter, and never crosses the WASM boundary.
    #[serde(default)]
    pub rate_limit: Option<RouteRateLimit>,
}

/// The match dimensions of a route (`[route.match]`, ADR 000034), modelled on Gateway-API v1.5.0
/// HTTPRoute matching. A request matches when EVERY specified dimension matches (AND); an
/// unspecified dimension is a wildcard. Among matching routes the most specific wins (see
/// `route::select`): host-constrained > longest `path_prefix` > `method` present > more header
/// matches > more query matches, with manifest order the final stable tie-break.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteMatch {
    /// Match only this authority (case-insensitive, port ignored). `None` matches any host.
    #[serde(default)]
    pub host: Option<String>,
    /// Match requests whose path starts with this prefix (on a `/` boundary). Longest wins.
    pub path_prefix: String,
    /// Match only this HTTP method (exact, upper-case token, e.g. `"POST"`). `None` matches any.
    #[serde(default)]
    pub method: Option<String>,
    /// Header matches: every entry must be present with an exact value. Header NAME is matched
    /// case-insensitively (lower-cased here at parse-ish time); the VALUE is matched byte-exact.
    /// `BTreeMap` (not `HashMap`) to keep the manifest's deterministic-serialisation invariant.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Query-parameter matches: every entry must be present with an exact value. Parameter NAME is
    /// case-sensitive (Gateway-API semantics, asymmetric with headers); the VALUE is matched exact.
    #[serde(default)]
    pub query: BTreeMap<String, String>,
}

/// One weighted backend of a route's traffic split (`[[route.backends]]`, ADR 000034): the
/// `[[upstream]]` `name` and its integer `weight`. The proportion a backend receives is
/// `weight / Σweights` (Gateway-API semantics). `weight` defaults to 1, caps at 1_000_000 (Σ
/// overflow guard), and `0` drains the backend (no traffic). Validated at build (ADR 000034 5b).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// The `[[upstream]]` `name` this backend forwards to.
    pub upstream: String,
    /// This backend's integer weight in the split (default 1, max 1_000_000, `0` = drain).
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Upper bound on a single backend weight (Gateway-API `Maximum=1000000`). Caps the summed weight
/// so the weighted-split accumulator and the precomputed table stay bounded (ADR 000034 5b).
pub(crate) const MAX_BACKEND_WEIGHT: u32 = 1_000_000;

impl Route {
    /// This route's forwarding targets as `(upstream_name, weight)` pairs (ADR 000034): the single
    /// `upstream` shorthand normalised to one weight-1 backend, or the explicit weighted `backends`.
    /// EXACTLY ONE of the two must be set — both or neither is a config error (returned as a reason
    /// the caller wraps with the route's context). Borrows the names from `self` (no allocation).
    pub(crate) fn targets(&self) -> Result<Vec<(&str, u32)>, &'static str> {
        match (self.upstream.as_deref(), self.backends.as_slice()) {
            (Some(_), [_, ..]) => {
                Err("a route sets both `upstream` and `backends`; set exactly one")
            }
            (None, []) => Err("a route sets neither `upstream` nor `backends`; set exactly one"),
            (Some(name), []) => Ok(vec![(name, 1)]),
            (None, backends) => Ok(backends
                .iter()
                .map(|b| (b.upstream.as_str(), b.weight))
                .collect()),
        }
    }
}

/// Native per-route rate-limit spec (ADR 000033), declared as `[route.rate_limit]`. A coarse
/// token bucket the fast path consults before forwarding — the Tier-0 baseline a filterless route
/// otherwise lacks. `rate`/`burst` map onto the same token-bucket math as `host-ratelimit`
/// (`capacity = burst`, refill `rate` tokens every second), but the surface is deliberately the
/// friendlier two-knob (rate + burst) form, since this is a blunt floor, not a policy limiter.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RouteRateLimit {
    /// Sustained requests per second (tokens added each second). Must be non-zero.
    pub rate: u64,
    /// Burst capacity: the most tokens the bucket holds (and starts full with). Must be non-zero.
    pub burst: u64,
    /// What the bucket counts against (default `route`). `route` shares one bucket across every
    /// client of the route (a total floor); `client-ip` gives each client its own bucket (fairness
    /// between clients), keyed on the connection peer (v4 /32, v6 /64).
    #[serde(default)]
    pub key: RateLimitKeyKind,
}

/// The dimension a native route rate limit counts against (ADR 000033).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitKeyKind {
    /// One shared bucket for the whole route — a total cap regardless of client.
    #[default]
    Route,
    /// A per-client-IP bucket (peer address, v4 /32 + v6 /64), bounded to a fixed-size table.
    ClientIp,
}

/// Trust roots: paths (manifest-relative) to trusted signer public keys, PEM (ADR 000006).
/// `PartialEq` lets `reload` detect a trust-section change (which it rejects — trust is fixed
/// at construction, f000004 #1).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    #[serde(default)]
    pub keys: Vec<String>,
}

/// Host-side token-bucket spec for a filter's `host-ratelimit` (ADR 000026), set in the manifest
/// as an inline table `ratelimit = { capacity = .., refill_tokens = .., refill_interval_ms = .. }`.
/// The operator owns it, so an untrusted filter cannot supply or override its own limit (the WIT
/// `try-acquire` carries only `key` + `cost`).
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Maximum tokens the bucket can hold.
    pub capacity: u64,
    /// Tokens added each refill interval.
    pub refill_tokens: u64,
    /// Refill interval in milliseconds (the host advances by whole intervals).
    pub refill_interval_ms: u64,
}

/// A URL scheme an outbound allowlist entry may name (ADR 000036). Defaults to `https`.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SchemeKind {
    #[default]
    Https,
    Http,
}

impl SchemeKind {
    #[cfg(feature = "outbound-http")]
    fn default_port(self) -> u16 {
        match self {
            SchemeKind::Https => 443,
            SchemeKind::Http => 80,
        }
    }
}

/// One allowed outbound destination — an exact `(scheme, host, port)` triple (ADR 000036). No
/// wildcards: the target endpoints (JWKS / introspection / ext_authz) are fixed and known.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowDest {
    /// Exact host — a DNS name (matched case-insensitively) or an IP literal.
    pub host: String,
    /// Destination port. Defaults to the scheme's default (443/80) when omitted.
    pub port: Option<u16>,
    /// URL scheme (default `https`).
    #[serde(default)]
    pub scheme: SchemeKind,
}

/// A filter's outbound HTTP policy (ADR 000036), declared as `[filter.outbound]`. The operator owns
/// it — an untrusted filter cannot supply, widen, or override it (the `wasi:http/outgoing-handler`
/// import carries only the request). Absent = the filter is lent no outbound capability.
///
/// `allow` is deny-by-default: only listed destinations are reachable. `allow_private` opts specific
/// RFC1918 / ULA CIDRs past the SSRF guard's private-range block (for internal ext_authz); it never
/// opens the always-blocked reserved floor (loopback / link-local / cloud-metadata). Timeouts and
/// sizes are host-clamped.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    /// The exact destinations this filter may call. Must be non-empty when the section is present.
    pub allow: Vec<AllowDest>,
    /// Private/ULA CIDRs (e.g. `"10.1.0.0/16"`) this filter may reach despite the SSRF private-range
    /// block. Empty (default) leaves all private space blocked.
    #[serde(default)]
    pub allow_private: Vec<String>,
    /// TCP connect timeout (ms). Host default/ceiling apply when omitted/exceeded.
    pub connect_timeout_ms: Option<u64>,
    /// Whole-call wall-clock timeout (ms). Host default/ceiling apply when omitted/exceeded.
    pub total_timeout_ms: Option<u64>,
    /// Cap on the response body the host buffers back (bytes). Host default/ceiling apply.
    pub max_response_bytes: Option<u64>,
    /// Cap on concurrent in-flight outbound calls for this filter. Host default/ceiling apply.
    pub max_concurrent: Option<u32>,
}

/// One filter to load, pinned by OCI digest.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterEntry {
    /// Host-assigned identity; namespaces the filter's KV (ADR 000011) and names it in chains.
    ///
    /// KV continuity is **per-id and survives reload** (f000004 #4): reloading the same `id`
    /// with a new `digest` keeps the same KV namespace, so the new version inherits the old
    /// version's bytes (good for rate-limit counters — a reload doesn't reset them). If a new
    /// version changes its state encoding, handle the migration or use a new `id` (= a fresh
    /// namespace).
    pub id: String,
    /// Manifest-relative path to the local OCI image-layout for this filter.
    pub source: String,
    /// Pinned OCI image-manifest digest, `sha256:...` (reproducibility / supply chain).
    pub digest: String,
    #[serde(default)]
    pub isolation: IsolationKind,
    pub init_deadline_ms: Option<u64>,
    pub request_deadline_ms: Option<u64>,
    pub max_memory_bytes: Option<u64>,
    /// Host-side token bucket for this filter's `host-ratelimit` (ADR 000026). Absent = the filter
    /// has no limiter (its `try-acquire` fails closed). Operator-configured so an untrusted filter
    /// cannot override its own limit.
    pub ratelimit: Option<RateLimitConfig>,
    /// This filter's outbound HTTP policy (ADR 000036), `[filter.outbound]`. Absent = no outbound
    /// capability. Requires the `outbound-http` build; otherwise a present section is rejected at
    /// validate (fail-closed).
    #[serde(default)]
    pub outbound: Option<OutboundConfig>,
}

/// Manifest spelling of the host's `Isolation`. Defaults to `untrusted` (fail-closed).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IsolationKind {
    #[default]
    Untrusted,
    Trusted,
}

/// The single ordered chain for v0.1 (named chains / route matching are deferred to the
/// fast-path server).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    #[serde(default)]
    pub filters: Vec<String>,
}

impl Manifest {
    /// Parse a manifest from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ControlError> {
        Ok(toml::from_str(s)?)
    }

    /// The **semantic** content hash of this manifest — `sha256:<hex>` over a canonical
    /// serialisation, not over the raw TOML. Two manifests that mean the same thing (differing
    /// only in comments, whitespace, key order, or an explicit default written vs. omitted)
    /// hash identically; any meaningful change flips the hash.
    ///
    /// This is the manifest's `config version`: the unit `reload_from_disk` compares for
    /// idempotency, the value an operator audits, and the value a future opt-in consensus
    /// layer (ADR 000008 openraft) would agree on. Canonical form is `serde_json` over the
    /// derived `Serialize` — deterministic because the struct field order is fixed and the
    /// manifest holds no maps (only ordered `Vec`s).
    pub fn content_hash(&self) -> Result<String, ControlError> {
        let bytes = serde_json::to_vec(self)?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
    }
}

impl FilterEntry {
    /// Reject out-of-range metering / rate-limit values before they reach the host (/
    /// CWE-20): a zero deadline would make every call instantly time out, a zero memory cap is
    /// unusable, and a rate-limit bucket with `capacity == 0` or `refill_interval_ms == 0`
    /// (with refills) can never serve a token — a config typo, not an intended state. Fail-closed.
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        let bad = |reason: &str| ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason: reason.to_string(),
        };
        if self.init_deadline_ms == Some(0) {
            return Err(bad("init_deadline_ms must be non-zero"));
        }
        if self.request_deadline_ms == Some(0) {
            return Err(bad("request_deadline_ms must be non-zero"));
        }
        if self.max_memory_bytes == Some(0) {
            return Err(bad("max_memory_bytes must be non-zero"));
        }
        if let Some(rl) = self.ratelimit {
            if rl.capacity == 0 {
                return Err(bad("ratelimit.capacity must be non-zero"));
            }
            // refill_tokens == 0 is a valid one-shot (no-refill) bucket; but a positive refill with
            // a zero interval can never advance — reject that typo.
            if rl.refill_tokens > 0 && rl.refill_interval_ms == 0 {
                return Err(bad(
                    "ratelimit.refill_interval_ms must be non-zero when refill_tokens > 0",
                ));
            }
        }
        if let Some(ob) = &self.outbound {
            self.validate_outbound(ob)?;
        }
        Ok(())
    }

    /// Validate an outbound section. Without the `outbound-http` build the host cannot provide the
    /// capability, so any declared outbound is rejected (fail-closed). With it, the allowlist must be
    /// non-empty, `allow_private` CIDRs must parse, and any explicit metering value must be non-zero.
    #[cfg(not(feature = "outbound-http"))]
    fn validate_outbound(&self, _ob: &OutboundConfig) -> Result<(), ControlError> {
        Err(ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason: "outbound requested but this build lacks the `outbound-http` feature"
                .to_string(),
        })
    }

    #[cfg(feature = "outbound-http")]
    fn validate_outbound(&self, ob: &OutboundConfig) -> Result<(), ControlError> {
        let bad = |reason: String| ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason,
        };
        if ob.allow.is_empty() {
            return Err(bad(
                "outbound.allow must list at least one destination".into()
            ));
        }
        for dest in &ob.allow {
            if dest.host.trim().is_empty() {
                return Err(bad("outbound.allow entry has an empty host".into()));
            }
            if dest.port == Some(0) {
                return Err(bad(format!("outbound.allow host {} has port 0", dest.host)));
            }
        }
        for cidr in &ob.allow_private {
            cidr.parse::<ipnet::IpNet>().map_err(|e| {
                bad(format!(
                    "outbound.allow_private has invalid CIDR {cidr:?}: {e}"
                ))
            })?;
        }
        if ob.connect_timeout_ms == Some(0) {
            return Err(bad("outbound.connect_timeout_ms must be non-zero".into()));
        }
        if ob.total_timeout_ms == Some(0) {
            return Err(bad("outbound.total_timeout_ms must be non-zero".into()));
        }
        if ob.max_response_bytes == Some(0) {
            return Err(bad("outbound.max_response_bytes must be non-zero".into()));
        }
        if ob.max_concurrent == Some(0) {
            return Err(bad("outbound.max_concurrent must be non-zero".into()));
        }
        Ok(())
    }

    /// The host `LoadOptions` for this entry: isolation plus any metering overrides
    /// (ADR 000006). Unset knobs keep the host defaults.
    pub(crate) fn load_options(&self) -> LoadOptions {
        let mut opts = match self.isolation {
            IsolationKind::Trusted => LoadOptions::trusted(),
            IsolationKind::Untrusted => LoadOptions::untrusted(),
        };
        if let Some(ms) = self.init_deadline_ms {
            opts = opts.with_init_deadline_ms(ms);
        }
        if let Some(ms) = self.request_deadline_ms {
            opts = opts.with_request_deadline_ms(ms);
        }
        if let Some(bytes) = self.max_memory_bytes {
            opts = opts.with_max_memory_bytes(bytes);
        }
        if let Some(rl) = self.ratelimit {
            opts = opts.with_ratelimit_bucket(rl.capacity, rl.refill_tokens, rl.refill_interval_ms);
        }
        #[cfg(feature = "outbound-http")]
        if let Some(ob) = &self.outbound {
            // Validated already (`validate`), so the CIDR parses and the allowlist is non-empty.
            let allow = ob
                .allow
                .iter()
                .map(|d| plecto_host::AllowEntry {
                    scheme: match d.scheme {
                        SchemeKind::Https => plecto_host::Scheme::Https,
                        SchemeKind::Http => plecto_host::Scheme::Http,
                    },
                    host: d.host.clone(),
                    port: d.port.unwrap_or_else(|| d.scheme.default_port()),
                })
                .collect();
            opts = opts.with_outbound(
                allow,
                ob.allow_private.clone(),
                ob.connect_timeout_ms,
                ob.total_timeout_ms,
                ob.max_response_bytes,
                ob.max_concurrent,
            );
        }
        opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_defaults_off_and_parses_when_present() {
        // Absent `[observability]` → admin endpoint off, access log off (operational simplicity).
        let bare = Manifest::from_toml("").unwrap();
        assert_eq!(bare.observability.admin_addr, None);
        assert!(!bare.observability.access_log);

        // Present → both knobs are read.
        let m = Manifest::from_toml(
            r#"
[observability]
admin_addr = "127.0.0.1:9090"
access_log = true
"#,
        )
        .unwrap();
        assert_eq!(
            m.observability.admin_addr.as_deref(),
            Some("127.0.0.1:9090")
        );
        assert!(m.observability.access_log);
    }

    #[test]
    fn observability_is_not_part_of_the_content_hash() {
        // `[observability]` is operational, not config identity (`skip_serializing`): toggling it
        // must NOT change the `content_hash` / config version, so an admin-only edit is a reload
        // no-op rather than a spurious "config changed".
        let without = Manifest::from_toml("").unwrap();
        let with = Manifest::from_toml(
            r#"
[observability]
admin_addr = "127.0.0.1:9090"
access_log = true
"#,
        )
        .unwrap();
        assert_eq!(
            without.content_hash().unwrap(),
            with.content_hash().unwrap(),
            "observability config must not affect the semantic content hash"
        );
    }

    #[test]
    fn upstream_circuit_breaker_defaults_unlimited_and_parses() {
        // Absent `[upstream.circuit_breaker]` → unlimited (max_requests 0), the safe default.
        let m = Manifest::from_toml(
            r#"
[[upstream]]
name = "a"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(
            m.upstreams[0].circuit_breaker.max_requests, 0,
            "an absent breaker is unlimited"
        );

        // Present → the cap is read.
        let m2 = Manifest::from_toml(
            r#"
[[upstream]]
name = "a"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/healthz"
[upstream.circuit_breaker]
max_requests = 64
"#,
        )
        .unwrap();
        assert_eq!(m2.upstreams[0].circuit_breaker.max_requests, 64);
    }

    #[test]
    fn route_rate_limit_defaults_absent_and_parses_with_key() {
        // Absent `[route.rate_limit]` → no native limiter (unlimited), the default.
        let m = Manifest::from_toml(
            r#"
[[route]]
upstream = "a"
[route.match]
path_prefix = "/"
"#,
        )
        .unwrap();
        assert!(
            m.routes[0].rate_limit.is_none(),
            "an absent rate_limit is unlimited"
        );

        // Present → rate/burst are read; `key` defaults to `route`.
        let m2 = Manifest::from_toml(
            r#"
[[route]]
upstream = "a"
[route.match]
path_prefix = "/"
[route.rate_limit]
rate = 100
burst = 200
"#,
        )
        .unwrap();
        let rl = m2.routes[0].rate_limit.unwrap();
        assert_eq!(rl.rate, 100);
        assert_eq!(rl.burst, 200);
        assert_eq!(rl.key, RateLimitKeyKind::Route, "key defaults to route");

        // `key = "client-ip"` is the kebab-case spelling.
        let m3 = Manifest::from_toml(
            r#"
[[route]]
upstream = "a"
[route.match]
path_prefix = "/"
[route.rate_limit]
rate = 5
burst = 5
key = "client-ip"
"#,
        )
        .unwrap();
        assert_eq!(
            m3.routes[0].rate_limit.unwrap().key,
            RateLimitKeyKind::ClientIp
        );
    }

    #[test]
    fn parses_filters_and_chain_with_defaults() {
        let m = Manifest::from_toml(
            r#"
[[filter]]
id = "auth"
source = "artifacts/auth"
digest = "sha256:abc"

[[filter]]
id = "rl"
source = "artifacts/rl"
digest = "sha256:def"
isolation = "trusted"
request_deadline_ms = 25

[chain]
filters = ["auth", "rl"]
"#,
        )
        .unwrap();

        assert_eq!(m.filters.len(), 2);
        assert_eq!(m.filters[0].isolation, IsolationKind::Untrusted); // default
        assert_eq!(m.filters[1].isolation, IsolationKind::Trusted);
        assert_eq!(m.filters[1].request_deadline_ms, Some(25));
        assert_eq!(m.chain.filters, vec!["auth".to_string(), "rl".to_string()]);
    }

    #[test]
    fn content_hash_is_semantic_not_textual() {
        // Representation noise that does NOT change meaning must NOT change the hash:
        // comments, whitespace, key order, and an explicit default (`isolation = "untrusted"`)
        // written vs. omitted all canonicalise away.
        let terse = Manifest::from_toml(
            r#"
[[filter]]
id = "auth"
source = "artifacts/auth"
digest = "sha256:abc"

[chain]
filters = ["auth"]
"#,
        )
        .unwrap();

        let noisy = Manifest::from_toml(
            r#"
# a leading comment
[chain]
filters = ["auth"]   # chain first, with trailing comment

[[filter]]
digest   = "sha256:abc"
source   = "artifacts/auth"
id       = "auth"
isolation = "untrusted"   # the default, written explicitly
"#,
        )
        .unwrap();

        assert_eq!(
            terse.content_hash().unwrap(),
            noisy.content_hash().unwrap(),
            "semantically identical manifests must share a content hash"
        );
        assert!(terse.content_hash().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn content_hash_changes_on_meaningful_edit() {
        let v1 = Manifest::from_toml(
            r#"
[[filter]]
id = "auth"
source = "artifacts/auth"
digest = "sha256:abc"

[chain]
filters = ["auth"]
"#,
        )
        .unwrap();
        // Same filter, different chain (drops it) — a real config change.
        let v2 = Manifest::from_toml(
            r#"
[[filter]]
id = "auth"
source = "artifacts/auth"
digest = "sha256:abc"

[chain]
filters = []
"#,
        )
        .unwrap();

        assert_ne!(
            v1.content_hash().unwrap(),
            v2.content_hash().unwrap(),
            "a chain change must flip the content hash"
        );
    }

    #[test]
    fn parses_routes_and_upstreams() {
        let m = Manifest::from_toml(
            r#"
[[filter]]
id = "auth"
source = "artifacts/auth"
digest = "sha256:abc"

[[upstream]]
name = "api-svc"
addresses = ["127.0.0.1:9000", "127.0.0.1:9001"]
[upstream.health]
path = "/healthz"

[[route]]
filters = ["auth"]
upstream = "api-svc"
strip_prefix = "/api"
[route.match]
host = "example.com"
path_prefix = "/api"
"#,
        )
        .unwrap();

        assert_eq!(m.upstreams.len(), 1);
        let addrs: Vec<&str> = m.upstreams[0]
            .addresses
            .iter()
            .map(|a| a.address())
            .collect();
        assert_eq!(addrs, vec!["127.0.0.1:9000", "127.0.0.1:9001"]);
        assert!(
            m.upstreams[0].addresses.iter().all(|a| a.weight() == 1),
            "bare addresses default to weight 1"
        );
        // health is required; the unspecified knobs take their defaults
        assert_eq!(m.upstreams[0].health.path, "/healthz");
        assert_eq!(m.upstreams[0].health.interval_ms, 2000);
        assert_eq!(m.upstreams[0].health.timeout_ms, 1000);
        assert_eq!(m.upstreams[0].health.healthy_threshold, 2);
        assert_eq!(m.upstreams[0].health.unhealthy_threshold, 3);
        assert_eq!(m.routes.len(), 1);
        let r = &m.routes[0];
        assert_eq!(r.matcher.host.as_deref(), Some("example.com"));
        assert_eq!(r.matcher.path_prefix, "/api");
        assert_eq!(r.filters, vec!["auth".to_string()]);
        assert_eq!(r.upstream.as_deref(), Some("api-svc"));
        assert!(r.backends.is_empty(), "single upstream uses the shorthand");
        assert_eq!(r.strip_prefix.as_deref(), Some("/api"));
        // a routing edit must flip the config version (routes ride the semantic hash)
        let mut m2 = m.clone();
        m2.routes[0].matcher.path_prefix = "/v2".to_string();
        assert_ne!(
            m.content_hash().unwrap(),
            m2.content_hash().unwrap(),
            "a route change must flip the content hash"
        );
    }

    #[test]
    fn upstream_requires_health() {
        // health is mandatory for every upstream (ADR 000017): a missing `[upstream.health]`
        // table is rejected, since instances start pessimistic and need a probe to enter rotation.
        let parsed = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
"#,
        );
        assert!(
            parsed.is_err(),
            "an upstream without [upstream.health] is rejected"
        );
    }

    #[test]
    fn health_requires_path_but_defaults_the_rest() {
        // `path` is required; thresholds/interval/timeout default.
        let no_path = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
[upstream.health]
interval_ms = 500
"#,
        );
        assert!(no_path.is_err(), "health without a probe path is rejected");

        // explicit overrides ride through
        let m = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/up"
interval_ms = 250
timeout_ms = 100
healthy_threshold = 1
unhealthy_threshold = 5
"#,
        )
        .unwrap();
        let h = &m.upstreams[0].health;
        assert_eq!(h.interval_ms, 250);
        assert_eq!(h.timeout_ms, 100);
        assert_eq!(h.healthy_threshold, 1);
        assert_eq!(h.unhealthy_threshold, 5);
    }

    #[test]
    fn upstream_request_timeout_defaults_and_overrides() {
        // ADR 000019 / review f000005 P2#4: an upstream gets a 30s default end-to-end timeout when
        // unspecified; an explicit value (incl. 0 = disabled) rides through and flips the hash.
        let defaulted = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(
            defaulted.upstreams[0].request_timeout_ms, 30_000,
            "an unspecified upstream timeout defaults to 30s"
        );

        let overridden = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
request_timeout_ms = 250
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(overridden.upstreams[0].request_timeout_ms, 250);
        // a timeout change is a real config change → the content hash must flip.
        assert_ne!(
            defaulted.content_hash().unwrap(),
            overridden.content_hash().unwrap(),
            "changing the upstream timeout must flip the config version"
        );

        // `0` is an explicit opt-out (long-poll / streaming upstream) and must parse, not error.
        let disabled = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
request_timeout_ms = 0
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(
            disabled.upstreams[0].request_timeout_ms, 0,
            "request_timeout_ms = 0 disables the timeout and must parse"
        );
    }

    #[test]
    fn upstream_max_retries_defaults_and_overrides() {
        // ADR 000023: an upstream gets 1 retry by default; an explicit value (incl. 0 = disabled)
        // rides through and flips the content hash.
        let defaulted = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(
            defaulted.upstreams[0].max_retries, 1,
            "an unspecified upstream defaults to one retry"
        );

        let disabled = Manifest::from_toml(
            r#"
[[upstream]]
name = "x"
addresses = ["127.0.0.1:9000"]
max_retries = 0
[upstream.health]
path = "/healthz"
"#,
        )
        .unwrap();
        assert_eq!(disabled.upstreams[0].max_retries, 0, "0 disables retry");
        assert_ne!(
            defaulted.content_hash().unwrap(),
            disabled.content_hash().unwrap(),
            "changing max_retries must flip the config version"
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let parsed = Manifest::from_toml(
            r#"
[[filter]]
id = "x"
source = "s"
digest = "sha256:abc"
typo_field = true
"#,
        );
        assert!(parsed.is_err(), "deny_unknown_fields should reject a typo");
    }

    #[test]
    fn load_options_maps_isolation_and_overrides() {
        let entry = FilterEntry {
            id: "x".to_string(),
            source: "s".to_string(),
            digest: "sha256:abc".to_string(),
            isolation: IsolationKind::Trusted,
            init_deadline_ms: None,
            request_deadline_ms: Some(40),
            max_memory_bytes: Some(1024),
            ratelimit: Some(RateLimitConfig {
                capacity: 100,
                refill_tokens: 10,
                refill_interval_ms: 1000,
            }),
            outbound: None,
        };
        let opts = entry.load_options();

        assert_eq!(opts.isolation, plecto_host::Isolation::Trusted);
        assert_eq!(opts.request_deadline_ms, 40);
        assert_eq!(opts.max_memory_bytes, 1024);
        // an unset knob keeps the host default
        assert_eq!(
            opts.init_deadline_ms,
            LoadOptions::trusted().init_deadline_ms
        );
        // the per-filter manifest bucket maps to the host-side spec (ADR 000026) — the filter
        // cannot supply or override it.
        let bucket = opts
            .ratelimit_bucket
            .expect("a manifest ratelimit maps to the host bucket");
        assert_eq!(bucket.capacity, 100);
        assert_eq!(bucket.refill_tokens, 10);
        assert_eq!(bucket.refill_interval_ms, 1000);
    }

    #[test]
    fn invalid_filter_metering_is_rejected() {
        // out-of-range metering / rate-limit values are rejected fail-closed at build.
        let base = FilterEntry {
            id: "x".to_string(),
            source: "s".to_string(),
            digest: "sha256:abc".to_string(),
            isolation: IsolationKind::Untrusted,
            init_deadline_ms: None,
            request_deadline_ms: None,
            max_memory_bytes: None,
            ratelimit: None,
            outbound: None,
        };
        assert!(base.validate().is_ok(), "defaults are valid");

        assert!(
            FilterEntry {
                request_deadline_ms: Some(0),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "a zero request deadline is rejected"
        );
        assert!(
            FilterEntry {
                max_memory_bytes: Some(0),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "a zero memory cap is rejected"
        );
        assert!(
            FilterEntry {
                ratelimit: Some(RateLimitConfig {
                    capacity: 10,
                    refill_tokens: 1,
                    refill_interval_ms: 0,
                }),
                ..base.clone()
            }
            .validate()
            .is_err(),
            "a refilling bucket with a zero interval is rejected"
        );
        assert!(
            FilterEntry {
                ratelimit: Some(RateLimitConfig {
                    capacity: 10,
                    refill_tokens: 0,
                    refill_interval_ms: 0,
                }),
                ..base.clone()
            }
            .validate()
            .is_ok(),
            "a one-shot (no-refill) bucket is valid"
        );
    }

    // ----- ADR 000035: lb_algorithm, per-instance weight, maglev hash config -----

    fn upstream_toml(body: &str) -> Result<Manifest, ControlError> {
        Manifest::from_toml(&format!(
            "[[upstream]]\nname = \"u\"\n{body}\n[upstream.health]\npath = \"/healthz\"\n"
        ))
    }

    #[test]
    fn lb_algorithm_defaults_round_robin_and_parses() {
        // Absent → round_robin (the pre-000035 default).
        let m = upstream_toml("addresses = [\"a:1\"]").unwrap();
        assert_eq!(m.upstreams[0].lb_algorithm, LbAlgorithm::RoundRobin);

        let lr = upstream_toml("addresses = [\"a:1\"]\nlb_algorithm = \"least_request\"").unwrap();
        assert_eq!(lr.upstreams[0].lb_algorithm, LbAlgorithm::LeastRequest);

        // a non-default algorithm flips the content hash (it is part of config identity).
        assert_ne!(
            m.content_hash().unwrap(),
            lr.content_hash().unwrap(),
            "changing lb_algorithm must flip the config version"
        );
    }

    #[test]
    fn addresses_parse_bare_and_weighted_mixed() {
        // A bare string and a weighted inline table coexist in one list (ADR 000035).
        let m = upstream_toml(
            "addresses = [\"a:1\", { address = \"b:2\", weight = 5 }, { address = \"c:3\" }]",
        )
        .unwrap();
        let a = &m.upstreams[0].addresses;
        assert_eq!(a[0].address(), "a:1");
        assert_eq!(a[0].weight(), 1, "bare = weight 1");
        assert_eq!(a[1].address(), "b:2");
        assert_eq!(a[1].weight(), 5);
        assert_eq!(a[2].address(), "c:3");
        assert_eq!(a[2].weight(), 1, "weighted form defaults weight to 1");
    }

    #[test]
    fn explicit_weight_one_hashes_like_a_bare_address() {
        // The determinism invariant: an explicit `weight = 1` is representation noise vs a bare
        // string, so the two must share a content hash (like an explicit `isolation = "untrusted"`).
        let bare = upstream_toml("addresses = [\"a:1\"]").unwrap();
        let explicit = upstream_toml("addresses = [{ address = \"a:1\", weight = 1 }]").unwrap();
        assert_eq!(
            bare.content_hash().unwrap(),
            explicit.content_hash().unwrap(),
            "an explicit default weight must not change the config version"
        );

        // …but a non-default weight DOES change it.
        let weighted = upstream_toml("addresses = [{ address = \"a:1\", weight = 3 }]").unwrap();
        assert_ne!(
            bare.content_hash().unwrap(),
            weighted.content_hash().unwrap()
        );
    }

    #[test]
    fn maglev_hash_config_parses() {
        let m = upstream_toml(
            "addresses = [\"a:1\", \"b:2\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"header\"\nheader = \"x-user\"\ntable_size = 1009",
        )
        .unwrap();
        let up = &m.upstreams[0];
        assert_eq!(up.lb_algorithm, LbAlgorithm::Maglev);
        let hash = up.hash.as_ref().unwrap();
        assert_eq!(hash.key, HashKeyKind::Header);
        assert_eq!(hash.header.as_deref(), Some("x-user"));
        assert_eq!(hash.table_size, 1009);
        assert!(up.validate_lb().is_ok());
    }

    #[test]
    fn hash_table_size_defaults_to_65537() {
        let m = upstream_toml(
            "addresses = [\"a:1\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"source_ip\"",
        )
        .unwrap();
        assert_eq!(m.upstreams[0].hash.as_ref().unwrap().table_size, 65537);
        assert_eq!(
            m.upstreams[0].hash.as_ref().unwrap().key,
            HashKeyKind::SourceIp
        );
    }

    #[test]
    fn validate_lb_rejects_bad_configs() {
        // weight 0 (drain via address removal, not weight 0)
        let w0 = upstream_toml("addresses = [{ address = \"a:1\", weight = 0 }]").unwrap();
        assert!(w0.upstreams[0].validate_lb().is_err(), "weight 0 rejected");

        // weight over the cap
        let wbig = upstream_toml(&format!(
            "addresses = [{{ address = \"a:1\", weight = {} }}]",
            MAX_INSTANCE_WEIGHT + 1
        ))
        .unwrap();
        assert!(
            wbig.upstreams[0].validate_lb().is_err(),
            "over-cap weight rejected"
        );

        // maglev without a hash block
        let no_hash = upstream_toml("addresses = [\"a:1\"]\nlb_algorithm = \"maglev\"").unwrap();
        assert!(
            no_hash.upstreams[0].validate_lb().is_err(),
            "maglev needs [upstream.hash]"
        );

        // hash block on a non-maglev algorithm
        let stray_hash =
            upstream_toml("addresses = [\"a:1\"]\n[upstream.hash]\nkey = \"source_ip\"").unwrap();
        assert!(
            stray_hash.upstreams[0].validate_lb().is_err(),
            "[upstream.hash] only valid with maglev"
        );

        // header key with no header name
        let no_header = upstream_toml(
            "addresses = [\"a:1\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"header\"",
        )
        .unwrap();
        assert!(
            no_header.upstreams[0].validate_lb().is_err(),
            "header key needs a name"
        );

        // non-prime table size
        let nonprime = upstream_toml(
            "addresses = [\"a:1\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"source_ip\"\ntable_size = 1000",
        )
        .unwrap();
        assert!(
            nonprime.upstreams[0].validate_lb().is_err(),
            "table_size must be prime"
        );

        // table smaller than the instance count
        let too_small = upstream_toml(
            "addresses = [\"a:1\", \"b:2\", \"c:3\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"source_ip\"\ntable_size = 2",
        )
        .unwrap();
        assert!(
            too_small.upstreams[0].validate_lb().is_err(),
            "M must be >= instance count"
        );

        // a valid maglev config passes
        let ok = upstream_toml(
            "addresses = [\"a:1\", \"b:2\"]\nlb_algorithm = \"maglev\"\n[upstream.hash]\nkey = \"source_ip\"\ntable_size = 97",
        )
        .unwrap();
        assert!(ok.upstreams[0].validate_lb().is_ok());
    }

    #[test]
    fn is_prime_is_correct() {
        for p in [2u32, 3, 5, 97, 1009, 65537, 5_000_011] {
            assert!(is_prime(p), "{p} is prime");
        }
        for c in [0u32, 1, 4, 9, 100, 1000, 65536] {
            assert!(!is_prime(c), "{c} is not prime");
        }
    }

    const OUTBOUND_TOML: &str = r#"
[[filter]]
id = "extauthz"
source = "oci/extauthz"
digest = "sha256:abc"

[filter.outbound]
allow = [
  { host = "authz.example.com", port = 8443, scheme = "https" },
  { host = "jwks.example.com" },
]
allow_private = ["10.1.0.0/16"]
connect_timeout_ms = 1500
"#;

    #[test]
    fn outbound_section_parses() {
        let m = Manifest::from_toml(OUTBOUND_TOML).unwrap();
        let ob = m.filters[0].outbound.as_ref().expect("outbound present");
        assert_eq!(ob.allow.len(), 2);
        assert_eq!(ob.allow[0].host, "authz.example.com");
        assert_eq!(ob.allow[0].port, Some(8443));
        assert_eq!(ob.allow[0].scheme, SchemeKind::Https);
        assert_eq!(ob.allow[1].port, None); // defaulted at lowering time
        assert_eq!(ob.allow_private, vec!["10.1.0.0/16".to_string()]);
        assert_eq!(ob.connect_timeout_ms, Some(1500));
    }

    #[cfg(feature = "outbound-http")]
    #[test]
    fn outbound_validates_and_lowers_to_policy() {
        let m = Manifest::from_toml(OUTBOUND_TOML).unwrap();
        let entry = &m.filters[0];
        entry.validate().expect("valid outbound section");

        let opts = entry.load_options();
        let policy = opts.outbound.expect("outbound lowered into LoadOptions");
        assert_eq!(policy.allow.len(), 2);
        // exact allowlist matching + scheme default port
        assert!(policy.allows(plecto_host::Scheme::Https, "authz.example.com", 8443));
        assert!(policy.allows(plecto_host::Scheme::Https, "jwks.example.com", 443));
        assert!(!policy.allows(plecto_host::Scheme::Http, "authz.example.com", 8443));
        // allow_private opt-in reaches the SSRF classifier
        assert_eq!(
            policy.classify("10.1.2.3".parse().unwrap()),
            plecto_host::AddrVerdict::Allowed
        );
        assert_eq!(
            policy.classify("169.254.169.254".parse().unwrap()),
            plecto_host::AddrVerdict::BlockedReserved
        );
        // small value passes through; the connect timeout was 1500ms
        assert_eq!(
            policy.connect_timeout,
            std::time::Duration::from_millis(1500)
        );
    }

    #[cfg(feature = "outbound-http")]
    #[test]
    fn outbound_clamps_oversized_values() {
        let toml = r#"
[[filter]]
id = "x"
source = "s"
digest = "sha256:abc"
[filter.outbound]
allow = [{ host = "a.example.com" }]
total_timeout_ms = 999999999
max_concurrent = 100000
"#;
        let m = Manifest::from_toml(toml).unwrap();
        let policy = m.filters[0].load_options().outbound.unwrap();
        assert!(policy.total_timeout <= std::time::Duration::from_secs(30));
        assert!(policy.max_concurrent <= 64);
    }

    #[cfg(feature = "outbound-http")]
    #[test]
    fn outbound_rejects_bad_config() {
        let cases = [
            // empty allowlist
            ("allow = []", "empty allowlist"),
            // unparseable CIDR
            (
                "allow = [{ host = \"a\" }]\nallow_private = [\"not-a-cidr\"]",
                "bad CIDR",
            ),
            // zero timeout
            (
                "allow = [{ host = \"a\" }]\nconnect_timeout_ms = 0",
                "zero connect timeout",
            ),
        ];
        for (body, why) in cases {
            let toml = format!(
                "[[filter]]\nid = \"x\"\nsource = \"s\"\ndigest = \"sha256:abc\"\n[filter.outbound]\n{body}\n"
            );
            let m = Manifest::from_toml(&toml).unwrap();
            assert!(m.filters[0].validate().is_err(), "{why} must be rejected");
        }
    }

    #[cfg(not(feature = "outbound-http"))]
    #[test]
    fn outbound_rejected_without_feature() {
        // A manifest that asks for outbound must fail closed on a build that cannot provide it.
        let m = Manifest::from_toml(OUTBOUND_TOML).unwrap();
        assert!(
            m.filters[0].validate().is_err(),
            "outbound requires the outbound-http build"
        );
    }
}
