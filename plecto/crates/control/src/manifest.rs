//! The declarative manifest (ADR 000007 / 000008): the single, static source of truth for
//! which filters are loaded, pinned by OCI digest, with which trust roots, in what chain
//! order. TOML (mirrors Cargo; ADR 000008 static config). Routes are deferred until the
//! fast-path server exists; v0.1 has a single chain.

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
/// upstream's instances; the fast path round-robins across the healthy ones. Every upstream
/// carries an active-health-check policy (`health`) — required, because instances start
/// pessimistic (unhealthy) and only a passing probe puts one into rotation (ADR 000017).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    /// `host:port` of each backend instance (e.g. `["127.0.0.1:9000", "127.0.0.1:9001"]`). No
    /// scheme; plain HTTP/1.1. Must be non-empty (validated when the routing table is built).
    pub addresses: Vec<String>,
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

/// One routing rule (ADR 000013): match a request by host (optional) + path prefix, run an
/// inline chain of `filters`, and forward to `upstream`. `strip_prefix` is a **host-native**
/// path rewrite applied to the *forwarded* request only (the chain still sees the original
/// path) — the common reverse-proxy prefix-strip, without a `plecto:filter` contract change.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Match only this authority (case-insensitive, port ignored). `None` matches any host.
    #[serde(default)]
    pub host: Option<String>,
    /// Match requests whose path starts with this prefix (on a `/` boundary). Longest wins.
    pub path_prefix: String,
    /// This route's chain: filter ids run in order (may be empty for a pure pass-through route).
    #[serde(default)]
    pub filters: Vec<String>,
    /// The `[[upstream]]` `name` to forward a passing request to.
    pub upstream: String,
    /// If set and the forwarded path starts with it, strip it before forwarding to the upstream
    /// (host-native rewrite; the chain saw the original path). E.g. `/api` + `/api/x` → `/x`.
    #[serde(default)]
    pub strip_prefix: Option<String>,
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
host = "example.com"
path_prefix = "/api"
filters = ["auth"]
upstream = "api-svc"
strip_prefix = "/api"
"#,
        )
        .unwrap();

        assert_eq!(m.upstreams.len(), 1);
        assert_eq!(
            m.upstreams[0].addresses,
            vec!["127.0.0.1:9000".to_string(), "127.0.0.1:9001".to_string()]
        );
        // health is required; the unspecified knobs take their defaults
        assert_eq!(m.upstreams[0].health.path, "/healthz");
        assert_eq!(m.upstreams[0].health.interval_ms, 2000);
        assert_eq!(m.upstreams[0].health.timeout_ms, 1000);
        assert_eq!(m.upstreams[0].health.healthy_threshold, 2);
        assert_eq!(m.upstreams[0].health.unhealthy_threshold, 3);
        assert_eq!(m.routes.len(), 1);
        let r = &m.routes[0];
        assert_eq!(r.host.as_deref(), Some("example.com"));
        assert_eq!(r.path_prefix, "/api");
        assert_eq!(r.filters, vec!["auth".to_string()]);
        assert_eq!(r.upstream, "api-svc");
        assert_eq!(r.strip_prefix.as_deref(), Some("/api"));
        // a routing edit must flip the config version (routes ride the semantic hash)
        let mut m2 = m.clone();
        m2.routes[0].path_prefix = "/v2".to_string();
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
}
