//! Typed control-plane errors (bp-rust: domain errors are `thiserror` enums, not `anyhow`).
//! A caller can tell a config mistake (`ManifestParse`, `UnknownChainFilter`) apart from a
//! supply-chain failure (`DigestMismatch`, `Load`) — both are fail-closed, but distinguishable.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("manifest parse error: {0}")]
    ManifestParse(#[from] toml::de::Error),

    /// The manifest could not be canonicalised for content-hashing. Serialising our own
    /// derived types is infallible in practice; a typed variant keeps `content_hash`
    /// panic-free (bp-rust: no `expect` outside binary entry points).
    #[error("manifest serialisation failed: {0}")]
    ManifestSerialize(#[from] serde_json::Error),

    /// `reload_from_disk` was called on a `Control` built from an in-memory manifest (no
    /// backing path). Construct with `from_manifest_path` / `load_at` to enable disk reload.
    #[error("control plane has no manifest path on disk to reload from")]
    NoManifestPath,

    /// A reload's manifest changed the `[trust]` section. Trust roots are fixed at
    /// construction (same `Host`, same epoch ticker — ADR 000006 / 000008); a reload only
    /// swaps the filter set + chain, never the trust policy. Rejecting the change fail-closed
    /// (rather than silently ignoring it) keeps an operator from believing a key rotation took
    /// effect when it did not — rotate trust by restarting with the new manifest.
    #[error("manifest [trust] changed; trust roots are fixed at construction — restart to apply")]
    TrustChangeRequiresRestart,

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("trusted key error: {0}")]
    TrustKey(String),

    #[error("host initialisation failed: {0}")]
    HostInit(String),

    /// The artifact could not be resolved or was malformed (missing layer, bad layout, …).
    #[error("artifact {source_ref:?}: {reason}")]
    Artifact { source_ref: String, reason: String },

    /// The resolved artifact's content digest did not equal the manifest's pin (ADR 000007
    /// reproducibility / supply-chain integrity). Fail-closed.
    #[error(
        "content digest mismatch for {source_ref:?}: manifest pinned {expected}, artifact is {actual}"
    )]
    DigestMismatch {
        source_ref: String,
        expected: String,
        actual: String,
    },

    /// The host rejected the filter at the provenance/load gate (ADR 000006 signature/SBOM,
    /// or instantiation). Carries the host's `anyhow` error for its message.
    #[error("filter {id:?} failed the load gate: {err}")]
    Load { id: String, err: anyhow::Error },

    /// A filter entry carried an out-of-range metering / rate-limit value (e.g. a zero deadline,
    /// zero memory cap, or a rate-limit bucket that can never refill). Rejected fail-closed at
    /// build so a config typo cannot reach the host's metering arithmetic (CWE-20).
    #[error("filter {id:?} has invalid config: {reason}")]
    InvalidFilterConfig { id: String, reason: String },

    #[error("chain references unknown filter {0:?}")]
    UnknownChainFilter(String),

    #[error("duplicate filter id {0:?} in manifest")]
    DuplicateFilterId(String),

    #[error("duplicate upstream name {0:?} in manifest")]
    DuplicateUpstream(String),

    /// An upstream declared no `addresses` (ADR 000017). An upstream must have at least one
    /// instance to forward to; an empty list is fail-closed at build time, not at request time.
    #[error("upstream {0:?} has no addresses")]
    EmptyUpstreamAddresses(String),

    /// The upstream registry's lock was poisoned (a thread panicked while holding it). Surfaced
    /// rather than re-panicked so a reconcile fails closed (the running set stays live).
    #[error("upstream registry lock poisoned")]
    UpstreamRegistryPoisoned,

    #[error("route (prefix {path_prefix:?}) references unknown upstream {upstream:?}")]
    UnknownRouteUpstream {
        path_prefix: String,
        upstream: String,
    },

    #[error("route (prefix {path_prefix:?}) references unknown filter {filter:?}")]
    UnknownRouteFilter { path_prefix: String, filter: String },

    /// A route's native rate limit (ADR 000033) had an out-of-range value (`rate` or `burst` of
    /// zero — a bucket that can never serve a token). Rejected fail-closed at build, like the
    /// per-filter rate-limit validation, so a config typo cannot reach the limiter arithmetic.
    #[error("route (prefix {path_prefix:?}) has invalid rate_limit: {reason}")]
    InvalidRouteRateLimit { path_prefix: String, reason: String },

    /// A TLS cert/key file could not be read, parsed, or built into a usable certificate
    /// (ADR 000014). Fail-closed: a bad cert aborts the build, so reload never swaps in a TLS
    /// config that cannot serve. `host` is the SNI the entry was for (`None` = default cert).
    #[error("TLS cert for {host:?} ({path:?}): {reason}")]
    TlsCert {
        host: Option<String>,
        path: String,
        reason: String,
    },
}
