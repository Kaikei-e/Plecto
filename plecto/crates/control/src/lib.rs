//! plecto-control — the control plane (ADR 000007 / 000008).
//!
//! A single declarative TOML manifest pins filters by OCI digest and declares one chain. An
//! `ArtifactStore` resolves each filter from a local, offline OCI image-layout (remote
//! registry fetch via `wkg` is an out-of-band operator step, kept out of the runtime), the
//! `Host` loads it through the ADR 000006 provenance gate, and a chain dispatcher drives a
//! request through the loaded filters. `reload` rebuilds the set and swaps it **atomically**
//! (ArcSwap): new requests see the new set, in-flight holders keep the old one until it
//! drops. Single-node-first (ADR 000008).
//!
//! The trust policy lives on the `Host` and is fixed at construction; changing trust roots
//! requires a new `Control`. `reload` swaps only the filter set + chain (same `Host`, same
//! epoch ticker), so a runaway filter stays bounded across reloads.

mod artifact;
mod chain;
mod error;
mod manifest;
pub mod oci;
mod reload;
mod route;
mod snapshot;
mod tls;
mod upstream;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use plecto_host::{LoadedFilter, SignedArtifact};

pub use artifact::{ArtifactStore, MemoryStore, ResolvedArtifact};
pub use chain::{ChainOutcome, RequestBodyOutcome};
pub use error::ControlError;
pub use manifest::{
    Chain, CircuitBreaker, FilterEntry, HealthConfig, IsolationKind, Manifest, Observability,
    OutlierDetection, Route, TlsCert, Trust, Upstream,
};
#[cfg(unix)]
pub use reload::SignalReloadSource;
pub use reload::{ReloadOutcome, ReloadSource, serve_reloads};
pub use route::{RouteInfo, normalize_path};
/// The rustls TLS server config the fast path terminates with (ADR 000014), re-exported so
/// `plecto-server` names the same `rustls` type the control plane built.
pub use rustls::ServerConfig as TlsServerConfig;
pub use snapshot::ConfigSnapshot;
pub use upstream::{UpstreamGroup, UpstreamInstance, UpstreamRegistry};

// Re-export the host surface a caller drives the control plane with, so they need not depend
// on `plecto-host` directly for the common path — including the ADR 000009 observability
// types (build a `Host` with a sink, then drive snapshots that carry the trace context).
pub use plecto_host::{
    FanOutSink, FilterSpan, Header, Host, HttpRequest, HttpResponse, InMemorySink, MetricsSink,
    MetricsSnapshot, NoopSink, RequestTrace, SpanOutcome, TelemetrySink, TrustPolicy,
};

/// The atomically-swappable active configuration: the loaded filters, the chain order, and
/// the `content_hash` of the manifest that produced them. Held behind an `ArcSwap`; never
/// mutated in place — `reload` replaces it wholesale. The hash rides with the config it
/// describes so `reload_from_disk` can compare the running `config version` without a
/// separate lock.
pub(crate) struct ActiveConfig {
    pub(crate) filters: HashMap<String, Arc<LoadedFilter>>,
    pub(crate) chain: Vec<String>,
    /// Compiled routing table (ADR 000013): empty unless the manifest declares `[[route]]`.
    /// The fast-path server matches against these; the chain-only `on_request` ignores them.
    pub(crate) routes: Vec<route::CompiledRoute>,
    /// TLS server config built from `[[tls]]` (ADR 000014), or `None` for plain HTTP/1.1. Rides
    /// the `ArcSwap` with the rest, so a reload swaps certs atomically (new conns get new certs).
    pub(crate) tls: Option<Arc<rustls::ServerConfig>>,
    /// QUIC TLS server config for HTTP/3 (ADR 000016): ALPN `h3`, TLS 1.3, same SNI cert resolver
    /// as `tls`. `None` whenever `tls` is `None` (h3 requires TLS). Rides the same `ArcSwap`.
    pub(crate) quic_tls: Option<Arc<rustls::ServerConfig>>,
    pub(crate) hash: String,
}

/// The control plane: owns the `Host` (and thus the trust policy + epoch ticker) and the
/// artifact store, and holds the active filter set behind an `ArcSwap` for lock-free reads
/// and atomic reload. `manifest_path` is `Some` only when the plane was built from an on-disk
/// manifest — that is what `reload_from_disk` (and the SIGHUP loop) re-reads.
pub struct Control {
    host: Host,
    store: Box<dyn ArtifactStore>,
    active: ArcSwap<ActiveConfig>,
    /// The upstream instances + their health state (ADR 000017). Lives OUTSIDE `active` so a
    /// reload's `build_active` reconciles it in place — health state survives the swap. The
    /// fast-path server reads it both via routing (`RouteInfo.upstream`, resolved at build time)
    /// and via `upstream_groups` (the health-check supervisor).
    upstreams: Arc<UpstreamRegistry>,
    manifest_path: Option<PathBuf>,
    /// The `[trust]` section the `Host` was built from, captured at construction. A reload that
    /// would change it is rejected (`TrustChangeRequiresRestart`) rather than silently dropped
    /// (f000004 #1): trust roots are fixed for the life of the `Host` / epoch ticker.
    trust: Trust,
    /// Base directory the manifest's relative paths (filter `source`, TLS `cert_path`/`key_path`)
    /// resolve against (ADR 000014). Captured at construction so a reload re-reads certs from the
    /// same root. `"."` for the in-memory `load` core (tests use absolute cert paths).
    base_dir: PathBuf,
    /// Host-aggregated filter-execution metrics (ADR 000009): the `MetricsSink` wired into the
    /// `Host` at construction, snapshotted by the fast path's admin `/metrics` endpoint.
    filter_metrics: Arc<MetricsSink>,
    /// Operational observability config (`[observability]`, ADR 000009), captured at construction:
    /// the admin endpoint bind address and the access-log toggle. Not part of the config version.
    observability: Observability,
}

impl Control {
    /// Build a control plane entirely from a manifest and a base directory — the ops
    /// entrypoint. Reads the trusted-key PEMs (ADR 000006), constructs the `Host`, and
    /// resolves filters from offline OCI image-layouts under `base_dir` (ADR 000007). Every
    /// path in the manifest (`trust.keys`, each filter `source`) is resolved relative to
    /// `base_dir`. Remote fetch (`wkg`) is an out-of-band step that populates those layouts.
    pub fn from_manifest(manifest: &Manifest, base_dir: &Path) -> Result<Self, ControlError> {
        let (host, store, filter_metrics) = build_host_and_store(manifest, base_dir)?;
        let upstreams = Arc::new(UpstreamRegistry::new());
        let active = build_active(&host, manifest, &store, base_dir, &upstreams)?;
        Ok(Self {
            host,
            store: Box::new(store),
            active: ArcSwap::from_pointee(active),
            upstreams,
            manifest_path: None,
            trust: manifest.trust.clone(),
            base_dir: base_dir.to_path_buf(),
            filter_metrics,
            observability: manifest.observability.clone(),
        })
    }

    /// Build from a pre-constructed `Host` (carrying its `TrustPolicy`) and an artifact store
    /// — the testable core. Each manifest filter is resolved through `store` (digest pin),
    /// loaded through the host's ADR 000006 gate (signature + SBOM), and the chain order is
    /// validated against the loaded set. Any failure aborts the build (nothing is loaded
    /// half-way into a live set).
    pub fn load(
        host: Host,
        manifest: &Manifest,
        store: Box<dyn ArtifactStore>,
    ) -> Result<Self, ControlError> {
        // The in-memory core has no manifest directory; relative paths resolve against the cwd.
        // Tests that exercise `[[tls]]` use absolute cert paths, so this base does not bite them.
        let base_dir = Path::new(".");
        let upstreams = Arc::new(UpstreamRegistry::new());
        let active = build_active(&host, manifest, store.as_ref(), base_dir, &upstreams)?;
        Ok(Self {
            host,
            store,
            active: ArcSwap::from_pointee(active),
            upstreams,
            manifest_path: None,
            trust: manifest.trust.clone(),
            base_dir: base_dir.to_path_buf(),
            // The caller supplied the `Host`, so its sink is the caller's (or `NoopSink`); this
            // testable core keeps its own empty tally rather than reaching into that host.
            filter_metrics: Arc::new(MetricsSink::new()),
            observability: manifest.observability.clone(),
        })
    }

    /// Build the whole control plane from a single on-disk manifest file — the
    /// disk-reloadable ops entrypoint (ADR 000007 / 000008). Like `from_manifest`, but reads
    /// and *remembers* the manifest path so SIGHUP / `reload_from_disk` can pick up an
    /// operator's edits. Trusted-key PEMs and filter layouts resolve relative to the
    /// manifest's own directory.
    pub fn from_manifest_path(manifest_path: &Path) -> Result<Self, ControlError> {
        let base_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
        let manifest = read_manifest(manifest_path)?;
        let (host, store, filter_metrics) = build_host_and_store(&manifest, base_dir)?;
        let upstreams = Arc::new(UpstreamRegistry::new());
        let active = build_active(&host, &manifest, &store, base_dir, &upstreams)?;
        Ok(Self {
            host,
            store: Box::new(store),
            active: ArcSwap::from_pointee(active),
            upstreams,
            manifest_path: Some(manifest_path.to_path_buf()),
            trust: manifest.trust.clone(),
            base_dir: base_dir.to_path_buf(),
            filter_metrics,
            observability: manifest.observability.clone(),
        })
    }

    /// Like `load`, but the manifest lives on disk at `manifest_path`: the path is remembered
    /// so `reload_from_disk` can re-read it, while artifacts still resolve through the injected
    /// `store` (so a test can pair an on-disk manifest with an in-memory artifact store). The
    /// trust policy stays fixed on `host`.
    pub fn load_at(
        host: Host,
        manifest_path: &Path,
        store: Box<dyn ArtifactStore>,
    ) -> Result<Self, ControlError> {
        let base_dir = manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let manifest = read_manifest(manifest_path)?;
        let upstreams = Arc::new(UpstreamRegistry::new());
        let active = build_active(&host, &manifest, store.as_ref(), &base_dir, &upstreams)?;
        Ok(Self {
            host,
            store,
            active: ArcSwap::from_pointee(active),
            upstreams,
            manifest_path: Some(manifest_path.to_path_buf()),
            trust: manifest.trust.clone(),
            base_dir,
            filter_metrics: Arc::new(MetricsSink::new()),
            observability: manifest.observability.clone(),
        })
    }

    /// Atomically swap to a new manifest's filter set + chain (ADR 000007: build the new set
    /// fully, then switch in one store; the old set is drained as its `Arc` refs drop). If any
    /// filter fails to resolve / verify / load, the swap does **not** happen and the current
    /// set stays live — reload is all-or-nothing. The trust policy is fixed at construction.
    pub fn reload(&self, manifest: &Manifest) -> Result<(), ControlError> {
        self.ensure_trust_unchanged(manifest)?;
        let active = build_active(
            &self.host,
            manifest,
            self.store.as_ref(),
            &self.base_dir,
            &self.upstreams,
        )?;
        self.active.store(Arc::new(active));
        Ok(())
    }

    /// Reject a reload whose manifest changes the `[trust]` section (f000004 #1). Trust roots
    /// are fixed for the life of the `Host` / epoch ticker; an operator rotates them by
    /// restarting with the new manifest, not by reloading — otherwise a trust-only edit would
    /// flip the content hash and be reported as a successful reload while having no effect.
    fn ensure_trust_unchanged(&self, manifest: &Manifest) -> Result<(), ControlError> {
        if manifest.trust != self.trust {
            return Err(ControlError::TrustChangeRequiresRestart);
        }
        Ok(())
    }

    /// Re-read the on-disk manifest and reload if its `config version` changed. The trigger
    /// (SIGHUP, `serve_reloads`) is content-free, so this is where the new config is actually
    /// read. Idempotent: an unchanged manifest (same semantic `content_hash`) is a no-op —
    /// no rebuild, no drain. A changed one is built fully and swapped atomically; on any
    /// build failure the running set is left untouched (fail-closed) and the error returned.
    ///
    /// Errors with `NoManifestPath` if this plane was not built from an on-disk manifest
    /// (`load` / `from_manifest`); use `from_manifest_path` / `load_at` for a reloadable plane.
    pub fn reload_from_disk(&self) -> Result<ReloadOutcome, ControlError> {
        let path = self
            .manifest_path
            .as_ref()
            .ok_or(ControlError::NoManifestPath)?;
        let manifest = read_manifest(path)?;
        // A [trust] change is rejected before anything else: it must never be reported as a
        // successful reload (f000004 #1), even though it would flip the content hash below.
        self.ensure_trust_unchanged(&manifest)?;
        let new_hash = manifest.content_hash()?;
        // Cheap idempotency gate: skip the rebuild + drain entirely when the config version
        // is unchanged (a comment-only edit, or a spurious trigger).
        if new_hash == self.active.load().hash {
            return Ok(ReloadOutcome::Unchanged);
        }
        // Build the new set fully before swapping; on failure the running set is untouched.
        let active = build_active(
            &self.host,
            &manifest,
            self.store.as_ref(),
            &self.base_dir,
            &self.upstreams,
        )?;
        self.active.store(Arc::new(active));
        Ok(ReloadOutcome::Reloaded { hash: new_hash })
    }

    /// The active config's `content_hash` (ADR 000008 `config version`): the audit identity of
    /// what is loaded right now, and the unit a future opt-in consensus layer would agree on.
    pub fn config_version(&self) -> String {
        self.active.load().hash.clone()
    }

    /// A snapshot of the host-aggregated filter-execution metrics (ADR 000009): the tally the
    /// `MetricsSink` wired at construction has accumulated. The fast path's admin `/metrics`
    /// endpoint renders this alongside its native RED metrics.
    pub fn filter_metrics(&self) -> MetricsSnapshot {
        self.filter_metrics.snapshot()
    }

    /// The admin endpoint bind address (`[observability] admin_addr`), or `None` when no admin
    /// listener is configured (the default). The fast path binds a separate listener there for
    /// `/metrics` + liveness/readiness (ADR 000009 Stage A).
    pub fn admin_addr(&self) -> Option<&str> {
        self.observability.admin_addr.as_deref()
    }

    /// Whether the structured access log is enabled (`[observability] access_log`, ADR 000009).
    pub fn access_log_enabled(&self) -> bool {
        self.observability.access_log
    }

    /// The active TLS server config (ADR 000014), or `None` for plain HTTP/1.1. The fast-path
    /// server reads this per accepted connection, so a reload's new certs apply to new connections
    /// while in-flight ones keep the cert they negotiated with.
    pub fn tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.active.load().tls.clone()
    }

    /// The active QUIC TLS config for HTTP/3 (ADR 000016): ALPN `h3`, TLS 1.3, sharing the TCP
    /// config's SNI cert resolver. `None` whenever there is no `[[tls]]` (h3 requires TLS, so it is
    /// only offered alongside TLS termination). The fast-path server reads this once to decide
    /// whether to bind a QUIC listener and what to advertise via `Alt-Svc`.
    pub fn quic_tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.active.load().quic_tls.clone()
    }

    /// A snapshot of the current upstream groups (ADR 000017), for the fast-path server's
    /// health-check supervisor to probe. Reflects the latest reconcile, so a reload's added /
    /// removed instances are picked up on the supervisor's next tick without restarting it.
    pub fn upstream_groups(&self) -> Vec<Arc<UpstreamGroup>> {
        self.upstreams.groups()
    }

    /// Pin the active config for one request transaction (see [`ConfigSnapshot`]). The
    /// fast-path server takes one snapshot per request and drives both halves through it, so a
    /// concurrent reload cannot desync the request and response sides of the same transaction.
    pub fn snapshot(&self) -> ConfigSnapshot {
        self.snapshot_with_trace(RequestTrace::root())
    }

    /// Like [`Control::snapshot`], but continue an inbound trace context (ADR 000009): the
    /// fast-path server parses the request's W3C `traceparent` into a [`RequestTrace`] and
    /// passes it here, so the chain's spans join the caller's distributed trace instead of
    /// starting a fresh root.
    pub fn snapshot_with_trace(&self, trace: RequestTrace) -> ConfigSnapshot {
        ConfigSnapshot::new(self.active.load_full(), trace)
    }

    /// Drive a request through the chain. Returns whether to forward the (possibly edited)
    /// request upstream, or to respond now (a filter short-circuited, or the chain failed
    /// closed on a trap / deadline). Convenience for a one-shot caller; a request transaction
    /// that also runs a response should use [`Control::snapshot`] to pin one config.
    pub fn on_request(&self, request: HttpRequest) -> ChainOutcome {
        self.snapshot().on_request(request)
    }

    /// Drive a response back through the chain in reverse, applying response edits. A trapped
    /// filter yields a fail-closed 5xx. See [`Control::snapshot`] for the transaction-pinned form.
    pub fn on_response(&self, response: HttpResponse) -> HttpResponse {
        self.snapshot().on_response(response)
    }

    /// The ids currently loaded (for diagnostics / tests). Order is unspecified.
    pub fn loaded_ids(&self) -> Vec<String> {
        self.active.load().filters.keys().cloned().collect()
    }
}

/// Read + parse a manifest from disk (shared by the on-disk constructors and `reload_from_disk`).
fn read_manifest(path: &Path) -> Result<Manifest, ControlError> {
    let toml = std::fs::read_to_string(path)?;
    Manifest::from_toml(&toml)
}

/// Construct the `Host` (trust roots from the manifest's PEMs, ADR 000006) and the offline OCI
/// artifact store, both rooted at `base_dir`. Shared by `from_manifest` and `from_manifest_path`.
fn build_host_and_store(
    manifest: &Manifest,
    base_dir: &Path,
) -> Result<(Host, oci::OciLayoutStore, Arc<MetricsSink>), ControlError> {
    let mut pems: Vec<Vec<u8>> = Vec::with_capacity(manifest.trust.keys.len());
    for key_path in &manifest.trust.keys {
        pems.push(std::fs::read(base_dir.join(key_path))?);
    }
    let trust =
        TrustPolicy::from_pem_keys(&pems).map_err(|e| ControlError::TrustKey(e.to_string()))?;
    // Wire the host-aggregated filter metrics (ADR 000009): a `MetricsSink` tallies every filter
    // execution. Set BEFORE filters load (the sink is cloned into each at `load`), and retained on
    // `Control` so the fast path's admin endpoint can snapshot it. The default was `NoopSink`
    // (observability off) — this is the wiring that makes the M5 span/metrics stage observable.
    let filter_metrics = Arc::new(MetricsSink::new());
    let host = Host::new(trust)
        .map_err(|e| ControlError::HostInit(e.to_string()))?
        .with_telemetry_sink(filter_metrics.clone());
    let store = oci::OciLayoutStore::new(base_dir);
    Ok((host, store, filter_metrics))
}

/// Resolve + verify + load every manifest filter into a fresh `ActiveConfig`. Pure w.r.t. the
/// live set: it touches nothing until it fully succeeds, so a failed `reload` leaves the
/// running set untouched.
fn build_active(
    host: &Host,
    manifest: &Manifest,
    store: &dyn ArtifactStore,
    base_dir: &Path,
    registry: &UpstreamRegistry,
) -> Result<ActiveConfig, ControlError> {
    let mut filters: HashMap<String, Arc<LoadedFilter>> = HashMap::new();
    for entry in &manifest.filters {
        if filters.contains_key(&entry.id) {
            return Err(ControlError::DuplicateFilterId(entry.id.clone()));
        }
        // Reject out-of-range metering / rate-limit values before they reach the host.
        entry.validate()?;
        let artifact = store.resolve(&entry.source, &entry.digest)?;
        let signed = SignedArtifact {
            component_bytes: &artifact.component,
            component_signature: &artifact.component_signature,
            sbom: &artifact.sbom,
            sbom_signature: &artifact.sbom_signature,
        };
        let loaded = host
            .load(&entry.id, &signed, entry.load_options())
            .map_err(|err| ControlError::Load {
                id: entry.id.clone(),
                err,
            })?;
        filters.insert(entry.id.clone(), Arc::new(loaded));
    }
    for id in &manifest.chain.filters {
        if !filters.contains_key(id) {
            return Err(ControlError::UnknownChainFilter(id.clone()));
        }
    }

    // Routing table (ADR 000013 / 000017). Validate every route reference (upstream name, filter
    // ids) PURELY first — before the persistent upstream registry is mutated — so a manifest we'd
    // reject never reconciles the registry (reload stays all-or-nothing; the running upstream
    // health state is untouched on a failed reload).
    let upstream_names: HashSet<&str> =
        manifest.upstreams.iter().map(|u| u.name.as_str()).collect();
    for r in &manifest.routes {
        if !upstream_names.contains(r.upstream.as_str()) {
            return Err(ControlError::UnknownRouteUpstream {
                path_prefix: r.path_prefix.clone(),
                upstream: r.upstream.clone(),
            });
        }
        for f in &r.filters {
            if !filters.contains_key(f) {
                return Err(ControlError::UnknownRouteFilter {
                    path_prefix: r.path_prefix.clone(),
                    filter: f.clone(),
                });
            }
        }
    }

    // TLS termination config (ADR 000014 TCP / ADR 000016 QUIC): build the rustls ServerConfigs
    // from `[[tls]]`, sharing one SNI cert resolver. A bad cert is fail-closed here, so a failed
    // reload never swaps in a TLS config that cannot serve. Built before the registry is touched.
    let (tls, quic_tls) = match tls::build_server_configs(&manifest.tls, base_dir)? {
        Some(configs) => (Some(configs.tcp), Some(configs.quic)),
        None => (None, None),
    };

    // Compute the content hash BEFORE the registry reconcile (review f000005 P3#8). `reconcile`
    // is the step that MUTATES persistent state (the health registry, which survives reloads), so
    // every other fallible step — including this hash — must run before it for the "after reconcile
    // the build is infallible" / all-or-nothing invariant to hold literally, not just in practice.
    let hash = manifest.content_hash()?;

    // Reconcile the upstream registry LAST among the fallible steps (ADR 000017): this validates
    // duplicate names / empty address lists and preserves health for unchanged `(name, address)`
    // instances across the reload. After it returns Ok the build is infallible, so a rejected
    // reload never leaves the registry reconciled to a manifest whose `active` was not swapped in.
    registry.reconcile(&manifest.upstreams)?;
    let mut routes = Vec::with_capacity(manifest.routes.len());
    for r in &manifest.routes {
        // present: the name was validated above and reconcile built a group for each manifest
        // upstream. Fall back to the error (unreachable) rather than panic (data-plane no-panic).
        let Some(upstream) = registry.group(&r.upstream) else {
            return Err(ControlError::UnknownRouteUpstream {
                path_prefix: r.path_prefix.clone(),
                upstream: r.upstream.clone(),
            });
        };
        routes.push(route::CompiledRoute {
            host: r.host.as_ref().map(|h| h.to_ascii_lowercase()),
            path_prefix: r.path_prefix.clone(),
            filters: r.filters.clone(),
            upstream,
            strip_prefix: r.strip_prefix.clone(),
        });
    }

    Ok(ActiveConfig {
        filters,
        chain: manifest.chain.filters.clone(),
        routes,
        tls,
        quic_tls,
        hash,
    })
}
