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
mod snapshot;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use plecto_host::{LoadedFilter, SignedArtifact};

pub use artifact::{ArtifactStore, MemoryStore, ResolvedArtifact};
pub use chain::ChainOutcome;
pub use error::ControlError;
pub use manifest::{Chain, FilterEntry, IsolationKind, Manifest, Trust};
#[cfg(unix)]
pub use reload::SignalReloadSource;
pub use reload::{ReloadOutcome, ReloadSource, serve_reloads};
pub use snapshot::ConfigSnapshot;

// Re-export the host surface a caller drives the control plane with, so they need not depend
// on `plecto-host` directly for the common path — including the ADR 000009 observability
// types (build a `Host` with a sink, then drive snapshots that carry the trace context).
pub use plecto_host::{
    FanOutSink, FilterSpan, Host, HttpRequest, HttpResponse, InMemorySink, MetricsSink,
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
    manifest_path: Option<PathBuf>,
    /// The `[trust]` section the `Host` was built from, captured at construction. A reload that
    /// would change it is rejected (`TrustChangeRequiresRestart`) rather than silently dropped
    /// (f000004 #1): trust roots are fixed for the life of the `Host` / epoch ticker.
    trust: Trust,
}

impl Control {
    /// Build a control plane entirely from a manifest and a base directory — the ops
    /// entrypoint. Reads the trusted-key PEMs (ADR 000006), constructs the `Host`, and
    /// resolves filters from offline OCI image-layouts under `base_dir` (ADR 000007). Every
    /// path in the manifest (`trust.keys`, each filter `source`) is resolved relative to
    /// `base_dir`. Remote fetch (`wkg`) is an out-of-band step that populates those layouts.
    pub fn from_manifest(manifest: &Manifest, base_dir: &Path) -> Result<Self, ControlError> {
        let (host, store) = build_host_and_store(manifest, base_dir)?;
        Self::load(host, manifest, Box::new(store))
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
        let active = build_active(&host, manifest, store.as_ref())?;
        Ok(Self {
            host,
            store,
            active: ArcSwap::from_pointee(active),
            manifest_path: None,
            trust: manifest.trust.clone(),
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
        let (host, store) = build_host_and_store(&manifest, base_dir)?;
        let active = build_active(&host, &manifest, &store)?;
        Ok(Self {
            host,
            store: Box::new(store),
            active: ArcSwap::from_pointee(active),
            manifest_path: Some(manifest_path.to_path_buf()),
            trust: manifest.trust.clone(),
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
        let manifest = read_manifest(manifest_path)?;
        let active = build_active(&host, &manifest, store.as_ref())?;
        Ok(Self {
            host,
            store,
            active: ArcSwap::from_pointee(active),
            manifest_path: Some(manifest_path.to_path_buf()),
            trust: manifest.trust.clone(),
        })
    }

    /// Atomically swap to a new manifest's filter set + chain (ADR 000007: build the new set
    /// fully, then switch in one store; the old set is drained as its `Arc` refs drop). If any
    /// filter fails to resolve / verify / load, the swap does **not** happen and the current
    /// set stays live — reload is all-or-nothing. The trust policy is fixed at construction.
    pub fn reload(&self, manifest: &Manifest) -> Result<(), ControlError> {
        self.ensure_trust_unchanged(manifest)?;
        let active = build_active(&self.host, manifest, self.store.as_ref())?;
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
        let active = build_active(&self.host, &manifest, self.store.as_ref())?;
        self.active.store(Arc::new(active));
        Ok(ReloadOutcome::Reloaded { hash: new_hash })
    }

    /// The active config's `content_hash` (ADR 000008 `config version`): the audit identity of
    /// what is loaded right now, and the unit a future opt-in consensus layer would agree on.
    pub fn config_version(&self) -> String {
        self.active.load().hash.clone()
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
) -> Result<(Host, oci::OciLayoutStore), ControlError> {
    let mut pems: Vec<Vec<u8>> = Vec::with_capacity(manifest.trust.keys.len());
    for key_path in &manifest.trust.keys {
        pems.push(std::fs::read(base_dir.join(key_path))?);
    }
    let trust =
        TrustPolicy::from_pem_keys(&pems).map_err(|e| ControlError::TrustKey(e.to_string()))?;
    let host = Host::new(trust).map_err(|e| ControlError::HostInit(e.to_string()))?;
    let store = oci::OciLayoutStore::new(base_dir);
    Ok((host, store))
}

/// Resolve + verify + load every manifest filter into a fresh `ActiveConfig`. Pure w.r.t. the
/// live set: it touches nothing until it fully succeeds, so a failed `reload` leaves the
/// running set untouched.
fn build_active(
    host: &Host,
    manifest: &Manifest,
    store: &dyn ArtifactStore,
) -> Result<ActiveConfig, ControlError> {
    let mut filters: HashMap<String, Arc<LoadedFilter>> = HashMap::new();
    for entry in &manifest.filters {
        if filters.contains_key(&entry.id) {
            return Err(ControlError::DuplicateFilterId(entry.id.clone()));
        }
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
    Ok(ActiveConfig {
        filters,
        chain: manifest.chain.filters.clone(),
        hash: manifest.content_hash()?,
    })
}
