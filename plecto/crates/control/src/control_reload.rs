//! `Control`'s reload surface (ADR 000007 / 000008): atomically swap to a new manifest, or
//! re-read the on-disk manifest and reload if its `config version` changed. Split out from
//! `lib.rs` since this is the crate's most correctness-sensitive method group (trust-change
//! rejection, all-or-nothing swap) — its own file matches "where's the thing that does X".

use std::sync::Arc;

use crate::error::ControlError;
use crate::manifest::Manifest;
use crate::reload::ReloadOutcome;
use crate::{Control, build_active, read_manifest};

impl Control {
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
    pub(crate) fn ensure_trust_unchanged(&self, manifest: &Manifest) -> Result<(), ControlError> {
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
}
