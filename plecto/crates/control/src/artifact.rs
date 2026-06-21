//! Resolving a manifest `source` into the bytes to load, verifying the content-digest pin
//! (ADR 000007). `ArtifactStore` is the seam (cf. host's `KvBackend`): the offline OCI
//! image-layout reader (`oci::OciLayoutStore`) and a future remote/wkg fetcher plug in here
//! without touching the manifest / chain / reload logic. `MemoryStore` is the reference /
//! test store.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::error::ControlError;

/// The verified bytes a filter loads from: the component plus its cosign signature, and the
/// (mandatory) SBOM plus its signature (ADR 000006). Produced after the digest-pin check.
#[derive(Debug, Clone)]
pub struct ResolvedArtifact {
    pub component: Vec<u8>,
    pub component_signature: Vec<u8>,
    pub sbom: Vec<u8>,
    pub sbom_signature: Vec<u8>,
}

/// Resolves a manifest `source` into a `ResolvedArtifact`, verifying that the artifact's
/// content digest equals `pinned_digest` (`sha256:...`). Implementations are fail-closed on
/// any mismatch or malformed artifact.
pub trait ArtifactStore: Send + Sync {
    fn resolve(&self, source: &str, pinned_digest: &str) -> Result<ResolvedArtifact, ControlError>;
}

/// `sha256:<hex>` over `bytes` — the OCI content-digest form.
pub(crate) fn sha256_pinned(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// An in-memory `ArtifactStore` keyed by source name — the reference / test store. Its
/// content digest is `sha256` over the **component bytes**, so the pin mechanism is exercised
/// without an on-disk OCI layout.
///
/// Note the pin semantics differ from the real store (f000004 #5): `OciLayoutStore` pins the
/// OCI **image-manifest** digest (the Merkle root over all layers), whereas this store pins
/// the component digest directly. The `digest` a manifest carries therefore means different
/// things across stores — a deliberate test simplification, not a portable pin. The offline
/// `OciLayoutStore` is the real one; production manifests pin image-manifest digests.
#[derive(Default)]
pub struct MemoryStore {
    artifacts: HashMap<String, ResolvedArtifact>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an artifact under `source`; returns the `sha256:...` digest to pin it by in a
    /// manifest.
    pub fn insert(&mut self, source: impl Into<String>, artifact: ResolvedArtifact) -> String {
        let digest = sha256_pinned(&artifact.component);
        self.artifacts.insert(source.into(), artifact);
        digest
    }
}

impl ArtifactStore for MemoryStore {
    fn resolve(&self, source: &str, pinned_digest: &str) -> Result<ResolvedArtifact, ControlError> {
        let artifact = self
            .artifacts
            .get(source)
            .ok_or_else(|| ControlError::Artifact {
                source_ref: source.to_string(),
                reason: "not found in store".to_string(),
            })?;
        let actual = sha256_pinned(&artifact.component);
        if actual != pinned_digest {
            return Err(ControlError::DigestMismatch {
                source_ref: source.to_string(),
                expected: pinned_digest.to_string(),
                actual,
            });
        }
        Ok(artifact.clone())
    }
}
