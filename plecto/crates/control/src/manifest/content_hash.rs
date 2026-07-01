//! The manifest's semantic content hash (ADR 000008 `config version`).

use sha2::{Digest, Sha256};

use super::Manifest;
use crate::error::ControlError;

impl Manifest {
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
