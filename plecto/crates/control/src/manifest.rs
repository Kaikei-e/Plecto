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
    #[serde(default)]
    pub chain: Chain,
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
        opts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
