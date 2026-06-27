//! Offline OCI image-layout `ArtifactStore` (ADR 000007). Reads a local image-layout
//! directory — no registry, no network — per the CNCF Wasm OCI Artifact layout, verifies the
//! image-manifest digest against the manifest pin, and extracts the component plus its
//! bundled signature / SBOM layers (custom mediaTypes). Remote fetch (`wkg`) is an
//! out-of-band operator step that produces such a layout.
//!
//! Hand-rolled over `oci-spec` types + `sha2` (no openssl / tokio): the spec-correct types do
//! the structure; we own the sha256 digest verification we are fail-closed on anyway.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use oci_spec::image::{
    Descriptor, DescriptorBuilder, Digest, ImageIndex, ImageIndexBuilder, ImageManifest,
    ImageManifestBuilder, MediaType, OciLayoutBuilder,
};
use sha2::{Digest as _, Sha256};

use crate::artifact::{ArtifactStore, ResolvedArtifact};
use crate::error::ControlError;

const WASM_CONFIG_MT: &str = "application/vnd.wasm.config.v0+json";
const WASM_LAYER_MT: &str = "application/wasm";
const SIG_MT: &str = "application/vnd.plecto.signature";
const SBOM_MT: &str = "application/vnd.plecto.sbom";
const SBOM_SIG_MT: &str = "application/vnd.plecto.sbom.signature";

/// Sanity ceiling on any blob the loader reads (CWE-770): a wasm component plus its
/// signature / SBOM layers are well under this. Bounds the read so a malicious or oversized
/// layout cannot OOM the shared data-plane process before the digest check runs.
const MAX_BLOB_BYTES: u64 = 512 << 20; // 512 MiB
/// Cap on `index.json` — it carries a single image-manifest descriptor (a few KiB at most).
const MAX_INDEX_BYTES: u64 = 1 << 20; // 1 MiB

fn artifact_err(source_ref: &str, reason: impl Into<String>) -> ControlError {
    ControlError::Artifact {
        source_ref: source_ref.to_string(),
        reason: reason.into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// An `ArtifactStore` backed by local OCI image-layout directories under `root`. A manifest
/// `source` is a path (relative to `root`) to one image-layout directory.
pub struct OciLayoutStore {
    root: PathBuf,
}

impl OciLayoutStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ArtifactStore for OciLayoutStore {
    fn resolve(&self, source: &str, pinned_digest: &str) -> Result<ResolvedArtifact, ControlError> {
        read_layout(&self.root.join(source), source, pinned_digest)
    }
}

/// Read + verify one image-layout: pin-check the image-manifest digest, then extract and
/// digest-verify each bundled layer.
fn read_layout(
    layout: &Path,
    source: &str,
    pinned: &str,
) -> Result<ResolvedArtifact, ControlError> {
    let index_bytes = read_capped(&layout.join("index.json"), MAX_INDEX_BYTES, source)?;
    let index = ImageIndex::from_reader(index_bytes.as_slice())
        .map_err(|e| artifact_err(source, format!("read index.json: {e}")))?;
    let manifest_desc = index
        .manifests()
        .first()
        .ok_or_else(|| artifact_err(source, "index.json has no manifests"))?;

    // Content pinning (ADR 000007): the image-manifest digest must equal the manifest's pin.
    let actual = manifest_desc.digest().to_string();
    if actual != pinned {
        return Err(ControlError::DigestMismatch {
            source_ref: source.to_string(),
            expected: pinned.to_string(),
            actual,
        });
    }

    let manifest_bytes = read_blob(layout, manifest_desc, source)?;
    let manifest = ImageManifest::from_reader(manifest_bytes.as_slice())
        .map_err(|e| artifact_err(source, format!("parse image manifest: {e}")))?;

    let component = read_blob(
        layout,
        layer_by_media_type(&manifest, WASM_LAYER_MT, source)?,
        source,
    )?;
    let component_signature = read_blob(
        layout,
        layer_by_media_type(&manifest, SIG_MT, source)?,
        source,
    )?;
    let sbom = read_blob(
        layout,
        layer_by_media_type(&manifest, SBOM_MT, source)?,
        source,
    )?;
    let sbom_signature = read_blob(
        layout,
        layer_by_media_type(&manifest, SBOM_SIG_MT, source)?,
        source,
    )?;

    Ok(ResolvedArtifact {
        component,
        component_signature,
        sbom,
        sbom_signature,
    })
}

fn layer_by_media_type<'a>(
    manifest: &'a ImageManifest,
    media_type: &str,
    source: &str,
) -> Result<&'a Descriptor, ControlError> {
    manifest
        .layers()
        .iter()
        .find(|d| matches!(d.media_type(), MediaType::Other(s) if s == media_type))
        .ok_or_else(|| artifact_err(source, format!("missing layer of type {media_type}")))
}

/// Read a file with a hard byte ceiling, refusing symlinks (CWE-59) and anything over `max`
/// (CWE-770). Used for control-plane inputs whose on-disk size we do not trust.
fn read_capped(path: &Path, max: u64, source: &str) -> Result<Vec<u8>, ControlError> {
    use std::io::Read;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| artifact_err(source, format!("stat {}: {e}", path.display())))?;
    if meta.file_type().is_symlink() {
        return Err(artifact_err(
            source,
            format!("{} is a symlink (refused)", path.display()),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|e| artifact_err(source, format!("open {}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| artifact_err(source, format!("read {}: {e}", path.display())))?;
    if bytes.len() as u64 > max {
        return Err(artifact_err(
            source,
            format!("{} exceeds the {max}-byte cap", path.display()),
        ));
    }
    Ok(bytes)
}

/// Read a digest-addressed blob and verify its content hashes to the descriptor's digest. The
/// read is bounded by the descriptor's declared size and a sanity ceiling, symlinks are refused,
/// and the digest hex is validated as a path component before the `join`.
fn read_blob(layout: &Path, desc: &Descriptor, source: &str) -> Result<Vec<u8>, ControlError> {
    use std::io::Read;

    let digest = desc.digest().to_string(); // "sha256:<hex>"
    let (algo, hex) = digest
        .split_once(':')
        .ok_or_else(|| artifact_err(source, format!("malformed digest {digest}")))?;
    if algo != "sha256" {
        return Err(artifact_err(
            source,
            format!("unsupported digest algorithm {algo}"),
        ));
    }
    // Defense-in-depth (CWE-22): the hex becomes a filesystem path component, so verify it
    // is exactly 64 lowercase hex chars locally instead of relying solely on oci-spec's `Digest`
    // parser — a `..`/`/`-bearing digest can then never reach `Path::join`.
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(artifact_err(
            source,
            format!("invalid sha256 digest encoding {hex}"),
        ));
    }
    // The descriptor's declared size bounds the read; reject an over-ceiling blob up front.
    let declared = desc.size();
    if declared > MAX_BLOB_BYTES {
        return Err(artifact_err(
            source,
            format!("blob {hex} declared size {declared} exceeds the {MAX_BLOB_BYTES}-byte cap"),
        ));
    }
    let path = layout.join("blobs").join(algo).join(hex);
    // Refuse a symlinked blob (CWE-59): a layout pointing `blobs/sha256/<hex>` at `/dev/zero` or
    // any host file must not be followed and read unbounded.
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|e| artifact_err(source, format!("stat blob {hex}: {e}")))?;
    if meta.file_type().is_symlink() {
        return Err(artifact_err(
            source,
            format!("blob {hex} is a symlink (refused)"),
        ));
    }
    // Read at most `declared` bytes (+1 to detect an oversized file), so even a file swapped after
    // the stat cannot grow the buffer past the bound; the digest check below rejects any mismatch.
    let file = std::fs::File::open(&path)
        .map_err(|e| artifact_err(source, format!("open blob {hex}: {e}")))?;
    let mut bytes = Vec::new();
    file.take(declared + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| artifact_err(source, format!("read blob {hex}: {e}")))?;
    if bytes.len() as u64 != declared {
        return Err(artifact_err(
            source,
            format!(
                "blob {hex} size mismatch (declared {declared}, read {})",
                bytes.len()
            ),
        ));
    }
    let actual = sha256_hex(&bytes);
    if actual != hex {
        return Err(artifact_err(
            source,
            format!("blob {hex} content digest mismatch (computed {actual})"),
        ));
    }
    Ok(bytes)
}

/// Write a filter as an offline OCI image-layout under `layout` (the wasm component plus its
/// signature / SBOM bundled as custom-mediaType layers). Returns the `sha256:...`
/// image-manifest digest to pin it by in a manifest. Test / dev / tooling helper —
/// production artifacts come from `wkg` (out-of-band).
pub fn write_layout(layout: &Path, artifact: &ResolvedArtifact) -> Result<String, ControlError> {
    std::fs::create_dir_all(layout.join("blobs").join("sha256"))?;

    // oci-layout marker file.
    OciLayoutBuilder::default()
        .image_layout_version("1.0.0")
        .build()
        .map_err(|e| artifact_err("write", format!("build oci-layout: {e}")))?
        .to_file(layout.join("oci-layout"))
        .map_err(|e| artifact_err("write", format!("write oci-layout: {e}")))?;

    let config = write_blob(layout, b"{}", MediaType::Other(WASM_CONFIG_MT.to_string()))?;
    let layers = vec![
        write_blob(
            layout,
            &artifact.component,
            MediaType::Other(WASM_LAYER_MT.to_string()),
        )?,
        write_blob(
            layout,
            &artifact.component_signature,
            MediaType::Other(SIG_MT.to_string()),
        )?,
        write_blob(
            layout,
            &artifact.sbom,
            MediaType::Other(SBOM_MT.to_string()),
        )?,
        write_blob(
            layout,
            &artifact.sbom_signature,
            MediaType::Other(SBOM_SIG_MT.to_string()),
        )?,
    ];

    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(config)
        .layers(layers)
        .build()
        .map_err(|e| artifact_err("write", format!("build manifest: {e}")))?;

    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|e| artifact_err("write", format!("serialize manifest: {e}")))?;
    let manifest_desc = write_blob(layout, &manifest_bytes, MediaType::ImageManifest)?;

    let index = ImageIndexBuilder::default()
        .schema_version(2u32)
        .manifests(vec![manifest_desc.clone()])
        .build()
        .map_err(|e| artifact_err("write", format!("build index: {e}")))?;
    index
        .to_file(layout.join("index.json"))
        .map_err(|e| artifact_err("write", format!("write index.json: {e}")))?;

    Ok(manifest_desc.digest().to_string())
}

/// Hash `bytes`, write them to `blobs/sha256/<hex>`, and return a descriptor (digest + size +
/// mediaType) over them.
fn write_blob(
    layout: &Path,
    bytes: &[u8],
    media_type: MediaType,
) -> Result<Descriptor, ControlError> {
    let hex = sha256_hex(bytes);
    std::fs::write(layout.join("blobs").join("sha256").join(&hex), bytes)?;
    let digest = Digest::from_str(&format!("sha256:{hex}"))
        .map_err(|e| artifact_err("write", format!("build digest: {e}")))?;
    DescriptorBuilder::default()
        .media_type(media_type)
        .digest(digest)
        .size(bytes.len() as u64)
        .build()
        .map_err(|e| artifact_err("write", format!("build descriptor: {e}")))
}
