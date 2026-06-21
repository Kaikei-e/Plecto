//! E2E (tdd-workflow Phase 0) for the reload-trigger seam (ADR 000008: static declarative
//! config + hot reload). An operator edits the on-disk manifest and "pushes" a reload; the
//! control plane re-reads it and swaps the active set atomically. We drive the seam with a
//! fake `ReloadSource` (the real one is SIGHUP — process-global, not unit-testable) and an
//! in-memory artifact store paired with an on-disk manifest file.

use std::path::Path;

use plecto_control::{
    ChainOutcome, Control, ControlError, Host, HttpRequest, MemoryStore, ReloadOutcome,
    ReloadSource, ResolvedArtifact, serve_reloads,
};
use plecto_host::Header;
use plecto_host::test_support::{TestSigner, bound_sbom, filter_hello_component};
use tempfile::tempdir;

fn req(headers: &[(&str, &str)]) -> HttpRequest {
    HttpRequest {
        method: "GET".to_string(),
        path: "/".to_string(),
        authority: "example.test".to_string(),
        scheme: "https".to_string(),
        headers: headers
            .iter()
            .map(|(n, v)| Header {
                name: (*n).to_string(),
                value: (*v).to_string(),
            })
            .collect(),
    }
}

/// filter-hello signed with a fresh key (the host built from `signer` trusts it).
fn signed_filter_hello() -> (TestSigner, ResolvedArtifact) {
    let component = filter_hello_component();
    let signer = TestSigner::new().unwrap();
    let component_signature = signer.sign(&component).unwrap();
    let sbom = bound_sbom(&component);
    let sbom_signature = signer.sign(&sbom).unwrap();
    (
        signer,
        ResolvedArtifact {
            component,
            component_signature,
            sbom,
            sbom_signature,
        },
    )
}

/// A manifest naming filter `fh` (pinned at `digest`) with the given chain order.
fn manifest_toml(digest: &str, chain: &[&str]) -> String {
    let chain_list = chain
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"
[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "untrusted"

[chain]
filters = [{chain_list}]
"#
    )
}

/// A host trusting filter-hello, an in-memory store holding it, and the pinned digest.
fn setup() -> (Host, MemoryStore, String) {
    let (signer, artifact) = signed_filter_hello();
    let mut store = MemoryStore::new();
    let digest = store.insert("fh", artifact);
    let host = Host::new(signer.trust_policy().unwrap()).unwrap();
    (host, store, digest)
}

fn write_manifest(path: &Path, digest: &str, chain: &[&str]) {
    std::fs::write(path, manifest_toml(digest, chain)).unwrap();
}

/// A scripted reload trigger: yields `n` triggers then ends. Stands in for SIGHUP so the loop
/// is exercised deterministically without process-global signals.
struct FakeReloadSource {
    remaining: usize,
}

impl ReloadSource for FakeReloadSource {
    fn recv(&mut self) -> Option<()> {
        if self.remaining == 0 {
            None
        } else {
            self.remaining -= 1;
            Some(())
        }
    }
}

#[test]
fn reload_from_disk_swaps_on_change_and_is_idempotent() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("plecto.toml");
    let (host, store, digest) = setup();

    // v1: the filter is in the chain → a "block" request short-circuits.
    write_manifest(&manifest_path, &digest, &["fh"]);
    let control = Control::load_at(host, &manifest_path, Box::new(store)).unwrap();
    assert!(
        matches!(control.on_request(req(&[("x-plecto-block", "1")])), ChainOutcome::Respond(r) if r.status == 403),
        "v1 chain blocks"
    );

    // Operator edits the manifest: drop the filter from the chain. A reload picks it up.
    write_manifest(&manifest_path, &digest, &[]);
    match control.reload_from_disk().unwrap() {
        ReloadOutcome::Reloaded { hash } => assert!(hash.starts_with("sha256:")),
        ReloadOutcome::Unchanged => panic!("the manifest changed; reload must swap"),
    }
    assert!(
        matches!(
            control.on_request(req(&[("x-plecto-block", "1")])),
            ChainOutcome::Forward(_)
        ),
        "after reload the chain is empty → the same request forwards"
    );

    // No further edit → the reload is a no-op (same config version), no needless drain.
    assert_eq!(
        control.reload_from_disk().unwrap(),
        ReloadOutcome::Unchanged,
        "an unchanged manifest reloads to Unchanged"
    );
}

#[test]
fn serve_reloads_drives_reload_from_a_trigger() {
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("plecto.toml");
    let (host, store, digest) = setup();

    write_manifest(&manifest_path, &digest, &["fh"]);
    let control = Control::load_at(host, &manifest_path, Box::new(store)).unwrap();

    // Operator edits the file, then fires one trigger (a stand-in SIGHUP).
    write_manifest(&manifest_path, &digest, &[]);
    let mut source = FakeReloadSource { remaining: 1 };
    serve_reloads(&control, &mut source);

    assert!(
        matches!(
            control.on_request(req(&[("x-plecto-block", "1")])),
            ChainOutcome::Forward(_)
        ),
        "serve_reloads must have re-read the manifest and swapped the chain"
    );
}

#[test]
fn reload_rejecting_a_trust_change_is_fail_closed() {
    // f000004 #1: an edit to the manifest's [trust] section must NOT be silently dropped and
    // then reported as a successful reload. Trust roots are fixed at construction; a reload
    // swaps only filters + chain. The change is rejected fail-closed (no false "Reloaded").
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("plecto.toml");
    let (host, store, digest) = setup();

    let v1 = format!(
        r#"
[trust]
keys = ["a.pub"]

[[filter]]
id = "fh"
source = "fh"
digest = "{digest}"
isolation = "untrusted"

[chain]
filters = ["fh"]
"#
    );
    std::fs::write(&manifest_path, &v1).unwrap();
    let control = Control::load_at(host, &manifest_path, Box::new(store)).unwrap();

    // Operator rotates the declared key in the manifest and fires a reload.
    std::fs::write(&manifest_path, v1.replace("a.pub", "b.pub")).unwrap();
    match control.reload_from_disk() {
        Err(ControlError::TrustChangeRequiresRestart) => {}
        other => panic!("a [trust] edit must be rejected fail-closed, got {other:?}"),
    }

    // The running set is untouched — the rejected reload left config A live (still blocks).
    assert!(
        matches!(control.on_request(req(&[("x-plecto-block", "1")])), ChainOutcome::Respond(r) if r.status == 403),
        "the live set is unchanged after a rejected trust-change reload"
    );
}

#[test]
fn snapshot_pins_config_across_a_reload() {
    // f000004 #2: a request transaction takes one snapshot and runs both halves against it, so
    // a concurrent reload cannot desync the request/response sides. The snapshot keeps config A
    // even after the live set swaps to B.
    let dir = tempdir().unwrap();
    let manifest_path = dir.path().join("plecto.toml");
    let (host, store, digest) = setup();

    write_manifest(&manifest_path, &digest, &["fh"]); // v1 chain blocks
    let control = Control::load_at(host, &manifest_path, Box::new(store)).unwrap();

    let snap = control.snapshot();

    // Reload the live set to an empty chain (forwards) while `snap` is held.
    write_manifest(&manifest_path, &digest, &[]);
    assert!(matches!(
        control.reload_from_disk().unwrap(),
        ReloadOutcome::Reloaded { .. }
    ));

    // The pinned snapshot still sees config A (blocks); a fresh request sees config B (forwards).
    assert!(
        matches!(snap.on_request(req(&[("x-plecto-block", "1")])), ChainOutcome::Respond(r) if r.status == 403),
        "the snapshot stays pinned to the pre-reload config"
    );
    assert!(
        matches!(
            control.on_request(req(&[("x-plecto-block", "1")])),
            ChainOutcome::Forward(_)
        ),
        "a fresh request through Control sees the reloaded config"
    );
}

#[test]
fn reload_from_disk_without_a_path_errors() {
    // A plane built from an in-memory manifest (`load`) has no disk path to re-read.
    let (host, store, digest) = setup();
    let manifest = plecto_control::Manifest::from_toml(&manifest_toml(&digest, &["fh"])).unwrap();
    let control = Control::load(host, &manifest, Box::new(store)).unwrap();

    match control.reload_from_disk() {
        Err(ControlError::NoManifestPath) => {}
        other => panic!("expected NoManifestPath, got {other:?}"),
    }
}
