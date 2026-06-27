//! Builds the example `plecto:filter` guests and componentizes them, so the host's tests and the
//! server's examples can load real `plecto:filter` components (tdd-workflow Phase 0/1 fixtures).
//!
//! Target policy (ADR 000010): no-WASI header-only filters build for
//! `wasm32-unknown-unknown` and are wrapped into a component with `wit-component`
//! (no WASI adapter needed — the component imports ONLY granted plecto
//! capabilities). The body / stream<u8> / wasi:http increment moves to
//! `wasm32-wasip2` once wasmtime 46 ships.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let crates = manifest.parent().unwrap(); // plecto/crates
    let plecto = crates.parent().unwrap(); // plecto
    let wit = plecto.join("wit"); // plecto/wit
    // The example filter guests live OUTSIDE the workspace, under examples/filters/ (each its own
    // workspace), built here for wasm32 and componentized.
    let filters = plecto.join("examples").join("filters");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    println!("cargo:rerun-if-changed={}", wit.display());

    // Each guest crate → a componentized `plecto:filter`, exposed to `test_support` via an env var.
    // filter-hello is the conformance fixture; filter-apikey is the real-world example (auth gate).
    build_component(
        &cargo,
        &filters.join("filter-hello"),
        &out_dir,
        "filter_hello",
        "FILTER_HELLO_COMPONENT",
    );
    build_component(
        &cargo,
        &filters.join("filter-apikey"),
        &out_dir,
        "filter_apikey",
        "FILTER_APIKEY_COMPONENT",
    );
}

/// Build one guest crate for `wasm32-unknown-unknown`, wrap the core module into a Component (no
/// WASI adapter — it imports only granted plecto capabilities), and emit
/// `cargo:rustc-env=<env_var>=<path>` so `test_support` can read the component bytes. `stem` is the
/// crate's wasm output name (the crate name with `-` → `_`).
fn build_component(cargo: &str, guest: &Path, out_dir: &Path, stem: &str, env_var: &str) {
    println!("cargo:rerun-if-changed={}", guest.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        guest.join("Cargo.toml").display()
    );

    // 1) Build the guest core module (no WASI imports on this target).
    let target_dir = guest.join("target");
    let status = Command::new(cargo)
        .current_dir(guest)
        .env_remove("CARGO_TARGET_DIR")
        .args([
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--release",
            "--target-dir",
        ])
        .arg(&target_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn cargo to build {}: {e}", guest.display()));
    if !status.success() {
        panic!(
            "building {} for wasm32-unknown-unknown failed.\n\
             The usual cause is a missing WASM target. It is installed automatically by \
             plecto/rust-toolchain.toml; if you build outside that toolchain, run:\n    \
             rustup target add wasm32-unknown-unknown",
            guest.display()
        );
    }

    let core = target_dir.join(format!("wasm32-unknown-unknown/release/{stem}.wasm"));
    assert!(
        core.exists(),
        "guest core module not found at {}",
        core.display()
    );

    // 2) Wrap the core module into a Component (no adapter: imports only plecto).
    let core_bytes = std::fs::read(&core).expect("read guest core module");
    let component_bytes = wit_component::ComponentEncoder::default()
        .module(&core_bytes)
        .expect("ComponentEncoder::module")
        .validate(true)
        .encode()
        .unwrap_or_else(|e| panic!("encode {stem} component: {e}"));

    let component = out_dir.join(format!("{stem}.component.wasm"));
    std::fs::write(&component, &component_bytes).expect("write guest component");
    println!("cargo:rustc-env={env_var}={}", component.display());
}
