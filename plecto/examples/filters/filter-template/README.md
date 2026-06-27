# Plecto filter template

A minimal, self-contained starting point for a `plecto:filter`. The WIT contract is **vendored**
under [`wit/`](wit/), so this crate builds wherever you copy it — no relative path back into the
Plecto repo.

## Start a new filter

Either copy this directory:

```bash
cp -r plecto/examples/filters/filter-template my-filter
```

…or generate it with [`cargo generate`](https://github.com/cargo-generate/cargo-generate):

```bash
cargo generate --git https://github.com/Kaikei-e/Plecto.git \
  examples/filters/filter-template --name my-filter
```

Then set the package `name` in `Cargo.toml` and write your policy in `on_request` (and the body /
response hooks) in `src/lib.rs`.

## Build

```bash
cargo build --target wasm32-unknown-unknown --release
```

That produces a core WASM module; Plecto wraps it into a Component before loading it. The full
build, sign, package, and run walkthrough — plus the manifest field reference — is in
[`docs/writing-a-filter.md`](../../../../docs/writing-a-filter.md). A ready-to-edit
[`manifest.toml`](manifest.toml) is included here.

## Keep the vendored WIT current

The vendored [`wit/world.wit`](wit/world.wit) is a copy of the canonical `plecto/wit/world.wit`.
Inside this repo you can refresh it with `just sync-template-wit`.
