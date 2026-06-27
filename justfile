# Plecto task shortcuts — run from the repository root.
# The Rust workspace lives in plecto/; every recipe cd's there for you, so you never
# have to remember the working directory. `just` with no args lists all recipes.

plecto := "plecto"

# list available recipes
default:
    @just --list

# full local CI parity: fmt check + clippy (-D warnings) + tests — run before every PR
check: lint test

# run the test suite
test:
    cd {{plecto}} && cargo test --all

# format the workspace
fmt:
    cd {{plecto}} && cargo fmt --all

# check formatting without writing
fmt-check:
    cd {{plecto}} && cargo fmt --all -- --check

# clippy with warnings as errors
clippy:
    cd {{plecto}} && cargo clippy --all-targets --all-features -- -D warnings

# fmt check + clippy
lint: fmt-check clippy

# run a guided demo end to end: wasm-auth | load-balancing | filter-chain | tls-http | hot-reload
demo NAME:
    cd {{plecto}} && ./examples/try.sh {{NAME}}

# run every guided demo in turn
demo-all:
    cd {{plecto}} && ./examples/try.sh all

# run an example server directly (Ctrl-C to stop)
example NAME:
    cd {{plecto}} && cargo run -p plecto-server --example {{NAME}}

# build the example filter guests for wasm32-unknown-unknown
build-filters:
    cd {{plecto}}/examples/filters/filter-hello && cargo build --target wasm32-unknown-unknown --release
    cd {{plecto}}/examples/filters/filter-apikey && cargo build --target wasm32-unknown-unknown --release

# refresh the filter template's vendored WIT from the canonical contract (idempotent)
sync-template-wit:
    cp {{plecto}}/wit/world.wit {{plecto}}/examples/filters/filter-template/wit/world.wit
    @echo "synced filter-template/wit/world.wit from plecto/wit/world.wit"
