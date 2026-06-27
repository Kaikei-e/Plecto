# Writing a filter

A **filter** is your request logic, running as a sandboxed WebAssembly component. Plecto's native
fast path handles connections, TLS, HTTP, routing, and load balancing; it hands each request to your
filter, which **inspects it and returns one typed decision**. This guide takes you from an empty
directory to a running filter.

New to the model? Read the [README](../README.md) first — the architecture, the three decisions, and
the trusted/untrusted execution split. This guide is the practical how-to.

## 1. The contract in one minute

A filter implements the `plecto:filter` world (see [`plecto/wit/world.wit`](../plecto/wit/world.wit)).
It exports four functions:

| Export | When it runs | Returns |
| --- | --- | --- |
| `init` | once per instance (heavy setup) | — |
| `on-request` | per request, on the headers | `continue` / `modified(edit)` / `short-circuit(response)` |
| `on-request-body` | per request, on the buffered body | `continue(body)` / `short-circuit(response)` |
| `on-response` | per response, on the headers | `continue` / `modified(edit)` |

A filter is **stateless**. Anything it must remember lives in host state, reached only through the
capabilities the host explicitly lends it — **deny-by-default**:

- `host-log` — structured logging.
- `host-clock` — a per-request millisecond clock snapshot (deterministic within a request).
- `host-kv` — per-filter key/value bytes (session, cache).
- `host-counter` — atomic named counters.
- `host-ratelimit` — a host-native token bucket; the filter passes only `(key, cost)`, never the spec.

Nothing else — no network, no filesystem, no sockets — is reachable. That is enforced by the
Component Model sandbox, not by convention.

## 2. Scaffold

Start from the template in [`plecto/examples/filters/filter-template/`](../plecto/examples/filters/filter-template/).
Either copy it or generate it:

```bash
# copy
cp -r plecto/examples/filters/filter-template my-filter

# …or with cargo-generate
cargo generate --git https://github.com/Kaikei-e/Plecto.git \
  examples/filters/filter-template --name my-filter
```

Then set the package `name` in `Cargo.toml` and edit `src/lib.rs`. The template implements the whole
world with a pass-through default; replace the body of `on_request` with your policy.

The contract is **vendored** in the template under `wit/`, and the binding macro references it
locally:

```rust
wit_bindgen::generate!({ path: "wit", world: "filter" });
```

That vendored copy is why a generated filter builds anywhere. Keeping it in sync with the canonical
`plecto/wit/world.wit` is your responsibility; inside this repo, `just sync-template-wit` refreshes it.

Because the contract is WIT, **any language that compiles to a WASM component can write a filter** —
see [section 7](#7-other-languages).

## 3. Build and componentize

A filter is built for `wasm32-unknown-unknown` (no WASI: it imports only the granted Plecto
capabilities, ADR 000010), then wrapped into a **component**:

```bash
cargo build --target wasm32-unknown-unknown --release
# core module → component (no WASI adapter needed):
wasm-tools component new \
  target/wasm32-unknown-unknown/release/my_filter.wasm -o my-filter.component.wasm
```

For the example filters **inside this repo**, this two-step is automatic:
[`plecto/crates/host/build.rs`](../plecto/crates/host/build.rs) builds each guest and runs the
`wit-component` encoder, so `cargo test --all` and the demos just work. For your own out-of-tree
filter, run the `wasm-tools component new` step yourself (or wire an equivalent into your build).

Verify what it imports and exports:

```bash
wasm-tools component wit my-filter.component.wasm
```

A correct filter imports only `plecto:filter/*` — no `wasi:*`, no network, no filesystem.

## 4. The manifest

The manifest is the static source of truth for which filters load, with which trust roots, in what
order, and how requests route to upstreams (ADR 000007 / 000008). It is TOML. A ready-to-edit copy
ships with the template ([`manifest.toml`](../plecto/examples/filters/filter-template/manifest.toml)).
The authoritative schema is [`plecto/crates/control/src/manifest.rs`](../plecto/crates/control/src/manifest.rs);
the field reference below mirrors it.

### `[trust]`

```toml
[trust]
keys = ["keys/signer.pub"]    # PEM public keys (manifest-relative) trusted to sign filters
```

Trust is fixed at construction — a reload that changes `[trust]` is rejected.

### `[[filter]]`

```toml
[[filter]]
id = "my-filter"               # required: host identity; namespaces this filter's KV (survives reload)
source = "artifacts/my-filter" # required: manifest-relative path to the local OCI image-layout
digest = "sha256:..."          # required: pinned OCI image-manifest digest
isolation = "untrusted"        # "untrusted" (default, fresh per request) | "trusted" (pooled, fast)
init_deadline_ms = 200         # optional: metering overrides; unset = host default
request_deadline_ms = 25       # optional
max_memory_bytes = 16777216    # optional
ratelimit = { capacity = 100, refill_tokens = 10, refill_interval_ms = 1000 }  # optional, ADR 000026
```

`isolation` is the biggest performance lever. `trusted` filters are built once and pooled (fast hot
path); `untrusted` filters run fresh per request with linear memory wiped each time (stronger
isolation, slower). The default is `untrusted` — fail-closed. `ratelimit`, when present, is the
**host-side** bucket spec for this filter's `host-ratelimit`; the operator owns it so an untrusted
filter cannot widen its own limit.

### `[[upstream]]`

```toml
[[upstream]]
name = "app"                          # required
addresses = ["127.0.0.1:9000", "127.0.0.1:9001"]  # required: host:port instances, round-robined
request_timeout_ms = 30000            # optional (default 30000; 0 disables — long-poll/streaming)
max_retries = 1                       # optional (default 1; 0 disables retry onto another instance)
[upstream.health]                     # required: instances start unhealthy, a probe admits them
path = "/healthz"                     # required
interval_ms = 2000                    # optional (default 2000)
timeout_ms = 1000                     # optional (default 1000)
healthy_threshold = 2                 # optional (default 2)
unhealthy_threshold = 3               # optional (default 3)
```

Every upstream **requires** a `[upstream.health]` block with at least `path`, because instances start
pessimistic and only a passing probe puts one into rotation (ADR 000017).

### `[[route]]`

```toml
[[route]]
path_prefix = "/api"     # required: match requests whose path starts here (longest prefix wins)
upstream = "app"         # required: the [[upstream]] name to forward a passing request to
filters = ["my-filter"]  # optional: filter ids run in order (empty = pure pass-through)
host = "example.com"     # optional: match only this authority (case-insensitive); omit = any host
strip_prefix = "/api"    # optional: strip this prefix before forwarding (the chain saw the original)
```

### `[[tls]]`

```toml
[[tls]]
cert_path = "certs/app.pem"   # required: PEM cert chain (manifest-relative)
key_path = "certs/app.key"    # required: PEM private key
host = "example.com"          # optional SNI host; omit = the default cert
```

With no `[[tls]]`, the fast path serves plain HTTP/1.1; one or more certs enable TLS termination
(rustls, ADR 000014). `[chain]` exists for the single-chain convenience API, but the fast-path server
uses `[[route]]`.

## 5. Package, sign, and run

Plecto loads filters from a local, digest-pinned OCI image-layout and **verifies a cosign signature**
plus an SBOM↔component binding before running them (ADR 000006 / 000007) — bad signature, refused,
fail-closed. The public key must be listed in `[trust]`.

The complete, worked pipeline is the [`wasm-auth` example](../plecto/examples/wasm-auth/main.rs): it
signs the component, writes the offline OCI layout, computes the digest, and starts a real proxy — all
in one runnable file. **Read it as your reference.** For production, sign with `cosign sign-blob`
using a key whose public half is in `[trust].keys`.

Streamlined packaging/signing tooling (`plecto`-side helpers) is on the roadmap (M6); today the
example is the canonical recipe.

## 6. Test it locally

The fastest way to see *your* filter run end to end is to adapt an example:

```bash
# run the bundled examples to see the shape of a working setup
just demo wasm-auth      # a signed auth filter, signed + packaged + served, with curl recipes
just demo filter-chain   # continue / modify / short-circuit / host-native rate limit
```

Then copy the example whose shape matches yours (e.g. `plecto/examples/wasm-auth/`), point it at your
component, and run it with `cargo run -p plecto-server --example ...`. The examples use
`plecto_host::test_support::TestSigner` to sign on the fly — that is a **test/example convenience**;
real deployments sign out of band with cosign and pin the digest in the manifest.

To exercise the contract without a full proxy, load the component into the host directly the way the
host's conformance tests do (see `plecto/crates/host/`), asserting on the typed decision your filter
returns.

## 7. Other languages

Because the contract is WIT, a filter can be written in any language that targets a WASM component —
Rust (this guide), Go (TinyGo), JavaScript/TypeScript (`jco`), or Python (`componentize-py`). The
Rust path is the supported one today; first-class polyglot SDKs and reference filters (auth, rate
limit, WAF) are on the [roadmap](../README.md#roadmap) (M6). The contract and the manifest are the
same regardless of language; only the binding toolchain differs.
