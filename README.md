<div align="center">

# Plecto

**A self-hostable, programmable L7 reverse proxy & API gateway — in Rust, extended with WebAssembly.**

[![CI](https://github.com/Kaikei-e/Plecto/actions/workflows/ci.yml/badge.svg)](https://github.com/Kaikei-e/Plecto/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust edition 2024](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://doc.rust-lang.org/edition-guide/)
[![Status: early development](https://img.shields.io/badge/status-early%20development-yellow.svg)](#roadmap)

English · [日本語](README.ja.md)

</div>

---

Plecto pairs **two complementary halves** through a typed [WIT](https://component-model.bytecodealliance.org/) contract:

- a **fast path** in native Rust — connection handling, TLS termination, HTTP/1.1·2·3, routing, load balancing, and upstream management;
- an **extension plane** of **WebAssembly Component Model filters** — the per-request *decisions* (auth, header/body rewriting, rate limiting, WAF, policy) that you write in **any language**, plug in over the `plecto:filter` contract, and **hot-swap with zero downtime**.

The speed-critical path stays native Rust. Your request logic runs as a sandboxed WASM component that can touch **only** the capabilities the host explicitly lends it — enforced by the sandbox, not by convention.

> [!WARNING]
> **Status: early development.** The design is settled (17 ADRs) and the foundation now runs end to end: the `plecto:filter` contract, a wasmtime host that loads and runs filters, **and a real fast path** that terminates **HTTP/1.1, HTTP/2 (ALPN) and HTTP/3 (QUIC)**, terminates TLS, routes by host + path prefix, and **load-balances across healthy upstream instances** (round-robin + active/passive health checks). The full test suite is green and on CI. This is a foundation you can read, run, and build filters against. See the [Roadmap](#roadmap).

## Why Plecto?

Every gateway eventually faces the same question: **where does custom logic go?** The classic answers each involve trade-offs:

| Approach | In-process speed | Sandboxed | Any language | Hot-swap |
| --- | :---: | :---: | :---: | :---: |
| Config / DSL | ✅ | ✅ | ❌ | ✅ |
| Recompile into the binary | ✅ | ❌ | ❌ | ❌ |
| Out-of-process (`ext_proc`, sidecar) | ❌ | ✅ | ✅ | ✅ |
| **WASM filters — Plecto** | ✅ | ✅ | ✅ | ✅ |

Running data-plane filters as WASM is an idea **Envoy and proxy-wasm pioneered and proved** over the better part of a decade — Plecto owes them the core insight. proxy-wasm targets the earlier WASM ABI (v0.2.1); since then the **Component Model and WIT** have matured into a typed, polyglot, composable foundation, and Plecto explores what a gateway looks like when it is built natively on them. High-performance Rust proxies such as **Cloudflare's Pingora** likewise show how fast a native data path can be. Plecto's particular focus is **pairing that native speed with a Component-Model extension plane** — for teams who want to self-host and keep their traffic and secrets on their own infrastructure, with **data sovereignty** as a first principle.

See [ADR 000001](docs/ADR/000001.md) for the full rationale and rejected alternatives.

## Design tenets

> Safety × portability × self-hostability × operational simplicity **＞** feature breadth × broad privilege × distributed-by-default.

- **Deny-by-default capabilities** — a filter can reach nothing but the host-API explicitly lent to it (KV, counter, metrics, log, clock, random). No outbound network, filesystem, or sockets unless granted. Enforced by the Component Model sandbox.
- **Decisions are typed** — a filter returns a `decision` variant: `continue` / `modified` / `short-circuit`. Never an ambiguous flag or an implicit side effect.
- **Init vs per-request** — expensive setup (regex compile, schema build) goes in an `init` hook; the per-request hot path stays lean.
- **Filters are stateless** — rate-limit, session, and cache state live in host KV, so filters pool, scale, and hot-swap cleanly.
- **Fail-closed** — a filter trap or deadline overrun never silently passes traffic through.
- **Single-node first** — one node completes the job; distribution (membership, config consensus) is opt-in.
- **No panics in the data plane** — a single bad request must never take down a worker.

## Architecture

```
            ┌────────────────────────── fast path (native Rust) ──────────────────────────┐
client ───▶ │ accept · TLS · HTTP/1.1·2·3 · routing · LB · upstream conn mgmt · hot-reload │ ───▶ upstream
            └───────────────┬───────────────────────────────────────────────┬─────────────┘
                            │  request chain                    response chain │
                            ▼  (WIT: plecto:filter)             (reverse)       ▲
            ┌──────────── extension plane (WASM Component Model filters) ───────────────┐
            │  per filter: init hook (heavy, once) + per-request hook (hot)             │
            │  returns a decision: continue | modified | short-circuit                  │
            │  touches ONLY the host-API the host lent it (deny-by-default capability)   │
            └───────────────────────────────────────────────────────────────────────────┘
                                         │ host-API (KV / counter / metrics / log / clock / random)
                                         ▼
                              host-held state: redb (KV / rate-limit / cache)
```

**Rule of thumb:** user-specific logic / policy / WAF / auth / rewrite → a WASM filter; TLS / routing / LB / connection pools / global counters → native Rust. The WASM "tax" (data copy + host-call overhead) is charged only to request-decision logic, never to the speed path.

## The filter contract

The heart of Plecto is the `plecto:filter` WIT world — a custom world that defines Plecto's own vocabulary (the typed `decision`, init/per-request hooks, the deny-by-default host-API) while reusing standard types for polyglot compatibility.

```wit
package plecto:filter@0.1.0;

interface types {
  // The typed outcome of a request-side filter. Never a bare flag.
  variant request-decision {
    %continue,                       // pass unchanged to the next filter
    modified(request-edit),          // apply the edit, then continue
    short-circuit(http-response),    // stop the chain; synthesise a response now
  }
}

// deny-by-default: one capability per interface; a filter imports only what it is lent.
interface host-kv      { get: func(key: string) -> option<list<u8>>; set: func(key: string, value: list<u8>); /* … */ }
interface host-counter { increment: func(key: string, delta: s64) -> s64; /* atomic named counter */ }
interface host-log     { log: func(level: level, message: string); }
// host-ratelimit keeps the token bucket host-native — the hot-path refill/counting never crosses
// the WASM boundary; the filter only decides to consult it and on what key (ADR 000005).

world filter {
  // granted capabilities only — log · clock · kv · counter · rate-limit
  import host-log;  import host-clock;  import host-kv;  import host-counter;  import host-ratelimit;
  export init: func();                                       // heavy, once per instance
  export on-request:  func(req: http-request)  -> request-decision;   // hot path
  export on-response: func(resp: http-response) -> response-decision;  // hot path
}
```

> v0.1.0 is intentionally **sync + header-only** on the stable wasmtime 45 toolchain. `stream<u8>` bodies, async hooks, and `wasi:http` type reuse arrive with wasmtime 46 — see [ADR 000003](docs/ADR/000003.md) / [ADR 000010](docs/ADR/000010.md).

## Writing a filter

A filter is just a component that implements the world. Here is the included example (`crates/filter-hello`), in Rust:

```rust
wit_bindgen::generate!({ path: "../../wit", world: "filter" });

struct FilterHello;

impl Guest for FilterHello {
    fn init() {}

    fn on_request(req: HttpRequest) -> RequestDecision {
        host_log::log(host_log::Level::Info, "filter-hello: on-request");
        if req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("x-plecto-block")) {
            RequestDecision::ShortCircuit(HttpResponse { status: 403, /* … */ })
        } else {
            RequestDecision::Continue
        }
    }

    fn on_response(_: HttpResponse) -> ResponseDecision { ResponseDecision::Continue }
}

export!(FilterHello);
```

Because the contract is WIT, **any language that compiles to a WASM component can write a filter** — Rust, Go (TinyGo), JavaScript/TypeScript (`jco`), or Python (`componentize-py`). Polyglot filter SDKs are on the [roadmap](#roadmap).

## Try it

```bash
# Prerequisites: Rust 1.96+ (edition 2024) and the wasm32-unknown-unknown target.
rustup target add wasm32-unknown-unknown

# Build and test everything. The host build script compiles the example filter to a
# WASM component and the tests load it into the wasmtime host and exercise the contract.
cd plecto
cargo test --all
```

The suite proves the slice end-to-end: a request flows through the host into a real filter component, the typed `decision` round-trips, and the filter reaches **only** the capabilities it was lent (the example component imports `plecto:filter/*` and nothing else — zero WASI, network, or filesystem access).

### Run the demos

Five self-contained, use-case-focused examples live under `examples/<name>/`. Each wires the **production load path** (sign + offline OCI layout + verify + load, all fail-closed), starts a tiny upstream, serves a real proxy, and prints copy-paste `curl` commands on startup. Run one with:

```bash
cd plecto
cargo run -p plecto-server --example <name>   # Ctrl-C to stop
```

Or take a guided tour: `./examples/try.sh <name>` (or `all`) starts the example, waits for it, runs the `curl` commands, visualizes the output, and cleans up — no manual orchestration.

| `<name>` | What it shows |
| --- | --- |
| `wasm-auth` | **A real WASM filter doing real work** — a signed API-key auth component (`crates/filter-apikey`) that 401s without a valid key, stamps the caller's identity, and counts per-user requests in host KV. The point of Plecto. |
| `load-balancing` | One upstream over three instances: round-robin across the healthy set, active health probes, ejection when an instance goes unhealthy, and 503 when none are left (ADR 000017). |
| `filter-chain` | The filter chain over plain HTTP: continue / modify (header rewrite) / short-circuit 403 / host-native rate limit. |
| `tls-http` | TLS termination with HTTP/1.1, HTTP/2 (ALPN) and HTTP/3 (QUIC) on one port, plus `Alt-Svc` h3 advertisement. |
| `hot-reload` | Edit the manifest, `kill -HUP <pid>`, and watch the config swap atomically with zero downtime (a broken edit is fail-closed). |

Read `wasm-auth` first: it shows custom request logic running as a sandboxed component that can touch only the host-API it was lent — cosign-style signature + SBOM verification, the typed `decision`, and host-held state, end to end.

## Roadmap

Plecto is built ADR-first; each milestone realizes specific design decisions in `docs/ADR/`.

- **M0 — Foundation** ✅ *(done)*
  The `plecto:filter@0.1.0` contract, a wasmtime host that loads & runs filters, a deny-by-default capability boundary (log / clock / kv), an example filter, E2E/conformance/unit tests, and CI. — [ADR 1](docs/ADR/000001.md) · [2](docs/ADR/000002.md) · [10](docs/ADR/000010.md)
- **M1 — Filter runtime hardening** ✅ *(landed)*
  The trust-branched runtime — `InstancePre`; trusted filters reuse instances from a fixed-capacity, lazily-filled **pool** checked out per request (so the pooling engine finally earns its keep; saturation waits a bounded time then fails closed, a pool-wide circuit breaker trips on a deterministically-trapping filter, and an instance is recycled after N requests to bound state accumulation), untrusted = fresh-per-request on an on-demand engine (linear memory fresh by construction, so no zeroization needed); redb-backed host KV + atomic counters + **host-native token-bucket rate limiting**; every host-API key namespaced per filter; ephemeral hot-path state skips the per-commit fsync; **epoch metering + memory/table limits** are in place. The trusted/untrusted split is *forced* (not just perf) by the init/zeroization knot. **Deferred to M2** (coupled to the fast-path server): binding the pool to the tokio/quinn data path (sync↔async bridge) and state-backend sharding. — [ADR 4](docs/ADR/000004.md) · [5](docs/ADR/000005.md) · [6](docs/ADR/000006.md) · [11](docs/ADR/000011.md) · [12](docs/ADR/000012.md)
- **M2 — The data path (fast path)** 🚧 *(slices 1–5 landed)*
  **Landed (slice 1):** a `plecto-server` crate — a tokio + hyper **HTTP/1.1** listener that routes each request by host + path prefix, runs that route's filter chain via a `spawn_blocking` bridge to the M1 trusted pool (wasmtime's `!Send` Store never crosses `.await`), applies a host-native prefix strip, and forwards to the route's upstream (hyper-util pooling client), streaming bodies opaquely. *Plecto is now an actual reverse proxy.* **Landed (slice 2 — TLS):** rustls (ring) **TLS termination** with certificates declared in the manifest (`[[tls]]`, SNI selection + a host-less default), built in the control plane so a bad cert fails the load **closed** and reload swaps certs atomically. *Plecto now terminates HTTPS.* **Landed (slice 3 — HTTP/2):** **h2 over TLS+ALPN** (ALPN advertises `h2` then `http/1.1`; no h2c), capped at 100 concurrent streams per connection to bound the M1 pool. **Landed (slice 4 — HTTP/3):** an independent **quinn(QUIC) + h3** UDP listener on the same port (TLS 1.3, ALPN `h3`, 0-RTT disabled per RFC 8470), advertised to TCP clients via `Alt-Svc`; all three HTTP versions share one transport-agnostic transaction core. *Plecto now speaks HTTP/1.1, HTTP/2 and HTTP/3.* **Landed (slice 5 — load balancing):** an upstream is now **one or more instances**; the fast path **round-robins across the healthy set**, a background supervisor **active-health-checks** each instance (`GET health.path`; pessimistic start with a cold-start fast probe), a real request's connect failure **passively ejects** an instance, health state survives reload (reconciled outside the atomic config swap), and an upstream with no healthy instance **fails closed with 503**. *Plecto now load-balances.* **Pending (next slice):** upstream TLS, least-conn/EWMA, request-level retry. — [ADR 12](docs/ADR/000012.md) · [13](docs/ADR/000013.md) · [14](docs/ADR/000014.md) · [15](docs/ADR/000015.md) · [16](docs/ADR/000016.md) · [17](docs/ADR/000017.md)
- **M3 — Async & bodies** *(two-stage trigger)*
  **Stage 1 — host can run P3:** upgrade to wasmtime 46 (Component Model async + WASI 0.3 on by default). **Stage 2 — P3 guests are practical to write:** `wasm32-wasip3` reaching Tier 2 / wit-bindgen async maturing. The body work (async-first contract, `stream<u8>` bodies, `wasi:http` type reuse, body-transform filters) is tied to **Stage 2** — starting it the moment wasmtime 46 lands risks stalling on guest tooling. Body-untouching is expressed at the **type level** (separate header/body exports) so zero-copy bypass follows from the contract; stream splicing itself lands later with WASI 0.3.x. — [ADR 3](docs/ADR/000003.md) · [5](docs/ADR/000005.md) · [10](docs/ADR/000010.md)
- **M4 — Provenance & zero-downtime reload**
  OCI-artifact filter distribution + cosign signature verification, content-hash-reconciled hot reload from a declarative manifest. — [ADR 6](docs/ADR/000006.md) · [8](docs/ADR/000008.md)
- **M5 — Observability & opt-in distribution**
  `wasi-otel` tracing with host-propagated span context; opt-in `foca`/`openraft` config consensus. — [ADR 7](docs/ADR/000007.md) · [9](docs/ADR/000009.md)
- **M6 — Polyglot SDKs & reference filters**
  Go / JS / Python filter templates and reference auth / rate-limit / WAF filters.

## Project layout

```
.
├── plecto/                    # Rust workspace (the native half)
│   ├── wit/world.wit          # the plecto:filter contract (contract-first)
│   ├── deny.toml              # cargo-deny supply-chain policy (CI-blocking)
│   ├── examples/<use-case>/   # five runnable demos (cargo run -p plecto-server --example <name>)
│   └── crates/
│       ├── host/              # wasmtime embedding: Linker, InstancePre, host-API (+ CONTEXT.md)
│       ├── control/           # control plane: manifest, OCI load, chain, reload, TLS/QUIC (+ CONTEXT.md)
│       ├── server/            # fast path: HTTP/1.1·2 (hyper) + HTTP/3 (quinn), routing, LB, upstream (+ CONTEXT.md)
│       ├── filter-hello/      # conformance-fixture filter (wasm32-unknown-unknown guest)
│       └── filter-apikey/     # real-world example filter: API-key auth gate (WASM component)
├── docs/ADR/                  # Architecture Decision Records (000001–000017)
├── CLAUDE.md                  # project conventions & design summary
└── CONTEXT-MAP.md             # domain glossary map (split per context)
```

## Design decisions

Plecto records every load-bearing decision as an ADR, in the Fork form (*decision / rationale / re-examination condition*):

| # | Decision |
| --- | --- |
| [001](docs/ADR/000001.md) | Adopt the WASM Component Model / WIT; structure Plecto as two complementary halves |
| [002](docs/ADR/000002.md) | Define a custom `plecto:filter` world that reuses `wasi:http` types |
| [003](docs/ADR/000003.md) | Async-first contract: `stream<u8>` bodies, `wasm32-wasip2` → P3 |
| [004](docs/ADR/000004.md) | Pooled, stateless filters; state lives in host KV (redb) |
| [005](docs/ADR/000005.md) | Split header-only vs body-transform; keep the hot path native |
| [006](docs/ADR/000006.md) | Security: deny-by-default capabilities, epoch metering, OCI signing, pooling zeroization |
| [007](docs/ADR/000007.md) | Observability via `wasi-otel`; host-managed trace span propagation |
| [008](docs/ADR/000008.md) | OCI-artifact distribution; content-hash-reconciled zero-downtime reload |
| [009](docs/ADR/000009.md) | Single-node first; distribution opt-in; static declarative config + hot reload |
| [010](docs/ADR/000010.md) | First increment: sync + own http types on `wasm32-unknown-unknown`; defer async to wasmtime 46 |
| [011](docs/ADR/000011.md) | "Stateless" = no carried-over mutable state; the trusted/untrusted instance split is forced by the init/zeroization knot |

## Contributing

Plecto follows outside-in TDD (E2E → WIT-conformance → unit) and records load-bearing decisions as ADRs. See [CLAUDE.md](CLAUDE.md) for conventions. Local CI parity before a PR:

```bash
cd plecto
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE). The Apache-2.0 patent grant suits an infrastructure project; it is the license used by Envoy, Linkerd, and containerd.

## Prior art & acknowledgements

Plecto stands on the shoulders of [Envoy](https://www.envoyproxy.io/) / [proxy-wasm](https://github.com/proxy-wasm), [Cloudflare Pingora](https://github.com/cloudflare/pingora), and the [Bytecode Alliance](https://bytecodealliance.org/) — [wasmtime](https://wasmtime.dev/), [WIT, and the Component Model](https://component-model.bytecodealliance.org/).
