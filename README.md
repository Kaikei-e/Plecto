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
> **Status: early development.** The design is settled (37 ADRs, 35 accepted) and the foundation runs end to end: the `plecto:filter` contract, a wasmtime host that loads and runs filters, and a **fast path** that terminates **HTTP/1.1, HTTP/2 (ALPN), HTTP/3 (QUIC)** and **TLS**, **routes** by host · path-prefix · method · header · query in specificity order with weighted **traffic split (canary)**, runs the route's filter chain over headers **and** a request body, propagates the client IP in an edge model, and **load-balances across healthy upstream instances** — round-robin, **weighted least-request (power-of-two-choices)**, or **weighted Maglev consistent hashing** — backed by active/passive **health checks**, **outlier detection**, a per-upstream **circuit breaker**, two-tier (per-try + overall) **timeouts**, jittered **retry**, and a native L7 **rate-limit** floor. A security-hardening pass ([ADR 000027](docs/ADR/000027.md)) makes route selection a reliable auth boundary — the path is normalized at ingress and encoded escapes are rejected fail-closed — bounds host-held state with per-filter quotas, and enforces inbound resource limits. The full suite is green on CI — a foundation you can read, run, and build filters against. See the [Roadmap](#roadmap).

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

Plecto is a fast **native highway** plus a **checkpoint where your own code runs**. The highway
(native Rust) accepts connections, terminates TLS, speaks HTTP, routes and load-balances. The
checkpoint is the **extension plane**: every request is handed to your *filter* — a small sandboxed
WASM program — which **inspects it and returns one of three decisions**. That decision is where the
policy lives.

```mermaid
flowchart LR
    client(["Client"])
    upstream(["Upstream service"])

    subgraph fast["Fast path · native Rust"]
        direction TB
        edge["accept · TLS · HTTP/1·2·3"]
        route["route match · load balance"]
        edge --> route
    end

    subgraph ext["Extension plane · your filter, sandboxed WASM"]
        direction TB
        inspect["inspect each request<br/>headers, and the body if it asks"]
        decide{"decide"}
        inspect --> decide
    end

    state[("Host-held state and services<br/>rate-limit · KV · counter · log · clock")]

    client -->|"1 · request"| edge
    route -->|"2 · run the filter chain"| inspect
    decide -->|"3 · continue / modify, then forward"| upstream
    decide -.->|"3 · reject and answer now<br/>401 / 403 / 429 — upstream never reached"| client
    upstream -->|"4 · response — filters may edit on the way back"| client
    decide <-->|"borrows only the capabilities it was lent"| state
```

The three decisions are the whole mental model: **continue** (pass through), **modify** (rewrite a
header/body, then pass), or **reject** (answer the client *now* — a `401/403/429` that **never
reaches the upstream**, so bad traffic is shed at the edge). The filter is **stateless**: anything it
needs to remember (a counter, a rate-limit bucket, a cached value) lives in the host, and it can call
**only** the host services it was explicitly lent — nothing else (deny-by-default).

A filter is just a signed WASM component, and the **same** component can run two ways depending on
how much you trust it — which is the single biggest performance lever:

```mermaid
flowchart TB
    wasm["A filter is one signed WASM component<br/>(write it in any language)"]
    verify["verify the signature, then load<br/>bad signature → refused (fail-closed)"]
    profile{"how much is it trusted?"}

    pooled["trusted → pooled<br/>built once, instances reused<br/>fast hot path (~2 µs / request)"]
    fresh["untrusted → fresh per request<br/>rebuilt and wiped each time<br/>stronger isolation (~12× slower)"]

    guards["always on, every instance:<br/>time limit · memory limit<br/>fail-closed on trap or timeout"]

    wasm --> verify --> profile
    profile -->|trusted| pooled
    profile -->|untrusted| fresh
    pooled --> guards
    fresh --> guards
```

**Rule of thumb:** user-specific logic / policy / WAF / auth / rewrite → a WASM filter; TLS / routing / LB / connection pools / global counters → native Rust. This split is the project's governing principle, fixed as a role-driven placement rule in [ADR 000029](docs/ADR/000029.md) — native grows only for cross-cutting data-plane concerns and global counters, never for per-request policy. The WASM "tax" (data copy + host-call overhead) is charged only to request-decision logic, never to the speed path — measured at **~2 µs/request** for a pooled filter ([performance](performance/README.md)).

## What the gateway does today

The native fast path has matured well past "a proxy that works." A snapshot of what is implemented and CI-green (each row links the deciding ADR):

| Concern | Today |
| --- | --- |
| **Edge & HTTP** | HTTP/1.1, HTTP/2 (ALPN), HTTP/3 (QUIC, Alt-Svc advertised); TLS termination with SNI cert selection (rustls, manifest-declared certs, fail-closed) — [13](docs/ADR/000013.md) · [14](docs/ADR/000014.md) · [15](docs/ADR/000015.md) · [16](docs/ADR/000016.md) |
| **Routing** | match on host · path-prefix · method · header(exact) · query, resolved in **specificity order**; weighted **traffic split / canary**; host-native prefix strip; path normalized at ingress as a fail-closed auth boundary — [13](docs/ADR/000013.md) · [27](docs/ADR/000027.md) · [34](docs/ADR/000034.md) |
| **Load balancing** | per-upstream **round-robin** (default), **weighted least-request** (power-of-two-choices), or **weighted Maglev** consistent hashing (header / source-IP affinity) — [17](docs/ADR/000017.md) · [24](docs/ADR/000024.md) · [35](docs/ADR/000035.md) |
| **Resilience** | active **+** passive **health checks**; **outlier detection** (eject misbehaving instances); per-upstream **circuit breaker** (concurrency cap); **two-tier timeouts** (per-try + overall); **bounded retry** with jittered backoff + retry-on-5xx — [17](docs/ADR/000017.md) · [28](docs/ADR/000028.md) · [30](docs/ADR/000030.md) · [31](docs/ADR/000031.md) · [32](docs/ADR/000032.md) |
| **Rate limiting** | native L7 token-bucket floor per **route** / per **client-IP**; plus the per-filter `host-ratelimit` capability lent to filters — [26](docs/ADR/000026.md) · [33](docs/ADR/000033.md) |
| **Extension plane** | `plecto:filter` chain over headers **and** a request body; typed `decision`; trusted **pooled** / untrusted **fresh** instances; deny-by-default host-API (kv · counter · log · clock · rate-limit) with per-filter + host-wide quotas — [1](docs/ADR/000001.md) · [12](docs/ADR/000012.md) · [25](docs/ADR/000025.md) · [27](docs/ADR/000027.md) |
| **Client IP** | edge-model propagation — strip the inbound forwarding-header family, re-issue `X-Forwarded-For` / `X-Real-IP` from the real peer before the chain runs — [18](docs/ADR/000018.md) · [22](docs/ADR/000022.md) |
| **Supply chain & ops** | OCI digest-pinned filters; cosign signature + SBOM↔component verification; zero-downtime SIGHUP reload (atomic `ArcSwap`, all-or-nothing); W3C trace propagation + host-aggregated RED metrics + opt-in access log — [6](docs/ADR/000006.md) · [7](docs/ADR/000007.md) · [8](docs/ADR/000008.md) · [9](docs/ADR/000009.md) |

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
// the WASM boundary. The bucket spec (capacity/refill) is host-configured in the manifest; the
// filter passes only (key, cost), so an untrusted filter cannot widen its own limit (ADR 000005 / 000026).

world filter {
  // granted capabilities only — log · clock · kv · counter · rate-limit
  import host-log;  import host-clock;  import host-kv;  import host-counter;  import host-ratelimit;
  export init: func();                                        // heavy, once per instance
  export on-request:      func(req: http-request)  -> request-decision;       // hot path (headers)
  export on-request-body: func(body: list<u8>)     -> request-body-decision;  // body hook (ADR 000025)
  export on-response:     func(resp: http-response) -> response-decision;     // hot path (headers)
}
```

> v0.1.0 started **sync + header-only**; the request-side **body hook** (`on-request-body`, a buffered `list<u8>` in v1, [ADR 000025](docs/ADR/000025.md)) now runs end-to-end, so a filter can transform or short-circuit on the body, not just headers — the [roadmap](#roadmap) covers how the fast path buffers it. An **experimental, feature-gated** `stream<u8>` body world ([ADR 000020](docs/ADR/000020.md)) and `wasi:http` type reuse come next, gated on the P3 guest toolchain.

## Writing a filter

A filter is just a component that implements the world. Here is the included example (`examples/filters/filter-hello`), in Rust:

```rust
wit_bindgen::generate!({ path: "../../../wit", world: "filter" });

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

A complete how-to — scaffold, build, the manifest field reference, signing, and local testing — is in [**Writing a filter**](docs/writing-a-filter.md). A copy-ready starting point with the contract already vendored lives in [`examples/filters/filter-template`](plecto/examples/filters/filter-template).

## Try it

The repository pins its toolchain and WASM target in
[`plecto/rust-toolchain.toml`](plecto/rust-toolchain.toml), so [`rustup`](https://rustup.rs/) sets
up the right Rust (edition 2024) and the `wasm32-unknown-unknown` target on your first build — no
manual `rustup target add` step.

```bash
# Build and test everything. The host build script compiles the example filter to a
# WASM component and the tests load it into the wasmtime host and exercise the contract.
cd plecto
cargo test --all
```

(Building outside that toolchain? Add the target once: `rustup target add wasm32-unknown-unknown`.)

The suite proves the slice end-to-end: a request flows through the host into a real filter component, the typed `decision` round-trips, and the filter reaches **only** the capabilities it was lent (the example component imports `plecto:filter/*` and nothing else — zero WASI, network, or filesystem access).

### Run the demos

Five self-contained, use-case-focused demos live under `examples/<name>/`. Each wires the **production load path** (sign + offline OCI layout + verify + load, all fail-closed), starts a tiny upstream, serves a real proxy, and prints copy-paste `curl` commands on startup.

The quickest way to see one work end to end is the guided tour — it starts the demo, waits for it, runs the `curl` commands, visualizes the output, and cleans up:

```bash
cd plecto
./examples/try.sh <name>      # or `all`; or `just demo <name>` from the repo root
```

Prefer to drive it yourself? Run the server directly and use the `curl` recipes it prints on startup:

```bash
cargo run -p plecto-server --example <name>   # Ctrl-C to stop
```

| `<name>` | What it shows |
| --- | --- |
| `wasm-auth` | **A real WASM filter doing real work** — a signed API-key auth component (`examples/filters/filter-apikey`) that 401s without a valid key, stamps the caller's identity, and counts per-user requests in host KV. The point of Plecto. |
| `load-balancing` | One upstream over three instances: round-robin across the healthy set, active health probes, ejection when an instance goes unhealthy, and 503 when none are left (ADR 000017). Least-request (P2C) and Maglev consistent hashing, plus circuit breaking and outlier detection, are opt-in per-upstream knobs on the same upstream (ADR 000028 / 000032 / 000035). |
| `filter-chain` | The filter chain over plain HTTP: continue / modify (header rewrite) / short-circuit 403 / host-native rate limit. |
| `tls-http` | TLS termination with HTTP/1.1, HTTP/2 (ALPN) and HTTP/3 (QUIC) on one port, plus `Alt-Svc` h3 advertisement. |
| `hot-reload` | Edit the manifest, `kill -HUP <pid>`, and watch the config swap atomically with zero downtime (a broken edit is fail-closed). |

Read `wasm-auth` first: it shows custom request logic running as a sandboxed component that can touch only the host-API it was lent — cosign-style signature + SBOM verification, the typed `decision`, and host-held state, end to end.

Two more examples under `examples/` are micro-benchmarks rather than demos — `wasm-bench` and `edge-bench` — and produce the numbers in [performance](performance/README.md).

## Roadmap

Plecto is built ADR-first; each milestone realizes specific design decisions in `docs/ADR/`.

- **M0 — Foundation** ✅ *(done)*
  The `plecto:filter@0.1.0` contract, a wasmtime host that loads & runs filters, a deny-by-default capability boundary (log / clock / kv), an example filter, E2E/conformance/unit tests, and CI. — [ADR 1](docs/ADR/000001.md) · [2](docs/ADR/000002.md) · [10](docs/ADR/000010.md)
- **M1 — Filter runtime hardening** ✅ *(landed)*
  Trust-branched instances: trusted filters reuse a fixed-capacity, lazily-filled **pool** checked out per request (bounded-wait fail-closed, pool-wide circuit breaker, recycle-after-N); untrusted run **fresh-per-request** (linear memory fresh by construction). redb-backed host KV + atomic counters + **host-native token-bucket rate limiting** (bucket spec host-set in the manifest, keyed per request — an untrusted filter cannot widen its own limit, [ADR 26](docs/ADR/000026.md)), per-filter key namespacing, **per-filter + host-wide quotas** on that state (fail-closed over quota, untrusted `init` deadline tightened — [ADR 27](docs/ADR/000027.md)), and **epoch metering + memory/table limits**. The trusted/untrusted split is *forced* (not just perf) by the init/zeroization knot.
- **M2 — The data path (fast path)** 🚧 *(matured by the role-driven model of [ADR 29](docs/ADR/000029.md))*
  A tokio + hyper + quinn `plecto-server` that terminates **HTTP/1.1, HTTP/2 (ALPN) and HTTP/3 (QUIC)** and **TLS** (rustls, manifest-declared certs, fail-closed), **routes** by host · path-prefix · method · header · query in specificity order with weighted **traffic split / canary** ([ADR 34](docs/ADR/000034.md)), runs the route's filter chain via a `spawn_blocking` bridge to the M1 pool, and **load-balances** across healthy upstream instances with a per-upstream choice of **round-robin**, **weighted least-request (P2C)**, or **weighted Maglev** consistent hashing ([ADR 35](docs/ADR/000035.md)). Resilience is layered on the same upstream: active/passive **health checks** (pessimistic start, fail-closed 503 when none healthy), **outlier detection** ([ADR 32](docs/ADR/000032.md)), a per-upstream **circuit breaker** ([ADR 28](docs/ADR/000028.md)), **two-tier timeouts** (per-try + overall, [ADR 31](docs/ADR/000031.md)), **bounded retry** with jittered backoff and retry-on-5xx ([ADR 30](docs/ADR/000030.md)), and a native L7 **rate-limit** floor per route / client-IP ([ADR 33](docs/ADR/000033.md)). Edge-model client-IP propagation re-issues `X-Forwarded-For` / `X-Real-IP` from the real peer ([ADR 18](docs/ADR/000018.md) / [22](docs/ADR/000022.md)). The data path is **security-hardened** ([ADR 27](docs/ADR/000027.md)): the request path is normalized once at ingress so a per-route filter is a reliable auth boundary (encoded separators / dot-escapes rejected fail-closed), inbound resource limits are enforced (connection cap, header-read timeout, body-read deadline, body-buffer budget), and filter-untouched header bytes pass through **byte-for-byte**. *Next:* upstream TLS, EWMA/latency-aware LB, ring-hash hashing, header-presence / regex match.
- **M4 — Provenance & zero-downtime reload** ✅ *(landed)*
  OCI-artifact filter distribution (offline image-layout, digest-pinned) + cosign signature verification + SBOM↔component binding, and content-hash-reconciled hot reload from a declarative manifest (atomic `ArcSwap`, all-or-nothing, SIGHUP-driven). What remains is a *remote* registry fetch path (the `wkg` boundary, out-of-band by design). — [ADR 6](docs/ADR/000006.md) · [8](docs/ADR/000008.md)
- **M5 — Observability & opt-in distribution** 🚧 *(span/metrics core landed; export deferred)*
  **Landed:** host-propagated W3C trace context (inbound `traceparent` continued through the proxy), one span per filter execution over the OpenTelemetry data model, and a sync `TelemetrySink` (in-memory + host-aggregated RED metrics). **Deferred:** OTLP network export (`wasi-otel` / SDK exporter, named-deferred to stay no-tokio) and opt-in `foca`/`openraft` config consensus. — [ADR 7](docs/ADR/000007.md) · [9](docs/ADR/000009.md)
- **M3 — Async & bodies** 🚧 *(Stage 1 landed; Stage 2 in progress)*
  The frontier, since M4/M5 are largely done. **Stage 1 (landed):** [wasmtime 46](https://github.com/bytecodealliance/wasmtime/releases/tag/v46.0.0) (2026-06-22) made WASI 0.3 + Component Model async default-on; the host runs guest hooks via `call_async` on wasmtime fibers, bridged to its still-sync public API with `block_on`. **Stage 2 (in progress):** the request-side **body hook** is wired **end-to-end** — `on-request-body` (buffer-then-decide; body as a buffered `list<u8>` in v1) through the contract, the host, **and the fast path** (the proxy buffers a filtered route's body bounded — 16 MiB cap, fail-closed 413 — while bodyless requests and filter-less routes stay zero-copy), conformance- and E2E-green ([ADR 25](docs/ADR/000025.md)). An **experimental, feature-gated** `stream<u8>` increment has landed: behind the off-by-default `streaming-body` feature, a separate `plecto:filter-streaming` world drives an async `process-body(stream<u8>)` on the host (no whole-body buffer; server-side wiring is the next increment) over a minimal WASI slice, and stays out of the default build until `wasm32-wasip3` reaches Tier-2. Header **byte-equivalence** through the proxy (filter-untouched bytes preserved) landed alongside. [ADR 20](docs/ADR/000020.md) keeps the `wasi:http` convergence direction — deny-by-default independent of the type vocabulary.
- **M6 — Polyglot SDKs & reference filters**
  Go / JS / Python filter templates and reference auth / rate-limit / WAF filters. The capability surface a filter can be lent is expanding deny-by-default: outbound HTTP with an SSRF guard and a per-filter allowlist is in design ([ADR 36](docs/ADR/000036.md)), and WAF is deliberately placed in the extension plane rather than native ([ADR 37](docs/ADR/000037.md)).

## Project layout

```
.
├── plecto/                    # Rust workspace (the native half)
│   ├── wit/world.wit          # the plecto:filter contract (contract-first)
│   ├── deny.toml              # cargo-deny supply-chain policy (CI-blocking)
│   ├── crates/
│   │   ├── host/              # wasmtime embedding: Linker, InstancePre, host-API (+ CONTEXT.md)
│   │   ├── control/           # control plane: manifest, OCI load, chain, reload, TLS/QUIC (+ CONTEXT.md)
│   │   └── server/            # fast path: HTTP/1.1·2 (hyper) + HTTP/3 (quinn), routing, LB, upstream (+ CONTEXT.md)
│   └── examples/              # runnable demos (<use-case>/) + example filter guests (filters/)
│       ├── <use-case>/        # five demos: cargo run -p plecto-server --example <name>
│       └── filters/           # example plecto:filter guests (own workspace, componentized by build.rs)
│           ├── filter-hello/  # conformance-fixture filter (wasm32-unknown-unknown guest)
│           ├── filter-apikey/ # real-world example filter: API-key auth gate (WASM component)
│           ├── filter-template/ # copy-ready starting point for your own filter (vendored WIT)
│           └── filter-streaming/ # experimental stream<u8> body filter (feature-gated, wasm32-wasip2)
├── docs/ADR/                  # Architecture Decision Records (000001–000037)
├── CLAUDE.md                  # project conventions & design summary
└── CONTEXT-MAP.md             # domain glossary map (split per context)
```

## Design decisions

Plecto records every load-bearing decision as an ADR in the Fork form (*decision / rationale / re-examination condition*). All 37 (35 accepted, 2 proposed) live in [`docs/ADR/`](docs/ADR/) — start at [ADR 000001](docs/ADR/000001.md) (the two complementary halves); each cross-links the decisions it builds on.

## Contributing

Contributions are deliberate: please **agree an approach in an issue or [Discussion](https://github.com/Kaikei-e/Plecto/discussions) before opening a PR** (unsolicited PRs may be closed). Plecto follows outside-in TDD (E2E → WIT-conformance → unit) and records load-bearing decisions as ADRs. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide — including the areas that need extra care and DCO sign-off — and [CLAUDE.md](CLAUDE.md) for conventions. Local CI parity before a PR:

```bash
cd plecto
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

(or just `just check` from the repository root.)

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE). The Apache-2.0 patent grant suits an infrastructure project; it is the license used by Envoy, Linkerd, and containerd.

## Prior art & acknowledgements

Plecto stands on the shoulders of [Envoy](https://www.envoyproxy.io/) / [proxy-wasm](https://github.com/proxy-wasm), [Cloudflare Pingora](https://github.com/cloudflare/pingora), and the [Bytecode Alliance](https://bytecodealliance.org/) — [wasmtime](https://wasmtime.dev/), [WIT, and the Component Model](https://component-model.bytecodealliance.org/).
