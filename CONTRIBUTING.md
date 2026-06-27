# Contributing to Plecto

Thanks for your interest in Plecto — a self-hostable, programmable L7 reverse proxy and API
gateway in Rust, extended with WebAssembly filters. This guide gets you from a clean clone to a
green test run and a well-formed pull request.

> **Status: early development — invitation-only for code.** The design is settled (see
> [`docs/ADR/`](docs/ADR/)) and the foundation runs end to end, but interfaces still move, and
> contributions are handled **deliberately, not by volume**. **Plecto does not accept unsolicited
> pull requests.** Open an [issue or Discussion](https://github.com/Kaikei-e/Plecto/discussions),
> agree the approach, and once a maintainer labels the issue `accepting-pr`, open a PR that
> references it. A PR that is neither from a maintainer nor references an `accepting-pr` issue is
> **closed automatically** ([`.github/workflows/pr-policy.yml`](.github/workflows/pr-policy.yml)).
> That is not unfriendliness; it keeps the codebase reviewable.

## Ground rules

- **Be excellent to each other.** This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues are not public issues.** If you find a vulnerability, follow
  [`SECURITY.md`](SECURITY.md) — please do not open a public issue or PR.
- **By contributing, you agree** your work is licensed under the project's
  [Apache-2.0](LICENSE) license.

## Prerequisites

You need a recent Rust toolchain. You do **not** need to install anything by hand: the repository
pins the toolchain and the WASM target in [`plecto/rust-toolchain.toml`](plecto/rust-toolchain.toml),
so [`rustup`](https://rustup.rs/) installs the right channel (and the `wasm32-unknown-unknown`
target the example filters compile to) automatically on your first `cargo` command.

Optional but recommended: [`just`](https://github.com/casey/just) for the task shortcuts below, and
`curl` to drive the demos.

## First build

The Rust workspace lives under `plecto/`. Run commands from there (or use `just`, which `cd`s for
you from the repository root):

```bash
git clone https://github.com/Kaikei-e/Plecto
cd Plecto

just check         # fmt --check + clippy -D warnings + test  (full local CI parity)
# …or directly:
cd plecto && cargo test --all
```

The first build is large (it compiles the wasmtime host); subsequent builds are incremental. The
test suite compiles the example filter to a WASM component, loads it into the wasmtime host, and
exercises the `plecto:filter` contract end to end.

See the demos run for real:

```bash
just demo wasm-auth      # a signed WASM filter doing API-key auth, end to end
just demo-all            # every guided demo in turn
```

## Task shortcuts (`just`)

| Command | What it does |
| --- | --- |
| `just check` | fmt check + clippy (`-D warnings`) + tests — run this before every PR |
| `just test` | `cargo test --all` |
| `just fmt` | format the workspace |
| `just lint` | fmt check + clippy |
| `just demo NAME` | run a guided demo (`wasm-auth`, `load-balancing`, `filter-chain`, `tls-http`, `hot-reload`) |
| `just example NAME` | run an example server directly (`cargo run -p plecto-server --example NAME`) |
| `just build-filters` | build the example filter guests for `wasm32-unknown-unknown` |

Run `just` with no arguments to list every recipe.

## How we work

**Outside-in TDD.** Plecto is built test-first, from the outside in:

1. **E2E** — a request flowing through the filter chain.
2. **WIT-conformance** — when a change crosses the filter/host boundary (the `plecto:filter`
   contract), prove the contract resolves.
3. **Unit** — the smallest red-green-refactor loop.

Keep the **RED** commit (the failing test) and the **GREEN** commit (the implementation that passes
it) separate, so the history shows the test driving the code.

**Architecture Decision Records.** Load-bearing decisions are recorded as ADRs in
[`docs/ADR/`](docs/ADR/) using the Fork form (*decision / rationale / re-examination condition*). If
your change makes or revisits such a decision, add an ADR (`docs/ADR/NNNNNN.md`, six-digit, from
[`docs/ADR/template.md`](docs/ADR/template.md)). The design tenets in the
[README](README.md#design-tenets) and [`CLAUDE.md`](CLAUDE.md) are the north star; a change that
conflicts with a tenet should say which one and why.

**Orienting yourself.** Start with the [README](README.md), then the domain glossary in
[`CONTEXT-MAP.md`](CONTEXT-MAP.md) and the per-crate `CONTEXT.md` files
(`plecto/crates/{host,control,server}/CONTEXT.md`). To write a filter, see
[`docs/writing-a-filter.md`](docs/writing-a-filter.md).

## Coding conventions

- **Format and lint clean.** `cargo fmt` and `cargo clippy --all-targets --all-features -D warnings`
  must pass. CI enforces both, plus [`cargo-deny`](plecto/deny.toml) for the supply chain.
- **Documents in prose, identifiers in English.** Project prose may be bilingual; code, comments,
  commit messages, and identifiers are English.
- **Comments explain *why*, not *what*.** Reach for a clear name before a comment; add a one-line
  comment only when the reasoning is non-obvious.
- **No panics in the data plane.** Untrusted input must never take down a worker (a project tenet).
- **Keep transient state out of the code.** Don't bake issue numbers or milestone names into code or
  comments — those live in the PR, the ADR, or the issue.

## Changes that need extra care

Some areas sit on the request path and get **extra scrutiny** — discuss and agree them before any
code, and keep them in their own focused PR:

- the WASM **sandbox / capability boundary** and the host-API surface (deny-by-default);
- **provenance** — signature verification and the SBOM↔component binding at filter load;
- **TLS / crypto** and certificate handling;
- **routing and upstream construction** (request smuggling, header injection, SSRF);
- **dependencies** — any change to `Cargo.toml`, `Cargo.lock`, or [`deny.toml`](plecto/deny.toml).
  A new dependency needs a clear justification; the supply chain is CI-gated by `cargo-deny`.

Keep such changes **small, isolated, and never bundled** with unrelated edits, so they can be
reviewed line by line. Found a *vulnerability*? Do **not** open a PR — follow
[`SECURITY.md`](SECURITY.md).

## Pull requests

Plecto is **invitation-only for code**: a PR that is neither from a maintainer nor references an
`accepting-pr`-labelled issue is closed automatically (see above). Once your change has an agreed,
`accepting-pr`-labelled issue, open the PR and reference it. PRs are then reviewed deliberately, not
merged on green CI alone. Before you open one:

- [ ] It references the **agreed, `accepting-pr`-labelled issue** (e.g. `Agreed in: #123`).
- [ ] `just check` is green (fmt, clippy `-D warnings`, tests).
- [ ] New behaviour is covered by tests, written test-first where practical (RED and GREEN commits separated).
- [ ] A load-bearing decision is captured in an ADR (if applicable).
- [ ] The change is **focused**; unrelated cleanups — and any change to the areas above — go in their own PR.
- [ ] Every commit is **signed off** (DCO — see below).
- [ ] Commit messages are in English and explain the *why*.

Open the PR against `main` and fill in the template, including its security-impact section. Expect
review questions grounded in the design tenets and the ADRs. A focused, well-scoped PR built on an
agreed approach is reviewed far faster than a large, unsolicited one.

### Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of
Origin](https://developercertificate.org/): sign off every commit to certify that you wrote the
patch, or otherwise have the right to submit it under the project's license. Add the trailer with
`git commit -s`:

```
Signed-off-by: Your Name <you@example.com>
```

A pull request whose commits are not signed off will not be merged.

## Questions

Use [GitHub Discussions](https://github.com/Kaikei-e/Plecto/discussions) for questions and ideas,
and [Issues](https://github.com/Kaikei-e/Plecto/issues) for bugs and concrete proposals. Thanks for
helping build Plecto.
