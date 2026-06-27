<!--
Thanks for contributing to Plecto! Please read CONTRIBUTING.md first.
Plecto is invitation-only for code: a PR that is neither from a maintainer nor references an
`accepting-pr`-labelled issue is closed automatically. Open an issue and agree the approach first.
For a vulnerability, do NOT open a PR — see SECURITY.md.
-->

## What & why

<!-- What does this change do, and what problem does it solve? -->

Agreed in: #          <!-- required: the `accepting-pr`-labelled issue where this was agreed -->
Closes: #

## How it was tested

<!-- Tests added/changed, and how you verified it (e.g. `just check`, a demo, a manual curl). -->

## Risk & scope

<!-- Be explicit about whether this touches an area that needs extra care (see CONTRIBUTING.md). -->

- [ ] This change does **not** touch the WASM sandbox / capability boundary, the host-API,
      provenance (signing / SBOM), TLS / crypto, routing / upstream construction, or dependencies
      (`Cargo.toml` / `Cargo.lock` / `deny.toml`).
- [ ] If it does, the area is named above, the change is isolated from unrelated edits, and it was
      discussed and agreed first.

## Checklist

- [ ] References an `accepting-pr`-labelled issue (this PR was invited).
- [ ] `just check` is green (fmt, clippy `-D warnings`, tests).
- [ ] New behavior is covered by tests (test-first where practical; RED and GREEN commits separated).
- [ ] A load-bearing decision is recorded as an ADR in `docs/ADR/` (if applicable).
- [ ] Every commit is signed off (DCO): `git commit -s`.
- [ ] Commit messages are in English and explain the *why*.
- [ ] This change respects the design tenets; if it revisits one, I said which and why.
