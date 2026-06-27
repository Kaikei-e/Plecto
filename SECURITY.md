# Security Policy

Plecto is a reverse proxy and API gateway that sits in the request path and terminates TLS. We take
vulnerability reports seriously and appreciate your help in disclosing them responsibly.

> **Status: early development.** Plecto has no released, production-supported version yet, so there
> is no formal patch SLA or bug-bounty program. We will still investigate every credible report and
> credit reporters who ask to be credited.

## Reporting a vulnerability

**Please do not open a public issue, pull request, or Discussion for a security problem.**

Report privately through GitHub's **[Private Vulnerability
Reporting](https://github.com/Kaikei-e/Plecto/security/advisories/new)** (the *Security* tab →
*Report a vulnerability*). This keeps the report confidential while we triage it and gives us a
private channel to coordinate a fix and disclosure with you.

A useful report includes:

- the affected component (fast path, host/extension plane, control plane, or a specific crate);
- the version or commit you tested;
- a clear description of the impact and a minimal way to reproduce it;
- any proof-of-concept, logs, or configuration needed to observe the issue.

We aim to acknowledge a report within a few days, keep you updated as we investigate, and agree a
coordinated disclosure timeline with you before any public write-up.

## Scope

Plecto's threat model centers on running **untrusted, possibly multi-tenant WASM filters** behind a
deny-by-default capability boundary, and on the L7 data path. Reports are especially valuable when
they concern:

- **The sandbox / capability boundary** — a filter reaching a capability it was never lent, escaping
  the WASM sandbox, defeating epoch/memory metering, or leaking state across pooled instances.
- **Provenance** — bypassing signature verification or the SBOM↔component binding at filter load.
- **The L7 data path** — request smuggling or splitting, header injection, SSRF in upstream
  construction, TLS-termination weaknesses, or rate-limit / policy bypass.
- **Fail-open behaviour** — any path where a filter trap, deadline overrun, or malformed input
  silently passes traffic through instead of failing closed.

Out of scope: the example filters under `plecto/examples/filters/` are intentionally minimal
demonstrations, and `IsolationKind::untrusted` filters are *expected* to run with no ambient
authority — that is the design, not a vulnerability.

## Supported versions

While Plecto is pre-release, only the `main` branch is supported. Please reproduce against the
latest `main` before reporting.
