#!/usr/bin/env python3
"""Render Plecto's performance charts (WebP) from the measured CSVs in ``data/``.

Covers both planes documented in README.md:

  Load-balancing fast path
    * throughput_vs_concurrency.webp  — sustained req/s vs VUs (closed-loop sweep)
    * latency_vs_concurrency.webp     — p50/p95/p99 vs VUs (log y)
    * rr_distribution.webp            — per-instance share under steady load
    * ejection_timeline.webp          — per-upstream traffic + 503/s over the fault run
    * tls_vs_plain.webp               — TLS(h2) vs plain(h1) throughput & p99

  WASM extension plane
    * wasm_throughput.webp            — req/s by decision path (baseline/pooled/on-demand)
    * wasm_latency.webp               — per-request latency by decision path (log y)
    * wasm_shortcircuit.webp          — accept vs reject latency (short-circuit 401)

Each figure is guarded — a missing CSV just skips it.

Usage:
    python3 plot.py                # reads ./data, writes ./img
Requires: matplotlib (pulls numpy + Pillow; Pillow provides WebP encoding).
"""
from __future__ import annotations

import csv
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / "data"
IMG = HERE / "img"
IMG.mkdir(exist_ok=True)

# A restrained, readable palette (instances a/b/c, plus a failure red).
C_A, C_B, C_C = "#4C9F70", "#E1A53D", "#3D7AB5"
C_FAIL = "#C0392B"
C_P50, C_P95, C_P99 = "#3D7AB5", "#E1A53D", "#C0392B"
DPI = 150


def _read(path: pathlib.Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _save(fig, name: str) -> None:
    out = IMG / name
    fig.savefig(out, format="webp", dpi=DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out.relative_to(HERE)}")


# ---------------------------------------------------------------- LB fast path
def throughput_vs_concurrency() -> None:
    rows = sorted(_read(DATA / "sweep.csv"), key=lambda r: int(r["vus"]))
    vus = [int(r["vus"]) for r in rows]
    rps = [float(r["rps"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    ax.plot(vus, rps, marker="o", color=C_C, lw=2.2)
    for x, y in zip(vus, rps):
        ax.annotate(f"{int(round(y))}", (x, y), textcoords="offset points",
                    xytext=(0, 7), ha="center", fontsize=8)
    ax.set_xlabel("concurrent VUs (closed-loop)")
    ax.set_ylabel("sustained requests / second")
    ax.set_title("Throughput vs concurrency (single host, loopback, 0 ms backend)")
    ax.set_xticks(vus)
    ax.set_ylim(0, max(rps) * 1.18)
    ax.grid(alpha=0.3)
    _save(fig, "throughput_vs_concurrency.webp")


def latency_vs_concurrency() -> None:
    rows = sorted(_read(DATA / "sweep.csv"), key=lambda r: int(r["vus"]))
    vus = [int(r["vus"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    for key, color, lbl in (("p50", C_P50, "p50"), ("p95", C_P95, "p95"), ("p99", C_P99, "p99")):
        ax.plot(vus, [float(r[key]) for r in rows], marker="o", color=color, lw=2.0, label=lbl)
    ax.set_xlabel("concurrent VUs (closed-loop)")
    ax.set_ylabel("request duration (ms, log scale)")
    ax.set_yscale("log")
    ax.set_title("Latency percentiles vs concurrency")
    ax.set_xticks(vus)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3, which="both")
    _save(fig, "latency_vs_concurrency.webp")


def rr_distribution() -> None:
    rows = _read(DATA / "rr.csv")
    labels = [r["instance"] for r in rows]
    counts = [int(r["count"]) for r in rows]
    total = sum(counts) or 1
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    bars = ax.bar(labels, counts, color=[C_A, C_B, C_C][: len(labels)], width=0.6)
    for b, c in zip(bars, counts):
        ax.text(b.get_x() + b.get_width() / 2, c, f"{c}\n({100 * c / total:.1f}%)",
                ha="center", va="bottom", fontsize=9)
    ax.axhline(total / len(labels), color="#444", ls="--", lw=1, alpha=0.7,
               label=f"even share ({total // len(labels)})")
    ax.set_ylabel("requests served")
    ax.set_xlabel("upstream instance")
    ax.set_title("Round-robin distribution under steady load (all healthy)")
    ax.set_ylim(0, max(counts) * 1.2)
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "rr_distribution.webp")


def ejection_timeline() -> None:
    rows = _read(DATA / "ejection_timeline.csv")
    t = [int(r["t"]) for r in rows]
    a = [float(r["a"]) for r in rows]
    b = [float(r["b"]) for r in rows]
    c = [float(r["c"]) for r in rows]
    failed = [float(r["failed"]) for r in rows]

    events = []
    epath = DATA / "ejection_events.csv"
    if epath.exists():
        events = [(int(r["t"]), r["label"]) for r in _read(epath)]

    fig, ax = plt.subplots(figsize=(9.5, 4.6))
    ax.stackplot(t, a, b, c, labels=["instance a", "instance b", "instance c"],
                 colors=[C_A, C_B, C_C], alpha=0.9)
    ax.plot(t, failed, color=C_FAIL, lw=2.2, label="failed / s (HTTP 503)")

    top = max(max(a[i] + b[i] + c[i], failed[i]) for i in range(len(t))) if t else 1
    for xt, lbl in events:
        ax.axvline(xt, color="#444", ls="--", lw=1, alpha=0.6)
        ax.text(xt + 0.4, top * 0.97, lbl, rotation=90, va="top", ha="left",
                fontsize=8, color="#333")

    ax.set_xlim(min(t), max(t))
    ax.set_ylim(0, top * 1.08)
    ax.set_xlabel("time (s)")
    ax.set_ylabel("requests / second")
    ax.set_title("Load balancing under fault injection — per-upstream traffic & failures")
    ax.legend(loc="upper right", fontsize=9, framealpha=0.9)
    ax.grid(axis="y", alpha=0.25)
    _save(fig, "ejection_timeline.webp")


def tls_vs_plain() -> None:
    rows = {r["variant"]: r for r in _read(DATA / "tls.csv")}
    order = [("plain (h1)", C_C), ("tls (h2)", C_A)]
    labels = [v for v, _ in order if v in rows]
    colors = [c for v, c in order if v in rows]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 4.0))

    rps = [float(rows[v]["rps"]) for v in labels]
    bars = ax1.bar(labels, rps, color=colors, width=0.55)
    ax1.bar_label(bars, fmt="%d", padding=3, fontsize=9)
    ax1.set_ylabel("requests / second")
    ax1.set_title("Throughput")
    ax1.set_ylim(0, max(rps) * 1.18)
    ax1.grid(axis="y", alpha=0.3)

    p99 = [float(rows[v]["p99"]) for v in labels]
    bars2 = ax2.bar(labels, p99, color=colors, width=0.55)
    ax2.bar_label(bars2, fmt="%.2f", padding=3, fontsize=9)
    ax2.set_ylabel("p99 latency (ms)")
    ax2.set_title("Tail latency")
    ax2.set_ylim(0, max(p99) * 1.18)
    ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("TLS termination overhead: TLS(h2) vs plain(h1), same LB path", fontsize=11)
    fig.tight_layout()
    _save(fig, "tls_vs_plain.webp")


# ----------------------------------------------------------- WASM filter plane
def wasm_throughput() -> None:
    rows = _read(DATA / "wasm_overhead.csv")
    labels = [r["route"] for r in rows]
    vals = [int(round(float(r["rps"]))) for r in rows]
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    bars = ax.bar(labels, vals, color=[C_C, C_A, C_B][: len(rows)], width=0.6)
    ax.bar_label(bars, fmt="%d", padding=3, fontsize=10)
    ax.set_ylabel("requests / second")
    ax.set_title("Throughput at fixed concurrency (50 VUs, 0 ms backend)")
    ax.set_ylim(0, max(vals) * 1.15)
    ax.grid(axis="y", alpha=0.3)
    ax.tick_params(axis="x", labelsize=9)
    _save(fig, "wasm_throughput.webp")


def wasm_latency() -> None:
    rows = _read(DATA / "wasm_overhead.csv")
    pct = ["p50", "p90", "p95", "p99"]
    x = range(len(pct))
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    n = len(rows)
    width = 0.8 / n
    palette = [C_C, C_A, C_B]
    for i, r in enumerate(rows):
        vals = [float(r[p]) for p in pct]
        off = (i - (n - 1) / 2) * width
        bars = ax.bar([xi + off for xi in x], vals, width=width,
                      label=r["route"], color=palette[i % len(palette)])
        ax.bar_label(bars, fmt="%.2f", padding=2, fontsize=7)
    ax.set_xticks(list(x))
    ax.set_xticklabels(pct)
    ax.set_yscale("log")
    ax.set_ylabel("request duration (ms, log scale)")
    ax.set_title("Per-request latency: native vs pooled vs on-demand filter (0 ms backend)")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, which="both")
    _save(fig, "wasm_latency.webp")


def wasm_shortcircuit() -> None:
    rows = {r["outcome"]: r for r in _read(DATA / "wasm_mixed.csv")}
    pct = ["p50", "p95", "p99"]
    order = [("accept", C_A), ("reject", C_FAIL)]
    x = range(len(pct))
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    width = 0.38
    for i, (outcome, color) in enumerate(order):
        r = rows.get(outcome)
        if not r:
            continue
        vals = [float(r[p]) for p in pct]
        off = (i - 0.5) * width
        n = r.get("count", "")
        bars = ax.bar([xi + off for xi in x], vals, width=width,
                      label=f"{outcome} (n={n})", color=color)
        ax.bar_label(bars, fmt="%.2f", padding=2, fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels(pct)
    ax.set_ylabel("request duration (ms)")
    ax.set_title("Accept vs reject under realistic traffic (15 ms backend, 90/10 mix)")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "wasm_shortcircuit.webp")


# ------------------------------------------------------- rate limiting (ADR 000026)
def ratelimit_overhead() -> None:
    rows = {r["route"].lstrip("/"): r for r in _read(DATA / "ratelimit_overhead.csv")}
    order = [("baseline", C_C), ("ratelimit", C_B)]
    labels = [v for v, _ in order if v in rows]
    colors = [c for v, c in order if v in rows]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 4.0))

    rps = [float(rows[v]["rps"]) for v in labels]
    bars = ax1.bar(labels, rps, color=colors, width=0.55)
    ax1.bar_label(bars, fmt="%d", padding=3, fontsize=9)
    ax1.set_ylabel("requests / second")
    ax1.set_title("Throughput")
    ax1.set_ylim(0, max(rps) * 1.18)
    ax1.grid(axis="y", alpha=0.3)

    p99 = [float(rows[v]["p99"]) for v in labels]
    bars2 = ax2.bar(labels, p99, color=colors, width=0.55)
    ax2.bar_label(bars2, fmt="%.2f", padding=3, fontsize=9)
    ax2.set_ylabel("p99 latency (ms)")
    ax2.set_title("Tail latency")
    ax2.set_ylim(0, max(p99) * 1.18)
    ax2.grid(axis="y", alpha=0.3)

    fig.suptitle("Rate-limit overhead: never-deny bucket vs no-filter baseline", fontsize=11)
    fig.tight_layout()
    _save(fig, "ratelimit_overhead.webp")


def ratelimit_enforce() -> None:
    m = {r["metric"]: float(r["value"]) for r in _read(DATA / "ratelimit_enforce.csv")}
    offered, allowed = m["target_rps"], m["allowed_rps"]
    shed = m.get("limited_frac", 0.0)
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    bars = ax.bar(["offered", "allowed (200)"], [offered, allowed],
                  color=[C_B, C_A], width=0.55)
    ax.bar_label(bars, fmt="%d", padding=3, fontsize=10)
    ax.set_ylabel("requests / second")
    ax.set_ylim(0, offered * 1.2)
    ax.set_title(f"Rate-limit enforcement: {shed * 100:.0f}% shed as 429, "
                 f"allowed converges to the host bucket's refill rate")
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "ratelimit_enforce.webp")


def ratelimit_fairness() -> None:
    rows = {r["key"]: r for r in _read(DATA / "ratelimit_fairness.csv")}
    keys = [k for k in ("hot", "light") if k in rows]
    x = range(len(keys))
    width = 0.38
    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    offered = [float(rows[k]["offered_rps"]) for k in keys]
    allowed = [float(rows[k]["allowed_rps"]) for k in keys]
    b1 = ax.bar([i - width / 2 for i in x], offered, width=width, label="offered", color=C_B)
    b2 = ax.bar([i + width / 2 for i in x], allowed, width=width, label="allowed (200)", color=C_A)
    ax.bar_label(b1, fmt="%d", padding=2, fontsize=8)
    ax.bar_label(b2, fmt="%d", padding=2, fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{k} key" for k in keys])
    ax.set_ylabel("requests / second")
    ax.set_title("Per-key fairness: a hot key is throttled to its bucket rate; a light key passes")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3)
    _save(fig, "ratelimit_fairness.webp")


# ------------------------------------------------------- request body hook (ADR 000025)
def body_hook() -> None:
    rows = _read(DATA / "body.csv")
    sizes = sorted({int(r["size"]) for r in rows})
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.4, 4.2))
    for route, color in (("baseline", C_C), ("body", C_B)):
        sel = {int(r["size"]): r for r in rows if r["route"].lstrip("/") == route}
        if not sel:
            continue
        mbps = [float(sel[s]["req_mbps"]) for s in sizes if s in sel]
        p99 = [float(sel[s]["p99"]) for s in sizes if s in sel]
        xs = [s for s in sizes if s in sel]
        ax1.plot(xs, mbps, marker="o", color=color, lw=2.0, label=route)
        ax2.plot(xs, p99, marker="o", color=color, lw=2.0, label=route)
    for ax in (ax1, ax2):
        ax.set_xscale("log")
        ax.set_xticks(sizes)
        ax.set_xticklabels([f"{s // 1024}K" if s < 1 << 20 else f"{s >> 20}M" for s in sizes])
        ax.set_xlabel("request body size")
        ax.grid(alpha=0.3, which="both")
        ax.legend(fontsize=9)
    ax1.set_ylabel("request-body throughput (MB/s)")
    ax1.set_title("Throughput")
    ax2.set_ylabel("p99 latency (ms)")
    ax2.set_yscale("log")
    ax2.set_title("Tail latency")
    fig.suptitle("Request-body hook (buffer→transform) vs streaming passthrough, by payload size",
                 fontsize=11)
    fig.tight_layout()
    _save(fig, "body.webp")


# ------------------------------------------------------- connection churn
def churn() -> None:
    rows = {r["variant"]: r for r in _read(DATA / "churn.csv")}
    order = [("keep-alive", C_A), ("cold (TCP/req)", C_FAIL)]
    labels = [v for v, _ in order if v in rows]
    colors = [c for v, c in order if v in rows]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.0, 4.0))
    rps = [float(rows[v]["rps"]) for v in labels]
    b1 = ax1.bar(labels, rps, color=colors, width=0.55)
    ax1.bar_label(b1, fmt="%d", padding=3, fontsize=9)
    ax1.set_ylabel("requests / second")
    ax1.set_title("Throughput")
    ax1.set_ylim(0, max(rps) * 1.18)
    ax1.grid(axis="y", alpha=0.3)
    p99 = [float(rows[v]["p99"]) for v in labels]
    b2 = ax2.bar(labels, p99, color=colors, width=0.55)
    ax2.bar_label(b2, fmt="%.2f", padding=3, fontsize=9)
    ax2.set_ylabel("p99 latency (ms)")
    ax2.set_title("Tail latency")
    ax2.set_ylim(0, max(p99) * 1.18)
    ax2.grid(axis="y", alpha=0.3)
    fig.suptitle("Connection churn: a TCP handshake per request vs a kept-alive connection",
                 fontsize=11)
    fig.tight_layout()
    _save(fig, "churn.webp")


def main() -> None:
    figs = (throughput_vs_concurrency, latency_vs_concurrency, rr_distribution,
            ejection_timeline, tls_vs_plain,
            wasm_throughput, wasm_latency, wasm_shortcircuit,
            ratelimit_overhead, ratelimit_enforce, ratelimit_fairness, body_hook, churn)
    for fn in figs:
        try:
            fn()
        except FileNotFoundError as e:
            print(f"skip {fn.__name__}: missing {getattr(e, 'filename', e)}")
        except Exception as e:
            print(f"skip {fn.__name__}: {e}")


if __name__ == "__main__":
    main()
