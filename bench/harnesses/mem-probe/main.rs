//! mem-probe — Stage 1 mechanistic probe for the "body tax" memory investigation
//! (docs/plans/performance_evolution_001.md).
//!
//! It drives the host's public `on-request-body` hook DIRECTLY — no server, proxy, upstream, or
//! load generator — so the only memory in motion is (A) the host↔guest body-copy round-trip and
//! (B) the wasmtime pooling allocator's residency. That isolation is the whole point: the published
//! ~317 MB was a single VmRSS snapshot of a process that ALSO held an in-process upstream, fast-path
//! buffers and allocator arenas, so it could not attribute the cost. Here nothing else allocates.
//!
//! For each (filter × isolation × payload) cell it builds a FRESH host (empty pool), loads + inits
//! the filter, then reads two instruments the plan calls for:
//!   - `/proc/self/smaps_rollup` deltas (Rss / Pss / Private_Dirty / Referenced). This captures the
//!     GUEST linear memory too (wasmtime mmaps it, so it never shows on the Rust heap) — the (A)
//!     signal. A trusted/pooled instance's linear memory grows to fit the body and never shrinks,
//!     so its post-call RSS growth is the persistent per-instance body footprint.
//!   - `PoolingAllocatorMetrics::unused_memory_bytes_resident()` — bytes kept resident for
//!     unused-but-warm pool slots (the (B) signal). `linear_memory_keep_resident` is unset (default
//!     0), so this is expected to read ~0, refuting (B) in its "keep-resident" form.
//!
//! Optional dhat (`--features dhat-heap`) reports the HOST-heap peak (the lifted output body copy).
//! dhat sees only the Rust heap, not the guest linear memory, so it and smaps are complementary.
//!
//! Run:
//!   cargo run --release -p plecto-host --example mem-probe
//!   cargo run --release -p plecto-host --example mem-probe --features dhat-heap   # + host-heap peak
//!   PAYLOADS=1024,102400,1048576 ITERS=200 cargo run --release -p plecto-host --example mem-probe

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use plecto_host::test_support::{
    TestSigner, bound_sbom, filter_hello_component, filter_noop_component,
};
use plecto_host::{Host, LoadOptions, RequestTrace, SignedArtifact};

/// A `/proc/self/smaps_rollup` snapshot, in bytes. `private_dirty` is the load-bearing column: the
/// anonymous, written, unshared pages — where the guest linear-memory writes and host heap land.
#[derive(Clone, Copy, Default)]
struct Rollup {
    rss: u64,
    private_dirty: u64,
}

fn smaps_rollup() -> Rollup {
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap_or_default();
    let mut r = Rollup::default();
    for line in text.lines() {
        // Lines look like `Rss:               12345 kB`.
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let kb: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let bytes = kb * 1024;
        match key {
            "Rss:" => r.rss = bytes,
            "Private_Dirty:" => r.private_dirty = bytes,
            _ => {}
        }
    }
    r
}

/// Owned bytes for one signed artifact, so a borrowed `SignedArtifact` can point into it.
struct Art {
    component: Vec<u8>,
    csig: Vec<u8>,
    sbom: Vec<u8>,
    ssig: Vec<u8>,
}

impl Art {
    fn new(signer: &TestSigner, component: Vec<u8>) -> anyhow::Result<Self> {
        let csig = signer.sign(&component)?;
        let sbom = bound_sbom(&component);
        let ssig = signer.sign(&sbom)?;
        Ok(Self {
            component,
            csig,
            sbom,
            ssig,
        })
    }
    fn signed(&self) -> SignedArtifact<'_> {
        SignedArtifact {
            component_bytes: &self.component,
            component_signature: &self.csig,
            sbom: &self.sbom,
            sbom_signature: &self.ssig,
        }
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn payloads() -> Vec<usize> {
    match std::env::var("PAYLOADS") {
        Ok(s) => s.split(',').filter_map(|p| p.trim().parse().ok()).collect(),
        Err(_) => vec![1024, 102_400, 1_048_576],
    }
}

/// One measurement cell: display name, the fixture's component-bytes accessor, and whether it runs
/// trusted (pooled) or untrusted (fresh-per-request).
type Cell = (&'static str, fn() -> Vec<u8>, bool);

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let iters = env_usize("ITERS", 200);
    let payloads = payloads();

    // Each cell gets its OWN signer/trust + host so the pool starts empty and metrics are per-cell.
    // (filter, isolation): the four corners of the 2×2 — hello vs noop isolates the transform
    // allocation (③ uppercase); trusted vs untrusted isolates pooling / persistent-growth (B).
    let cells: &[Cell] = &[
        ("hello/trusted", filter_hello_component, true),
        ("noop/trusted", filter_noop_component, true),
        ("hello/untrusted", filter_hello_component, false),
        ("noop/untrusted", filter_noop_component, false),
    ];

    println!("# mem-probe — direct on_request_body, no server/proxy/upstream. iters={iters}");
    println!("# bytes unless noted. d_first = RSS growth from the first body call (guest linear");
    println!(
        "#   memory grown to hold the body, persistent for pooled); d_steady = growth over the"
    );
    println!(
        "#   next {iters} same-size calls (≈0 = plateaued). unused_resident = pooling (B) signal."
    );
    println!(
        "{:<16} {:>9} {:>10} {:>10} {:>11} {:>11} {:>11} {:>9} {:>6}",
        "cell",
        "payload",
        "d_first",
        "d_steady",
        "pd_first",
        "pd_steady",
        "unused_res",
        "mems",
        "xfoot"
    );

    let trace = RequestTrace::root();
    for (name, component_fn, trusted) in cells {
        for &size in &payloads {
            let signer = TestSigner::new()?;
            let host = Host::new(signer.trust_policy()?)?;
            let art = Art::new(&signer, component_fn())?;
            let opts = if *trusted {
                LoadOptions::trusted()
            } else {
                LoadOptions::untrusted()
            };
            let loaded = host.load("probe", &art.signed(), opts)?;

            // A body of all 'a' (no "deny-body" marker) → filter-hello uppercases it and returns
            // `continue(body)`; filter-noop returns it untouched. Either way the full body crosses
            // into guest linear memory and (for continue) a copy is lifted back out.
            let body = vec![b'a'; size];

            let rss0 = smaps_rollup();
            let _ = loaded.on_request_body(&body, &trace)?; // first call: grows guest memory
            let rss1 = smaps_rollup();
            for _ in 0..iters {
                let _ = loaded.on_request_body(&body, &trace)?;
            }
            let rss2 = smaps_rollup();

            let (unused_res, mems) = match host.pooling_allocator_metrics() {
                Some(m) => (m.unused_memory_bytes_resident() as u64, m.memories() as u64),
                None => (0, 0), // untrusted → on-demand engine → no pooling metrics
            };

            // xfoot = d_first / payload, the per-request persistent footprint multiplier (the (A)
            // number for pooled cells; for untrusted the instance is dropped, so this reads ~0).
            let xfoot = rss1.rss.saturating_sub(rss0.rss) as f64 / size as f64;

            println!(
                "{:<16} {:>9} {:>10} {:>10} {:>11} {:>11} {:>11} {:>9} {:>6.2}",
                name,
                size,
                rss1.rss.saturating_sub(rss0.rss),
                rss2.rss.saturating_sub(rss1.rss),
                rss1.private_dirty.saturating_sub(rss0.private_dirty),
                rss2.private_dirty.saturating_sub(rss1.private_dirty),
                unused_res,
                mems,
                xfoot,
            );
        }
    }

    #[cfg(feature = "dhat-heap")]
    println!(
        "\n# dhat: host-heap peak written to dhat-heap.json (view at https://nnethercote.github.io/dh_view/dh_view.html)"
    );
    Ok(())
}
