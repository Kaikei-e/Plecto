//! A tiny self-rolled PRNG for the power-of-two-choices instance pick (ADR 000035).
//!
//! Least-request load balancing (ADR 000035) needs two uniformly-random instance indices per pick.
//! Rather than add a `rand` dependency (and the `deny.toml` / supply-chain surface a direct dep
//! brings — the same reasoning ADR 000024 used to avoid `smallvec`), we implement the published
//! **SplitMix64** algorithm (Steele, Lea & Flood, "Fast Splittable Pseudorandom Number Generators",
//! OOPSLA 2014; the reference `splitmix64.c` by Vigna is dedicated to the public domain) and
//! **Lemire's nearly-divisionless** bounded-integer method (Lemire, "Fast Random Integer Generation
//! in an Interval", ACM TOMACS 2019). Both are reimplemented here from their published descriptions,
//! not copied from any library.
//!
//! This is non-cryptographic — instance selection is not a secret — and lives off the success hot
//! path's allocation budget: one `thread_local` `u64` of state, seeded once per worker, advanced by
//! a wrapping add and a fixed mix. No locking, no shared state, no per-call syscall (unlike the
//! retry-jitter helper in `plecto-server`, which reads the wall clock each call).

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// SplitMix64's golden-ratio increment (the additive Weyl step). Public-domain reference constant.
const GOLDEN_GAMMA: u64 = 0x9E37_79B9_7F4A_7C15;

thread_local! {
    /// This worker's SplitMix64 state, seeded once on first use.
    static STATE: Cell<u64> = Cell::new(seed());
}

/// Distinct per-thread counter folded into each seed so two workers starting in the same wall-clock
/// nanosecond still get decorrelated streams. SplitMix64's finalizer is a strong decorrelator of
/// near-identical seeds — exactly the property its authors recommend it for as a seed generator.
static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Build a per-thread seed from the wall clock and a per-thread counter, pre-avalanched through the
/// finalizer so even adjacent counters yield unrelated streams.
fn seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = SEED_COUNTER.fetch_add(1, Ordering::Relaxed);
    mix(nanos ^ counter.wrapping_mul(GOLDEN_GAMMA))
}

/// SplitMix64's finalizer (a MurmurHash3-style `fmix64` variant). Constants and shifts (30, 27, 31)
/// are from the public-domain reference `splitmix64.c`.
fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// One 64-bit draw from this worker's stream: advance the state by the golden gamma (a full-period
/// Weyl sequence) and return its finalized mix.
fn next_u64() -> u64 {
    STATE.with(|s| {
        let z = s.get().wrapping_add(GOLDEN_GAMMA);
        s.set(z);
        mix(z)
    })
}

/// A uniform integer in `[0, n)` with NO modulo bias — Lemire's nearly-divisionless method. The
/// multiply-shift maps the 64-bit draw into `[0, n)`; the rare rejection (only when the low word
/// falls in the biased remainder `2^64 mod n`) costs the single division `(-n) % n`. `n` must be > 0.
pub(crate) fn below(n: u32) -> u32 {
    debug_assert!(n > 0);
    let n = n as u64;
    let mut m = (next_u64() as u128).wrapping_mul(n as u128);
    let mut l = m as u64; // low 64 bits of the 128-bit product
    if l < n {
        let threshold = n.wrapping_neg() % n; // == 2^64 mod n
        while l < threshold {
            m = (next_u64() as u128).wrapping_mul(n as u128);
            l = m as u64;
        }
    }
    (m >> 64) as u32
}

/// Two DISTINCT uniform indices in `[0, n)` for power-of-two-choices (ADR 000035); `n` must be >= 2.
/// Draw the second in `[0, n-1)` and skip past the first — unbiased, with no rejection loop.
pub(crate) fn two_distinct_below(n: u32) -> (u32, u32) {
    debug_assert!(n >= 2);
    let i = below(n);
    let mut j = below(n - 1);
    if j >= i {
        j += 1;
    }
    (i, j)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn below_stays_in_range() {
        for n in [1u32, 2, 3, 7, 10, 1000] {
            for _ in 0..10_000 {
                assert!(below(n) < n, "below({n}) must be < {n}");
            }
        }
    }

    #[test]
    fn two_distinct_are_distinct_and_in_range() {
        for n in [2u32, 3, 5, 10] {
            for _ in 0..10_000 {
                let (i, j) = two_distinct_below(n);
                assert!(i < n && j < n, "both indices in [0,{n})");
                assert_ne!(i, j, "the two picks must differ");
            }
        }
    }

    #[test]
    fn below_covers_the_range_roughly_uniformly() {
        // A coarse uniformity smoke test: every bucket of a small range is hit, and none is wildly
        // over-represented. Not a statistical test — just a guard against a stuck or biased draw.
        let n = 8u32;
        let mut counts = [0u32; 8];
        let trials = 80_000;
        for _ in 0..trials {
            counts[below(n) as usize] += 1;
        }
        let expected = trials / n;
        for (b, &c) in counts.iter().enumerate() {
            assert!(c > 0, "bucket {b} was never hit");
            assert!(
                c < expected * 2 && c > expected / 2,
                "bucket {b} count {c} is far from the expected {expected}"
            );
        }
    }

    #[test]
    fn two_distinct_covers_both_orders() {
        // Over many draws from n=2 we must see both (0,1) and (1,0) — the skip trick must not pin
        // the order.
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            seen.insert(two_distinct_below(2));
        }
        assert!(seen.contains(&(0, 1)) && seen.contains(&(1, 0)));
    }
}
