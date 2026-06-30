//! MurmurHash3 (x64, 128-bit) — a self-rolled stable hash for Maglev consistent hashing (ADR
//! 000035).
//!
//! Maglev needs a hash that is (1) well-distributed (the offset/skip permutation and the key→slot
//! mapping must spread evenly — FNV's distribution is too weak for this per SMHasher) and (2)
//! DETERMINISTIC across processes and library versions (so the table and lookups agree; `std`'s
//! `DefaultHasher` is randomly seeded per process and `ahash` varies by build — both disqualified).
//! MurmurHash3 (Austin Appleby) satisfies both and is placed in the public domain by its author; it
//! is reimplemented here from the published reference, not copied from any library.
//!
//! The 128-bit output gives Maglev its TWO independent hashes (offset, skip) from one pass — the
//! low and high words avalanche independently, which double-hashing requires (Kirsch & Mitzenmacher,
//! "Less Hashing, Same Performance"). Re-seeding one hash twice would NOT be independent (shared
//! multiplicative structure), so we split a real 128-bit hash instead.

const C1: u64 = 0x87c3_7b91_1142_53d5;
const C2: u64 = 0x4cf5_ad43_2745_937f;

/// MurmurHash3's 64-bit finalizer (`fmix64`): all shifts are 33; constants from the reference.
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

/// `MurmurHash3_x64_128`: hash `data` to a 128-bit value, returned as `(low, high)` 64-bit words.
/// Reads the body little-endian so the result is identical on every platform (stable hashing). For
/// Maglev: `low` seeds the permutation offset, `high` the skip; for a request key, `low % M` is the
/// table slot.
pub(crate) fn murmur3_x64_128(data: &[u8], seed: u64) -> (u64, u64) {
    let mut h1 = seed;
    let mut h2 = seed;
    let nblocks = data.len() / 16;

    // body — full 16-byte blocks
    for i in 0..nblocks {
        let base = i * 16;
        let mut k1 = u64::from_le_bytes(data[base..base + 8].try_into().unwrap());
        let mut k2 = u64::from_le_bytes(data[base + 8..base + 16].try_into().unwrap());

        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dc_e729);

        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x3849_5ab5);
    }

    // tail — the remaining 0..15 bytes, low word (k1) and high word (k2) of the final block
    let tail = &data[nblocks * 16..];
    let tlen = tail.len();
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    if tlen >= 9 {
        for i in (8..tlen).rev() {
            k2 ^= (tail[i] as u64) << (8 * (i - 8));
        }
        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
    }
    if tlen >= 1 {
        let upto = tlen.min(8);
        for i in (0..upto).rev() {
            k1 ^= (tail[i] as u64) << (8 * i);
        }
        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
    }

    // finalization
    let len = data.len() as u64;
    h1 ^= len;
    h2 ^= len;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}

/// A single 64-bit stable hash of `data` — the low word of the 128-bit hash. Used to map a request
/// key to a Maglev table slot.
pub(crate) fn hash64(data: &[u8]) -> u64 {
    murmur3_x64_128(data, 0).0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn deterministic_across_calls() {
        // The defining property for Maglev: the same bytes always hash the same (so the table and
        // every lookup agree, across processes/restarts).
        assert_eq!(
            murmur3_x64_128(b"127.0.0.1:9000", 0),
            murmur3_x64_128(b"127.0.0.1:9000", 0)
        );
        assert_eq!(hash64(b"user-42"), hash64(b"user-42"));
    }

    #[test]
    fn distinct_inputs_diverge() {
        assert_ne!(hash64(b"a:1"), hash64(b"a:2"));
        assert_ne!(hash64(b""), hash64(b"\0"));
        let (l, h) = murmur3_x64_128(b"some-backend-name", 0);
        assert_ne!(l, h, "the two 64-bit halves are independent, not equal");
    }

    #[test]
    fn handles_all_tail_lengths_without_panic() {
        // Tail handling covers lengths 0..16 (and beyond); exercise each so an off-by-one in the
        // byte-shift loop would surface (data-plane no-panic on arbitrary key bytes).
        for len in 0..40usize {
            let data: Vec<u8> = (0..len as u8).collect();
            let _ = murmur3_x64_128(&data, 0);
        }
    }

    #[test]
    fn spreads_sequential_keys() {
        // Sequential keys (user-0, user-1, …) must not collide on a small modulus en masse — a coarse
        // dispersion guard for the key→slot mapping.
        let m = 97u64;
        let mut slots = HashSet::new();
        for i in 0..80 {
            slots.insert(hash64(format!("user-{i}").as_bytes()) % m);
        }
        assert!(
            slots.len() > 40,
            "sequential keys should spread across slots"
        );
    }
}
