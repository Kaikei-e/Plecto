//! Weighted Maglev consistent hashing (ADR 000035): a precomputed lookup table that maps a request
//! hash key to a STABLE instance, for session affinity / backend-cache locality.
//!
//! ## The construction (general algorithm, not a library port)
//!
//! Each backend `i` gets a permutation of the table positions from two independent hashes of its
//! name — `offset = h1(name) mod M`, `skip = h2(name) mod (M−1) + 1` — so `(offset + j·skip) mod M`
//! enumerates all of `0..M` when `M` is prime (`skip` is then coprime to `M`). The table is filled
//! by letting backends take turns claiming their most-preferred still-empty slot (Maglev, Eisenbud
//! et al., NSDI 2016, Pseudocode 1), which gives each backend `⌊M/N⌋..⌈M/N⌉` entries — near-perfect
//! balance.
//!
//! The Maglev paper deliberately omits how to WEIGHT backends ("by altering the relative frequency
//! of the backends' turns; the implementation details are not described"). We implement the
//! **smooth weighted-frequency** generalisation (a backend of weight `w` takes a turn every
//! `max_weight / w` rounds): it needs only `M ≥ N`, gives every positive-weight backend at least one
//! entry in the first round (no zero-entry corner case), and reduces to the paper's plain round-robin
//! when all weights are equal. This is the de-facto technique across the field (Envoy / Cilium /
//! Katran-V2 converged on it); we implement the documented algorithm from first principles, not
//! their code.
//!
//! ## Stability across health flips
//!
//! The table is built over the FULL instance set and is rebuilt only when that set changes (a
//! reconcile), NOT when an instance's health bit flips — so affinity survives a transient eject.
//! `UpstreamGroup::pick` looks up `table[hash(key) mod M]`, returns that instance when it is
//! eligible, and otherwise falls back to the healthy-set round-robin (the affinity target is down →
//! best-effort, the same fail-soft Envoy uses).

use crate::hash::murmur3_x64_128;

/// A precomputed Maglev lookup table (ADR 000035). `table[slot]` is an index into the upstream
/// group's `instances`, so a lookup is one modulo + one array read. `u16` entries: an upstream is
/// validated to hold at most `u16::MAX` instances.
#[derive(Debug)]
pub(crate) struct MaglevTable {
    table: Box<[u16]>,
}

impl MaglevTable {
    /// Build the table for `entries` (`(instance name, weight)`, in instance order) at size `m`.
    /// `m` MUST be prime and `>= entries.len() >= 1`, and every weight `>= 1` — all guaranteed by
    /// the manifest's build-time validation (`Upstream::validate_lb`). Runs the weighted-frequency
    /// populate once; the result is a stable schedule reused for the life of the group.
    // INVARIANT: `offset`/`skip`/`weights`/`target`/`next` all have length `n` (built together,
    // just below), and every index into them is bounded by `0..n`; `entry`/`table` are bounded by
    // `0..m`. The debug_assert!s pin this so the indexing below is checked in debug/test builds.
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn build(entries: &[(&str, u32)], m: usize) -> Self {
        let n = entries.len();
        // Per-backend permutation parameters from two independent hashes (the 128-bit halves).
        let mut offset = vec![0usize; n];
        let mut skip = vec![0usize; n];
        for (i, (name, _)) in entries.iter().enumerate() {
            let (h1, h2) = murmur3_x64_128(name.as_bytes(), 0);
            offset[i] = (h1 % m as u64) as usize;
            // skip ∈ [1, M−1] so it is coprime to the prime M (a 0 skip would freeze the permutation).
            skip[i] = (h2 % (m as u64 - 1)) as usize + 1;
        }

        let weights: Vec<u64> = entries.iter().map(|(_, w)| *w as u64).collect();
        let max_w = weights.iter().copied().max().unwrap_or(1).max(1);
        debug_assert_eq!(offset.len(), n);
        debug_assert_eq!(skip.len(), n);
        debug_assert_eq!(weights.len(), n);

        // `target[i]` seeded to `weight[i]` makes round 1 place every positive-weight backend (so
        // each gets >= 1 entry); thereafter backend `i` takes a turn every `max_w / weight[i]` rounds.
        let mut target = weights.clone();
        let mut next = vec![0usize; n];
        let mut entry = vec![-1i64; m];
        let mut filled = 0usize;
        let mut round = 0u64;
        debug_assert_eq!(target.len(), n);
        debug_assert_eq!(next.len(), n);
        debug_assert_eq!(entry.len(), m);

        'fill: while filled < m {
            round += 1;
            for i in 0..n {
                if weights[i] == 0 {
                    continue; // defensive: validation forbids weight 0, but never loop forever on it
                }
                if round * weights[i] < target[i] {
                    continue; // not this backend's turn yet
                }
                target[i] += max_w;
                // Probe this backend's permutation for its most-preferred empty slot. A prime M makes
                // the sequence a full permutation, so an empty slot is found within M steps whenever
                // one exists (filled < m) — the inner loop always terminates.
                let mut c = (offset[i] + next[i].wrapping_mul(skip[i])) % m;
                while entry[c] >= 0 {
                    next[i] += 1;
                    c = (offset[i] + next[i].wrapping_mul(skip[i])) % m;
                }
                entry[c] = i as i64;
                next[i] += 1;
                filled += 1;
                if filled == m {
                    break 'fill;
                }
            }
        }

        let table: Vec<u16> = entry.iter().map(|&e| e as u16).collect();
        Self {
            table: table.into_boxed_slice(),
        }
    }

    /// The instance index a request key maps to: `key_hash mod M`, then the table entry. The caller
    /// hashes the key (header bytes or peer-IP octets) so this stays allocation-free. Returns `None`
    /// only on an empty table (never built that way; guarded for data-plane no-panic).
    // INVARIANT: slot = key_hash % m, so slot < m == self.table.len() always (checked below).
    #[allow(clippy::indexing_slicing)]
    pub(crate) fn lookup(&self, key_hash: u64) -> Option<usize> {
        let m = self.table.len();
        if m == 0 {
            return None;
        }
        let slot = (key_hash % m as u64) as usize;
        debug_assert!(slot < self.table.len());
        Some(self.table[slot] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash64;
    use std::collections::HashMap;

    /// Look up a string key (hashing it the way `UpstreamGroup::pick` does).
    fn lk(t: &MaglevTable, key: &str) -> usize {
        t.lookup(hash64(key.as_bytes())).unwrap()
    }

    fn counts(entries: &[(&str, u32)], m: usize, draws: usize) -> HashMap<usize, usize> {
        let t = MaglevTable::build(entries, m);
        let mut c = HashMap::new();
        for i in 0..draws {
            *c.entry(lk(&t, &format!("key-{i}"))).or_insert(0) += 1;
        }
        c
    }

    #[test]
    fn fills_every_slot_unweighted() {
        // Each of N equal-weight backends gets ⌊M/N⌋..⌈M/N⌉ entries (differ by <= 1) and the table
        // is fully populated.
        let entries = [("a:1", 1), ("b:2", 1), ("c:3", 1)];
        let m = 97;
        let t = MaglevTable::build(&entries, m);
        let mut per = [0usize; 3];
        for &e in t.table.iter() {
            per[e as usize] += 1;
        }
        assert_eq!(per.iter().sum::<usize>(), m, "table fully filled");
        let (lo, hi) = (per.iter().min().unwrap(), per.iter().max().unwrap());
        assert!(hi - lo <= 1, "balanced to within one entry: {per:?}");
    }

    #[test]
    fn same_key_maps_to_same_instance() {
        // The affinity property: a key always resolves to the same instance.
        let entries = [("a:1", 1), ("b:2", 1), ("c:3", 1)];
        let t = MaglevTable::build(&entries, 97);
        assert_eq!(lk(&t, "session-xyz"), lk(&t, "session-xyz"));
    }

    #[test]
    fn keys_spread_across_instances() {
        // Distinct keys land on every backend (a single backend would mean a broken permutation).
        let c = counts(&[("a:1", 1), ("b:2", 1), ("c:3", 1)], 97, 3000);
        assert_eq!(c.len(), 3, "all three backends receive traffic");
    }

    #[test]
    fn weight_biases_table_share() {
        // A weight-3 backend should claim roughly 3× the entries (and traffic) of a weight-1 one.
        let entries = [("big", 3), ("small", 1)];
        let m = 1009;
        let t = MaglevTable::build(&entries, m);
        let big = t.table.iter().filter(|&&e| e == 0).count();
        let small = t.table.iter().filter(|&&e| e == 1).count();
        assert_eq!(big + small, m);
        // ideal 3:1 → big ≈ 757, small ≈ 252. Allow generous slack for the discrete schedule.
        let ratio = big as f64 / small as f64;
        assert!(
            (2.5..3.5).contains(&ratio),
            "weight-3 backend should get ~3× share, got ratio {ratio:.2} ({big} vs {small})"
        );
    }

    #[test]
    fn tiny_weight_still_gets_an_entry() {
        // The zero-entry corner case the weighted-frequency seed avoids: even a weight-1 backend
        // against a weight-1000 one gets at least one slot (never silently starved).
        let entries = [("huge", 1000), ("tiny", 1)];
        let t = MaglevTable::build(&entries, 1009);
        let tiny = t.table.iter().filter(|&&e| e == 1).count();
        assert!(
            tiny >= 1,
            "a positive-weight backend always gets >= 1 entry"
        );
    }

    #[test]
    fn single_instance_takes_the_whole_table() {
        let t = MaglevTable::build(&[("only", 1)], 17);
        assert!(t.table.iter().all(|&e| e == 0));
        assert_eq!(lk(&t, "anything"), 0);
    }

    #[test]
    fn minimal_disruption_on_add() {
        // Adding a backend should move only a minority of keys (consistent hashing's point). With 3→4
        // equal backends the ideal churn is ~1/4; assert well under half move.
        let three = MaglevTable::build(&[("a", 1), ("b", 1), ("c", 1)], 1009);
        let four = MaglevTable::build(&[("a", 1), ("b", 1), ("c", 1), ("d", 1)], 1009);
        let moved = (0..5000)
            .filter(|i| lk(&three, &format!("key-{i}")) != lk(&four, &format!("key-{i}")))
            .count();
        assert!(
            moved < 5000 / 2,
            "adding one of four backends moved {moved}/5000 keys — expected well under half"
        );
    }
}
