//! Native fast-path rate limiting (ADR 000033).
//!
//! A coarse token-bucket baseline the fast path consults BEFORE a route's filter chain, so a flood
//! is shed at the front door without spending any WASM CPU. This is the operator's native *floor*
//! — distinct from the per-filter `host-ratelimit` capability (ADR 000026), which is a filter-driven
//! *policy* limiter. The bucket math is shared (`plecto_host::apply_bucket`); only the state lives
//! here, and consulting it never crosses the WASM boundary.
//!
//! Two keying modes (manifest `key`):
//! - `route` — one shared bucket: a total cap on the route regardless of client.
//! - `client-ip` — a per-client bucket keyed on the connection peer (v4 /32, v6 /64). The peer is
//!   the kernel's address, not a forgeable `X-Forwarded-For` (ADR 000018), so an attacker cannot
//!   spoof a request onto another client's bucket.
//!
//! CWE-770 (unbounded keys → OOM): a per-IP *map* would grow one entry per distinct source address,
//! so a many-source or spoofed-QUIC flood could exhaust memory. We bound it BY CONSTRUCTION — a
//! fixed-size table of buckets, the peer hashed into a slot. Memory is O(1); an attacker cannot grow
//! it at all. The cost is hash collisions (two IPs share a slot and over-throttle each other under a
//! flood), which is bounded collateral, never an allocation. The table hash is per-instance seeded,
//! so an attacker cannot pre-compute which source IPs collide with a victim's slot.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use plecto_host::{Bucket, apply_bucket};

use crate::manifest::{RateLimitKeyKind, RouteRateLimit};

/// Slots in a per-client-IP table. A power of two so `slot = hash & (N - 1)`. At 16 bytes of bucket
/// state per slot this is a fixed ~1 MiB per `client-ip` route, independent of traffic — the
/// structural CWE-770 bound. Routes with a per-IP limit are operator-declared and few.
const IP_SLOTS: usize = 1 << 16;

/// Wall-clock milliseconds — the same request clock the upstream registry uses for outlier windows
/// (ADR 000032). The token-bucket math is difference-based with `saturating_sub`, so a backward NTP
/// step just yields zero refill until the clock catches up (never spurious tokens) and a forward
/// step grants at most `capacity` extra. Monotonicity is not required.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The fast path's view of a rate-limit consult (ADR 000033).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// A token was available (or the route has no limiter) — forward.
    Allow,
    /// The bucket was empty — fail closed with 429. `retry_after_ms` is an advisory upper bound on
    /// when a token next frees up (surfaced as `Retry-After`).
    Limit { retry_after_ms: u64 },
}

/// A compiled native rate limiter for one route. Holds the token-bucket spec plus per-key state;
/// shared (`Arc`) across all requests on the route within a config generation, so a reload resets
/// the buckets — node-local and ephemeral (the floor simply re-arms full, which is safe).
pub(crate) struct NativeRateLimit {
    spec: Bucket,
    state: LimiterState,
}

// Manual: `RandomState` is not `Debug`, and dumping the bucket table would lock every cell. The
// route's `CompiledRoute`/`RouteInfo` derive `Debug`, so this keeps that cheap and lock-free.
impl std::fmt::Debug for NativeRateLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = match self.state {
            LimiterState::Route(_) => "route",
            LimiterState::ClientIp { .. } => "client-ip",
        };
        f.debug_struct("NativeRateLimit")
            .field("capacity", &self.spec.capacity)
            .field("refill_tokens", &self.spec.refill_tokens)
            .field("key", &key)
            .finish()
    }
}

enum LimiterState {
    /// One bucket shared by the whole route.
    Route(Mutex<(u64, u64)>),
    /// A fixed-size table of per-IP buckets, the peer hashed into a slot (seeded per instance).
    ClientIp {
        slots: Box<[Mutex<(u64, u64)>]>,
        hasher: RandomState,
    },
}

impl NativeRateLimit {
    /// Build a limiter from a manifest spec. `rate`/`burst` are validated non-zero by `build_active`
    /// before this runs, so the bucket always refills and can always hold at least one token.
    pub(crate) fn new(cfg: RouteRateLimit) -> Self {
        let spec = Bucket {
            capacity: cfg.burst,
            refill_tokens: cfg.rate,
            refill_interval_ms: 1000,
        };
        let state = match cfg.key {
            RateLimitKeyKind::Route => LimiterState::Route(Mutex::new((0, 0))),
            RateLimitKeyKind::ClientIp => LimiterState::ClientIp {
                // Zero-initialised: a zero cell `(0, 0)` refills from epoch on first use, so a
                // never-touched slot reads as a full bucket — no separate "first sight" sentinel.
                slots: (0..IP_SLOTS).map(|_| Mutex::new((0, 0))).collect(),
                hasher: RandomState::new(),
            },
        };
        Self { spec, state }
    }

    /// Consult the limiter for one request (cost 1). `peer` is the connection's real remote IP.
    pub(crate) fn check(&self, peer: IpAddr) -> RateLimitDecision {
        self.check_at(peer, now_millis())
    }

    /// `check` against an explicit clock — the real entry point, with `now_ms` injectable for
    /// deterministic tests (the bucket math advances purely by `now_ms`).
    // INVARIANT: `slot_for_ip` masks its hash with `len - 1` (`IP_SLOTS` is a power of two), so the
    // result is always `< slots.len()`.
    #[allow(clippy::indexing_slicing)]
    fn check_at(&self, peer: IpAddr, now_ms: u64) -> RateLimitDecision {
        let cell = match &self.state {
            LimiterState::Route(cell) => cell,
            LimiterState::ClientIp { slots, hasher } => {
                let slot = slot_for_ip(peer, hasher, slots.len());
                debug_assert!(slot < slots.len());
                &slots[slot]
            }
        };
        let mut guard = cell.lock();
        let (next, acq) = apply_bucket(Some(*guard), 1, self.spec, now_ms);
        *guard = next;
        if acq.allowed {
            RateLimitDecision::Allow
        } else {
            RateLimitDecision::Limit {
                retry_after_ms: acq.retry_after_ms,
            }
        }
    }
}

/// The fixed 8-byte key a peer hashes on: v4 /32 (the four octets) or v6 /64 (the top eight). An
/// IPv4-mapped IPv6 peer (`::ffff:a.b.c.d` on a dual-stack listener) collapses to its v4 form,
/// matching the `X-Forwarded-For` value the fast path emits (ADR 000018) so the same client is one
/// key. Coarsening v6 to /64 stops a single host evading its bucket by rotating addresses within the
/// /64 it controls.
fn ip_key_bytes(peer: IpAddr) -> [u8; 8] {
    let peer = match peer {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    match peer {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1], o[2], o[3], 0, 0, 0, 0]
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]
        }
    }
}

fn slot_for_ip(peer: IpAddr, hasher: &RandomState, len: usize) -> usize {
    let mut h = hasher.build_hasher();
    h.write(&ip_key_bytes(peer));
    (h.finish() as usize) & (len - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn route_limit(rate: u64, burst: u64, key: RateLimitKeyKind) -> NativeRateLimit {
        NativeRateLimit::new(RouteRateLimit { rate, burst, key })
    }

    #[test]
    fn route_bucket_starts_full_drains_then_refills() {
        // burst = 3, rate = 2/s, route-keyed (one shared bucket). At a pinned clock the bucket
        // starts full (the zero cell refills from epoch), so the first 3 consume, the 4th is denied.
        let rl = route_limit(2, 3, RateLimitKeyKind::Route);
        let peer = ip("203.0.113.7");
        let t0 = 1_000_000;
        for _ in 0..3 {
            assert_eq!(rl.check_at(peer, t0), RateLimitDecision::Allow);
        }
        match rl.check_at(peer, t0) {
            RateLimitDecision::Limit { retry_after_ms } => {
                // 1 token needed, 2/s refill, 1000ms interval → one whole interval away.
                assert_eq!(retry_after_ms, 1000);
            }
            RateLimitDecision::Allow => panic!("4th request over a burst of 3 must be limited"),
        }
        // After one refill interval, `rate` tokens are back.
        assert_eq!(rl.check_at(peer, t0 + 1000), RateLimitDecision::Allow);
        assert_eq!(rl.check_at(peer, t0 + 1000), RateLimitDecision::Allow);
        assert_eq!(
            rl.check_at(peer, t0 + 1000),
            RateLimitDecision::Limit {
                retry_after_ms: 1000
            },
            "only `rate` (2) tokens refill per interval, capped well under the 4th"
        );
    }

    #[test]
    fn client_ip_drains_one_peer_independently() {
        // Same peer drains its own bucket deterministically (same slot every time).
        let rl = route_limit(1, 2, RateLimitKeyKind::ClientIp);
        let a = ip("198.51.100.1");
        let t0 = 5_000_000;
        assert_eq!(rl.check_at(a, t0), RateLimitDecision::Allow);
        assert_eq!(rl.check_at(a, t0), RateLimitDecision::Allow);
        assert!(matches!(
            rl.check_at(a, t0),
            RateLimitDecision::Limit { .. }
        ));
    }

    #[test]
    fn client_ip_isolates_distinct_peers() {
        // Drain one peer's bucket, then a wide sample of other peers must still pass: only the few
        // (≈0) colliding with the drained slot could be affected. With 256 distinct IPs over 65536
        // slots, the expected collisions with one slot is ~0, so the generous bound is deterministic.
        let rl = route_limit(1, 1, RateLimitKeyKind::ClientIp);
        let t0 = 7_000_000;
        let drained = ip("192.0.2.255");
        assert_eq!(rl.check_at(drained, t0), RateLimitDecision::Allow);
        assert!(
            matches!(rl.check_at(drained, t0), RateLimitDecision::Limit { .. }),
            "the drained peer is now limited"
        );

        let allowed = (0..=255u8)
            .map(|n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n)))
            .filter(|p| *p != drained)
            .filter(|p| rl.check_at(*p, t0) == RateLimitDecision::Allow)
            .count();
        assert!(
            allowed >= 250,
            "distinct peers get independent buckets (got {allowed}/255 allowed)"
        );
    }

    #[test]
    fn ipv4_mapped_v6_collapses_to_v4_key() {
        // A dual-stack listener sees an IPv4 client as `::ffff:a.b.c.d`; it must key identically to
        // the bare v4 form so the client is one bucket, matching the emitted X-Forwarded-For.
        let v4 = ip("198.51.100.9");
        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 9).to_ipv6_mapped());
        assert_eq!(ip_key_bytes(v4), ip_key_bytes(mapped));
    }

    #[test]
    fn ipv6_key_is_the_64_prefix() {
        // Two addresses sharing a /64 collapse to the same key; a different /64 does not.
        let a = IpAddr::V6("2001:db8:abcd:1::1".parse::<Ipv6Addr>().unwrap());
        let b = IpAddr::V6(
            "2001:db8:abcd:1:ffff:ffff:ffff:ffff"
                .parse::<Ipv6Addr>()
                .unwrap(),
        );
        let other = IpAddr::V6("2001:db8:abcd:2::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ip_key_bytes(a), ip_key_bytes(b));
        assert_ne!(ip_key_bytes(a), ip_key_bytes(other));
    }
}
