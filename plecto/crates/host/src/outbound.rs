//! Outbound HTTP capability policy (ADR 000036).
//!
//! When a filter is lent `wasi:http/outgoing-handler`, every call it makes is gated by two
//! independent checks that this module owns:
//!
//! 1. **Outbound allowlist** — an operator-declared set of exact `(scheme, host, port)` triples.
//!    Deny-by-default: a destination not on the list is rejected. The filter cannot supply or widen
//!    it (the same "operator owns the limit" shape as `host-ratelimit`, ADR 000026).
//! 2. **SSRF guard** — classification of the *resolved* IP. link-local (cloud metadata), loopback,
//!    unspecified, multicast and other reserved ranges are blocked regardless of the allowlist (the
//!    rebinding floor); RFC1918 / ULA private ranges are blocked unless the operator opted in with a
//!    covering CIDR. The guard runs on the address the host itself resolved, so a name that passes
//!    the allowlist but resolves to a blocked IP is still rejected (defeats DNS rebinding).
//!
//! This module is the pure policy — no wasmtime, no I/O. The wiring that resolves DNS, pins the
//! vetted IP, connects, and bounds the call lives in [`super::outbound_http`] (feature-gated). The
//! deny ranges below are hand-written octet predicates (transparent + auditable, and not dependent
//! on unstable `IpAddr` methods like `is_global`); only the operator `allow_private` opt-in uses
//! `ipnet` for CIDR containment. The range set follows the OWASP SSRF Prevention algorithm.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// URL scheme a filter may target. `https` is the default; `http` is only reachable when an
/// allowlist entry names it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// The default port for this scheme, used when an allowlist entry (or a request authority)
    /// omits the port.
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// One operator-declared allowed destination: an EXACT `(scheme, host, port)` triple. No wildcards
/// or suffix matching — the target use cases (JWKS / introspection / ext_authz) are fixed endpoints,
/// and exact matching is the most auditable deny-by-default form (ADR 000036).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub scheme: Scheme,
    /// Exact host: a DNS name (matched case-insensitively) or an IP literal.
    pub host: String,
    pub port: u16,
}

/// The verdict of classifying a single resolved IP against the SSRF guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrVerdict {
    /// A global unicast address, or a private address the operator explicitly opted into.
    Allowed,
    /// A reserved range blocked regardless of the allowlist or opt-in (the rebinding floor):
    /// loopback, link-local (incl. cloud metadata), unspecified, multicast, broadcast, and other
    /// non-routable/reserved space.
    BlockedReserved,
    /// An RFC1918 / ULA private address that the operator did not opt into for this filter.
    BlockedPrivate,
}

/// The per-filter outbound policy the host enforces at the `send_request` seam. Built from the
/// manifest `[filter.outbound]` section via `LoadOptions` (values already clamped to host maxima).
#[derive(Debug, Clone)]
pub struct OutboundPolicy {
    /// Exact allowed destinations. Empty means the filter can reach nothing (deny-by-default).
    pub allow: Vec<AllowEntry>,
    /// Private/ULA ranges the operator opted this filter into (e.g. an internal ext_authz subnet).
    /// Empty (the default) leaves all private space blocked. Never opens the reserved floor.
    pub allow_private: Vec<IpNet>,
    /// Timeout for establishing the TCP connection to a vetted address.
    pub connect_timeout: std::time::Duration,
    /// Wall-clock ceiling for the whole outbound call (connect + request + response). Bounds the
    /// blocking host call that epoch interruption cannot reach (ADR 000006 / 000036).
    pub total_timeout: std::time::Duration,
    /// Cap on the response body the host will buffer/forward back to the guest (CWE-770).
    pub max_response_bytes: u64,
    /// Cap on concurrent in-flight outbound calls for this filter.
    pub max_concurrent: u32,
}

impl OutboundPolicy {
    /// Whether `(scheme, host, port)` is on the allowlist. Host comparison is ASCII-case-insensitive
    /// (DNS is case-insensitive); scheme and port must match exactly.
    pub fn allows(&self, scheme: Scheme, host: &str, port: u16) -> bool {
        self.allow
            .iter()
            .any(|e| e.scheme == scheme && e.port == port && e.host.eq_ignore_ascii_case(host))
    }

    /// Classify a resolved IP against the SSRF guard, honoring this filter's `allow_private` opt-in.
    pub fn classify(&self, ip: IpAddr) -> AddrVerdict {
        classify(ip, &self.allow_private)
    }
}

/// Classify a resolved IP: reserved floor first (allowlist-independent), then private (opt-in),
/// else allowed. Pure function — the core of the SSRF guard.
pub fn classify(ip: IpAddr, allow_private: &[IpNet]) -> AddrVerdict {
    let canonical = canonicalize(ip);
    if is_always_blocked(canonical) {
        return AddrVerdict::BlockedReserved;
    }
    if is_private(canonical) {
        return if allow_private.iter().any(|net| net.contains(&canonical)) {
            AddrVerdict::Allowed
        } else {
            AddrVerdict::BlockedPrivate
        };
    }
    AddrVerdict::Allowed
}

/// Collapse an IPv6 address that merely *embeds* an IPv4 address (IPv4-mapped `::ffff:a.b.c.d` and
/// the deprecated IPv4-compatible `::a.b.c.d`) down to that IPv4 address, so the v4 range checks
/// apply and an attacker cannot smuggle a blocked v4 target through a v6 wrapper.
fn canonicalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            // IPv4-compatible ::a.b.c.d (high 96 bits zero), excluding :: and ::1 which are their
            // own reserved addresses handled by the v6 predicates.
            let seg = v6.segments();
            if seg[0..6].iter().all(|&s| s == 0) && !v6.is_loopback() && !v6.is_unspecified() {
                let [a, b] = seg[6].to_be_bytes();
                let [c, d] = seg[7].to_be_bytes();
                return IpAddr::V4(Ipv4Addr::new(a, b, c, d));
            }
            IpAddr::V6(v6)
        }
        v4 => v4,
    }
}

/// The rebinding floor: ranges blocked regardless of the allowlist or the private opt-in.
fn is_always_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => v4_always_blocked(a),
        IpAddr::V6(a) => v6_always_blocked(a),
    }
}

fn v4_always_blocked(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()            // 127.0.0.0/8
        || a.is_link_local()   // 169.254.0.0/16 — includes the cloud metadata endpoint
        || a.is_broadcast()    // 255.255.255.255
        || a.is_multicast()    // 224.0.0.0/4
        || a.is_documentation()// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET)
        || o[0] == 0                                   // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)      // 100.64.0.0/10 CGNAT (RFC 6598)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 IETF protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18)        // 198.18.0.0/15 benchmarking
        || (o[0] & 0xf0) == 240 // 240.0.0.0/4 reserved (future use), incl. 255.0.0.0/8
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private(), // 10/8, 172.16/12, 192.168/16
        IpAddr::V6(a) => (a.segments()[0] & 0xfe00) == 0xfc00, // fc00::/7 ULA
    }
}

fn v6_always_blocked(a: Ipv6Addr) -> bool {
    let seg = a.segments();
    a.is_loopback()          // ::1
        || a.is_unspecified()// ::
        || a.is_multicast()  // ff00::/8
        || (seg[0] & 0xffc0) == 0xfe80                 // fe80::/10 link-local
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)      // 2001:db8::/32 documentation
        || (seg[0] == 0x2001 && seg[1] == 0x0000)      // 2001::/32 Teredo (embeds a v4 endpoint)
        || (seg[0] == 0x0064 && seg[1] == 0xff9b)      // 64:ff9b::/96 NAT64 (embeds a v4 endpoint)
        || (seg[0] == 0x0100 && seg[1..4].iter().all(|&s| s == 0)) // 100::/64 discard-only
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    // --- SSRF floor: always blocked regardless of opt-in ---

    #[test]
    fn cloud_metadata_is_always_blocked() {
        // The canonical cloud metadata endpoint is link-local; block it even with a wide opt-in.
        let wide = vec![net("0.0.0.0/0")];
        assert_eq!(
            classify(ip("169.254.169.254"), &wide),
            AddrVerdict::BlockedReserved
        );
        assert_eq!(
            classify(ip("169.254.169.254"), &[]),
            AddrVerdict::BlockedReserved
        );
    }

    #[test]
    fn loopback_link_local_unspecified_multicast_blocked() {
        for s in [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "169.254.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
        ] {
            assert_eq!(classify(ip(s), &[]), AddrVerdict::BlockedReserved, "{s}");
        }
    }

    #[test]
    fn other_v4_reserved_ranges_blocked() {
        for s in [
            "100.64.0.1",  // CGNAT
            "192.0.0.1",   // IETF protocol
            "198.18.0.1",  // benchmarking
            "192.0.2.5",   // TEST-NET-1
            "203.0.113.9", // TEST-NET-3
            "240.0.0.1",   // reserved future use
        ] {
            assert_eq!(classify(ip(s), &[]), AddrVerdict::BlockedReserved, "{s}");
        }
    }

    #[test]
    fn v4_mapped_and_compat_v6_reclassify_to_embedded_v4() {
        // An attacker must not smuggle a blocked v4 target through a v6 wrapper.
        assert_eq!(
            classify(ip("::ffff:169.254.169.254"), &[]),
            AddrVerdict::BlockedReserved
        );
        assert_eq!(
            classify(ip("::ffff:127.0.0.1"), &[]),
            AddrVerdict::BlockedReserved
        );
        // IPv4-compatible ::a.b.c.d
        assert_eq!(classify(ip("::10.0.0.5"), &[]), AddrVerdict::BlockedPrivate);
        // A mapped *public* v4 is allowed.
        assert_eq!(classify(ip("::ffff:8.8.8.8"), &[]), AddrVerdict::Allowed);
    }

    #[test]
    fn nat64_and_teredo_blocked() {
        assert_eq!(
            classify(ip("64:ff9b::8.8.8.8"), &[]),
            AddrVerdict::BlockedReserved
        );
        assert_eq!(
            classify(ip("2001:0:1:2::"), &[]),
            AddrVerdict::BlockedReserved
        );
        assert_eq!(
            classify(ip("2001:db8::1"), &[]),
            AddrVerdict::BlockedReserved
        );
    }

    // --- private ranges: opt-in ---

    #[test]
    fn private_blocked_without_optin() {
        for s in [
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "fc00::1",
            "fd12::abcd",
        ] {
            assert_eq!(classify(ip(s), &[]), AddrVerdict::BlockedPrivate, "{s}");
        }
    }

    #[test]
    fn private_allowed_only_within_optin_cidr() {
        let optin = vec![net("10.1.0.0/16")];
        assert_eq!(classify(ip("10.1.2.3"), &optin), AddrVerdict::Allowed);
        // A private address outside the opted-in subnet stays blocked (defense in depth).
        assert_eq!(
            classify(ip("10.2.0.1"), &optin),
            AddrVerdict::BlockedPrivate
        );
        assert_eq!(
            classify(ip("192.168.0.1"), &optin),
            AddrVerdict::BlockedPrivate
        );
    }

    #[test]
    fn optin_never_opens_the_reserved_floor() {
        // Even opting into everything cannot reach metadata/loopback.
        let optin = vec![net("0.0.0.0/0"), net("::/0")];
        assert_eq!(
            classify(ip("169.254.169.254"), &optin),
            AddrVerdict::BlockedReserved
        );
        assert_eq!(
            classify(ip("127.0.0.1"), &optin),
            AddrVerdict::BlockedReserved
        );
    }

    #[test]
    fn ula_optin() {
        let optin = vec![net("fd00::/8")];
        assert_eq!(classify(ip("fd12::1"), &optin), AddrVerdict::Allowed);
        assert_eq!(classify(ip("fc00::1"), &optin), AddrVerdict::BlockedPrivate);
    }

    // --- global unicast allowed ---

    #[test]
    fn public_addresses_allowed() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert_eq!(classify(ip(s), &[]), AddrVerdict::Allowed, "{s}");
        }
    }

    // --- allowlist matching ---

    fn policy(entries: Vec<AllowEntry>) -> OutboundPolicy {
        OutboundPolicy {
            allow: entries,
            allow_private: vec![],
            connect_timeout: std::time::Duration::from_secs(2),
            total_timeout: std::time::Duration::from_secs(5),
            max_response_bytes: 64 * 1024,
            max_concurrent: 8,
        }
    }

    #[test]
    fn allowlist_exact_match_case_insensitive_host() {
        let p = policy(vec![AllowEntry {
            scheme: Scheme::Https,
            host: "authz.example.com".into(),
            port: 443,
        }]);
        assert!(p.allows(Scheme::Https, "authz.example.com", 443));
        assert!(p.allows(Scheme::Https, "AUTHZ.Example.COM", 443)); // DNS case-insensitive
        assert!(!p.allows(Scheme::Http, "authz.example.com", 443)); // scheme must match
        assert!(!p.allows(Scheme::Https, "authz.example.com", 8443)); // port must match
        assert!(!p.allows(Scheme::Https, "evil.example.com", 443)); // exact host only
        assert!(!p.allows(Scheme::Https, "sub.authz.example.com", 443)); // no suffix match
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let p = policy(vec![]);
        assert!(!p.allows(Scheme::Https, "authz.example.com", 443));
    }
}
