//! Build-time validation (ADR 000006 / 000020 / 000035 / 000036): reject an out-of-range
//! upstream load-balancing config or filter metering/outbound config fail-closed, before the
//! persistent state (upstream registry / host load) is ever touched.

use super::{
    FilterEntry, HashKeyKind, LbAlgorithm, MAX_HASH_TABLE_SIZE, MAX_INSTANCE_WEIGHT,
    OutboundConfig, Upstream,
};
use crate::error::ControlError;

impl Upstream {
    /// Validate this upstream's load-balancing config (ADR 000035) fail-closed at build, before the
    /// persistent registry reconciles. Checks per-instance weights, the `lb_algorithm` ↔
    /// `[upstream.hash]` correspondence, and (for Maglev) the hash key and table size. Returns the
    /// reason a caller wraps with the upstream name.
    pub(crate) fn validate_lb(&self) -> Result<(), String> {
        for spec in &self.addresses {
            let w = spec.weight();
            if w == 0 {
                return Err(format!(
                    "instance {:?} has weight 0; drain an instance by removing its address, not by zeroing weight",
                    spec.address()
                ));
            }
            if w > MAX_INSTANCE_WEIGHT {
                return Err(format!(
                    "instance {:?} weight {w} exceeds the maximum {MAX_INSTANCE_WEIGHT}",
                    spec.address()
                ));
            }
        }

        match (self.lb_algorithm, &self.hash) {
            // Maglev needs a hash key; a key with no algorithm to use it is a config mistake.
            (LbAlgorithm::Maglev, None) => {
                return Err(
                    "lb_algorithm = \"maglev\" requires a [upstream.hash] block".to_string()
                );
            }
            (algo, Some(_)) if algo != LbAlgorithm::Maglev => {
                return Err(
                    "[upstream.hash] is only valid with lb_algorithm = \"maglev\"".to_string(),
                );
            }
            _ => {}
        }

        if let Some(hash) = &self.hash {
            if hash.key == HashKeyKind::Header
                && hash
                    .header
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
            {
                return Err(
                    "[upstream.hash] key = \"header\" requires a non-empty header name".to_string(),
                );
            }
            let m = hash.table_size;
            if m > MAX_HASH_TABLE_SIZE {
                return Err(format!(
                    "[upstream.hash] table_size {m} exceeds the maximum {MAX_HASH_TABLE_SIZE}"
                ));
            }
            if !is_prime(m) {
                return Err(format!(
                    "[upstream.hash] table_size {m} must be prime (the Maglev permutation needs skip coprime to M)"
                ));
            }
            // Each instance needs at least one table entry, and the table indexes instances with a
            // u16, so the pool must fit both bounds.
            let n = self.addresses.len();
            if n > m as usize {
                return Err(format!(
                    "[upstream.hash] table_size {m} is smaller than the {n} instances"
                ));
            }
            if n > u16::MAX as usize {
                return Err(format!(
                    "maglev supports at most {} instances, got {n}",
                    u16::MAX
                ));
            }
        }
        Ok(())
    }
}

/// Trial-division primality test for the Maglev `table_size` (ADR 000035). Build-time only and `M`
/// is capped at a few million, so trial division to `√M` (~2236 iterations at the cap) is trivial;
/// no need for a probabilistic test or a dependency.
pub(super) fn is_prime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut d = 3u64;
    let n = n as u64;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

impl FilterEntry {
    /// Reject out-of-range metering / rate-limit values before they reach the host (/
    /// CWE-20): a zero deadline would make every call instantly time out, a zero memory cap is
    /// unusable, and a rate-limit bucket with `capacity == 0` or `refill_interval_ms == 0`
    /// (with refills) can never serve a token — a config typo, not an intended state. Fail-closed.
    pub(crate) fn validate(&self) -> Result<(), ControlError> {
        let bad = |reason: &str| ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason: reason.to_string(),
        };
        if self.init_deadline_ms == Some(0) {
            return Err(bad("init_deadline_ms must be non-zero"));
        }
        if self.request_deadline_ms == Some(0) {
            return Err(bad("request_deadline_ms must be non-zero"));
        }
        if self.max_memory_bytes == Some(0) {
            return Err(bad("max_memory_bytes must be non-zero"));
        }
        if let Some(rl) = self.ratelimit {
            if rl.capacity == 0 {
                return Err(bad("ratelimit.capacity must be non-zero"));
            }
            // refill_tokens == 0 is a valid one-shot (no-refill) bucket; but a positive refill with
            // a zero interval can never advance — reject that typo.
            if rl.refill_tokens > 0 && rl.refill_interval_ms == 0 {
                return Err(bad(
                    "ratelimit.refill_interval_ms must be non-zero when refill_tokens > 0",
                ));
            }
        }
        if let Some(ob) = &self.outbound {
            self.validate_outbound(ob)?;
        }
        Ok(())
    }

    /// Validate an outbound section. Without the `outbound-http` build the host cannot provide the
    /// capability, so any declared outbound is rejected (fail-closed). With it, the allowlist must be
    /// non-empty, `allow_private` CIDRs must parse, and any explicit metering value must be non-zero.
    #[cfg(not(feature = "outbound-http"))]
    fn validate_outbound(&self, _ob: &OutboundConfig) -> Result<(), ControlError> {
        Err(ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason: "outbound requested but this build lacks the `outbound-http` feature"
                .to_string(),
        })
    }

    #[cfg(feature = "outbound-http")]
    fn validate_outbound(&self, ob: &OutboundConfig) -> Result<(), ControlError> {
        let bad = |reason: String| ControlError::InvalidFilterConfig {
            id: self.id.clone(),
            reason,
        };
        if ob.allow.is_empty() {
            return Err(bad(
                "outbound.allow must list at least one destination".into()
            ));
        }
        for dest in &ob.allow {
            if dest.host.trim().is_empty() {
                return Err(bad("outbound.allow entry has an empty host".into()));
            }
            if dest.port == Some(0) {
                return Err(bad(format!("outbound.allow host {} has port 0", dest.host)));
            }
        }
        for cidr in &ob.allow_private {
            cidr.parse::<ipnet::IpNet>().map_err(|e| {
                bad(format!(
                    "outbound.allow_private has invalid CIDR {cidr:?}: {e}"
                ))
            })?;
        }
        if ob.connect_timeout_ms == Some(0) {
            return Err(bad("outbound.connect_timeout_ms must be non-zero".into()));
        }
        if ob.total_timeout_ms == Some(0) {
            return Err(bad("outbound.total_timeout_ms must be non-zero".into()));
        }
        if ob.max_response_bytes == Some(0) {
            return Err(bad("outbound.max_response_bytes must be non-zero".into()));
        }
        if ob.max_concurrent == Some(0) {
            return Err(bad("outbound.max_concurrent must be non-zero".into()));
        }
        Ok(())
    }
}
