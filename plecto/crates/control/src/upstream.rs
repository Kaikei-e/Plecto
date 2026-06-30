//! Upstream instances, active-health-check state, and round-robin load balancing (ADR 000017).
//!
//! A manifest [`Upstream`] becomes a [`UpstreamGroup`] of [`UpstreamInstance`]s. Each instance
//! owns a single health state machine fed by BOTH sources: the background active-health prober
//! (the fast-path server runs it) and passive signals from real forwarded requests (a connect
//! failure demotes). The fast path picks a healthy instance per request by round-robin; when none
//! are healthy the upstream is fail-closed (the server responds 503).
//!
//! **The registry lives on `Control`, OUTSIDE the atomically-swapped `ActiveConfig`**, so health
//! state SURVIVES a reload (ADR 000017). [`UpstreamRegistry::reconcile`] diffs the manifest's
//! upstreams against the running set by `(name, address)`: an unchanged instance keeps its health,
//! a new address starts pessimistic (unhealthy), a removed one is dropped. Routing's
//! `CompiledRoute` holds an `Arc<UpstreamGroup>` rebuilt to point at the reconciled group on every
//! reload, so the per-request hot path never touches the registry lock.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::ControlError;
use crate::maglev::MaglevTable;
use crate::manifest::{HashKeyKind, HealthConfig, LbAlgorithm, Upstream};
use crate::rng;

/// Upper bound on the outlier ejection-time exponential backoff (ADR 000032): the window is
/// `base · 2^min(eject_count, cap)`, so the cap bounds it at `base · 2^6` (64×) however many times an
/// instance flaps.
const OUTLIER_BACKOFF_SHIFT_CAP: u32 = 6;

/// Wall-clock milliseconds since the epoch, for outlier-ejection windows (ADR 000032). Non-monotonic,
/// but the windows are coarse (seconds), so a backward clock step merely shortens or lengthens one
/// window — never a panic on untrusted input.
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Whether instance `a` has the lower `(in_flight + 1) / weight` than `b` (ADR 000035) — the
/// weighted least-request comparison, by integer cross-product so there is no float, and a tie keeps
/// `a` (the first sampled). `u128` keeps the product overflow-free for any `in_flight` / `weight`.
fn lower_load(a: &Arc<UpstreamInstance>, b: &Arc<UpstreamInstance>) -> bool {
    let la = (a.in_flight() as u128 + 1) * b.weight() as u128;
    let lb = (b.in_flight() as u128 + 1) * a.weight() as u128;
    la <= lb
}

/// One backend instance (`host:port`) of an upstream, with its health state (ADR 000017).
///
/// The hot path (`pick` → [`UpstreamInstance::is_healthy`]) reads a lock-free `AtomicBool`. State
/// transitions take a small per-instance `Mutex` so "increment a counter, compare the threshold,
/// flip the bit, reset" is race-free — but the mutex is touched only on a probe (cold, every
/// interval) or a passive connect failure (rare), never on the success hot path.
#[derive(Debug)]
pub struct UpstreamInstance {
    address: String,
    /// Load-balancing weight (ADR 000035): biases the least-request comparison and the Maglev table
    /// share toward higher-capacity instances. `1` for a bare address. Immutable for the instance's
    /// life; a weight change builds a fresh instance on reconcile (like a health-policy change).
    weight: u32,
    /// The lock-free read surface for `pick`. Written only while holding `counters`.
    healthy: AtomicBool,
    /// Active forwarded-request count to THIS instance (ADR 000035), the least-request load signal.
    /// Incremented when an attempt selects this instance and decremented when the attempt ends (RAII,
    /// across retries). Distinct from the per-group circuit-breaker in-flight (ADR 000028): that caps
    /// the upstream's saturation, this drives per-instance selection. Only touched under
    /// `least_request`; round-robin / maglev leave it at 0.
    in_flight: AtomicUsize,
    counters: Mutex<HealthCounters>,
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    /// Outlier ejection deadline (ms since epoch, `0` = not ejected); the lock-free read surface for
    /// `pick` (ADR 000032). Written by `record_outcome` while holding `counters`. Time-based, so it
    /// auto-expires when the window passes — independent of the `healthy` bit (a separate axis).
    outlier_ejected_until_ms: AtomicU64,
}

#[derive(Debug)]
struct HealthCounters {
    consecutive_ok: u32,
    consecutive_fail: u32,
    /// Whether this instance has EVER been healthy. While `false`, a single successful probe
    /// promotes it (cold-start fast path, ADR 000017); afterwards the full `healthy_threshold`
    /// applies for re-entry after an eject.
    ever_healthy: bool,
    /// Consecutive gateway-class 5xx on live traffic, for outlier detection (ADR 000032). Reset by a
    /// non-failure outcome; reaching the policy threshold ejects the instance.
    consecutive_gw_fail: u32,
    /// How many times this instance has been outlier-ejected, for the exponential ejection-time
    /// backoff (ADR 000032). Reset on a successful outcome.
    outlier_eject_count: u32,
}

impl UpstreamInstance {
    fn new(address: String, weight: u32, health: &HealthConfig) -> Self {
        Self {
            address,
            // a 0 weight would divide by zero in the least-request ratio; validation rejects it, but
            // clamp to >= 1 as defence in depth (data-plane no-panic).
            weight: weight.max(1),
            // pessimistic: a fresh instance is out of rotation until a probe passes (ADR 000017).
            healthy: AtomicBool::new(false),
            in_flight: AtomicUsize::new(0),
            counters: Mutex::new(HealthCounters {
                consecutive_ok: 0,
                consecutive_fail: 0,
                ever_healthy: false,
                consecutive_gw_fail: 0,
                outlier_eject_count: 0,
            }),
            // a 0 threshold would be a footgun (never promote / instant eject); clamp to >= 1.
            healthy_threshold: health.healthy_threshold.max(1),
            unhealthy_threshold: health.unhealthy_threshold.max(1),
            outlier_ejected_until_ms: AtomicU64::new(0),
        }
    }

    /// This instance's `host:port`.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// This instance's load-balancing weight (ADR 000035), `>= 1`.
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// Current active forwarded-request count to this instance (ADR 000035) — the least-request load
    /// signal. Lock-free read.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }

    /// Whether this instance is currently in rotation. Lock-free — the round-robin hot path.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Whether this instance is currently outlier-ejected at `now_ms` (ADR 000032). Lock-free — the
    /// `pick` hot path. The ejection auto-expires when its window passes (no probe needed); this is a
    /// distinct axis from `is_healthy` (an instance can be probe-healthy yet outlier-ejected).
    pub fn is_outlier_ejected(&self, now_ms: u64) -> bool {
        self.outlier_ejected_until_ms.load(Ordering::Acquire) > now_ms
    }

    /// Record a successful active probe (a 2xx within the timeout). Promotes a pessimistic / ejected
    /// instance once it reaches its threshold — one success the first time ever, `healthy_threshold`
    /// after a later eject — and resets the consecutive-failure streak.
    pub fn record_probe_success(&self) {
        // a poisoned lock means a thread panicked mid-transition; fail safe (leave state as-is).
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.consecutive_fail = 0;
        if self.healthy.load(Ordering::Acquire) {
            return; // already in rotation; nothing to promote
        }
        c.consecutive_ok = c.consecutive_ok.saturating_add(1);
        let need = if c.ever_healthy {
            self.healthy_threshold
        } else {
            1 // cold-start fast path: first ever promotion needs a single success
        };
        if c.consecutive_ok >= need {
            c.ever_healthy = true;
            c.consecutive_ok = 0;
            self.healthy.store(true, Ordering::Release);
        }
    }

    /// Record a failed active probe (non-2xx, timeout, or connect error).
    pub fn record_probe_failure(&self) {
        self.record_failure();
    }

    /// Record a *passive* failure — a real forwarded request that could not even connect to this
    /// instance (ADR 000017). It demotes exactly like a probe failure, but can only ever demote: an
    /// ejected instance receives no traffic, so only the active prober restores it.
    pub fn record_passive_failure(&self) {
        self.record_failure();
    }

    fn record_failure(&self) {
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        c.consecutive_ok = 0;
        c.consecutive_fail = c.consecutive_fail.saturating_add(1);
        if self.healthy.load(Ordering::Acquire) && c.consecutive_fail >= self.unhealthy_threshold {
            c.consecutive_fail = 0;
            self.healthy.store(false, Ordering::Release);
        }
    }
}

/// A named upstream: its instances, the round-robin cursor, and the health policy (ADR 000017).
#[derive(Debug)]
pub struct UpstreamGroup {
    /// The upstream `name` routes refer to.
    pub name: String,
    /// The active-health-check policy (the prober reads `path` / `interval_ms` / `timeout_ms`).
    pub health: HealthConfig,
    /// The instances, in manifest address order. Fixed for the life of this group value; a reload
    /// builds a NEW group, reusing unchanged instances' `Arc`s to preserve their health.
    pub instances: Vec<Arc<UpstreamInstance>>,
    /// Per-try timeout for ONE forward attempt to this upstream (ADR 000019, reframed as the per-try
    /// bound by ADR 000031); `Duration::ZERO` disables it. Bounds one attempt's time-to-response-
    /// headers, failing closed 504 on overrun. Not part of `health`, so a timeout-only change
    /// rebuilds the group but preserves instance health.
    request_timeout: Duration,
    /// Overall request deadline across the WHOLE transaction — every attempt PLUS the backoff between
    /// them (ADR 000031); `Duration::ZERO` = no overall bound (only the per-try `request_timeout`
    /// applies). The runtime applies the tighter of the two; exceeding it fails closed 504.
    overall_timeout: Duration,
    /// Max retries to a DIFFERENT instance after a retryable forward failure (ADR 000023); `0`
    /// disables retry. Like `request_timeout`, not part of `health`, so a retry-only change rebuilds
    /// the group but preserves instance health.
    max_retries: u64,
    /// Round-robin cursor. `Relaxed` suffices: it only needs to advance, not synchronise memory.
    rr: AtomicUsize,
    /// Circuit-breaker cap (ADR 000028): max concurrent in-flight requests to this upstream; `0` =
    /// unlimited. Rebuilt from the manifest on every reconcile, like `request_timeout`/`max_retries`,
    /// so it is not part of `health` and a breaker-only change preserves instance health.
    max_requests: usize,
    /// Current concurrent in-flight requests (ADR 000028) — held by a [`RequestPermit`] from forward
    /// time until the upstream response headers arrive (or it fails). A (re)built group starts at 0;
    /// in-flight requests of a superseded group decrement that group's own counter via their permit,
    /// so a reload never miscounts.
    in_flight: AtomicUsize,
    /// Outlier-detection policy (ADR 000032), rebuilt from the manifest like the other non-health
    /// knobs (so an outlier-config change preserves instance health): the consecutive gateway-5xx
    /// threshold (`0` = disabled), the base ejection window (× exponential backoff), and the cap on
    /// the fraction of the pool ejectable at once.
    outlier_consecutive: u32,
    outlier_base_ejection: Duration,
    outlier_max_ejection_percent: u32,
    /// The per-instance load-balancing algorithm (ADR 000035): `RoundRobin` (the default, uses `rr`),
    /// `LeastRequest` (power-of-two-choices over `in_flight`/`weight`), or `Maglev` (consistent
    /// hashing via the precomputed table). Rebuilt from the manifest on reconcile, so an
    /// algorithm/weight change rebuilds the table but is not part of `health`.
    lb: LbState,
    /// The request attribute a `Maglev` upstream hashes for affinity (ADR 000035); `None` for the
    /// other algorithms. The fast path reads this to project the hash key from a request.
    hash_key: Option<HashKeySource>,
}

/// The request attribute a Maglev upstream hashes for affinity (ADR 000035), resolved from the
/// manifest `[upstream.hash]`. The fast path turns this into a [`HashInput`] per request.
#[derive(Debug, Clone)]
pub enum HashKeySource {
    /// Hash a named request header's value (the name is stored lower-cased for case-insensitive lookup).
    Header(String),
    /// Hash the connection peer's IP address.
    SourceIp,
}

/// A request attribute to hash for Maglev affinity (ADR 000035), borrowed so the hot path allocates
/// nothing: a header value's bytes (borrowed from the request) or the peer IP (hashed as its
/// canonical octets, not a string). The fast path builds this from a group's [`HashKeySource`].
/// `Copy` so it can be passed to the initial `pick` and each retry's `pick_excluding` unchanged.
#[derive(Debug, Clone, Copy)]
pub enum HashInput<'a> {
    Bytes(&'a [u8]),
    Ip(IpAddr),
}

impl HashInput<'_> {
    /// The stable 64-bit hash of this key, fed to the Maglev table lookup.
    fn hash(&self) -> u64 {
        match self {
            HashInput::Bytes(b) => crate::hash::hash64(b),
            HashInput::Ip(IpAddr::V4(a)) => crate::hash::hash64(&a.octets()),
            HashInput::Ip(IpAddr::V6(a)) => crate::hash::hash64(&a.octets()),
        }
    }
}

/// The compiled per-instance load-balancing state of a group (ADR 000035). `Maglev` carries its
/// precomputed lookup table; the other two need no extra state (round-robin uses the group's `rr`
/// cursor, least-request reads the per-instance `in_flight`).
#[derive(Debug)]
enum LbState {
    RoundRobin,
    LeastRequest,
    Maglev(MaglevTable),
}

/// A chosen instance plus a guard tracking its load (ADR 000035). For `least_request` the guard
/// holds the selected instance's incremented active-request count and decrements it on drop — on
/// EVERY forward return path (success, retry, transport error) and on each retry hand-off, because
/// replacing the `Pick` drops the previous guard. For round-robin / maglev the guard is a no-op.
/// `Deref`s to the instance so callers read `address()` / `is_healthy()` directly.
pub struct Pick {
    instance: Arc<UpstreamInstance>,
    _load: InstanceLoad,
}

impl Pick {
    /// The chosen instance (for `pick_excluding` / `record_outcome` / passive-failure book-keeping).
    pub fn instance(&self) -> &Arc<UpstreamInstance> {
        &self.instance
    }
}

impl std::ops::Deref for Pick {
    type Target = UpstreamInstance;
    fn deref(&self) -> &UpstreamInstance {
        &self.instance
    }
}

/// RAII guard decrementing an instance's active-request count on drop (ADR 000035). `None` for
/// algorithms that do not track per-instance load (round-robin / maglev): a zero-cost no-op, so the
/// default RR hot path gains no atomic.
pub struct InstanceLoad {
    instance: Option<Arc<UpstreamInstance>>,
}

impl Drop for InstanceLoad {
    fn drop(&mut self) {
        if let Some(inst) = &self.instance {
            inst.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// A held slot in an upstream's circuit-breaker cap (ADR 000028). Decrements the group's in-flight
/// count on drop, so the slot is released on EVERY return path of a forward (success, retry
/// exhaustion, or transport error) — RAII, no manual book-keeping that a `?` could leak past.
#[derive(Debug)]
pub struct RequestPermit {
    /// `None` for an unlimited breaker (`max_requests == 0`): a zero-cost no-op permit.
    group: Option<Arc<UpstreamGroup>>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            group.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl UpstreamGroup {
    /// Pick an instance per the upstream's LB algorithm (ADR 000035), or `None` when nothing is
    /// eligible (the fast path then fails closed 503 — ADR 000017). `key` is the request's hash key
    /// for `maglev`; round-robin / least-request ignore it, and `None` (no key) falls back to
    /// round-robin.
    pub fn pick(&self, key: Option<HashInput>) -> Option<Pick> {
        self.pick_dispatch(None, key)
    }

    /// Pick an instance OTHER than `exclude`, to retry a failed forward on a different instance (ADR
    /// 000023). Same algorithm dispatch as `pick`; for `maglev` the affinity target is excluded, so
    /// it falls back to round-robin over the remaining eligible set.
    pub fn pick_excluding(
        &self,
        exclude: &Arc<UpstreamInstance>,
        key: Option<HashInput>,
    ) -> Option<Pick> {
        self.pick_dispatch(Some(exclude), key)
    }

    fn pick_dispatch(
        &self,
        exclude: Option<&Arc<UpstreamInstance>>,
        key: Option<HashInput>,
    ) -> Option<Pick> {
        match &self.lb {
            LbState::RoundRobin => self.round_robin_pick(exclude),
            LbState::LeastRequest => self.least_request_pick(exclude),
            LbState::Maglev(table) => self.maglev_pick(table, exclude, key),
        }
    }

    /// The hash-key source for a `maglev` upstream (ADR 000035), or `None` for the other algorithms.
    /// The fast path reads this to project a [`HashInput`] from the request.
    pub fn hash_key_source(&self) -> Option<&HashKeySource> {
        self.hash_key.as_ref()
    }

    /// The clock context for eligibility: whether outlier detection is on and, if so, `now` in ms.
    /// Read once per pick, and the clock only when the policy is enabled, so a disabled policy keeps
    /// the pre-000032 cost (a single lock-free `is_healthy` read).
    fn eligibility_ctx(&self) -> (bool, u64) {
        let check_outlier = self.outlier_enabled();
        let now_ms = if check_outlier { now_millis() } else { 0 };
        (check_outlier, now_ms)
    }

    /// Whether `inst` may serve this request: healthy, not outlier-ejected, and not the retry
    /// `exclude`.
    fn is_eligible(
        &self,
        inst: &Arc<UpstreamInstance>,
        exclude: Option<&Arc<UpstreamInstance>>,
        (check_outlier, now_ms): (bool, u64),
    ) -> bool {
        inst.is_healthy()
            && (!check_outlier || !inst.is_outlier_ejected(now_ms))
            && exclude.is_none_or(|ex| !Arc::ptr_eq(inst, ex))
    }

    /// Round-robin over the *eligible set* (ADR 000024): count the eligible, advance the cursor mod
    /// that count, index into them. An ejected/excluded instance's slot is never absorbed by its
    /// neighbour (degraded distribution stays even instead of skewing ~1:2). Two allocation-free
    /// passes; if an instance flips between them we return the last eligible seen rather than a
    /// spurious `None`. No per-instance load is metered — round-robin is the zero-overhead default.
    fn round_robin_pick(&self, exclude: Option<&Arc<UpstreamInstance>>) -> Option<Pick> {
        let ctx = self.eligibility_ctx();
        let eligible = self
            .instances
            .iter()
            .filter(|i| self.is_eligible(i, exclude, ctx))
            .count();
        if eligible == 0 {
            return None;
        }
        let target = self.rr.fetch_add(1, Ordering::Relaxed) % eligible;
        let mut seen = 0;
        let mut last = None;
        for inst in &self.instances {
            if self.is_eligible(inst, exclude, ctx) {
                last = Some(inst);
                if seen == target {
                    return Some(self.unmetered_pick(inst.clone()));
                }
                seen += 1;
            }
        }
        last.cloned().map(|i| self.unmetered_pick(i))
    }

    /// Weighted least-request via power-of-two-choices (ADR 000035): sample two distinct eligible
    /// instances and forward to the one with the smaller `(in_flight + 1) / weight` (compared by
    /// integer cross-product, no float; `+1` lets weight bias even idle instances). Two passes over
    /// the small instance list. The selected instance's load is metered (incremented now, decremented
    /// when the returned `Pick` drops — across the retry hand-off too).
    fn least_request_pick(&self, exclude: Option<&Arc<UpstreamInstance>>) -> Option<Pick> {
        let ctx = self.eligibility_ctx();
        let n = self
            .instances
            .iter()
            .filter(|i| self.is_eligible(i, exclude, ctx))
            .count();
        if n == 0 {
            return None;
        }
        if n == 1 {
            let only = self
                .instances
                .iter()
                .find(|i| self.is_eligible(i, exclude, ctx))?;
            return Some(self.metered_pick(only.clone()));
        }
        let (a, b) = rng::two_distinct_below(n as u32);
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        // One pass capturing the lo-th and hi-th eligible instances by ordinal.
        let mut cand_lo = None;
        let mut cand_hi = None;
        let mut seen = 0u32;
        for inst in &self.instances {
            if self.is_eligible(inst, exclude, ctx) {
                if seen == lo {
                    cand_lo = Some(inst);
                }
                if seen == hi {
                    cand_hi = Some(inst);
                }
                seen += 1;
            }
        }
        let (x, y) = (cand_lo?, cand_hi?);
        let chosen = if lower_load(x, y) { x } else { y };
        Some(self.metered_pick(chosen.clone()))
    }

    /// Consistent hashing via the Maglev table (ADR 000035): map the request key to a stable instance
    /// for affinity. When the primary is ineligible (unhealthy / outlier-ejected / the retry
    /// `exclude`) or there is no key, fall back to the eligible-set round-robin (best-effort affinity,
    /// fail-soft). No per-instance load is metered (selection is by hash, not load).
    fn maglev_pick(
        &self,
        table: &MaglevTable,
        exclude: Option<&Arc<UpstreamInstance>>,
        key: Option<HashInput>,
    ) -> Option<Pick> {
        if let Some(k) = key {
            let ctx = self.eligibility_ctx();
            if let Some(idx) = table.lookup(k.hash())
                && let Some(inst) = self.instances.get(idx)
                && self.is_eligible(inst, exclude, ctx)
            {
                return Some(self.unmetered_pick(inst.clone()));
            }
        }
        // No key, or the affinity target can't serve → fall back to round-robin over the eligible set.
        self.round_robin_pick(exclude)
    }

    /// Wrap an instance in a `Pick` with NO load metering (round-robin / maglev).
    fn unmetered_pick(&self, instance: Arc<UpstreamInstance>) -> Pick {
        Pick {
            instance,
            _load: InstanceLoad { instance: None },
        }
    }

    /// Wrap an instance in a `Pick` that meters its load (least-request): increment its active-request
    /// count now and hand back a guard that decrements it on drop.
    fn metered_pick(&self, instance: Arc<UpstreamInstance>) -> Pick {
        instance.in_flight.fetch_add(1, Ordering::Relaxed);
        Pick {
            instance: instance.clone(),
            _load: InstanceLoad {
                instance: Some(instance),
            },
        }
    }

    /// Whether this upstream has at least one eligible instance (healthy and not outlier-ejected).
    /// A cursor-free, allocation-free probe the weighted traffic split (ADR 000034) uses to skip a
    /// backend whose group can serve nothing (renormalize over healthy). Same eligibility as the
    /// pick path minus the retry `exclude`; a `false` here means a `pick` would return `None`.
    pub fn has_eligible(&self) -> bool {
        let (check_outlier, now_ms) = self.eligibility_ctx();
        self.instances
            .iter()
            .any(|inst| inst.is_healthy() && (!check_outlier || !inst.is_outlier_ejected(now_ms)))
    }

    /// The PER-TRY timeout the fast path applies to one forward attempt (ADR 000019, per-try by ADR
    /// 000031). `Duration::ZERO` means no per-try bound (e.g. a streaming / long-poll backend);
    /// otherwise one attempt is bounded and overrun fails closed 504.
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// The OVERALL request deadline across all attempts + backoff (ADR 000031); `Duration::ZERO`
    /// means no overall bound (only the per-try `request_timeout` applies). Exceeding it fails
    /// closed 504 `request-timeout` with no further retry.
    pub fn overall_timeout(&self) -> Duration {
        self.overall_timeout
    }

    /// The max number of retries to a different instance on a retryable forward failure (ADR
    /// 000023); `0` disables retry.
    pub fn max_retries(&self) -> u64 {
        self.max_retries
    }

    /// Whether outlier detection is enabled for this upstream (ADR 000032).
    fn outlier_enabled(&self) -> bool {
        self.outlier_consecutive > 0
    }

    /// Record one forward's outcome against `instance` for outlier detection (ADR 000032).
    /// `gateway_failure` is `true` only for a gateway-class 5xx (502/503/504) the upstream actually
    /// RETURNED — never a circuit-breaker shed or a per-try timeout (those are other axes). Returns
    /// `true` iff this call ejected the instance (the caller bumps the ejection metric). A success
    /// resets the failure streak and ejection backoff; consecutive failures past the threshold eject
    /// the instance for a backing-off window — unless that would push the pool past
    /// `max_ejection_percent`, in which case it stays in rotation (fail-closed must not self-DoS).
    pub fn record_outcome(&self, instance: &Arc<UpstreamInstance>, gateway_failure: bool) -> bool {
        if !self.outlier_enabled() {
            return false;
        }
        // a poisoned lock means a thread panicked mid-transition; fail safe (no ejection).
        let Ok(mut c) = instance.counters.lock() else {
            return false;
        };
        if !gateway_failure {
            c.consecutive_gw_fail = 0;
            c.outlier_eject_count = 0;
            return false;
        }
        c.consecutive_gw_fail = c.consecutive_gw_fail.saturating_add(1);
        if c.consecutive_gw_fail < self.outlier_consecutive {
            return false;
        }

        // Threshold reached. Honour the ejection cap: never eject so many that the pool drops below
        // its working minimum (`100 - max_ejection_percent`). Integer math, no float.
        let now_ms = now_millis();
        let already_ejected = self
            .instances
            .iter()
            .filter(|i| i.is_outlier_ejected(now_ms))
            .count();
        if (already_ejected + 1) * 100
            > self.outlier_max_ejection_percent as usize * self.instances.len()
        {
            // Cap reached — keep this instance in rotation, but reset its streak so it gets a fresh
            // threshold's worth of chances rather than re-tripping on the very next failure.
            c.consecutive_gw_fail = 0;
            return false;
        }

        // Eject for `base · 2^min(eject_count, cap)` — exponential backoff, bounded.
        let shift = c.outlier_eject_count.min(OUTLIER_BACKOFF_SHIFT_CAP);
        let window = self.outlier_base_ejection.saturating_mul(1u32 << shift);
        instance.outlier_ejected_until_ms.store(
            now_ms.saturating_add(window.as_millis() as u64),
            Ordering::Release,
        );
        c.outlier_eject_count = c.outlier_eject_count.saturating_add(1);
        c.consecutive_gw_fail = 0;
        true
    }

    /// Try to take an in-flight slot under the circuit-breaker cap (ADR 000028). `None` means the
    /// upstream is at `max_requests` and the fast path should fail closed (503). An unlimited breaker
    /// (`max_requests == 0`, the default) always succeeds with a zero-cost no-op permit. Lock-free:
    /// an optimistic increment that backs out if it crossed the cap, so concurrent callers never
    /// hold more than `max_requests` permits at once.
    pub fn try_acquire(self: &Arc<Self>) -> Option<RequestPermit> {
        if self.max_requests == 0 {
            return Some(RequestPermit { group: None });
        }
        // `fetch_add` returns the PRIOR value: `prev >= max` means the cap was already full, so this
        // would be the (max+1)th in flight — back the increment out and reject. `Relaxed` suffices
        // (a bare counter, like `rr`; it guards no other memory).
        let prev = self.in_flight.fetch_add(1, Ordering::Relaxed);
        if prev >= self.max_requests {
            self.in_flight.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(RequestPermit {
            group: Some(self.clone()),
        })
    }
}

/// The live set of upstreams, keyed by name. Owned by `Control`, OUTSIDE the swapped
/// `ActiveConfig`, so health state survives a reload (ADR 000017). The `Mutex` is contended only by
/// `reconcile` (on reload) and the prober supervisor (`groups`) / a config build (`group`) — never
/// the per-request hot path, which holds an `Arc<UpstreamGroup>` resolved at build time.
#[derive(Debug, Default)]
pub struct UpstreamRegistry {
    groups: Mutex<HashMap<String, Arc<UpstreamGroup>>>,
}

impl UpstreamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconcile the registry to `upstreams` (ADR 000017). Validation (duplicate name, empty
    /// addresses, and the LB config — ADR 000035) runs FIRST against the whole list, so a bad
    /// manifest leaves the running set untouched (all-or-nothing, like the rest of a reload). Then,
    /// per upstream: build a new group whose instances reuse the existing `Arc<UpstreamInstance>` for
    /// any unchanged `(name, address, weight)` *when the health policy is unchanged* (preserving
    /// health), create a fresh pessimistic instance otherwise, build the LB state (a Maglev upstream
    /// recomputes its table from the instance set), and drop upstreams no longer present.
    pub fn reconcile(&self, upstreams: &[Upstream]) -> Result<(), ControlError> {
        let mut seen = HashSet::new();
        for up in upstreams {
            if up.addresses.is_empty() {
                return Err(ControlError::EmptyUpstreamAddresses(up.name.clone()));
            }
            if !seen.insert(up.name.as_str()) {
                return Err(ControlError::DuplicateUpstream(up.name.clone()));
            }
            up.validate_lb()
                .map_err(|reason| ControlError::InvalidUpstreamLb {
                    name: up.name.clone(),
                    reason,
                })?;
        }

        let mut groups = self
            .groups
            .lock()
            .map_err(|_| ControlError::UpstreamRegistryPoisoned)?;
        let mut next: HashMap<String, Arc<UpstreamGroup>> = HashMap::with_capacity(upstreams.len());
        for up in upstreams {
            let prev_any = groups.get(&up.name);
            // reuse the prior group's instances only if the health policy is identical; a policy
            // change re-probes the upstream from pessimistic (so new thresholds actually apply).
            let prev = prev_any.filter(|g| g.health == up.health);
            let instances: Vec<Arc<UpstreamInstance>> = up
                .addresses
                .iter()
                .map(|spec| {
                    let addr = spec.address();
                    let weight = spec.weight();
                    // reuse only when address AND weight are unchanged; a weight edit (LB capacity)
                    // builds a fresh instance, like a health-policy change.
                    prev.and_then(|g| {
                        g.instances
                            .iter()
                            .find(|i| i.address() == addr && i.weight() == weight)
                            .cloned()
                    })
                    .unwrap_or_else(|| {
                        Arc::new(UpstreamInstance::new(addr.to_string(), weight, &up.health))
                    })
                })
                .collect();
            // carry the round-robin cursor across the reload (independent of which instances or the
            // health policy changed — it is only a rotation counter) so the first post-reload pick
            // continues the rotation instead of restarting at the eligible set's head (ADR 000024).
            let rr = prev_any.map(|g| g.rr.load(Ordering::Relaxed)).unwrap_or(0);
            // Build the LB state from the manifest (ADR 000035). Maglev recomputes its lookup table
            // from the instance set + weights; validation above guaranteed a hash block and a valid
            // (prime, in-range) table size.
            let lb = match up.lb_algorithm {
                LbAlgorithm::RoundRobin => LbState::RoundRobin,
                LbAlgorithm::LeastRequest => LbState::LeastRequest,
                LbAlgorithm::Maglev => {
                    let entries: Vec<(&str, u32)> = instances
                        .iter()
                        .map(|i| (i.address(), i.weight()))
                        .collect();
                    let m = up.hash.as_ref().map(|h| h.table_size).unwrap_or(65537) as usize;
                    LbState::Maglev(MaglevTable::build(&entries, m))
                }
            };
            let hash_key = up.hash.as_ref().map(|h| match h.key {
                HashKeyKind::Header => {
                    HashKeySource::Header(h.header.clone().unwrap_or_default().to_ascii_lowercase())
                }
                HashKeyKind::SourceIp => HashKeySource::SourceIp,
            });
            next.insert(
                up.name.clone(),
                Arc::new(UpstreamGroup {
                    name: up.name.clone(),
                    health: up.health.clone(),
                    instances,
                    request_timeout: Duration::from_millis(up.request_timeout_ms),
                    overall_timeout: Duration::from_millis(up.overall_timeout_ms),
                    max_retries: up.max_retries,
                    rr: AtomicUsize::new(rr),
                    max_requests: up.circuit_breaker.max_requests as usize,
                    in_flight: AtomicUsize::new(0),
                    outlier_consecutive: up.outlier_detection.consecutive_gateway_failures,
                    outlier_base_ejection: Duration::from_millis(
                        up.outlier_detection.base_ejection_time_ms,
                    ),
                    outlier_max_ejection_percent: up.outlier_detection.max_ejection_percent,
                    lb,
                    hash_key,
                }),
            );
        }
        *groups = next;
        Ok(())
    }

    /// The group named `name`, if present — used to resolve a route's upstream at config-build time.
    pub fn group(&self, name: &str) -> Option<Arc<UpstreamGroup>> {
        self.groups.lock().ok()?.get(name).cloned()
    }

    /// A snapshot of every current group, for the health-check supervisor to probe.
    pub fn groups(&self) -> Vec<Arc<UpstreamGroup>> {
        self.groups
            .lock()
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        AddressSpec, CircuitBreaker, HashConfig, HashKeyKind, HealthConfig, OutlierDetection,
    };

    fn health(healthy_threshold: u32, unhealthy_threshold: u32) -> HealthConfig {
        HealthConfig {
            path: "/healthz".to_string(),
            interval_ms: 100,
            timeout_ms: 50,
            healthy_threshold,
            unhealthy_threshold,
        }
    }

    fn upstream(name: &str, addrs: &[&str], h: HealthConfig) -> Upstream {
        Upstream {
            name: name.to_string(),
            addresses: addrs
                .iter()
                .map(|s| AddressSpec::Bare(s.to_string()))
                .collect(),
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
            health: h,
            request_timeout_ms: 30_000,
            max_retries: 1,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
        }
    }

    fn instance(h: &HealthConfig) -> UpstreamInstance {
        UpstreamInstance::new("127.0.0.1:9000".to_string(), 1, h)
    }

    /// Resolve a `Pick`'s address (the common assertion after the `Pick` return type, ADR 000035).
    fn addr_of(p: &Pick) -> String {
        p.address().to_string()
    }

    #[test]
    fn starts_pessimistic_and_first_probe_promotes() {
        // ADR 000017: a fresh instance is unhealthy; the FIRST successful probe alone promotes it,
        // even when healthy_threshold > 1 (cold-start fast path).
        let h = health(3, 3);
        let inst = instance(&h);
        assert!(!inst.is_healthy(), "fresh instance starts pessimistic");
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success promotes a never-yet-healthy instance"
        );
    }

    #[test]
    fn ejects_after_unhealthy_threshold_then_needs_full_healthy_threshold() {
        // healthy_threshold=2, unhealthy_threshold=2.
        let h = health(2, 2);
        let inst = instance(&h);
        inst.record_probe_success(); // cold-start: healthy after 1
        assert!(inst.is_healthy());

        inst.record_probe_failure();
        assert!(
            inst.is_healthy(),
            "one failure is below the eject threshold"
        );
        inst.record_probe_failure();
        assert!(!inst.is_healthy(), "two consecutive failures eject");

        // re-entry now needs the FULL healthy_threshold (it has been healthy before)
        inst.record_probe_success();
        assert!(
            !inst.is_healthy(),
            "one success is not enough to re-enter after an eject"
        );
        inst.record_probe_success();
        assert!(inst.is_healthy(), "healthy_threshold successes restore it");
    }

    #[test]
    fn a_success_resets_the_failure_streak() {
        let h = health(1, 3);
        let inst = instance(&h);
        inst.record_probe_success();
        inst.record_probe_failure();
        inst.record_probe_failure();
        inst.record_probe_success(); // resets the streak
        inst.record_probe_failure();
        inst.record_probe_failure();
        assert!(inst.is_healthy(), "non-consecutive failures must not eject");
    }

    #[test]
    fn pick_excluding_returns_a_different_healthy_instance_or_none() {
        // ADR 000023: a retry must land on a DIFFERENT instance; when the failed one is the only
        // healthy member there is nothing to retry onto.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream(
            "pool",
            &["127.0.0.1:9000", "127.0.0.1:9001"],
            health(1, 3),
        )])
        .unwrap();
        let group = reg.group("pool").unwrap();
        // promote both (cold-start: one success each).
        group.instances[0].record_probe_success();
        group.instances[1].record_probe_success();

        let a = group.instances[0].clone();
        let other = group
            .pick_excluding(&a, None)
            .expect("a different healthy instance exists");
        assert!(
            Arc::ptr_eq(other.instance(), &group.instances[1]),
            "pick_excluding skips the excluded instance"
        );

        // eject instance[1] (unhealthy_threshold = 3) → `a` is the only healthy one left.
        for _ in 0..3 {
            group.instances[1].record_probe_failure();
        }
        assert!(!group.instances[1].is_healthy(), "instance[1] is ejected");
        assert!(
            group.pick_excluding(&a, None).is_none(),
            "the only healthy instance can't be retried around"
        );
    }

    #[test]
    fn passive_failure_demotes_a_healthy_instance() {
        // ADR 000017: a real request's connect failure feeds the SAME state machine and demotes.
        let h = health(1, 2);
        let inst = instance(&h);
        inst.record_probe_success();
        assert!(inst.is_healthy());
        inst.record_passive_failure();
        inst.record_passive_failure();
        assert!(
            !inst.is_healthy(),
            "passive failures eject like probe failures"
        );
    }

    #[test]
    fn round_robin_distributes_over_healthy_only() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();

        assert!(
            g.pick(None).is_none(),
            "all pessimistic → no pick (fail-closed)"
        );

        // make a and c healthy, leave b unhealthy
        g.instances[0].record_probe_success();
        g.instances[2].record_probe_success();

        let mut seen = HashSet::new();
        for _ in 0..6 {
            seen.insert(g.pick(None).unwrap().address().to_string());
        }
        assert_eq!(
            seen,
            HashSet::from(["a:1".to_string(), "c:3".to_string()]),
            "round-robin only ever returns the healthy instances"
        );
    }

    #[test]
    fn reconcile_preserves_unchanged_adds_new_drops_removed() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2"], health(1, 3))])
            .unwrap();
        let g0 = reg.group("u").unwrap();
        g0.instances[0].record_probe_success(); // a:1 becomes healthy
        assert!(g0.instances[0].is_healthy());

        // reload: drop b:2, keep a:1, add c:3 — same health policy
        reg.reconcile(&[upstream("u", &["a:1", "c:3"], health(1, 3))])
            .unwrap();
        let g1 = reg.group("u").unwrap();
        assert_eq!(g1.instances.len(), 2);
        assert!(
            g1.instances[0].is_healthy(),
            "the unchanged a:1 keeps its health across reload"
        );
        assert_eq!(g1.instances[1].address(), "c:3");
        assert!(
            !g1.instances[1].is_healthy(),
            "the new c:3 starts pessimistic"
        );
    }

    #[test]
    fn reconcile_changing_health_policy_reprobes_from_pessimistic() {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1"], health(1, 3))])
            .unwrap();
        reg.group("u").unwrap().instances[0].record_probe_success();
        assert!(reg.group("u").unwrap().instances[0].is_healthy());

        // same address, different health policy → fresh pessimistic instance, new thresholds apply
        reg.reconcile(&[upstream("u", &["a:1"], health(2, 5))])
            .unwrap();
        assert!(
            !reg.group("u").unwrap().instances[0].is_healthy(),
            "a health-policy change re-probes the instance from pessimistic"
        );
    }

    #[test]
    fn reconcile_rejects_empty_addresses_and_duplicate_names() {
        let reg = UpstreamRegistry::new();
        let empty = reg.reconcile(&[upstream("u", &[], health(1, 1))]);
        assert!(matches!(
            empty,
            Err(ControlError::EmptyUpstreamAddresses(_))
        ));

        let dup = reg.reconcile(&[
            upstream("u", &["a:1"], health(1, 1)),
            upstream("u", &["b:2"], health(1, 1)),
        ]);
        assert!(matches!(dup, Err(ControlError::DuplicateUpstream(_))));
    }

    #[test]
    fn zero_thresholds_are_clamped_to_one() {
        // A manifest typo (`healthy_threshold = 0` / `unhealthy_threshold = 0`) must not become a
        // config-induced DoS. Without the `.max(1)` clamp a 0 healthy_threshold would make a
        // never-yet-healthy instance promote on the cold-start path anyway, but a 0
        // unhealthy_threshold would eject a healthy instance the instant it served — and re-entry
        // could be impossible. Clamping both to >=1 makes "one success promotes, one failure
        // ejects, one success restores" hold, never "never promote" or "instant eject".
        let inst = instance(&health(0, 0));
        assert!(!inst.is_healthy(), "still starts pessimistic");
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success promotes (healthy_threshold clamped to >=1)"
        );
        inst.record_probe_failure();
        assert!(
            !inst.is_healthy(),
            "one real failure ejects — not instant-eject before any failure"
        );
        inst.record_probe_success();
        assert!(
            inst.is_healthy(),
            "one success restores after an eject (re-entry is possible)"
        );
    }

    #[test]
    fn round_robin_is_even_over_the_healthy_set_when_degraded() {
        // With a MIDDLE instance ejected, the rotation must split evenly over whoever is left.
        // The old forward-scan-from-cursor handed the dead instance's slot to its neighbour, so
        // `[a, b(down), c]` skewed a:c to ~1:2. Rotating over the healthy SET removes that.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();
        g.instances[0].record_probe_success(); // a:1 healthy
        g.instances[2].record_probe_success(); // c:3 healthy, b:2 stays ejected

        let mut a = 0u32;
        let mut c = 0u32;
        for _ in 0..600 {
            match g.pick(None).unwrap().address() {
                "a:1" => a += 1,
                "c:3" => c += 1,
                other => panic!("picked a down/unknown instance: {other}"),
            }
        }
        assert_eq!(
            a, c,
            "degraded round-robin must split evenly over the healthy set (was ~1:2)"
        );
    }

    #[test]
    fn reconcile_carries_the_round_robin_cursor() {
        // A reload must not reset the cursor to 0, or the first post-reload pick always lands on
        // the head of the rotation — an index-0 bias under frequent reloads.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 3))])
            .unwrap();
        let g0 = reg.group("u").unwrap();
        for i in 0..3 {
            g0.instances[i].record_probe_success(); // all three healthy
        }
        // advance the cursor two steps: a:1, b:2 (cursor now at 2)
        assert_eq!(g0.pick(None).unwrap().address(), "a:1");
        assert_eq!(g0.pick(None).unwrap().address(), "b:2");

        // reload with the SAME upstream + health policy → instances and health are preserved
        reg.reconcile(&[upstream("u", &["a:1", "b:2", "c:3"], health(1, 3))])
            .unwrap();
        let g1 = reg.group("u").unwrap();
        assert!(
            g1.instances.iter().all(|i| i.is_healthy()),
            "health survives an unchanged-policy reload (ADR 000017)"
        );
        assert_eq!(
            g1.pick(None).unwrap().address(),
            "c:3",
            "the cursor carried across reload (would be a:1 if reset to 0)"
        );
    }

    #[test]
    fn circuit_breaker_caps_concurrent_in_flight_and_releases_on_drop() {
        // ADR 000028: `max_requests` bounds concurrent in-flight forwards to an upstream. At the cap
        // `try_acquire` returns None (the fast path fails closed 503); dropping a permit frees a slot.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses: vec![AddressSpec::Bare("a:1".to_string())],
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker { max_requests: 2 },
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        let g = reg.group("u").unwrap();

        let p1 = g.try_acquire().expect("1st slot is under the cap");
        let _p2 = g.try_acquire().expect("2nd slot is under the cap");
        assert!(
            g.try_acquire().is_none(),
            "the 3rd concurrent request is over the cap → rejected"
        );

        drop(p1);
        let _p3 = g.try_acquire().expect("a freed slot is reusable");
        assert!(
            g.try_acquire().is_none(),
            "still capped at 2 after reusing the freed slot"
        );
    }

    #[test]
    fn circuit_breaker_zero_is_unlimited() {
        // The default (`max_requests == 0`) never rejects — a zero-cost no-op permit, no cap. The
        // `upstream` helper leaves the breaker at its default, so this also covers the common config.
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[upstream("u", &["a:1"], health(1, 1))])
            .unwrap();
        let g = reg.group("u").unwrap();
        let permits: Vec<_> = (0..1000)
            .map(|_| g.try_acquire().expect("an unlimited breaker never rejects"))
            .collect();
        assert_eq!(permits.len(), 1000);
    }

    /// Build a healthy group with outlier detection configured (ADR 000032).
    fn outlier_group(
        addrs: &[&str],
        consecutive: u32,
        base_ms: u64,
        max_pct: u32,
    ) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses: addrs
                .iter()
                .map(|s| AddressSpec::Bare(s.to_string()))
                .collect(),
            lb_algorithm: LbAlgorithm::RoundRobin,
            hash: None,
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection {
                consecutive_gateway_failures: consecutive,
                base_ejection_time_ms: base_ms,
                max_ejection_percent: max_pct,
            },
        }])
        .unwrap();
        let g = reg.group("u").unwrap();
        for inst in &g.instances {
            inst.record_probe_success(); // cold-start: all healthy
        }
        g
    }

    #[test]
    fn outlier_ejects_after_consecutive_gateway_failures_and_success_resets() {
        let g = outlier_group(&["a:1", "b:2"], 2, 60_000, 100);
        let a = g.instances[0].clone();
        assert!(
            !g.record_outcome(&a, true),
            "1st failure is below the threshold"
        );
        // a success between failures resets the streak.
        assert!(!g.record_outcome(&a, false));
        assert!(
            !g.record_outcome(&a, true),
            "streak reset → this is the 1st again"
        );
        assert!(
            g.record_outcome(&a, true),
            "2nd consecutive failure ejects (returns true)"
        );
        assert!(a.is_outlier_ejected(now_millis()), "ejected from rotation");
        assert!(
            a.is_healthy(),
            "but the health bit is untouched — outlier detection is a separate axis (ADR 000032)"
        );
    }

    #[test]
    fn outlier_ejection_window_expires() {
        let g = outlier_group(&["a:1", "b:2"], 1, 1000, 100);
        let a = g.instances[0].clone();
        assert!(
            g.record_outcome(&a, true),
            "threshold 1 → one failure ejects"
        );
        let now = now_millis();
        assert!(a.is_outlier_ejected(now), "ejected at `now`");
        assert!(
            !a.is_outlier_ejected(now + 2000),
            "the 1s window has expired 2s later — auto-return, no probe needed"
        );
    }

    #[test]
    fn outlier_max_ejection_percent_keeps_some_in_rotation() {
        // 3 instances, 50% cap → at most 1 may be ejected; the rest stay in rotation even while
        // failing, so fail-closed never becomes a self-inflicted total outage.
        let g = outlier_group(&["a:1", "b:2", "c:3"], 1, 60_000, 50);
        let a = g.instances[0].clone();
        let b = g.instances[1].clone();
        assert!(g.record_outcome(&a, true), "a ejects (1/3 within 50%)");
        assert!(
            !g.record_outcome(&b, true),
            "b is NOT ejected — a 2nd ejection (2/3) would exceed the 50% cap"
        );
        assert!(!b.is_outlier_ejected(now_millis()), "b stays in rotation");
    }

    #[test]
    fn outlier_disabled_never_ejects() {
        let g = outlier_group(&["a:1"], 0, 60_000, 100); // consecutive 0 = disabled
        let a = g.instances[0].clone();
        for _ in 0..100 {
            assert!(
                !g.record_outcome(&a, true),
                "a disabled policy never ejects"
            );
        }
        assert!(!a.is_outlier_ejected(now_millis()));
    }

    #[test]
    fn outlier_ejected_instance_is_skipped_by_pick() {
        let g = outlier_group(&["a:1", "b:2"], 1, 60_000, 100);
        let a = g.instances[0].clone();
        assert!(g.record_outcome(&a, true), "eject a");
        for _ in 0..6 {
            assert_eq!(
                g.pick(None).unwrap().address(),
                "b:2",
                "round-robin skips the outlier-ejected (but still healthy) instance"
            );
        }
    }

    // ----- ADR 000035: weighted least-request (P2C) and weighted maglev -----

    /// A healthy upstream group with the given instances and LB config (ADR 000035).
    fn lb_group(
        addresses: Vec<AddressSpec>,
        algo: LbAlgorithm,
        hash: Option<HashConfig>,
    ) -> Arc<UpstreamGroup> {
        let reg = UpstreamRegistry::new();
        reg.reconcile(&[Upstream {
            name: "u".to_string(),
            addresses,
            lb_algorithm: algo,
            hash,
            health: health(1, 1),
            request_timeout_ms: 30_000,
            max_retries: 0,
            overall_timeout_ms: 0,
            circuit_breaker: CircuitBreaker::default(),
            outlier_detection: OutlierDetection::default(),
        }])
        .unwrap();
        let g = reg.group("u").unwrap();
        for inst in &g.instances {
            inst.record_probe_success(); // cold-start: all healthy
        }
        g
    }

    fn bare(addrs: &[&str]) -> Vec<AddressSpec> {
        addrs
            .iter()
            .map(|s| AddressSpec::Bare(s.to_string()))
            .collect()
    }

    #[test]
    fn least_request_avoids_the_busier_instance() {
        // With two instances, P2C compares both, so it deterministically routes to the one with the
        // lower (in_flight + 1) / weight. Holding a pick inflates its in-flight; the next pick must
        // then avoid it.
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        let p1 = g.pick(None).unwrap();
        let busy = addr_of(&p1);
        let p2 = g.pick(None).unwrap();
        assert_ne!(
            addr_of(&p2),
            busy,
            "least-request must avoid the instance already carrying a request"
        );
    }

    #[test]
    fn least_request_weight_biases_toward_higher_capacity() {
        // Both idle, so (0+1)/weight decides: the weight-3 instance (ratio 1/3) beats the weight-1
        // (ratio 1/1). With two instances P2C compares both, so the idle pick is deterministic.
        let g = lb_group(
            vec![
                AddressSpec::Bare("small".to_string()),
                AddressSpec::Weighted(crate::manifest::WeightedAddress {
                    address: "big".to_string(),
                    weight: 3,
                }),
            ],
            LbAlgorithm::LeastRequest,
            None,
        );
        assert_eq!(
            addr_of(&g.pick(None).unwrap()),
            "big",
            "a higher-weight idle instance is preferred"
        );
    }

    #[test]
    fn least_request_meters_in_flight_and_releases_on_drop() {
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        let total =
            |g: &UpstreamGroup| -> usize { g.instances.iter().map(|i| i.in_flight()).sum() };
        assert_eq!(total(&g), 0);
        {
            let _p = g.pick(None).unwrap();
            assert_eq!(total(&g), 1, "one in-flight while the Pick is held");
            let _q = g.pick(None).unwrap();
            assert_eq!(total(&g), 2, "two in-flight while both Picks are held");
        }
        assert_eq!(
            total(&g),
            0,
            "active-request counts released when the Picks drop"
        );
    }

    #[test]
    fn least_request_fails_closed_when_all_unhealthy() {
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::LeastRequest, None);
        for inst in &g.instances {
            inst.record_probe_failure(); // unhealthy_threshold = 1 → ejected
        }
        assert!(g.pick(None).is_none(), "no eligible instance → None → 503");
    }

    fn header_hash(m: u32) -> Option<HashConfig> {
        Some(HashConfig {
            key: HashKeyKind::Header,
            header: Some("x-user".to_string()),
            table_size: m,
        })
    }

    #[test]
    fn maglev_pins_a_key_to_one_instance() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"session-42");
        let pinned = addr_of(&g.pick(Some(key)).unwrap());
        for _ in 0..30 {
            assert_eq!(
                addr_of(&g.pick(Some(key)).unwrap()),
                pinned,
                "the same key always resolves to the same instance (affinity)"
            );
        }
    }

    #[test]
    fn maglev_spreads_distinct_keys() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let mut seen = HashSet::new();
        for i in 0..300 {
            let key = format!("user-{i}");
            seen.insert(addr_of(
                &g.pick(Some(HashInput::Bytes(key.as_bytes()))).unwrap(),
            ));
        }
        assert_eq!(seen.len(), 3, "distinct keys reach every instance");
    }

    #[test]
    fn maglev_falls_back_to_round_robin_without_a_key() {
        // No key (e.g. the configured header is absent) → round-robin over the eligible set, never None
        // while one is up.
        let g = lb_group(bare(&["a:1", "b:2"]), LbAlgorithm::Maglev, header_hash(97));
        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.insert(addr_of(&g.pick(None).unwrap()));
        }
        assert_eq!(
            seen.len(),
            2,
            "keyless maglev round-robins across instances"
        );
    }

    #[test]
    fn maglev_falls_back_when_the_primary_is_unhealthy() {
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"sticky-key");
        let primary = addr_of(&g.pick(Some(key)).unwrap());
        // eject the affinity target (unhealthy_threshold = 1).
        g.instances
            .iter()
            .find(|i| i.address() == primary)
            .unwrap()
            .record_probe_failure();
        let alt = g.pick(Some(key)).unwrap();
        assert_ne!(
            addr_of(&alt),
            primary,
            "a down primary falls back to another healthy instance"
        );
        assert!(alt.is_healthy());
    }

    #[test]
    fn maglev_excludes_on_retry() {
        // A retry must land elsewhere even for the affinity target (ADR 000023 semantics preserved).
        let g = lb_group(
            bare(&["a:1", "b:2", "c:3"]),
            LbAlgorithm::Maglev,
            header_hash(97),
        );
        let key = HashInput::Bytes(b"retry-key");
        let first = g.pick(Some(key)).unwrap();
        let retried = g.pick_excluding(first.instance(), Some(key)).unwrap();
        assert_ne!(
            addr_of(&retried),
            addr_of(&first),
            "retry skips the just-tried instance"
        );
    }
}
