//! plecto-host — embeds wasmtime to run `plecto:filter` components (ADR 000001 / 000002).
//!
//! ADR 000004 slice: the filter **runtime model**. The host branches on trust at load
//! (ADR 000011's knot, made concrete):
//!   - **trusted** filters get a fixed-capacity **pool** of reusable instances on a
//!     **pooling-allocator** engine, checked out per request (ADR 000012). `init` runs once
//!     *per instance* — Tenet 4 pays off (init-derived state stays resident). The pool is
//!     lazily filled: a single thread only ever needs one instance, so init stays once; under
//!     concurrency the pool builds more (up to its cap), which is where the pooling allocator
//!     finally earns its keep. Saturation (every instance checked out) waits a bounded time
//!     then fails **closed** (`Unavailable`), and an instance is recycled after serving a
//!     configured number of requests to bound linear-memory state accumulation (§6.6).
//!     Binding the pool to the tokio/quinn fast path (blocking pool vs fiber) is M2's job.
//!   - **untrusted** filters get a **fresh instance per request** on an on-demand engine,
//!     so linear memory is zeroized **by construction** (no slot reuse → CVE-2022-39393
//!     surface absent, ADR 000006). The cost is `init` every request — the deliberate
//!     trade of isolation (ADR 000011).
//!
//! State lives behind a `KvBackend` (in-memory or redb) — filters are stateless (Fork 4),
//! keys are host-namespaced per filter identity + primitive (ADR 000011). The `Linker`
//! stays **deny-by-default**: it lends ONLY the plecto host-API (log / clock / kv /
//! counter / ratelimit). No WASI, network, filesystem, or sockets (ADR 000006).

mod backend;
mod observe;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use parking_lot::{Condvar, Mutex};
use sha2::{Digest, Sha256};
use sigstore::crypto::{CosignVerificationKey, Signature};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store, StoreLimits,
    StoreLimitsBuilder,
};

pub use backend::{Acquire, Bucket, KvBackend, MemoryBackend, RedbBackend};
pub use observe::{
    FanOutSink, FilterSpan, Hook, InMemorySink, MetricsSink, MetricsSnapshot, NoopSink,
    RequestTrace, SpanOutcome, TelemetrySink,
};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../../wit",
        world: "filter",
        // M3 Stage 1 (ADR 000021): the guest's exported hooks (init / on-request / on-response) run
        // via call_async on wasmtime fibers — the prerequisite for future WASI async host calls. The
        // trivial plecto host-API IMPORTS stay sync (they never block, so they don't need to be
        // async). Body / stream<u8> contract stays frozen until Stage 2.
        exports: { default: async },
    });
}

// One canonical set of contract types for callers and tests.
pub use bindings::plecto::filter::host_log::Level as LogLevel;
pub use bindings::plecto::filter::types::{
    Header, HttpRequest, HttpResponse, RequestBodyDecision, RequestDecision, RequestEdit,
    ResponseDecision, ResponseEdit,
};
use bindings::plecto::filter::{host_clock, host_counter, host_kv, host_log, host_ratelimit};
use bindings::{Filter, FilterPre};

/// How a filter is instantiated and isolated (ADR 000004 / 000011). Not a "trust score":
/// it selects the **instance lifecycle**, mirroring how Fastly/Spin model per-request vs
/// reusable sandboxes. *Who* is trusted is decided elsewhere (OCI signing, ADR 000006);
/// this only says which lifecycle a loaded filter gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Own filters: a pool of reusable instances, `init` once per instance, checked out per
    /// request (ADR 000012). No per-request zeroization (same trust domain). Statelessness
    /// (Fork 4) is therefore honored by *trust*, not *enforced*: a trusted filter that stashes
    /// mutable state in its own linear memory silently carries it across requests on a reused
    /// instance — and, with a pool, *which* instance a request lands on becomes observable
    /// (§6.6 footgun). That is not a security boundary (same trust domain); periodic recycling
    /// (`max_requests_per_instance`) bounds the accumulation, but only `Untrusted`'s
    /// fresh-per-request memory enforces statelessness structurally (ADR 000011).
    Trusted,
    /// Third-party filters: fresh instance per request, memory fresh by construction.
    Untrusted,
}

/// Generous default budget for the heavy once-per-instance `init` of a **trusted** filter
/// (Tenet 4): regex compile, schema build, config parse. Trusted init runs once per instance
/// and is then reused, so a large budget is paid once — separate from, and much larger than,
/// the per-request budget so a legitimately heavy init is not mistaken for a runaway (ADR 000006).
const DEFAULT_INIT_DEADLINE_MS: u64 = 5_000;
/// Tight default `init` budget for an **untrusted** filter. Untrusted filters instantiate fresh
/// and re-run `init` on EVERY request (the isolation trade, ADR 000011), on the worker thread, so
/// init is on the hot path: the generous 5s trusted budget would let an adversarial untrusted
/// `init` busy-loop and pin a core for ~5s per request (CWE-770). Bound it near the
/// per-request budget; an operator may still raise it per filter via the manifest.
const DEFAULT_UNTRUSTED_INIT_DEADLINE_MS: u64 = 250;
/// Tight default budget for the hot per-request hooks. This is a *safety* bound that traps
/// runaway filters (infinite loops), not a latency SLA; header-only filters finish in well
/// under a millisecond.
const DEFAULT_REQUEST_DEADLINE_MS: u64 = 100;

// --- host-state (KV / counter / ratelimit) quotas (CWE-770). The host charges every
// --- value, counter, and bucket against the owning filter's namespace and a global ceiling so
// --- an untrusted, multi-tenant filter cannot grow host memory/disk without bound. ---

/// Largest value a filter may store under one KV key. A bigger `set` is dropped (fail-closed).
const MAX_KV_VALUE_BYTES: usize = 256 * 1024;
/// Largest filter-supplied key. A longer key is dropped (bounds the namespaced key itself).
const MAX_KV_KEY_BYTES: usize = 1024;
/// Per-filter (namespace) cap on the number of distinct keys across kv + counter + ratelimit.
const MAX_NS_ENTRIES: usize = 100_000;
/// Per-filter (namespace) cap on total stored bytes (keys + values) across all primitives.
const MAX_NS_BYTES: usize = 64 << 20;
/// Host-wide cap on total entries across every filter (multi-tenant ceiling).
const MAX_TOTAL_ENTRIES: usize = 5_000_000;
/// Host-wide cap on total stored bytes across every filter (multi-tenant ceiling).
const MAX_TOTAL_BYTES: usize = 1 << 30;
/// Per-request cap on host-log lines a filter may emit (CWE-770). The last slot is a
/// single truncation marker so overflow stays observable.
const MAX_LOG_LINES_PER_REQUEST: usize = 256;
/// Per-line cap on a host-log message; a longer message is truncated on a char boundary.
const MAX_LOG_MSG_BYTES: usize = 8 * 1024;
/// Default per-instance linear-memory cap enforced via a `StoreLimits` (ADR 000006). Matches
/// the pooling engine's per-slot reservation so trusted and untrusted agree.
const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 << 20;

/// Per-instance cap on total table elements (review f000003 #2). `StoreLimits::memory_size`
/// bounds linear memory but NOT `table.grow`; a guest growing a huge funcref table could eat
/// host memory outside the linear-memory cap before the epoch deadline trips. This is generous
/// for any reasonable filter and bounds the pathological case — cheap defense-in-depth.
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// Bounded wait (ms) for a free trusted instance before a checkout fails closed (ADR 000012).
/// wasmtime's pooling allocator has no internal queue and the official guidance is for the
/// embedder to apply its own backpressure; this is that wait. Kept short — orders of magnitude
/// below a connection pool's seconds-long default — because on a gateway hot path it is better
/// to shed load (`Unavailable`) than to queue unboundedly. M2 ties this to the real SLO.
const DEFAULT_CHECKOUT_TIMEOUT_MS: u64 = 250;
/// Recycle (discard + rebuild) a trusted instance after it has served this many requests
/// (ADR 000012 / §6.6). Generous so steady-state reuse dominates (init-once still effectively
/// holds), while still bounding accidental linear-memory state accumulation over an instance's
/// life. Following Fastly's reusable-sandbox `max-requests`.
const DEFAULT_MAX_REQUESTS_PER_INSTANCE: u64 = 1 << 16;
/// Default ceiling for the auto-sized trusted pool (`available_parallelism`, clamped here).
/// Modest so a multi-filter manifest does not, by default, multiply out past the engine's
/// global pooling budget before the manifest registry (ADR 000007) can apportion it.
const TRUSTED_POOL_DEFAULT_CEIL: usize = 8;
/// Hard ceiling on a trusted pool, matched to the pooling engine's per-kind slot budget so a
/// single filter cannot, by itself, demand more instances than the engine reserved.
const TRUSTED_POOL_MAX: usize = TRUSTED_POOL_SLOTS;

/// Auto-sized default trusted pool capacity: worker-scale (foundation plan §6.3), approximated
/// by `available_parallelism` until the fast-path server brings real worker threads (M2). A
/// single-threaded caller still only ever builds one instance (lazy fill), so this does not
/// change the init-once behaviour observed serially.
fn default_trusted_pool_size() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, TRUSTED_POOL_DEFAULT_CEIL)
}

/// Options for `Host::load`. A struct (not a bare arg) because deny-by-default grows more
/// load-time knobs onto it. Defaults to the safe side: `Untrusted` (fail-closed) with
/// metering on (ADR 000006). A future declarative manifest (ADR 000007) injects these.
#[derive(Debug, Clone, Copy)]
pub struct LoadOptions {
    pub isolation: Isolation,
    /// Epoch deadline (ms) for the once-per-instance `init` export.
    pub init_deadline_ms: u64,
    /// Epoch deadline (ms) for each per-request hook (`on-request` / `on-response`).
    pub request_deadline_ms: u64,
    /// Per-instance linear-memory cap (bytes), enforced by a `StoreLimits`.
    pub max_memory_bytes: u64,
    /// Trusted pool: maximum concurrent reusable instances (lazily filled, ADR 000012).
    /// Clamped to `[1, TRUSTED_POOL_MAX]` at load. Ignored for `Untrusted` (fresh-per-request).
    pub trusted_pool_size: usize,
    /// Trusted pool: bounded wait (ms) for a free instance under saturation before failing
    /// closed (`RunError::Unavailable`). Ignored for `Untrusted`.
    pub checkout_timeout_ms: u64,
    /// Trusted pool: recycle an instance (discard + rebuild) after this many requests, bounding
    /// linear-memory state accumulation (§6.6). Ignored for `Untrusted`.
    pub max_requests_per_instance: u64,
    /// This filter's host-side token-bucket spec for `host-ratelimit` (manifest
    /// `[filter.ratelimit]`, ADR 000026). `None` = the filter has no limiter (its `try-acquire`
    /// fails closed). Host-configured so an untrusted filter cannot override its own limit.
    pub ratelimit_bucket: Option<Bucket>,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            isolation: Isolation::Untrusted,
            // default is untrusted → init re-runs per request, so bound it tight.
            init_deadline_ms: DEFAULT_UNTRUSTED_INIT_DEADLINE_MS,
            request_deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            trusted_pool_size: default_trusted_pool_size(),
            checkout_timeout_ms: DEFAULT_CHECKOUT_TIMEOUT_MS,
            max_requests_per_instance: DEFAULT_MAX_REQUESTS_PER_INSTANCE,
            ratelimit_bucket: None,
        }
    }
}

impl LoadOptions {
    pub fn trusted() -> Self {
        Self {
            isolation: Isolation::Trusted,
            // trusted init runs ONCE per instance and is reused → keep the generous budget.
            init_deadline_ms: DEFAULT_INIT_DEADLINE_MS,
            ..Self::default()
        }
    }
    pub fn untrusted() -> Self {
        Self::default()
    }
    /// Override the per-request hook deadline (ms).
    pub fn with_request_deadline_ms(mut self, ms: u64) -> Self {
        self.request_deadline_ms = ms;
        self
    }
    /// Override the `init` deadline (ms).
    pub fn with_init_deadline_ms(mut self, ms: u64) -> Self {
        self.init_deadline_ms = ms;
        self
    }
    /// Override the per-instance linear-memory cap (bytes).
    pub fn with_max_memory_bytes(mut self, bytes: u64) -> Self {
        self.max_memory_bytes = bytes;
        self
    }
    /// Override the trusted pool capacity (max concurrent reusable instances).
    pub fn with_trusted_pool_size(mut self, n: usize) -> Self {
        self.trusted_pool_size = n;
        self
    }
    /// Override the bounded checkout wait (ms) before a saturated trusted pool fails closed.
    pub fn with_checkout_timeout_ms(mut self, ms: u64) -> Self {
        self.checkout_timeout_ms = ms;
        self
    }
    /// Override how many requests a trusted instance serves before it is recycled.
    pub fn with_max_requests_per_instance(mut self, n: u64) -> Self {
        self.max_requests_per_instance = n;
        self
    }
    /// Configure this filter's host-side `host-ratelimit` token bucket (ADR 000026). Without it,
    /// the filter's `try-acquire` fails closed. The filter cannot supply or override these.
    pub fn with_ratelimit_bucket(
        mut self,
        capacity: u64,
        refill_tokens: u64,
        refill_interval_ms: u64,
    ) -> Self {
        self.ratelimit_bucket = Some(Bucket {
            capacity,
            refill_tokens,
            refill_interval_ms,
        });
        self
    }
}

/// Why a per-request filter call did not produce a `decision`. Kept deliberately distinct
/// from `RequestDecision`/`ResponseDecision` — those are the filter's *intentional* typed
/// output; a `RunError` is the filter *failing*. The fast path MUST fail-closed on it:
/// synthesise an error response and never forward to upstream (CLAUDE.md — no fail-open).
/// Keeping the two apart also makes "deadline" vs "trap" an observable health signal.
#[derive(Debug)]
pub enum RunError {
    /// The filter ran past its epoch deadline (ADR 000006 metering) and was interrupted.
    /// Fail-closed mapping: 504.
    Deadline,
    /// The filter trapped (`unreachable`, a guest panic, or an allocation past the Store
    /// memory limit that aborted the guest). Fail-closed mapping: 502.
    Trap(anyhow::Error),
    /// A fresh instance could not be created — untrusted per-request instantiation, or the
    /// rebuild of a trusted instance after a prior trap. Fail-closed mapping: 502.
    Instantiate(anyhow::Error),
    /// A trusted filter trapped on several consecutive requests, so the host is in a short
    /// trap-cooldown: it returns this cheap fail-closed response instead of re-instantiating +
    /// re-init'ing every request (circuit-breaker, review f000003 #5). Fail-closed mapping: 503.
    Unavailable,
}

impl RunError {
    /// Classify the error from a guest call: an epoch interrupt is a `Deadline`, anything
    /// else is a `Trap`. (`wasmtime 45` returns its own `wasmtime::Error`, distinct from
    /// `anyhow::Error`; we convert into `anyhow::Error` for storage.)
    fn from_call(e: wasmtime::Error) -> Self {
        match e.downcast_ref::<wasmtime::Trap>() {
            Some(wasmtime::Trap::Interrupt) => RunError::Deadline,
            _ => RunError::Trap(anyhow::Error::from(e)),
        }
    }

    /// A synthetic, fail-closed response for this fault (host helper; the fast path may send
    /// it directly). Deadline → 504, every other fault → 502. Never a pass-through.
    pub fn fail_closed_response(&self) -> HttpResponse {
        let (status, fault, msg): (u16, &str, &str) = match self {
            RunError::Deadline => (504, "deadline", "filter deadline exceeded"),
            RunError::Trap(_) => (502, "trap", "filter trapped"),
            RunError::Instantiate(_) => (502, "instantiate", "filter instantiation failed"),
            RunError::Unavailable => (503, "unavailable", "filter temporarily unavailable"),
        };
        HttpResponse {
            status,
            headers: vec![Header {
                name: "x-plecto-fault".to_string(),
                value: fault.to_string(),
            }],
            body: msg.as_bytes().to_vec(),
        }
    }
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Deadline => write!(f, "filter exceeded its epoch deadline"),
            RunError::Trap(e) => write!(f, "filter trapped: {e}"),
            RunError::Instantiate(e) => write!(f, "filter instantiation failed: {e}"),
            RunError::Unavailable => write!(f, "filter is in trap-cooldown (circuit open)"),
        }
    }
}

impl std::error::Error for RunError {}

/// The set of public keys the operator trusts to sign filters (ADR 000006 provenance). A
/// filter loads only if a trusted key verifies BOTH its component signature and its SBOM
/// signature (keyed cosign, offline — no Fulcio / Rekor / network). An **empty** policy
/// trusts no one, so nothing loads: deny-by-default / fail-closed, with no "allow unsigned"
/// escape hatch in the production API. The keys live on the `Host`, not on each `load` call,
/// so the operator manages one trust root.
///
/// This gates *whether a filter may load at all*. It deliberately does NOT pick the filter's
/// `Isolation` (trusted/untrusted lifecycle) — a valid signature from a third party's key is
/// still untrusted code. Mapping signer identity to isolation is left to the declarative
/// manifest (ADR 000007); here, isolation stays the caller's explicit `LoadOptions` choice.
pub struct TrustPolicy {
    keys: Vec<CosignVerificationKey>,
}

impl TrustPolicy {
    /// Trust the given public keys (SPKI PEM). The key type is auto-detected — cosign's
    /// default is ECDSA P-256; P-256 / Ed25519 / RSA cosign keys are all accepted.
    pub fn from_pem_keys<I, B>(pems: I) -> Result<Self>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let keys = pems
            .into_iter()
            .map(|pem| {
                CosignVerificationKey::try_from_pem(pem.as_ref())
                    .map_err(|e| anyhow::anyhow!("invalid trusted public key (PEM): {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { keys })
    }

    /// An explicitly empty policy — trusts no one, so every load fails closed. Useful to
    /// assert the fail-closed default.
    pub fn empty() -> Self {
        Self { keys: Vec::new() }
    }

    /// Does ANY trusted key verify this raw (DER) signature over `msg`? cosign ECDSA
    /// signatures are ASN.1 DER; verification hashes `msg` internally (do not pre-hash).
    fn verifies(&self, signature_der: &[u8], msg: &[u8]) -> bool {
        self.keys.iter().any(|k| {
            k.verify_signature(Signature::Raw(signature_der), msg)
                .is_ok()
        })
    }
}

/// The material the host verifies before instantiating a filter (ADR 000006). The component
/// bytes plus a keyed cosign signature over them, and a **mandatory** SBOM with its own
/// signature. Signatures are RAW DER ECDSA bytes: decoding cosign's base64 `.sig` and
/// fetching the artifact from an OCI registry is the ADR 000007 / `wkg` boundary, kept out
/// of the host so ADR 000006 (verify) and ADR 000007 (distribute) stay decoupled.
pub struct SignedArtifact<'a> {
    /// The WASM component bytes.
    pub component_bytes: &'a [u8],
    /// Raw DER signature over `component_bytes` (cosign `sign-blob`).
    pub component_signature: &'a [u8],
    /// The SBOM as an in-toto-style statement whose `subject[].digest.sha256` binds it to
    /// `component_bytes` (verified at load, review f000003 #1). The predicate (the SBOM body)
    /// stays opaque in v0.1 — content policy (CVE / license scanning) is deferred.
    pub sbom: &'a [u8],
    /// Raw DER signature over `sbom`.
    pub sbom_signature: &'a [u8],
}

/// Verify the SBOM attests THIS component: parse it as an in-toto-style statement and require
/// at least one `subject[].digest.sha256` to equal `sha256(component)`. Fail-closed on a
/// malformed SBOM or a missing / mismatched subject (review f000003 #1). Without this, a
/// validly-signed but UNRELATED SBOM could be paired with the component — harmless while the
/// SBOM is opaque, a latent gap the moment its content becomes load-bearing (CVE / license).
fn sbom_binds_component(sbom: &[u8], component: &[u8]) -> Result<()> {
    let statement: serde_json::Value = serde_json::from_slice(sbom)
        .map_err(|e| anyhow::anyhow!("SBOM is not a valid in-toto statement: {e}"))?;
    let want = hex::encode(Sha256::digest(component));
    let bound = statement
        .get("subject")
        .and_then(|s| s.as_array())
        .is_some_and(|subjects| {
            subjects.iter().any(|subject| {
                subject
                    .get("digest")
                    .and_then(|d| d.get("sha256"))
                    .and_then(|h| h.as_str())
                    == Some(want.as_str())
            })
        });
    anyhow::ensure!(
        bound,
        "SBOM does not attest this component: no subject digest matches sha256(component) \
         (fail-closed; ADR 000006 / review f000003)"
    );
    Ok(())
}

/// A log line captured from the host-log capability (test visibility / future tracing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub level: LogLevel,
    pub message: String,
}

/// Delimiter the host uses to namespace KV keys by filter identity. A filter can never
/// remove the host-applied prefix, so it cannot reach another filter's namespace —
/// capability isolation across a chain (ADR 000006 / 000011). Filter ids must not contain
/// this byte (enforced by `Host::load`).
const KV_NS_DELIM: char = '\u{1f}';

// Primitive sub-namespace tags, so a filter's kv "x", counter "x", and bucket "x" never
// collide in the shared backend keyspace.
const TAG_KV: u8 = b'k';
const TAG_COUNTER: u8 = b'c';
const TAG_RATELIMIT: u8 = b'r';

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Default, Clone, Copy)]
struct NsUsage {
    entries: usize,
    bytes: usize,
}

struct QuotaInner {
    ns: HashMap<String, NsUsage>,
    total_entries: usize,
    total_bytes: usize,
}

/// Per-filter (namespace) accounting and caps for host-held state (CWE-770). The host
/// charges every KV value, counter, and rate-limit bucket against the owning filter's namespace
/// and a host-wide ceiling, so an untrusted, multi-tenant filter cannot grow host memory (or the
/// redb file) without bound — the `StoreLimits` cap only bounds the guest's own linear memory,
/// not the host-side store. Enforced here at the capability boundary, keeping `KvBackend` generic.
/// One per `Host`, shared (`Arc`) across every filter's `HostState`.
struct KvQuota {
    inner: Mutex<QuotaInner>,
}

impl KvQuota {
    fn new() -> Self {
        Self {
            inner: Mutex::new(QuotaInner {
                ns: HashMap::new(),
                total_entries: 0,
                total_bytes: 0,
            }),
        }
    }

    /// Try to charge `(entries_delta, bytes_delta)` to namespace `ns`. A growth that would push
    /// the namespace or the host-wide total past a cap is rejected (returns `false`, the caller
    /// fails closed); a shrink (negative delta) always applies. Commits atomically under the lock.
    fn admit(&self, ns: &str, entries_delta: isize, bytes_delta: isize) -> bool {
        let mut g = self.inner.lock();
        let cur = g.ns.get(ns).copied().unwrap_or_default();
        let new_ns_entries = cur.entries as isize + entries_delta;
        let new_ns_bytes = cur.bytes as isize + bytes_delta;
        let new_total_entries = g.total_entries as isize + entries_delta;
        let new_total_bytes = g.total_bytes as isize + bytes_delta;
        // Only growth can violate a cap; a shrink (delete / smaller value) always applies.
        if (entries_delta > 0
            && (new_ns_entries as usize > MAX_NS_ENTRIES
                || new_total_entries as usize > MAX_TOTAL_ENTRIES))
            || (bytes_delta > 0
                && (new_ns_bytes as usize > MAX_NS_BYTES
                    || new_total_bytes as usize > MAX_TOTAL_BYTES))
        {
            return false;
        }
        let usage = g.ns.entry(ns.to_string()).or_default();
        usage.entries = new_ns_entries.max(0) as usize;
        usage.bytes = new_ns_bytes.max(0) as usize;
        g.total_entries = new_total_entries.max(0) as usize;
        g.total_bytes = new_total_bytes.max(0) as usize;
        true
    }

    /// Release `(entries, bytes)` from `ns` (a delete). Never rejects.
    fn release(&self, ns: &str, entries: usize, bytes: usize) {
        self.admit(ns, -(entries as isize), -(bytes as isize));
    }
}

/// Neutralize a guest-supplied log message (CWE-117): truncate to a byte cap on a char
/// boundary and replace control characters (CR/LF for log-line injection, C0/C1/ESC for terminal
/// ANSI) with the replacement char. The filter is untrusted and may embed `Authorization` header
/// bytes or escape sequences, so the host — the trust boundary — neutralizes before storing.
fn sanitize_log_message(mut message: String) -> String {
    if message.len() > MAX_LOG_MSG_BYTES {
        let mut end = MAX_LOG_MSG_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    if message.bytes().any(|b| b < 0x20 || b == 0x7f) {
        message = message
            .chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect();
    }
    message
}

/// Per-request host state: the capability handles lent to a filter plus request-scoped
/// buffers. For untrusted filters a fresh one is built per request; for trusted filters
/// the same one is reused with `begin_request` resetting the per-request fields, while the
/// instance's init-derived linear memory persists (ADR 000011).
pub struct HostState {
    kv: Arc<dyn KvBackend>,
    /// Host-owned prefix (`"{filter_id}\u{1f}"`) applied to every key. The filter cannot
    /// observe or alter it.
    kv_prefix: String,
    logs: Vec<LogLine>,
    /// Wall-clock ms captured once at request start: a stable per-request snapshot.
    now_ms: u64,
    /// Linear-memory / table / instance caps for this Store (ADR 000006). Wired via
    /// `Store::limiter`; a grow past the cap is denied, bounding mis-allocation and runaway
    /// growth even on the untrusted on-demand engine (which has no pooling reservation).
    limits: StoreLimits,
    /// This filter's host-configured token-bucket spec (manifest `[filter.ratelimit]`, ADR
    /// 000026). `None` = no bucket configured → `host-ratelimit/try-acquire` fails closed. The
    /// filter cannot supply or override it, so an untrusted filter cannot neuter its own limiter.
    ratelimit_bucket: Option<Bucket>,
    /// Shared per-namespace accounting + caps for host-held state. Charged on every
    /// `set` / `increment` / `try_acquire` that grows the store; over-quota writes fail closed.
    quota: Arc<KvQuota>,
}

impl HostState {
    fn new(
        kv: Arc<dyn KvBackend>,
        kv_prefix: String,
        max_memory_bytes: u64,
        ratelimit_bucket: Option<Bucket>,
        quota: Arc<KvQuota>,
    ) -> Self {
        Self {
            kv,
            kv_prefix,
            logs: Vec::new(),
            now_ms: wall_now_ms(),
            limits: StoreLimitsBuilder::new()
                .memory_size(max_memory_bytes as usize)
                .table_elements(MAX_TABLE_ELEMENTS)
                .build(),
            ratelimit_bucket,
            quota,
        }
    }

    /// Reset per-request state for a reused (trusted) instance. Clears the log buffer and
    /// re-snapshots the clock; the WASM instance's linear memory (init-derived) is untouched.
    fn begin_request(&mut self) {
        self.logs.clear();
        self.now_ms = wall_now_ms();
    }

    /// Namespace a filter-supplied key into `{filter_id}\u{1f}{tag}\u{1f}{key}` bytes.
    fn ns_key(&self, tag: u8, key: &str) -> Vec<u8> {
        let mut k = Vec::with_capacity(self.kv_prefix.len() + 2 + key.len());
        k.extend_from_slice(self.kv_prefix.as_bytes());
        k.push(tag);
        k.push(KV_NS_DELIM as u8);
        k.extend_from_slice(key.as_bytes());
        k
    }
}

// --- host-API capability implementations (deny-by-default: only these are lent) ---

// `types` is a type-only interface (no functions); the generated `Host` trait is empty.
impl bindings::plecto::filter::types::Host for HostState {}

impl host_log::Host for HostState {
    fn log(&mut self, level: LogLevel, message: String) {
        // Bound per-request log volume and neutralize control bytes: a guest can
        // loop `log` until its deadline, so cap the line count (reserving the last slot for one
        // truncation marker) and sanitize each message before it is stored.
        match self.logs.len() {
            n if n < MAX_LOG_LINES_PER_REQUEST - 1 => self.logs.push(LogLine {
                level,
                message: sanitize_log_message(message),
            }),
            n if n == MAX_LOG_LINES_PER_REQUEST - 1 => self.logs.push(LogLine {
                level: LogLevel::Warn,
                message: "… host-log truncated (per-request line cap reached)".to_string(),
            }),
            _ => {}
        }
    }
}

impl host_clock::Host for HostState {
    fn now_ms(&mut self) -> u64 {
        self.now_ms
    }
}

impl host_kv::Host for HostState {
    fn get(&mut self, key: String) -> Option<Vec<u8>> {
        self.kv.get(&self.ns_key(TAG_KV, &key))
    }
    fn set(&mut self, key: String, value: Vec<u8>) {
        // Per-key size limits + per-namespace/global quota. Over-limit writes are dropped
        // (fail-closed): from the filter's view the host-API is infallible ("reads vanish").
        if key.len() > MAX_KV_KEY_BYTES || value.len() > MAX_KV_VALUE_BYTES {
            return;
        }
        let nskey = self.ns_key(TAG_KV, &key);
        // Charge the byte delta vs. any existing value (a new key also charges its key bytes + 1
        // entry). The read-before-write keeps the byte accounting exact for variable-size values.
        let (entries_delta, bytes_delta) = match self.kv.get(&nskey).map(|v| v.len()) {
            None => (1isize, (key.len() + value.len()) as isize),
            Some(old) => (0isize, value.len() as isize - old as isize),
        };
        if !self
            .quota
            .admit(&self.kv_prefix, entries_delta, bytes_delta)
        {
            return;
        }
        self.kv.set(&nskey, value);
    }
    fn delete(&mut self, key: String) {
        let nskey = self.ns_key(TAG_KV, &key);
        if let Some(old) = self.kv.get(&nskey).map(|v| v.len()) {
            self.kv.delete(&nskey);
            self.quota.release(&self.kv_prefix, 1, key.len() + old);
        }
    }
}

impl host_counter::Host for HostState {
    fn increment(&mut self, key: String, delta: i64) -> i64 {
        let nskey = self.ns_key(TAG_COUNTER, &key);
        // A zero delta is a pure read (host-counter.get); it neither creates a key nor is charged.
        if delta == 0 {
            return self.kv.increment(&nskey, 0);
        }
        // A counter is a fixed 8-byte value: only a NEW key grows the store, so charge one entry
        // when first created and fail closed (report the current value, do not create) over quota.
        if self.kv.get(&nskey).is_none()
            && !self
                .quota
                .admit(&self.kv_prefix, 1, (key.len() + 8) as isize)
        {
            return 0;
        }
        self.kv.increment(&nskey, delta)
    }
    fn get(&mut self, key: String) -> i64 {
        // increment-by-zero is an atomic read of the current value (and the canonical
        // wasi:keyvalue/atomics idiom); keeps the counter encoding inside the backend.
        self.kv.increment(&self.ns_key(TAG_COUNTER, &key), 0)
    }
}

impl host_ratelimit::Host for HostState {
    fn try_acquire(&mut self, key: String, cost: u64) -> host_ratelimit::Acquire {
        // The bucket spec is host-configured per filter (manifest, ADR 000026); the filter cannot
        // supply or override it. A filter with no configured bucket is denied (fail-closed) — it
        // cannot opt out of its limiter.
        let Some(spec) = self.ratelimit_bucket else {
            return host_ratelimit::Acquire {
                allowed: false,
                remaining: 0,
                retry_after_ms: 0,
            };
        };
        let nskey = self.ns_key(TAG_RATELIMIT, &key);
        // A bucket is a fixed 16-byte value: charge one entry when first created. Over quota a
        // filter cannot mint unbounded distinct-key buckets — deny (fail-closed), do not create.
        if self.kv.get(&nskey).is_none()
            && !self
                .quota
                .admit(&self.kv_prefix, 1, (key.len() + 16) as isize)
        {
            return host_ratelimit::Acquire {
                allowed: false,
                remaining: 0,
                retry_after_ms: 0,
            };
        }
        let r = self.kv.try_acquire(&nskey, cost, spec, self.now_ms);
        host_ratelimit::Acquire {
            allowed: r.allowed,
            remaining: r.remaining,
            retry_after_ms: r.retry_after_ms,
        }
    }
}

/// Granularity of the epoch ticker. Deadlines are expressed in milliseconds and converted
/// 1:1 to epoch increments, so the effective deadline resolution is one tick.
const EPOCH_TICK: Duration = Duration::from_millis(1);

/// Background thread that advances each engine's epoch counter so per-`Store` deadlines fire
/// (ADR 000006 metering). Without it `set_epoch_deadline` never trips. Stops and joins on
/// `Host` drop. One ticker per `Host`; it drives both engines (each has its own counter).
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn spawn(engines: Vec<Engine>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                std::thread::sleep(EPOCH_TICK);
                for e in &engines {
                    e.increment_epoch();
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The wasmtime host: two engines (one per isolation mode) plus the shared state backend.
/// One per process/worker.
pub struct Host {
    /// Pooling-allocator engine for trusted, reused-instance filters (init-once).
    trusted_engine: Engine,
    /// On-demand engine for untrusted, fresh-per-request filters (memory fresh by
    /// construction). Allocation strategy is per-Engine and immutable, so the trust split
    /// is two engines, not one (confirmed wasmtime 45 behaviour).
    untrusted_engine: Engine,
    kv: Arc<dyn KvBackend>,
    /// Per-namespace host-state accounting + caps, shared into every loaded filter.
    kv_quota: Arc<KvQuota>,
    /// Public keys this host trusts to sign filters (ADR 000006). Verified at every `load`.
    trust: TrustPolicy,
    /// Where loaded filters emit their per-execution spans (ADR 000009). Default `NoopSink`
    /// (observability off); cloned into each filter at `load`, so set it before loading.
    sink: Arc<dyn TelemetrySink>,
    /// Drives epoch deadlines for both engines; stops on drop. Held only for its lifetime.
    _epoch_ticker: EpochTicker,
}

/// Pooling-engine per-kind slot budget (memories / tables / instances), shared by every
/// trusted filter's pool (ADR 000012). VA-reservation cost only (slots × `max_memory_size`).
const TRUSTED_POOL_SLOTS: usize = 256;

enum Allocation {
    Pooling,
    OnDemand,
}

fn build_engine(alloc: Allocation) -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    // epoch interruption: the low-overhead deadline mechanism for the data plane (ADR 000006;
    // epoch over fuel — lighter, no determinism requirement here). A background ticker
    // advances the epoch; each Store sets a deadline before every guest call so a runaway
    // filter traps instead of hanging the worker (fail-closed).
    config.epoch_interruption(true);
    // M3 Stage 1 (ADR 000021): the host runs the guest on wasmtime fibers via `call_async` and
    // bridges it to its still-sync public API with `block_on` (the server-side spawn_blocking
    // removal is Stage 2). wasmtime 46 needs no `Config::async_support` toggle (it is deprecated /
    // a no-op) — the async path is selected by the bindgen `exports: async` config plus
    // `instantiate_async` / `call_async`. `memory_init_cow` stays at its default (enabled): every
    // instance gets its own copy-on-write heap image — safe against CVE-2022-39393 (ADR 000006).
    if let Allocation::Pooling = alloc {
        let mut pool = PoolingAllocationConfig::default();
        // Global per-kind slot budget for ALL trusted filters' pools combined (ADR 000012). The
        // pool reserves virtual address space up front (slots × max_memory_size), so this caps
        // VA reservation, not resident memory. `TRUSTED_POOL_MAX` bounds any single filter's
        // pool below this; the manifest registry (ADR 000007) will apportion the budget across
        // filters when the fast-path server lands. Exhaustion is a hard error (no internal
        // queue), surfaced as a fail-closed `RunError::Instantiate`.
        let slots = TRUSTED_POOL_SLOTS as u32;
        pool.total_memories(slots);
        pool.total_tables(slots);
        pool.total_core_instances(slots);
        pool.total_component_instances(slots);
        pool.max_memory_size(64 << 20); // 64 MiB per linear memory
        config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    }
    Ok(Engine::new(&config)?)
}

impl Host {
    /// A host backed by an in-memory store (the default; process-lifetime state). `trust` is
    /// the set of keys allowed to sign loadable filters (ADR 000006) — pass `TrustPolicy::empty()`
    /// only if you intend that nothing can load.
    pub fn new(trust: TrustPolicy) -> Result<Self> {
        Self::with_backend(trust, Arc::new(MemoryBackend::default()))
    }

    /// A host backed by a caller-supplied store (e.g. `RedbBackend` for durability).
    pub fn with_backend(trust: TrustPolicy, kv: Arc<dyn KvBackend>) -> Result<Self> {
        let trusted_engine = build_engine(Allocation::Pooling)?;
        let untrusted_engine = build_engine(Allocation::OnDemand)?;
        let _epoch_ticker =
            EpochTicker::spawn(vec![trusted_engine.clone(), untrusted_engine.clone()]);
        Ok(Self {
            trusted_engine,
            untrusted_engine,
            kv,
            kv_quota: Arc::new(KvQuota::new()),
            trust,
            sink: Arc::new(NoopSink),
            _epoch_ticker,
        })
    }

    /// Set the telemetry sink (ADR 000009 observability stage). Filters loaded **after** this
    /// emit one span per `on_request` / `on_response` to `sink`; the default is `NoopSink`
    /// (observability off, zero cost). Builder style: `Host::new(trust)?.with_telemetry_sink(sink)`.
    /// The sink is cloned into each filter at `load`, so set it before loading.
    pub fn with_telemetry_sink(mut self, sink: Arc<dyn TelemetrySink>) -> Self {
        self.sink = sink;
        self
    }

    /// Load a filter component under the given isolation mode. Type-checks and resolves
    /// imports up front (`InstancePre`). For `Trusted`, the single persistent instance is
    /// created now and `init` runs once; for `Untrusted`, instantiation is deferred to
    /// each request.
    ///
    /// `filter_id` is the host-assigned identity used to namespace this filter's keyspace
    /// (ADR 000011). It must be non-empty and free of the namespace delimiter; the filter
    /// never sees or controls it. **Uniqueness is the caller's responsibility**: `load`
    /// rejects an empty or delimiter-bearing id but not a duplicate, so loading the same id
    /// twice shares one keyspace. A manifest-driven registry will assign and dedup ids
    /// (ADR 000007).
    pub fn load(
        &self,
        filter_id: &str,
        artifact: &SignedArtifact<'_>,
        opts: LoadOptions,
    ) -> Result<LoadedFilter> {
        anyhow::ensure!(
            !filter_id.is_empty() && !filter_id.contains(KV_NS_DELIM),
            "filter id must be non-empty and must not contain the KV namespace delimiter"
        );

        // --- provenance gate (ADR 000006): verify BEFORE instantiate, fail-closed. A
        // --- missing / untrusted / tampered signature or a missing SBOM means we never
        // --- touch the component bytes with wasmtime. Order is cheap-checks first.
        anyhow::ensure!(
            !artifact.sbom.is_empty(),
            "a signed SBOM is required to load a filter (fail-closed; ADR 000006)"
        );
        anyhow::ensure!(
            self.trust
                .verifies(artifact.component_signature, artifact.component_bytes),
            "component signature is not verified by any trusted key (fail-closed; ADR 000006)"
        );
        anyhow::ensure!(
            self.trust.verifies(artifact.sbom_signature, artifact.sbom),
            "SBOM signature is not verified by any trusted key (fail-closed; ADR 000006)"
        );
        // The SBOM must attest THIS component (its subject digest == sha256(component)), so a
        // validly-signed but unrelated SBOM cannot be paired with it (review f000003 #1).
        sbom_binds_component(artifact.sbom, artifact.component_bytes)?;

        let component_bytes = artifact.component_bytes;
        let engine = match opts.isolation {
            Isolation::Trusted => &self.trusted_engine,
            Isolation::Untrusted => &self.untrusted_engine,
        };
        let component = Component::from_binary(engine, component_bytes)?;
        let mut linker = Linker::<HostState>::new(engine);
        // deny-by-default: lend ONLY the plecto host-API (all five interfaces at once).
        // No WASI is added.
        Filter::add_to_linker::<_, HasSelf<HostState>>(&mut linker, |s: &mut HostState| s)?;
        let pre = FilterPre::new(linker.instantiate_pre(&component)?)?;

        let inner = LoadedInner {
            engine: engine.clone(),
            kv: self.kv.clone(),
            kv_prefix: format!("{filter_id}{KV_NS_DELIM}"),
            filter_id: filter_id.to_string(),
            sink: self.sink.clone(),
            pre,
            isolation: opts.isolation,
            init_deadline_ms: opts.init_deadline_ms,
            request_deadline_ms: opts.request_deadline_ms,
            max_memory_bytes: opts.max_memory_bytes,
            ratelimit_bucket: opts.ratelimit_bucket,
            kv_quota: self.kv_quota.clone(),
        };

        let trusted = match opts.isolation {
            Isolation::Untrusted => None,
            Isolation::Trusted => {
                let cap = opts.trusted_pool_size.clamp(1, TRUSTED_POOL_MAX);
                // Eager-build ONE instance now so a broken `init` surfaces at load (not on the
                // first request) and a single-threaded caller then reuses it (init-once holds).
                // The rest of the pool fills lazily, only when concurrency demands it (ADR 000012).
                let first = inner.instantiate_initialized()?;
                Some(TrustedPool::new(
                    cap,
                    Duration::from_millis(opts.checkout_timeout_ms),
                    opts.max_requests_per_instance,
                    first,
                ))
            }
        };

        Ok(LoadedFilter { inner, trusted })
    }
}

/// Shared, isolation-independent load result.
struct LoadedInner {
    engine: Engine,
    kv: Arc<dyn KvBackend>,
    kv_prefix: String,
    /// The filter id (span name + telemetry attribute, ADR 000009).
    filter_id: String,
    /// Where this filter's per-execution spans go (cloned from the `Host` at load).
    sink: Arc<dyn TelemetrySink>,
    pre: FilterPre<HostState>,
    isolation: Isolation,
    init_deadline_ms: u64,
    request_deadline_ms: u64,
    max_memory_bytes: u64,
    ratelimit_bucket: Option<Bucket>,
    kv_quota: Arc<KvQuota>,
}

impl LoadedInner {
    /// Instantiate a fresh instance and run `init` once, under the `init` epoch deadline and
    /// the Store memory limit (ADR 000006).
    fn instantiate_initialized(&self) -> Result<Instance> {
        let mut store = Store::new(
            &self.engine,
            HostState::new(
                self.kv.clone(),
                self.kv_prefix.clone(),
                self.max_memory_bytes,
                self.ratelimit_bucket,
                self.kv_quota.clone(),
            ),
        );
        store.limiter(|s| &mut s.limits);
        // `init` is heavy (Tenet 4) → the generous init budget, not the tight per-request one.
        store.set_epoch_deadline(self.init_deadline_ms);
        // Async (ADR 000021): the guest runs on a fiber; `block_on` drives it to completion (it
        // never suspends — epoch is trap-mode, host-API imports don't block) so this stays sync.
        let filter = pollster::block_on(self.pre.instantiate_async(&mut store))?;
        pollster::block_on(filter.call_init(&mut store))?;
        Ok(Instance { store, filter })
    }

    /// Check out a trusted instance from the pool (ADR 000012): reuse an idle one, lazily build
    /// a fresh one while under `cap`, or — when every instance is checked out — wait up to the
    /// pool's `checkout_timeout` for one to free and then fail **closed** (`Unavailable`).
    /// Also fails closed fast while the pool-wide breaker's cooldown is open. wasmtime's pooling
    /// allocator has no internal wait queue, so this bounded wait is the host-side backpressure
    /// its docs call for.
    fn checkout(&self, pool: &TrustedPool) -> std::result::Result<PooledInstance, RunError> {
        // The decision made under the lock; acted on (build / return) after releasing it.
        enum Step {
            Use(PooledInstance),
            Build,
            Retry,
        }
        loop {
            let step = {
                let mut g = pool.inner.lock();
                if wall_now_ms() < g.cooldown_until_ms {
                    return Err(RunError::Unavailable);
                }
                if let Some(p) = g.idle.pop() {
                    Step::Use(p)
                } else if g.live < pool.cap {
                    g.live += 1; // reserve the slot before the (slow) build, done outside the lock
                    Step::Build
                } else if pool
                    .available
                    .wait_for(&mut g, pool.checkout_timeout)
                    .timed_out()
                {
                    // saturated and nothing freed in time → shed load, fail closed.
                    return Err(RunError::Unavailable);
                } else {
                    Step::Retry
                }
            };
            match step {
                Step::Use(p) => return Ok(p),
                Step::Build => match self.instantiate_initialized() {
                    Ok(instance) => {
                        return Ok(PooledInstance {
                            instance,
                            served: 0,
                        });
                    }
                    Err(e) => {
                        // roll back the reserved slot and wake a waiter that may now build.
                        {
                            let mut g = pool.inner.lock();
                            g.live = g.live.saturating_sub(1);
                        }
                        pool.available.notify_one();
                        return Err(RunError::Instantiate(e));
                    }
                },
                Step::Retry => continue,
            }
        }
    }

    /// Run one request through the trusted pool (ADR 000012): check out an instance, run `call`
    /// under the per-request deadline, then check it back in — returning it to `idle`, recycling
    /// it once it has served `max_requests_per_instance` (so init re-runs, bounding linear-memory
    /// state accumulation, §6.6), or discarding it on a trap. The circuit breaker is **pool-wide**
    /// (review f000003 #5, generalised): a deterministically-trapping filter trips the whole pool
    /// once rather than forcing every instance to the threshold independently. A trapped
    /// instance's memory is undefined, so the discard is per-instance.
    fn run_pooled<T>(
        &self,
        pool: &TrustedPool,
        call: impl FnOnce(&Filter, &mut Store<HostState>) -> wasmtime::Result<T>,
    ) -> std::result::Result<(T, Vec<LogLine>), RunError> {
        let mut pooled = self.checkout(pool)?;

        pooled.instance.store.data_mut().begin_request();
        pooled
            .instance
            .store
            .set_epoch_deadline(self.request_deadline_ms);
        let result = call(&pooled.instance.filter, &mut pooled.instance.store);

        match result {
            Ok(value) => {
                let logs = std::mem::take(&mut pooled.instance.store.data_mut().logs);
                pooled.served = pooled.served.saturating_add(1);
                if pooled.served >= pool.max_requests_per_instance {
                    // Recycle: drop the Store (returning the slot + freeing memory) BEFORE the
                    // logical `live` decrement, so the physical instance count never transiently
                    // exceeds `cap`. The next checkout lazily rebuilds (re-init).
                    drop(pooled);
                    let mut g = pool.inner.lock();
                    g.clear_breaker();
                    g.live = g.live.saturating_sub(1);
                } else {
                    let mut g = pool.inner.lock();
                    g.clear_breaker();
                    g.idle.push(pooled);
                }
                pool.available.notify_one();
                Ok((value, logs))
            }
            Err(e) => {
                // Trap → this instance's linear memory is undefined → discard it (release the
                // slot first), then bump the pool-wide breaker; past the threshold open a short
                // cooldown so a deterministically-trapping filter fails closed cheaply.
                drop(pooled);
                let mut g = pool.inner.lock();
                g.live = g.live.saturating_sub(1);
                g.consecutive_traps = g.consecutive_traps.saturating_add(1);
                if g.consecutive_traps >= TRUSTED_TRAP_BREAKER_THRESHOLD {
                    g.cooldown_until_ms = wall_now_ms().saturating_add(TRUSTED_TRAP_COOLDOWN_MS);
                }
                drop(g);
                pool.available.notify_one();
                Err(RunError::from_call(e))
            }
        }
    }
}

/// A live, initialized filter instance (its `Store` plus the bound component instance).
struct Instance {
    store: Store<HostState>,
    filter: Filter,
}

/// Consecutive trusted-pool traps before the circuit-breaker opens a cooldown (review f000003
/// #5, now pool-wide — ADR 000012). The first few traps still self-heal (a fresh instance is
/// built on the next checkout); only a deterministically-trapping filter reaches the threshold.
const TRUSTED_TRAP_BREAKER_THRESHOLD: u32 = 3;
/// How long the breaker stays open once tripped: during it, trusted checkouts fail closed
/// cheaply (`RunError::Unavailable`) without rebuilding. After it, the next checkout retries.
const TRUSTED_TRAP_COOLDOWN_MS: u64 = 500;

/// An instance in the trusted pool, plus how many requests it has served since it was last
/// (re)initialized — the counter that drives recycling (ADR 000012 / §6.6).
struct PooledInstance {
    instance: Instance,
    served: u64,
}

/// The trusted pool's mutable interior, behind one lock (ADR 000012). `idle` holds warm
/// instances ready to check out; `live` counts every instance that currently exists (idle +
/// checked-out + being-built), bounding lazy fill to the pool `cap`. The circuit breaker is
/// **pool-wide**: a deterministically-trapping filter trips the whole pool once, not each
/// instance independently.
struct PoolInner {
    idle: Vec<PooledInstance>,
    live: usize,
    consecutive_traps: u32,
    cooldown_until_ms: u64,
}

impl PoolInner {
    /// Clear the breaker after a successful call (a healthy request resets the trap streak).
    fn clear_breaker(&mut self) {
        self.consecutive_traps = 0;
        self.cooldown_until_ms = 0;
    }
}

/// A fixed-capacity pool of reusable trusted instances (ADR 000012). Replaces the v0.1
/// single-instance-behind-one-`Mutex` placeholder (concurrency=1). Checkout reuses an idle
/// instance, lazily builds one while under `cap`, or waits up to `checkout_timeout` then fails
/// closed; `available` is signalled whenever an instance is returned or a slot is freed.
struct TrustedPool {
    inner: Mutex<PoolInner>,
    available: Condvar,
    cap: usize,
    checkout_timeout: Duration,
    max_requests_per_instance: u64,
}

impl TrustedPool {
    /// Build a pool seeded with one eager, already-initialized instance (so a single-threaded
    /// caller reuses it and `init` stays once). `cap` is the caller's clamped pool size.
    fn new(
        cap: usize,
        checkout_timeout: Duration,
        max_requests_per_instance: u64,
        first: Instance,
    ) -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                idle: vec![PooledInstance {
                    instance: first,
                    served: 0,
                }],
                live: 1,
                consecutive_traps: 0,
                cooldown_until_ms: 0,
            }),
            available: Condvar::new(),
            cap,
            checkout_timeout,
            max_requests_per_instance,
        }
    }
}

/// A loaded filter, ready to run per request. Trusted filters reuse instances from a
/// `TrustedPool` (checked out per request, ADR 000012); untrusted filters instantiate fresh
/// each request.
///
/// A trap leaves the guest's linear memory undefined, so the host discards that instance and a
/// later checkout rebuilds + re-inits one (self-heal, ADR 000006), with a pool-wide cooldown
/// bounding re-init storms (review f000003 #5). The `Option` is the isolation discriminator —
/// `None` means untrusted (fresh instance per request).
pub struct LoadedFilter {
    inner: LoadedInner,
    trusted: Option<TrustedPool>,
}

impl LoadedFilter {
    pub fn isolation(&self) -> Isolation {
        self.inner.isolation
    }

    /// Run the request-side hook under the request's trace context (`trace`, ADR 000009). The
    /// host times the call and emits one span — parented by `trace`, carrying the outcome and
    /// the filter's host-log lines as events — to its `TelemetrySink`. Returns the typed
    /// decision plus those log lines (the direct-access form), or a `RunError` the caller MUST
    /// fail-closed on (deadline / trap / instantiation — never a pass-through to upstream).
    pub fn on_request(
        &self,
        req: &HttpRequest,
        trace: &RequestTrace,
    ) -> std::result::Result<(RequestDecision, Vec<LogLine>), RunError> {
        let start = SystemTime::now();
        let elapsed = Instant::now();
        let result = self.run_on_request(req);
        let outcome = match &result {
            Ok((decision, _)) => SpanOutcome::from(decision),
            Err(err) => SpanOutcome::from(err),
        };
        self.emit_span(
            trace,
            Hook::OnRequest,
            outcome,
            start,
            elapsed.elapsed(),
            &result,
        );
        result
    }

    fn run_on_request(
        &self,
        req: &HttpRequest,
    ) -> std::result::Result<(RequestDecision, Vec<LogLine>), RunError> {
        match &self.trusted {
            // trusted: check an instance out of the pool (reuse / lazily build / fail closed).
            Some(pool) => self.inner.run_pooled(pool, |filter, store| {
                pollster::block_on(filter.call_on_request(store, req))
            }),
            // untrusted: fresh instance + init every request (the isolation trade).
            None => {
                let mut inst = self
                    .inner
                    .instantiate_initialized()
                    .map_err(RunError::Instantiate)?;
                inst.store
                    .set_epoch_deadline(self.inner.request_deadline_ms);
                match pollster::block_on(inst.filter.call_on_request(&mut inst.store, req)) {
                    Ok(decision) => {
                        let logs = std::mem::take(&mut inst.store.data_mut().logs);
                        Ok((decision, logs))
                    }
                    Err(e) => Err(RunError::from_call(e)),
                }
            }
        }
    }

    /// Run the request-side BODY hook (buffer-then-decide, ADR 000025). The host hands the filter
    /// the fully-buffered request body; the filter returns the (possibly transformed) body to
    /// continue, or a `short-circuit` response (synthesised before upstream is reached). Same
    /// fail-closed contract and span emission as `on_request`.
    pub fn on_request_body(
        &self,
        body: &[u8],
        trace: &RequestTrace,
    ) -> std::result::Result<(RequestBodyDecision, Vec<LogLine>), RunError> {
        let start = SystemTime::now();
        let elapsed = Instant::now();
        let result = self.run_on_request_body(body);
        let outcome = match &result {
            Ok((RequestBodyDecision::Continue(_), _)) => SpanOutcome::Continue,
            Ok((RequestBodyDecision::ShortCircuit(_), _)) => SpanOutcome::ShortCircuit,
            Err(err) => SpanOutcome::from(err),
        };
        self.emit_span(
            trace,
            Hook::OnRequestBody,
            outcome,
            start,
            elapsed.elapsed(),
            &result,
        );
        result
    }

    fn run_on_request_body(
        &self,
        body: &[u8],
    ) -> std::result::Result<(RequestBodyDecision, Vec<LogLine>), RunError> {
        match &self.trusted {
            Some(pool) => self.inner.run_pooled(pool, |filter, store| {
                pollster::block_on(filter.call_on_request_body(store, body))
            }),
            None => {
                let mut inst = self
                    .inner
                    .instantiate_initialized()
                    .map_err(RunError::Instantiate)?;
                inst.store
                    .set_epoch_deadline(self.inner.request_deadline_ms);
                match pollster::block_on(inst.filter.call_on_request_body(&mut inst.store, body)) {
                    Ok(decision) => {
                        let logs = std::mem::take(&mut inst.store.data_mut().logs);
                        Ok((decision, logs))
                    }
                    Err(e) => Err(RunError::from_call(e)),
                }
            }
        }
    }

    /// Build and emit the span for one filter execution (ADR 000009). The filter's host-log
    /// lines (`Ok`) become span events; a `RunError` carries no logs but its outcome
    /// (trap / deadline / …) is still recorded. Errors never abort emission — telemetry is
    /// best-effort and out of the fail-closed path.
    fn emit_span<T>(
        &self,
        trace: &RequestTrace,
        hook: Hook,
        outcome: SpanOutcome,
        start: SystemTime,
        duration: Duration,
        result: &std::result::Result<(T, Vec<LogLine>), RunError>,
    ) {
        let logs: &[LogLine] = match result {
            Ok((_, logs)) => logs,
            Err(_) => &[],
        };
        let span = observe::build_filter_span(
            trace,
            &self.inner.filter_id,
            self.inner.isolation,
            hook,
            outcome,
            start,
            duration,
            logs,
        );
        self.inner.sink.export(&span);
    }

    /// Run the response-side hook for one response. Same fail-closed contract as `on_request`.
    pub fn on_response(
        &self,
        resp: &HttpResponse,
        trace: &RequestTrace,
    ) -> std::result::Result<(ResponseDecision, Vec<LogLine>), RunError> {
        let start = SystemTime::now();
        let elapsed = Instant::now();
        let result = self.run_on_response(resp);
        let outcome = match &result {
            Ok((decision, _)) => SpanOutcome::from(decision),
            Err(err) => SpanOutcome::from(err),
        };
        self.emit_span(
            trace,
            Hook::OnResponse,
            outcome,
            start,
            elapsed.elapsed(),
            &result,
        );
        result
    }

    fn run_on_response(
        &self,
        resp: &HttpResponse,
    ) -> std::result::Result<(ResponseDecision, Vec<LogLine>), RunError> {
        match &self.trusted {
            Some(pool) => self.inner.run_pooled(pool, |filter, store| {
                pollster::block_on(filter.call_on_response(store, resp))
            }),
            None => {
                let mut inst = self
                    .inner
                    .instantiate_initialized()
                    .map_err(RunError::Instantiate)?;
                inst.store
                    .set_epoch_deadline(self.inner.request_deadline_ms);
                match pollster::block_on(inst.filter.call_on_response(&mut inst.store, resp)) {
                    Ok(decision) => {
                        let logs = std::mem::take(&mut inst.store.data_mut().logs);
                        Ok((decision, logs))
                    }
                    Err(e) => Err(RunError::from_call(e)),
                }
            }
        }
    }
}

/// Test / dev signing support — **NOT production provenance**. Generates a fresh ephemeral
/// ECDSA P-256 key (cosign's default scheme), signs blobs with it, and exposes the matching
/// public-key PEM so a test can build a `TrustPolicy` and drive the real verify path
/// end-to-end without the `cosign` CLI. The key is thrown away each time; this grants nothing
/// a caller could not already do with sigstore directly. `#[doc(hidden)]` — integration tests
/// need it `pub`, but it is not part of the supported surface.
#[doc(hidden)]
pub mod test_support {
    use super::TrustPolicy;
    use anyhow::{Result, anyhow};
    use sigstore::crypto::SigningScheme;
    use sigstore::crypto::signing_key::SigStoreSigner;

    /// A throwaway signer holding one ephemeral keypair, so the same key can sign both the
    /// component and the SBOM (and a matching `TrustPolicy` trusts exactly that key).
    pub struct TestSigner {
        signer: SigStoreSigner,
        public_key_pem: String,
    }

    impl TestSigner {
        pub fn new() -> Result<Self> {
            let signer = SigningScheme::ECDSA_P256_SHA256_ASN1
                .create_signer()
                .map_err(|e| anyhow!("create_signer: {e}"))?;
            let public_key_pem = signer
                .to_sigstore_keypair()
                .map_err(|e| anyhow!("to_sigstore_keypair: {e}"))?
                .public_key_to_pem()
                .map_err(|e| anyhow!("public_key_to_pem: {e}"))?;
            Ok(Self {
                signer,
                public_key_pem,
            })
        }

        /// Raw DER ECDSA signature over `msg` (the shape `SignedArtifact` expects).
        pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            self.signer.sign(msg).map_err(|e| anyhow!("sign: {e}"))
        }

        pub fn public_key_pem(&self) -> &str {
            &self.public_key_pem
        }

        /// A `TrustPolicy` that trusts exactly this signer's key.
        pub fn trust_policy(&self) -> Result<TrustPolicy> {
            TrustPolicy::from_pem_keys([self.public_key_pem.as_bytes()])
        }
    }

    /// The compiled `filter-hello` component bytes — the shared conformance fixture, built by
    /// this crate's `build.rs`. Exposed so dependent crates (e.g. `plecto-control`) can load a
    /// real `plecto:filter` component in their own tests.
    pub fn filter_hello_component() -> Vec<u8> {
        std::fs::read(env!("FILTER_HELLO_COMPONENT")).expect("read filter-hello component")
    }

    /// The compiled `filter-apikey` component bytes — the real-world example filter (an API-key
    /// auth gate), built by this crate's `build.rs`. Exposed so the server's `wasm-auth` example
    /// can sign and load it through the production path.
    pub fn filter_apikey_component() -> Vec<u8> {
        std::fs::read(env!("FILTER_APIKEY_COMPONENT")).expect("read filter-apikey component")
    }

    /// A minimal in-toto-style SBOM statement that binds `component`: its `subject` digest is
    /// `sha256(component)`, satisfying the load gate's SBOM↔component binding (review f000003
    /// #1). The predicate is empty (content policy is deferred). Test / dev helper — real
    /// attestations come from `cosign attest`.
    pub fn bound_sbom(component: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(component));
        format!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","subject":[{{"name":"filter","digest":{{"sha256":"{digest}"}}}}],"predicateType":"https://cyclonedx.org/bom","predicate":{{}}}}"#
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the deny-by-default host-API implementations (ADR 000006 / 000011).
    use super::*;
    use host_clock::Host as ClockHost;
    use host_counter::Host as CounterHost;
    use host_kv::Host as KvHost;
    use host_log::Host as LogHost;

    fn state(prefix: &str) -> HostState {
        HostState::new(
            Arc::new(MemoryBackend::default()),
            prefix.to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            None,
            Arc::new(KvQuota::new()),
        )
    }

    #[test]
    fn kv_get_set_delete_roundtrip() {
        let mut s = state("test\u{1f}");
        assert_eq!(KvHost::get(&mut s, "k".into()), None);
        KvHost::set(&mut s, "k".into(), b"v".to_vec());
        assert_eq!(KvHost::get(&mut s, "k".into()), Some(b"v".to_vec()));
        KvHost::delete(&mut s, "k".into());
        assert_eq!(KvHost::get(&mut s, "k".into()), None);
    }

    #[test]
    fn kv_is_namespaced_per_filter() {
        // Two filters sharing one backing store must not see each other's keys
        // (capability isolation across a chain, ADR 000006 / 000011).
        let shared: Arc<dyn KvBackend> = Arc::new(MemoryBackend::default());
        let mut a = HostState::new(
            shared.clone(),
            "filter-a\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            None,
            Arc::new(KvQuota::new()),
        );
        let mut b = HostState::new(
            shared.clone(),
            "filter-b\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            None,
            Arc::new(KvQuota::new()),
        );

        KvHost::set(&mut a, "count".into(), b"1".to_vec());
        assert_eq!(
            KvHost::get(&mut b, "count".into()),
            None,
            "b must not see a"
        );
        assert_eq!(KvHost::get(&mut a, "count".into()), Some(b"1".to_vec()));

        // a key that embeds the delimiter still cannot escape a's namespace
        KvHost::set(&mut a, format!("x{}count", '\u{1f}'), b"evil".to_vec());
        assert_eq!(KvHost::get(&mut b, "count".into()), None);
    }

    #[test]
    fn counter_is_namespaced_per_filter() {
        // The counter primitive shares the backend keyspace with kv/ratelimit, so its per-filter
        // isolation must hold too: one filter's `requests` counter must be invisible to another
        // (cross-tenant leakage, CWE-200). Only the `_KV_` test covered this before.
        let shared: Arc<dyn KvBackend> = Arc::new(MemoryBackend::default());
        let mut a = HostState::new(
            shared.clone(),
            "filter-a\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            None,
            Arc::new(KvQuota::new()),
        );
        let mut b = HostState::new(
            shared.clone(),
            "filter-b\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            None,
            Arc::new(KvQuota::new()),
        );

        assert_eq!(CounterHost::increment(&mut a, "hits".into(), 5), 5);
        assert_eq!(
            CounterHost::get(&mut b, "hits".into()),
            0,
            "b must not observe a's counter"
        );
        assert_eq!(
            CounterHost::increment(&mut b, "hits".into(), 1),
            1,
            "b's counter is independent of a's"
        );
        assert_eq!(
            CounterHost::get(&mut a, "hits".into()),
            5,
            "a's counter is untouched by b"
        );
    }

    #[test]
    fn ratelimit_bucket_is_namespaced_per_filter() {
        // A rate limiter is only a security control if one filter cannot drain — or be throttled
        // by — another filter's bucket under the same key. The token bucket lives in the shared
        // backend under a per-filter namespace; prove two filters' identical keys are independent.
        use host_ratelimit::Host as RateLimitHost;
        fn one_token_no_refill() -> Bucket {
            Bucket {
                capacity: 1,
                refill_tokens: 0,
                refill_interval_ms: 0,
            }
        }

        // The bucket spec is host-configured (ADR 000026), so each filter's HostState carries it.
        let shared: Arc<dyn KvBackend> = Arc::new(MemoryBackend::default());
        let mut a = HostState::new(
            shared.clone(),
            "filter-a\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            Some(one_token_no_refill()),
            Arc::new(KvQuota::new()),
        );
        let mut b = HostState::new(
            shared.clone(),
            "filter-b\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
            Some(one_token_no_refill()),
            Arc::new(KvQuota::new()),
        );

        // a drains its single-token bucket on key "k".
        assert!(RateLimitHost::try_acquire(&mut a, "k".into(), 1).allowed);
        assert!(
            !RateLimitHost::try_acquire(&mut a, "k".into(), 1).allowed,
            "a's bucket is now empty"
        );
        // b's bucket under the SAME key is a different namespace → still full.
        assert!(
            RateLimitHost::try_acquire(&mut b, "k".into(), 1).allowed,
            "b's limiter must not share a's drained bucket"
        );
    }

    #[test]
    fn kv_and_counter_do_not_collide() {
        // Same logical key under different primitives must stay distinct (tag sub-namespace).
        let mut s = state("f\u{1f}");
        KvHost::set(&mut s, "x".into(), b"bytes".to_vec());
        assert_eq!(CounterHost::increment(&mut s, "x".into(), 7), 7);
        assert_eq!(KvHost::get(&mut s, "x".into()), Some(b"bytes".to_vec()));
        assert_eq!(CounterHost::get(&mut s, "x".into()), 7);
    }

    #[test]
    fn counter_increment_and_read() {
        let mut s = state("f\u{1f}");
        assert_eq!(CounterHost::get(&mut s, "n".into()), 0);
        assert_eq!(CounterHost::increment(&mut s, "n".into(), 1), 1);
        assert_eq!(CounterHost::increment(&mut s, "n".into(), 2), 3);
        assert_eq!(CounterHost::get(&mut s, "n".into()), 3);
    }

    #[test]
    fn log_captures_lines() {
        let mut s = state("test\u{1f}");
        LogHost::log(&mut s, LogLevel::Info, "hello".into());
        assert_eq!(s.logs.len(), 1);
        assert_eq!(s.logs[0].message, "hello");
    }

    #[test]
    fn begin_request_resets_logs_keeps_namespace() {
        let mut s = state("test\u{1f}");
        LogHost::log(&mut s, LogLevel::Info, "first".into());
        s.begin_request();
        assert!(s.logs.is_empty(), "logs reset for the next request");
    }

    #[test]
    fn clock_returns_nonzero_wall_time() {
        let mut s = state("test\u{1f}");
        assert!(ClockHost::now_ms(&mut s) > 0);
    }

    #[test]
    fn run_error_maps_to_fail_closed_response() {
        // The host's synthetic responses are fail-closed (5xx), never a pass-through, and
        // distinguish a deadline (504) from any other trap (502) for observability (ADR 000006).
        let deadline = RunError::Deadline.fail_closed_response();
        assert_eq!(deadline.status, 504);
        assert!(
            deadline
                .headers
                .iter()
                .any(|h| h.name == "x-plecto-fault" && h.value == "deadline")
        );

        let trap = RunError::Trap(anyhow::anyhow!("boom")).fail_closed_response();
        assert_eq!(trap.status, 502);
        assert!(
            trap.headers
                .iter()
                .any(|h| h.name == "x-plecto-fault" && h.value == "trap")
        );
    }

    #[test]
    fn untrusted_init_deadline_is_tight_trusted_is_generous() {
        // untrusted filters re-run init per request, so their default init budget must be
        // bounded near the per-request budget, while a trusted filter (init once) keeps the
        // generous budget.
        assert_eq!(
            LoadOptions::untrusted().init_deadline_ms,
            DEFAULT_UNTRUSTED_INIT_DEADLINE_MS
        );
        assert_eq!(
            LoadOptions::trusted().init_deadline_ms,
            DEFAULT_INIT_DEADLINE_MS
        );
        assert!(
            LoadOptions::untrusted().init_deadline_ms < LoadOptions::trusted().init_deadline_ms
        );
    }

    #[test]
    fn kv_value_over_cap_is_dropped_fail_closed() {
        // a value past the per-key cap is dropped, not stored (host-API is infallible from
        // the filter's view). A within-cap value stores normally.
        let mut s = state("f\u{1f}");
        KvHost::set(&mut s, "big".into(), vec![0u8; MAX_KV_VALUE_BYTES + 1]);
        assert_eq!(
            KvHost::get(&mut s, "big".into()),
            None,
            "an over-cap value is dropped"
        );
        KvHost::set(&mut s, "ok".into(), vec![0u8; 128]);
        assert_eq!(KvHost::get(&mut s, "ok".into()), Some(vec![0u8; 128]));
    }

    #[test]
    fn quota_admit_rejects_growth_past_caps_and_allows_shrink() {
        // KvQuota accounting — a growth past a per-namespace or global cap is rejected; a
        // shrink (negative delta) always applies and frees the budget for a later growth.
        let q = KvQuota::new();
        assert!(q.admit("ns", 1, 100), "a small entry fits");
        assert!(
            !q.admit("ns", 1, MAX_NS_BYTES as isize),
            "a value that would exceed the per-namespace byte cap is rejected"
        );
        assert!(
            !q.admit("ns2", 1, MAX_TOTAL_BYTES as isize),
            "a value that would exceed the host-wide byte cap is rejected"
        );
        // a shrink always applies (release path), and never rejects.
        q.release("ns", 1, 100);
        assert!(
            q.admit("ns", 1, 100),
            "freed budget is reusable after a release"
        );
    }

    #[test]
    fn host_log_is_capped_and_sanitized() {
        // control bytes are neutralized (no CRLF log-line injection / ANSI), and
        // the per-request line count is bounded with a single truncation marker.
        let mut s = state("f\u{1f}");
        LogHost::log(&mut s, LogLevel::Info, "a\r\nInjected: x\u{1b}[31m".into());
        assert!(
            !s.logs[0].message.contains('\r') && !s.logs[0].message.contains('\n'),
            "CR/LF are neutralized (no log-line injection)"
        );
        assert!(
            !s.logs[0].message.contains('\u{1b}'),
            "the ANSI escape is neutralized"
        );

        // a long message is truncated to the byte cap.
        let mut s2 = state("f\u{1f}");
        LogHost::log(&mut s2, LogLevel::Info, "x".repeat(MAX_LOG_MSG_BYTES * 2));
        assert!(s2.logs[0].message.len() <= MAX_LOG_MSG_BYTES);

        // the per-request line count is bounded, last slot is a truncation marker.
        let mut s3 = state("f\u{1f}");
        for i in 0..(MAX_LOG_LINES_PER_REQUEST + 50) {
            LogHost::log(&mut s3, LogLevel::Info, format!("line {i}"));
        }
        assert_eq!(s3.logs.len(), MAX_LOG_LINES_PER_REQUEST);
        assert!(
            s3.logs.last().unwrap().message.contains("truncated"),
            "the final retained line is the truncation marker"
        );
    }
}
