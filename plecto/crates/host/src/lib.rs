//! plecto-host — embeds wasmtime to run `plecto:filter` components (ADR 000001 / 000002).
//!
//! ADR 000004 slice: the filter **runtime model**. The host branches on trust at load
//! (ADR 000011's knot, made concrete):
//!   - **trusted** filters get ONE persistent instance, `init` runs **once**, and every
//!     request reuses it — Tenet 4 finally pays off (init-derived state stays resident).
//!     Built on a **pooling-allocator** engine. Per-worker-thread sharding lands with the
//!     fast-path server; v0.1 reuses a single instance serially.
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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use parking_lot::Mutex;
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
    });
}

// One canonical set of contract types for callers and tests.
pub use bindings::plecto::filter::host_log::Level as LogLevel;
pub use bindings::plecto::filter::types::{
    Header, HttpRequest, HttpResponse, RequestDecision, RequestEdit, ResponseDecision, ResponseEdit,
};
use bindings::plecto::filter::{host_clock, host_counter, host_kv, host_log, host_ratelimit};
use bindings::{Filter, FilterPre};

/// How a filter is instantiated and isolated (ADR 000004 / 000011). Not a "trust score":
/// it selects the **instance lifecycle**, mirroring how Fastly/Spin model per-request vs
/// reusable sandboxes. *Who* is trusted is decided elsewhere (OCI signing, ADR 000006);
/// this only says which lifecycle a loaded filter gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Own filters: one persistent instance, `init` once, reused. No per-request
    /// zeroization (same trust domain). Statelessness (Fork 4) is therefore honored by
    /// *trust*, not *enforced*: a trusted filter that stashes mutable state in its own linear
    /// memory silently carries it across requests. That is not a security boundary (same
    /// trust domain) — only `Untrusted`'s fresh-per-request memory enforces statelessness
    /// structurally (ADR 000011).
    Trusted,
    /// Third-party filters: fresh instance per request, memory fresh by construction.
    Untrusted,
}

/// Generous default budget for the heavy once-per-instance `init` (Tenet 4): regex compile,
/// schema build, config parse. Separate from — and much larger than — the per-request budget
/// so a legitimately heavy init is not mistaken for a runaway (ADR 000006).
const DEFAULT_INIT_DEADLINE_MS: u64 = 5_000;
/// Tight default budget for the hot per-request hooks. This is a *safety* bound that traps
/// runaway filters (infinite loops), not a latency SLA; header-only filters finish in well
/// under a millisecond.
const DEFAULT_REQUEST_DEADLINE_MS: u64 = 100;
/// Default per-instance linear-memory cap enforced via a `StoreLimits` (ADR 000006). Matches
/// the pooling engine's per-slot reservation so trusted and untrusted agree.
const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 << 20;

/// Per-instance cap on total table elements (review f000003 #2). `StoreLimits::memory_size`
/// bounds linear memory but NOT `table.grow`; a guest growing a huge funcref table could eat
/// host memory outside the linear-memory cap before the epoch deadline trips. This is generous
/// for any reasonable filter and bounds the pathological case — cheap defense-in-depth.
const MAX_TABLE_ELEMENTS: usize = 100_000;

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
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            isolation: Isolation::Untrusted,
            init_deadline_ms: DEFAULT_INIT_DEADLINE_MS,
            request_deadline_ms: DEFAULT_REQUEST_DEADLINE_MS,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        }
    }
}

impl LoadOptions {
    pub fn trusted() -> Self {
        Self {
            isolation: Isolation::Trusted,
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
}

impl HostState {
    fn new(kv: Arc<dyn KvBackend>, kv_prefix: String, max_memory_bytes: u64) -> Self {
        Self {
            kv,
            kv_prefix,
            logs: Vec::new(),
            now_ms: wall_now_ms(),
            limits: StoreLimitsBuilder::new()
                .memory_size(max_memory_bytes as usize)
                .table_elements(MAX_TABLE_ELEMENTS)
                .build(),
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
        self.logs.push(LogLine { level, message });
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
        self.kv.set(&self.ns_key(TAG_KV, &key), value);
    }
    fn delete(&mut self, key: String) {
        self.kv.delete(&self.ns_key(TAG_KV, &key));
    }
}

impl host_counter::Host for HostState {
    fn increment(&mut self, key: String, delta: i64) -> i64 {
        self.kv.increment(&self.ns_key(TAG_COUNTER, &key), delta)
    }
    fn get(&mut self, key: String) -> i64 {
        // increment-by-zero is an atomic read of the current value (and the canonical
        // wasi:keyvalue/atomics idiom); keeps the counter encoding inside the backend.
        self.kv.increment(&self.ns_key(TAG_COUNTER, &key), 0)
    }
}

impl host_ratelimit::Host for HostState {
    fn try_acquire(
        &mut self,
        key: String,
        cost: u64,
        spec: host_ratelimit::Bucket,
    ) -> host_ratelimit::Acquire {
        let r = self.kv.try_acquire(
            &self.ns_key(TAG_RATELIMIT, &key),
            cost,
            Bucket {
                capacity: spec.capacity,
                refill_tokens: spec.refill_tokens,
                refill_interval_ms: spec.refill_interval_ms,
            },
            self.now_ms,
        );
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
    /// Public keys this host trusts to sign filters (ADR 000006). Verified at every `load`.
    trust: TrustPolicy,
    /// Where loaded filters emit their per-execution spans (ADR 000009). Default `NoopSink`
    /// (observability off); cloned into each filter at `load`, so set it before loading.
    sink: Arc<dyn TelemetrySink>,
    /// Drives epoch deadlines for both engines; stops on drop. Held only for its lifetime.
    _epoch_ticker: EpochTicker,
}

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
    // Sync path: we deliberately do NOT enable async_support on wasmtime 45 (ADR 000010).
    // `memory_init_cow` stays at its default (enabled): every instance gets its own
    // copy-on-write heap image — the safe posture against CVE-2022-39393 (ADR 000006).
    if let Allocation::Pooling = alloc {
        let mut pool = PoolingAllocationConfig::default();
        // Conservative v0.1 single-node caps (the pool reserves virtual address space up
        // front). Raised when per-worker-thread sharding arrives with the server.
        pool.total_memories(64);
        pool.total_tables(64);
        pool.total_core_instances(64);
        pool.total_component_instances(64);
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
        };

        let trusted = match opts.isolation {
            Isolation::Untrusted => None,
            // create the persistent instance and run init exactly once
            Isolation::Trusted => Some(Mutex::new(TrustedSlot::new(
                inner.instantiate_initialized()?,
            ))),
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
            ),
        );
        store.limiter(|s| &mut s.limits);
        // `init` is heavy (Tenet 4) → the generous init budget, not the tight per-request one.
        store.set_epoch_deadline(self.init_deadline_ms);
        let filter = self.pre.instantiate(&mut store)?;
        filter.call_init(&mut store)?;
        Ok(Instance { store, filter })
    }

    /// Run one trusted-instance call through the circuit-breaker (review f000003 #5). While in
    /// trap-cooldown, reject fast (`Unavailable`) without rebuilding. Otherwise (re)build the
    /// instance if a prior trap discarded it (self-heal, ADR 000006), run `call` under the
    /// per-request deadline, and record the outcome: reset on success; on trap discard the
    /// instance and — after `TRUSTED_TRAP_BREAKER_THRESHOLD` consecutive traps — open a short
    /// cooldown so a deterministically-trapping filter cannot force re-init every request.
    fn run_trusted<T>(
        &self,
        slot: &mut TrustedSlot,
        call: impl FnOnce(&Filter, &mut Store<HostState>) -> wasmtime::Result<T>,
    ) -> std::result::Result<(T, Vec<LogLine>), RunError> {
        if wall_now_ms() < slot.cooldown_until_ms {
            return Err(RunError::Unavailable);
        }
        if slot.instance.is_none() {
            slot.instance = Some(
                self.instantiate_initialized()
                    .map_err(RunError::Instantiate)?,
            );
        }
        // Scope the instance borrow so the breaker bookkeeping below can mutate `slot`.
        let outcome = {
            let inst = slot.instance.as_mut().expect("rebuilt above");
            inst.store.data_mut().begin_request();
            inst.store.set_epoch_deadline(self.request_deadline_ms);
            match call(&inst.filter, &mut inst.store) {
                Ok(value) => Ok((value, std::mem::take(&mut inst.store.data_mut().logs))),
                Err(e) => Err(e),
            }
        };
        match outcome {
            Ok(ok) => {
                slot.consecutive_traps = 0;
                slot.cooldown_until_ms = 0;
                Ok(ok)
            }
            Err(e) => {
                // A trap leaves linear memory undefined → discard the instance (self-heal on
                // the next allowed call); after the threshold, open the cooldown.
                slot.instance = None;
                slot.consecutive_traps = slot.consecutive_traps.saturating_add(1);
                if slot.consecutive_traps >= TRUSTED_TRAP_BREAKER_THRESHOLD {
                    slot.cooldown_until_ms = wall_now_ms().saturating_add(TRUSTED_TRAP_COOLDOWN_MS);
                }
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

/// Consecutive trusted-instance traps before the circuit-breaker opens a cooldown
/// (review f000003 #5). The first few traps still self-heal (rebuild + retry); only a
/// deterministically-trapping filter reaches the threshold.
const TRUSTED_TRAP_BREAKER_THRESHOLD: u32 = 3;
/// How long the breaker stays open once tripped: during it, trusted calls fail closed cheaply
/// (`RunError::Unavailable`) without re-instantiating. After it, the next call retries once.
const TRUSTED_TRAP_COOLDOWN_MS: u64 = 500;

/// The trusted-filter slot behind the per-filter lock: the persistent instance plus the
/// circuit-breaker state (review f000003 #5). `instance` is `None` only after a trap (rebuilt
/// on the next allowed call); the counters bound re-init storms from a deterministically-
/// trapping trusted filter.
struct TrustedSlot {
    instance: Option<Instance>,
    consecutive_traps: u32,
    cooldown_until_ms: u64,
}

impl TrustedSlot {
    fn new(instance: Instance) -> Self {
        Self {
            instance: Some(instance),
            consecutive_traps: 0,
            cooldown_until_ms: 0,
        }
    }
}

/// A loaded filter, ready to run per request. Trusted filters hold one persistent `Instance`
/// reused serially (in a `TrustedSlot` with circuit-breaker state); untrusted filters
/// instantiate fresh each request.
///
/// Inside the lock the trusted slot keeps the instance plus the breaker counters: a trap
/// leaves the guest's linear memory undefined, so the host discards the instance and the next
/// allowed request rebuilds + re-inits it (self-heal, ADR 000006), with a cooldown bounding
/// re-init storms (review f000003 #5). The outer `Option` is the isolation discriminator —
/// `None` means untrusted (fresh instance per request).
pub struct LoadedFilter {
    inner: LoadedInner,
    trusted: Option<Mutex<TrustedSlot>>,
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
            // trusted: reuse the persistent instance via the circuit-breaker.
            Some(cell) => {
                let mut guard = cell.lock();
                self.inner.run_trusted(&mut guard, |filter, store| {
                    filter.call_on_request(store, req)
                })
            }
            // untrusted: fresh instance + init every request (the isolation trade).
            None => {
                let mut inst = self
                    .inner
                    .instantiate_initialized()
                    .map_err(RunError::Instantiate)?;
                inst.store
                    .set_epoch_deadline(self.inner.request_deadline_ms);
                match inst.filter.call_on_request(&mut inst.store, req) {
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
            Some(cell) => {
                let mut guard = cell.lock();
                self.inner.run_trusted(&mut guard, |filter, store| {
                    filter.call_on_response(store, resp)
                })
            }
            None => {
                let mut inst = self
                    .inner
                    .instantiate_initialized()
                    .map_err(RunError::Instantiate)?;
                inst.store
                    .set_epoch_deadline(self.inner.request_deadline_ms);
                match inst.filter.call_on_response(&mut inst.store, resp) {
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
        );
        let mut b = HostState::new(
            shared.clone(),
            "filter-b\u{1f}".to_string(),
            DEFAULT_MAX_MEMORY_BYTES,
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
}
