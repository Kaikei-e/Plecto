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

use std::sync::Arc;

use anyhow::Result;
use parking_lot::Mutex;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store};

pub use backend::{Acquire, Bucket, KvBackend, MemoryBackend, RedbBackend};

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

/// Options for `Host::load`. A struct (not a bare arg) because deny-by-default will grow
/// more load-time knobs onto it (capability set, epoch budget, memory limit). Defaults to
/// the safe side: `Untrusted` (fail-closed).
#[derive(Debug, Clone, Copy)]
pub struct LoadOptions {
    pub isolation: Isolation,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            isolation: Isolation::Untrusted,
        }
    }
}

impl LoadOptions {
    pub fn trusted() -> Self {
        Self {
            isolation: Isolation::Trusted,
        }
    }
    pub fn untrusted() -> Self {
        Self {
            isolation: Isolation::Untrusted,
        }
    }
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
}

impl HostState {
    fn new(kv: Arc<dyn KvBackend>, kv_prefix: String) -> Self {
        Self {
            kv,
            kv_prefix,
            logs: Vec::new(),
            now_ms: wall_now_ms(),
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
}

enum Allocation {
    Pooling,
    OnDemand,
}

fn build_engine(alloc: Allocation) -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
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
    /// A host backed by an in-memory store (the default; process-lifetime state).
    pub fn new() -> Result<Self> {
        Self::with_backend(Arc::new(MemoryBackend::default()))
    }

    /// A host backed by a caller-supplied store (e.g. `RedbBackend` for durability).
    pub fn with_backend(kv: Arc<dyn KvBackend>) -> Result<Self> {
        Ok(Self {
            trusted_engine: build_engine(Allocation::Pooling)?,
            untrusted_engine: build_engine(Allocation::OnDemand)?,
            kv,
        })
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
        component_bytes: &[u8],
        opts: LoadOptions,
    ) -> Result<LoadedFilter> {
        anyhow::ensure!(
            !filter_id.is_empty() && !filter_id.contains(KV_NS_DELIM),
            "filter id must be non-empty and must not contain the KV namespace delimiter"
        );
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
            pre,
            isolation: opts.isolation,
        };

        let trusted = match opts.isolation {
            Isolation::Untrusted => None,
            // create the persistent instance and run init exactly once
            Isolation::Trusted => Some(Mutex::new(inner.instantiate_initialized()?)),
        };

        Ok(LoadedFilter { inner, trusted })
    }
}

/// Shared, isolation-independent load result.
struct LoadedInner {
    engine: Engine,
    kv: Arc<dyn KvBackend>,
    kv_prefix: String,
    pre: FilterPre<HostState>,
    isolation: Isolation,
}

impl LoadedInner {
    /// Instantiate a fresh instance and run `init` once.
    fn instantiate_initialized(&self) -> Result<Instance> {
        let mut store = Store::new(
            &self.engine,
            HostState::new(self.kv.clone(), self.kv_prefix.clone()),
        );
        let filter = self.pre.instantiate(&mut store)?;
        filter.call_init(&mut store)?;
        Ok(Instance { store, filter })
    }
}

/// A live, initialized filter instance (its `Store` plus the bound component instance).
struct Instance {
    store: Store<HostState>,
    filter: Filter,
}

/// A loaded filter, ready to run per request. Trusted filters hold one persistent
/// `Instance` reused serially; untrusted filters instantiate fresh each request.
pub struct LoadedFilter {
    inner: LoadedInner,
    trusted: Option<Mutex<Instance>>,
}

impl LoadedFilter {
    pub fn isolation(&self) -> Isolation {
        self.inner.isolation
    }

    /// Run the request-side hook. Returns the typed decision plus any log lines the filter
    /// emitted (captured via the host-log capability).
    pub fn on_request(&self, req: &HttpRequest) -> Result<(RequestDecision, Vec<LogLine>)> {
        match &self.trusted {
            // trusted: reuse the persistent instance, only resetting per-request state.
            Some(cell) => {
                let mut guard = cell.lock();
                let inst = &mut *guard;
                inst.store.data_mut().begin_request();
                let decision = inst.filter.call_on_request(&mut inst.store, req)?;
                let logs = std::mem::take(&mut inst.store.data_mut().logs);
                Ok((decision, logs))
            }
            // untrusted: fresh instance + init every request (the isolation trade).
            None => {
                let mut inst = self.inner.instantiate_initialized()?;
                let decision = inst.filter.call_on_request(&mut inst.store, req)?;
                let logs = std::mem::take(&mut inst.store.data_mut().logs);
                Ok((decision, logs))
            }
        }
    }

    /// Run the response-side hook for one response.
    pub fn on_response(&self, resp: &HttpResponse) -> Result<(ResponseDecision, Vec<LogLine>)> {
        match &self.trusted {
            Some(cell) => {
                let mut guard = cell.lock();
                let inst = &mut *guard;
                inst.store.data_mut().begin_request();
                let decision = inst.filter.call_on_response(&mut inst.store, resp)?;
                let logs = std::mem::take(&mut inst.store.data_mut().logs);
                Ok((decision, logs))
            }
            None => {
                let mut inst = self.inner.instantiate_initialized()?;
                let decision = inst.filter.call_on_response(&mut inst.store, resp)?;
                let logs = std::mem::take(&mut inst.store.data_mut().logs);
                Ok((decision, logs))
            }
        }
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
        HostState::new(Arc::new(MemoryBackend::default()), prefix.to_string())
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
        let mut a = HostState::new(shared.clone(), "filter-a\u{1f}".to_string());
        let mut b = HostState::new(shared.clone(), "filter-b\u{1f}".to_string());

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
}
