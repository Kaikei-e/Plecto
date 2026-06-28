//! SPIKE host (throwaway) — drives the async `stream<u8>` guest on wasmtime 46 to answer the ONE
//! question gating direction_0003 Part B.1 gates 1+2: does true streaming keep the guest's memory
//! flat in body size (vs the buffered `list<u8>` contract, which ADR 000025 measured at 1 MB -67%
//! and RSS linear in body)?
//!
//! Decisive assertion: cap the GUEST's linear memory at 4 MiB, then stream a 64 MiB body through it.
//! If the guest buffered the whole body (the `list<u8>` shape) it would need 64 MiB and OOM-trap;
//! success with the correct byte count proves the guest pulled the body lazily — true streaming.
//!
//! Run: `cargo run --release` (after the guest is built for wasm32-wasip2). This is a spike, not
//! shipped code; findings are echoed at the end and recorded in the chat report.

use wasmtime::component::{Component, Linker, ResourceTable, StreamReader};
use wasmtime::{Config, Engine, Result, Store, StoreLimits, StoreLimitsBuilder, ensure};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

mod bindings {
    wasmtime::component::bindgen!({
        path: "../wit",
        world: "streaming-filter",
        exports: { default: async },
    });
}

// The wasm32-wasip2 guest's async runtime imports `wasi:io/poll`, so the host must lend WASI even
// though this filter uses no I/O capability itself — a spike data point: the async/stream guest is
// NOT a no-WASI header-only filter (ADR 000010); it pulls in WASI preview2, which is exactly why the
// production contract stays on `wasm32-unknown-unknown` until the wasi:http convergence (ADR 000020).
struct Ctx {
    limits: StoreLimits,
    table: ResourceTable,
    wasi: WasiCtx,
}

impl WasiView for Ctx {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    const BODY: usize = 64 << 20; // 64 MiB streamed through the guest
    const GUEST_CAP: usize = 4 << 20; // 4 MiB linear-memory ceiling — far below the body

    let mut config = Config::new();
    config.wasm_component_model(true);
    config.wasm_component_model_async(true);
    let engine = Engine::new(&config)?;

    let guest_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../guest/target/wasm32-wasip2/release/streaming_guest.wasm"
    );
    let component = Component::from_file(&engine, guest_path)?;

    let mut linker: Linker<Ctx> = Linker::new(&engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;

    let limits = StoreLimitsBuilder::new().memory_size(GUEST_CAP).build();
    let mut store = Store::new(
        &engine,
        Ctx {
            limits,
            table: ResourceTable::new(),
            wasi: WasiCtxBuilder::new().build(),
        },
    );
    store.limiter(|c| &mut c.limits);

    let bindings =
        bindings::StreamingFilter::instantiate_async(&mut store, &component, &linker).await?;

    // Host-side source: a materialized 64 MiB body (the HOST isn't the thing under test — the GUEST
    // is, and it is capped at 4 MiB). wasmtime feeds it to the guest with stream backpressure.
    let body: Vec<u8> = vec![0u8; BODY];
    let reader = StreamReader::new(&mut store, body)?;

    // Async component exports run on the concurrent harness (`run_concurrent` drives the event loop
    // and hands the call an `Accessor` instead of a raw `&mut Store`). The guest pulls the stream to
    // completion here.
    let n = store
        .run_concurrent(async move |accessor| {
            bindings
                .plecto_streaming_spike_body_filter()
                .call_process_body(accessor, reader)
                .await
        })
        .await??;

    ensure!(
        n as usize == BODY,
        "guest counted {n} bytes, expected {BODY}"
    );
    println!(
        "SPIKE OK: guest streamed {} MiB under a {} MiB linear-memory cap → true streaming proven \
         (a buffered list<u8> guest would have OOM-trapped).",
        BODY >> 20,
        GUEST_CAP >> 20
    );
    Ok(())
}
