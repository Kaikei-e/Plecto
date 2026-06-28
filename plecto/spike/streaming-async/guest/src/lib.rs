//! SPIKE guest (throwaway) — an async `stream<u8>` consumer probing gate 1+2's toolchain.
//!
//! It pulls the body in fixed 64 KiB chunks into a REUSED buffer, counts the bytes, and discards
//! each chunk. Guest linear memory therefore stays flat regardless of body size — the property the
//! buffered `list<u8>` contract cannot have (ADR 000025 measured 1 MB at -67% / RSS linear in body).
//! `StreamReader::collect()` exists but would buffer the whole body, defeating the spike, so the
//! read/clear loop is deliberate.
#![allow(clippy::all)]

use wit_bindgen::StreamResult;

wit_bindgen::generate!({
    path: "../wit",
    world: "streaming-filter",
    async: true,
});

struct Spike;

impl exports::plecto::streaming_spike::body_filter::Guest for Spike {
    async fn process_body(input: wit_bindgen::StreamReader<u8>) -> u64 {
        const CHUNK: usize = 64 * 1024;
        let mut total: u64 = 0;
        let mut reader = input;
        let mut buf: Vec<u8> = Vec::with_capacity(CHUNK);
        loop {
            buf.clear(); // reset len, keep capacity → read fills the same spare 64 KiB
            let (status, returned) = reader.read(buf).await;
            buf = returned;
            match status {
                StreamResult::Complete(n) => total += n as u64,
                StreamResult::Dropped => break,
                StreamResult::Cancelled => break,
            }
        }
        total
    }
}

export!(Spike);
