//! Fuzz target: arbitrary bytes through the signature carver.
//!
//! The carver scans attacker-controlled disk images, so it must never panic
//! and every reported offset must stay inside the input.
//!
//! Run with: cargo +nightly fuzz run carve_parse

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut hits = Vec::new();
    gone_core::carve::find_signatures(data, 0, &mut hits);
    for hit in &hits {
        assert!(
            (hit.offset as usize) < data.len(),
            "hit offset {} escapes input of {} bytes",
            hit.offset,
            data.len()
        );
    }
});
