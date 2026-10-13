//! Fuzz target: entropy, block classifier, and the full read-only scan
//! pipeline on arbitrary bytes.
//!
//! Run with: cargo +nightly fuzz run scan_classify

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let entropy = gone_core::scan::shannon_entropy(data);
    assert!(
        (0.0..=8.0).contains(&entropy),
        "entropy {entropy} outside [0, 8] bits per byte"
    );
    let _class = gone_core::scan::classify(data);

    // End-to-end through the public scan path. Capped so a huge input
    // cannot turn the fuzzer into an OOM report; libFuzzer's default
    // max_len is 4096, so in practice this always runs.
    if data.len() <= 4 * 1024 * 1024 {
        // to_vec: EvidenceSource requires an owned, 'static reader.
        let owned = data.to_vec();
        if let Ok(mut src) = gone_core::io::EvidenceSource::from_reader("fuzz", Cursor::new(owned))
        {
            let _summary = gone_core::scan::scan_source(&mut src, 4096);
        }
    }
});
