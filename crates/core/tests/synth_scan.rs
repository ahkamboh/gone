//! End-to-end scan tests on a synthetic corpus built in memory.
//!
//! No fixture files are needed: the corpus is generated here so these tests
//! run anywhere, including offline CI. The mixed-image layout mirrors what
//! `cargo xtask synth-corpus` writes to fixtures/synth-mixed.img; keep the
//! two in sync (see xtask/src/main.rs).

use std::io::Cursor;

use gone_core::carve::find_signatures;
use gone_core::io::EvidenceSource;
use gone_core::report::Category;
use gone_core::scan::{
    BlockClass, ENTROPY_RANDOM_THRESHOLD, classify, scan_source, shannon_entropy,
};

const MIB: usize = 1024 * 1024;
const SCAN_BLOCK: u64 = MIB as u64;

/// xorshift64* byte stream. Deterministic, high entropy; NOT for security.
/// Seed 0 is a fixed point, never use it.
fn prng_fill(buf: &mut [u8], mut seed: u64) {
    for byte in buf.iter_mut() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed >> 32) as u8;
    }
}

/// Low-entropy ASCII filler: reads as `BlockClass::Structured` and contains
/// no signature magic bytes.
fn structured_fill(buf: &mut [u8]) {
    const FILLER: &[u8] = b"gone synthetic structured block payload; audit fixture. ";
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = FILLER[i % FILLER.len()];
    }
}

// Planted offsets inside the 6 MiB mixed image (block = 1 MiB).
const JPEG_OFF: u64 = 3 * MIB as u64 + 0x100;
const PDF_OFF: u64 = 3 * MIB as u64 + 0x200;
const SQLITE_OFF: u64 = 4 * MIB as u64 + 0x40;
const DECOY_GZIP_OFF: usize = 4 * MIB + 0x60;
const DECOY_JPEG_OFF: usize = 4 * MIB + 0x70;
const RANDOM_BLOCK_JPEG_OFF: usize = 2 * MIB + 0x80;

/// 6 MiB: 2 empty, 1 random (JPEG planted, must be ignored), 3 structured
/// holding exactly 3 real hits (JPEG, PDF, SQLite) plus validator decoys.
fn build_mixed_image() -> Vec<u8> {
    let mut image = vec![0u8; 6 * MIB];
    prng_fill(&mut image[2 * MIB..3 * MIB], 0x9E37_79B9_7F4A_7C15);
    image[RANDOM_BLOCK_JPEG_OFF..RANDOM_BLOCK_JPEG_OFF + 4]
        .copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    for block in 3..6 {
        structured_fill(&mut image[block * MIB..(block + 1) * MIB]);
    }
    image[JPEG_OFF as usize..JPEG_OFF as usize + 4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    image[PDF_OFF as usize..PDF_OFF as usize + 8].copy_from_slice(b"%PDF-1.7");
    image[SQLITE_OFF as usize..SQLITE_OFF as usize + 16].copy_from_slice(b"SQLite format 3\0");
    image[DECOY_GZIP_OFF..DECOY_GZIP_OFF + 4].copy_from_slice(&[0x1F, 0x8B, 0x00, 0x00]);
    image[DECOY_JPEG_OFF..DECOY_JPEG_OFF + 4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0x6C]);
    image
}

fn scan(image: Vec<u8>) -> gone_core::report::ScanSummary {
    let mut src = EvidenceSource::from_reader("synthetic", Cursor::new(image)).unwrap();
    scan_source(&mut src, SCAN_BLOCK).unwrap()
}

#[test]
fn mixed_image_classifies_blocks_three_one_two() {
    let summary = scan(build_mixed_image());
    assert_eq!(summary.bytes_scanned, 6 * MIB as u64);
    assert_eq!(summary.blocks_empty, 2);
    assert_eq!(summary.blocks_random, 1);
    assert_eq!(summary.blocks_structured, 3);
    assert_eq!(summary.blocks_fill, 0);
}

#[test]
fn mixed_image_finds_exactly_the_planted_hits() {
    let summary = scan(build_mixed_image());
    // Exactly the three real signatures: the JPEG planted in the random
    // block is skipped (carving is structured-space-only) and both decoys
    // fail their structural validators.
    assert_eq!(summary.hit_count(), 3);
    let mut got: Vec<(u64, &str)> = summary
        .hits()
        .iter()
        .map(|hit| (hit.offset, hit.signature_name))
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![
            (JPEG_OFF, "JPEG image"),
            (PDF_OFF, "PDF document"),
            (SQLITE_OFF, "SQLite database"),
        ]
    );
    let by_category = summary.hits_by_category();
    assert_eq!(by_category.len(), 3);
    assert_eq!(by_category.get(&Category::Photos), Some(&1));
    assert_eq!(by_category.get(&Category::Documents), Some(&1));
    assert_eq!(by_category.get(&Category::Databases), Some(&1));
}

#[test]
fn decoys_fail_validators_at_the_carve_layer() {
    let image = build_mixed_image();
    // Block 4 holds one real SQLite header plus both decoys.
    let block = &image[4 * MIB..5 * MIB];
    let mut hits = Vec::new();
    find_signatures(block, 4 * MIB as u64, &mut hits);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].signature_name, "SQLite database");
    assert_eq!(hits[0].offset, SQLITE_OFF);
    // The plain structured filler contains no magic at all.
    let mut hits = Vec::new();
    find_signatures(&image[5 * MIB..6 * MIB], 0, &mut hits);
    assert!(hits.is_empty());
}

#[test]
fn zeros_image_yields_clean_verdict() {
    let summary = scan(vec![0u8; 2 * MIB]);
    assert_eq!(summary.blocks_empty, 2);
    assert_eq!(summary.blocks_structured, 0);
    assert_eq!(summary.hit_count(), 0);
    assert_eq!(
        summary.verdict(),
        "Good news: nothing recoverable was found in the scanned space."
    );
}

/// Regression: random data used to trip the bare 2-byte gzip magic. Between
/// the structural validator and the structured-space-only carving rule, a
/// random image must produce zero hits.
#[test]
fn random_image_yields_zero_hits() {
    let mut image = vec![0u8; 2 * MIB];
    prng_fill(&mut image, 0xC0FF_EE15_600D_F00D);
    let summary = scan(image);
    assert_eq!(summary.blocks_random, 2);
    assert_eq!(summary.blocks_structured, 0);
    assert_eq!(summary.hit_count(), 0);
}

#[test]
fn ff_image_classifies_as_fill() {
    let summary = scan(vec![0xFF; 2 * MIB]);
    assert_eq!(summary.blocks_fill, 2);
    assert_eq!(summary.hit_count(), 0);
}

#[test]
fn classify_and_entropy_edge_cases() {
    assert_eq!(shannon_entropy(&[]), 0.0);
    assert_eq!(classify(&[]), BlockClass::Empty);
    assert_eq!(classify(&[0]), BlockClass::Empty);
    assert_eq!(classify(&[0xFF]), BlockClass::FillByte(0xFF));
    assert_eq!(classify(&[7; 4096]), BlockClass::FillByte(7));
    let mut random = vec![0u8; MIB];
    prng_fill(&mut random, 42);
    assert!(shannon_entropy(&random) >= ENTROPY_RANDOM_THRESHOLD);
    assert_eq!(classify(&random), BlockClass::RandomOrEncrypted);
}

#[test]
fn scan_handles_odd_trailing_block() {
    // One full structured block plus a 123-byte tail: the tail is its own
    // short region and must still classify and scan cleanly.
    let mut image = vec![0u8; MIB + 123];
    structured_fill(&mut image);
    let summary = scan(image.clone());
    assert_eq!(summary.bytes_scanned, (MIB + 123) as u64);
    assert_eq!(summary.blocks_structured, 2);
    // A signature straddling nothing: planted in the tail, still found.
    let tail = MIB + 10;
    image[tail..tail + 4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE1]);
    let summary = scan(image);
    assert_eq!(summary.hit_count(), 1);
    assert_eq!(summary.hits()[0].offset, tail as u64);
}
