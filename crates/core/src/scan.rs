//! Free-space mapping, entropy classification, and signature scanning.
//!
//! Classifies regions as zeros, uniform fills, random-or-encrypted, and
//! structured (potentially recoverable) data. The scanner is read-only
//! by construction: it never holds a write handle to the source.

use std::io;

use crate::carve;
use crate::io::EvidenceSource;
use crate::report::ScanSummary;

/// Blocks at or above this entropy (bits per byte) are treated as random
/// or encrypted. Both look identical to a host, and both are practically
/// unrecoverable without keys. WipeTrace's classifier uses the same line.
pub const ENTROPY_RANDOM_THRESHOLD: f64 = 7.6;

/// Shannon entropy in bits per byte: 0.0 for uniform data, approaching
/// 8.0 for random data.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// What a block of bytes looks like to a forensic examiner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockClass {
    /// All 0x00: erased, trimmed, or never written.
    Empty,
    /// A single repeated non-zero byte (for example 0xFF): a fill pattern.
    FillByte(u8),
    /// High entropy: random fill, compressed, or encrypted data.
    RandomOrEncrypted,
    /// Anything else: structured data that may hold recoverable content.
    Structured,
}

/// Classify one block of bytes.
pub fn classify(data: &[u8]) -> BlockClass {
    if data.is_empty() || data.iter().all(|&b| b == 0) {
        return BlockClass::Empty;
    }
    let first = data[0];
    if data.iter().all(|&b| b == first) {
        return BlockClass::FillByte(first);
    }
    if shannon_entropy(data) >= ENTROPY_RANDOM_THRESHOLD {
        return BlockClass::RandomOrEncrypted;
    }
    BlockClass::Structured
}

/// Scan an entire evidence source block by block, classifying space and
/// collecting signature hits. Read-only.
pub fn scan_source(src: &mut EvidenceSource, block_size: u64) -> io::Result<ScanSummary> {
    let mut summary = ScanSummary::new(src.name());
    let mut buf = vec![0u8; block_size as usize];
    for region in src.regions(block_size) {
        let n = src.read_at(region.offset, &mut buf)?;
        if n == 0 {
            break;
        }
        let block = &buf[..n];
        summary.bytes_scanned += n as u64;
        let class = classify(block);
        match class {
            BlockClass::Empty => summary.blocks_empty += 1,
            BlockClass::FillByte(_) => summary.blocks_fill += 1,
            BlockClass::RandomOrEncrypted => summary.blocks_random += 1,
            BlockClass::Structured => summary.blocks_structured += 1,
        }
        // Carving is only meaningful on structured space. A block that reads
        // as random or encrypted is unrecoverable noise to a host without
        // keys, so matches inside it would be false promises, not findings.
        if class == BlockClass::Structured {
            let mut hits = Vec::new();
            carve::find_signatures(block, region.offset, &mut hits);
            for hit in hits {
                summary.record_hit(hit);
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::EvidenceSource;
    use crate::report::Category;
    use std::io::Cursor;

    fn prng_bytes(n: usize, mut seed: u64) -> Vec<u8> {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(shannon_entropy(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn entropy_of_fair_coin_is_one() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0u8; 512]);
        data.extend_from_slice(&[1u8; 512]);
        assert!((shannon_entropy(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_prng_is_high() {
        let data = prng_bytes(65536, 0xDEADBEEF);
        assert!(shannon_entropy(&data) > ENTROPY_RANDOM_THRESHOLD);
    }

    #[test]
    fn classify_blocks() {
        assert_eq!(classify(&[0u8; 64]), BlockClass::Empty);
        assert_eq!(classify(&[0xFF; 64]), BlockClass::FillByte(0xFF));
        assert_eq!(
            classify(&prng_bytes(65536, 42)),
            BlockClass::RandomOrEncrypted
        );
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog. "
            .iter()
            .cycle()
            .take(4096)
            .copied()
            .collect();
        assert_eq!(classify(&text), BlockClass::Structured);
    }

    #[test]
    fn scan_source_counts_classes_and_hits() {
        let mut image = Vec::new();
        image.extend_from_slice(&[0u8; 1024]); // empty block
        image.extend_from_slice(&[0xFF; 1024]); // fill block
        image.extend_from_slice(
            &b"abcdefghij"
                .iter()
                .cycle()
                .take(1024)
                .copied()
                .collect::<Vec<u8>>(),
        ); // structured block, low entropy
        let mut structured = b"lorem ipsum dolor sit amet. "
            .iter()
            .cycle()
            .take(1024)
            .copied()
            .collect::<Vec<u8>>();
        structured[100..104].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // JFIF header
        structured[500..505].copy_from_slice(b"%PDF-"); // PDF header
        image.extend_from_slice(&structured);

        let mut src = EvidenceSource::from_reader("synthetic", Cursor::new(image)).unwrap();
        let summary = scan_source(&mut src, 1024).unwrap();

        assert_eq!(summary.bytes_scanned, 4096);
        assert_eq!(summary.blocks_empty, 1);
        assert_eq!(summary.blocks_fill, 1);
        assert_eq!(summary.blocks_structured, 2);
        assert_eq!(summary.blocks_random, 0);
        assert_eq!(summary.hit_count(), 2);
        let by_category = summary.hits_by_category();
        assert_eq!(by_category.get(&Category::Photos), Some(&1));
        assert_eq!(by_category.get(&Category::Documents), Some(&1));
    }
}
