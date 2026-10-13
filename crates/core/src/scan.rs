//! Free-space mapping, entropy classification, and signature scanning.
//!
//! Classifies regions as zeros, uniform fills, random-or-encrypted, and
//! structured (potentially recoverable) data. The scanner is read-only
//! by construction: it never holds a write handle to the source.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// How far a scan has read. `bytes_total` is the source size the caller
/// opened, which for a device is the size reported by the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
    pub bytes_read: u64,
    pub bytes_total: u64,
}

/// A finished scan, or the part that was read before cancel.
#[derive(Debug)]
pub struct ScanRun {
    pub summary: ScanSummary,
    /// True when `cancel` was set between blocks. The summary then covers
    /// only the bytes already read.
    pub canceled: bool,
}

/// Scan an entire evidence source block by block, classifying space and
/// collecting signature hits. Read-only.
pub fn scan_source(src: &mut EvidenceSource, block_size: u64) -> io::Result<ScanSummary> {
    Ok(scan_source_with(src, block_size, None, |_| {})?.summary)
}

/// Same scan as [`scan_source`], plus progress and cooperative cancel.
///
/// `on_progress` runs after each block with bytes read and the total.
/// When `cancel` is set, the scan stops before the next block and returns
/// the partial summary with [`ScanRun::canceled`] set. Existing callers
/// keep using [`scan_source`], which passes no flag and an empty callback.
pub fn scan_source_with(
    src: &mut EvidenceSource,
    block_size: u64,
    cancel: Option<&AtomicBool>,
    mut on_progress: impl FnMut(ScanProgress),
) -> io::Result<ScanRun> {
    if block_size == 0 || block_size > usize::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block size must be at least 1 byte",
        ));
    }
    let total = src.size();
    let mut summary = ScanSummary::new(src.name());
    let mut buf = vec![0u8; block_size as usize];
    for region in src.regions(block_size) {
        if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            return Ok(ScanRun {
                summary,
                canceled: true,
            });
        }
        // Ask only for this region. A raw device rejects a short read that
        // is not a multiple of its sector size, and it also rejects a read
        // that runs past the end. Callers that scan devices pass a size and
        // a block size that are both multiples of the sector.
        let want = region.len.min(buf.len() as u64) as usize;
        let n = read_full_at(src, region.offset, &mut buf[..want])?;
        if n < want {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the disk ended before its reported size",
            ));
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
        on_progress(ScanProgress {
            bytes_read: summary.bytes_scanned,
            bytes_total: total,
        });
    }
    Ok(ScanRun {
        summary,
        canceled: false,
    })
}

/// Read until `buf` is full. A short read that then returns 0 is the caller's
/// problem to report; this only retries interruptions.
fn read_full_at(src: &mut EvidenceSource, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read_at(offset + filled as u64, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
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

    #[test]
    fn progress_reports_bytes_read_against_total() {
        let image = vec![0u8; 4096];
        let mut src = EvidenceSource::from_reader("synthetic", Cursor::new(image)).unwrap();
        let mut seen = Vec::new();
        let run = scan_source_with(&mut src, 1024, None, |progress| seen.push(progress)).unwrap();
        assert!(!run.canceled);
        assert_eq!(run.summary.bytes_scanned, 4096);
        assert_eq!(
            seen,
            vec![
                ScanProgress {
                    bytes_read: 1024,
                    bytes_total: 4096
                },
                ScanProgress {
                    bytes_read: 2048,
                    bytes_total: 4096
                },
                ScanProgress {
                    bytes_read: 3072,
                    bytes_total: 4096
                },
                ScanProgress {
                    bytes_read: 4096,
                    bytes_total: 4096
                },
            ]
        );
    }

    #[test]
    fn cancel_stops_between_blocks() {
        let image = vec![0u8; 4096];
        let mut src = EvidenceSource::from_reader("synthetic", Cursor::new(image)).unwrap();
        let cancel = AtomicBool::new(false);
        let run = scan_source_with(&mut src, 1024, Some(&cancel), |progress| {
            if progress.bytes_read >= 1024 {
                cancel.store(true, Ordering::Relaxed);
            }
        })
        .unwrap();
        assert!(run.canceled);
        assert_eq!(run.summary.bytes_scanned, 1024);
        assert_eq!(run.summary.blocks_empty, 1);
    }
}
