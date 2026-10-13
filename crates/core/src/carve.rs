//! Deleted-file carving: signature matching first, validation later.
//!
//! A signature match is a candidate, not proof. Format-specific validators
//! (decode the candidate, discard failures) land with the full carving
//! milestone. Magic numbers at fixed offsets are facts, not copyrightable
//! work; the data-driven YAML signature database lands with gone-detect.

use crate::report::Category;

/// A file-type signature: magic bytes at the start of a file.
pub struct Signature {
    pub name: &'static str,
    pub extension: &'static str,
    pub category: Category,
    pub magic: &'static [u8],
    /// Cheap structural check on the bytes starting at the hit. Keeps short
    /// magics like gzip's 2-byte header from firing on random data, the same
    /// role header validation plays in PhotoRec.
    pub check: fn(&[u8]) -> bool,
}

/// One signature match at an absolute offset in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub signature_name: &'static str,
    pub extension: &'static str,
    pub category: Category,
    pub offset: u64,
}

/// After FFD8FF a JPEG has a marker byte: E0 (JFIF), E1 (Exif), or DB (DQT)
/// cover virtually every camera and phone photo.
fn check_jpeg(at: &[u8]) -> bool {
    matches!(at.get(3), Some(0xE0 | 0xE1 | 0xDB))
}

/// gzip byte 2 must be the compression method 0x08 (deflate), and the three
/// reserved flag bits in byte 3 must be zero.
fn check_gzip(at: &[u8]) -> bool {
    matches!(at.get(2), Some(0x08)) && at.get(3).is_some_and(|flg| flg & 0xE0 == 0)
}

/// A ZIP local file header stores "version needed to extract" right after the
/// magic. Real archivers write small values, so a huge one means noise.
fn check_zip(at: &[u8]) -> bool {
    at.get(4).is_some_and(|&version| version <= 99)
}

fn check_none(_at: &[u8]) -> bool {
    true
}

const fn sig(
    name: &'static str,
    extension: &'static str,
    category: Category,
    magic: &'static [u8],
    check: fn(&[u8]) -> bool,
) -> Signature {
    Signature {
        name,
        extension,
        category,
        magic,
        check,
    }
}

/// Starter signature table.
pub const DEFAULT_SIGNATURES: &[Signature] = &[
    sig(
        "JPEG image",
        "jpg",
        Category::Photos,
        &[0xFF, 0xD8, 0xFF],
        check_jpeg,
    ),
    sig(
        "PNG image",
        "png",
        Category::Photos,
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        check_none,
    ),
    sig(
        "PDF document",
        "pdf",
        Category::Documents,
        b"%PDF",
        check_none,
    ),
    sig(
        "ZIP archive",
        "zip",
        Category::Archives,
        &[0x50, 0x4B, 0x03, 0x04],
        check_zip,
    ),
    sig(
        "gzip stream",
        "gz",
        Category::Archives,
        &[0x1F, 0x8B],
        check_gzip,
    ),
    sig(
        "SQLite database",
        "sqlite",
        Category::Databases,
        b"SQLite format 3\x00",
        check_none,
    ),
];

/// Find all signature matches in `buf`, reporting absolute offsets by
/// adding `base_offset`.
pub fn find_signatures(buf: &[u8], base_offset: u64, out: &mut Vec<Hit>) {
    for signature in DEFAULT_SIGNATURES {
        let magic = signature.magic;
        if buf.len() < magic.len() {
            continue;
        }
        for (i, window) in buf.windows(magic.len()).enumerate() {
            if window == magic && (signature.check)(&buf[i..]) {
                out.push(Hit {
                    signature_name: signature.name,
                    extension: signature.extension,
                    category: signature.category,
                    offset: base_offset + i as u64,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_jpeg_at_exact_offset() {
        let mut buf = vec![0u8; 64];
        buf[10..14].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // JFIF header
        let mut hits = Vec::new();
        find_signatures(&buf, 1000, &mut hits);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].signature_name, "JPEG image");
        assert_eq!(hits[0].offset, 1010);
        assert_eq!(hits[0].category, Category::Photos);
    }

    #[test]
    fn finds_multiple_types() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.7 junk");
        buf.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        buf.extend_from_slice(b"SQLite format 3\x00");
        let mut hits = Vec::new();
        find_signatures(&buf, 0, &mut hits);
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].signature_name, "PDF document");
        assert_eq!(hits[1].signature_name, "ZIP archive");
        assert_eq!(hits[2].signature_name, "SQLite database");
    }

    #[test]
    fn no_hits_in_zeros() {
        let buf = vec![0u8; 4096];
        let mut hits = Vec::new();
        find_signatures(&buf, 0, &mut hits);
        assert!(hits.is_empty());
    }

    #[test]
    fn rejects_gzip_magic_without_valid_header() {
        // 1F 8B followed by an invalid compression method is noise, and a
        // valid header must follow: 1F 8B 08 with reserved flag bits zero.
        let mut hits = Vec::new();
        find_signatures(&[0x1F, 0x8B, 0x00, 0x00], 0, &mut hits);
        assert!(hits.is_empty());
        find_signatures(&[0x1F, 0x8B, 0x08, 0x08], 0, &mut hits);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn rejects_jpeg_magic_without_marker() {
        // FFD8FF at the very end of a block, or followed by a non-marker
        // byte, is not a photo.
        let mut hits = Vec::new();
        find_signatures(&[0x00, 0xFF, 0xD8, 0xFF], 0, &mut hits);
        assert!(hits.is_empty());
        find_signatures(&[0xFF, 0xD8, 0xFF, 0x6C], 0, &mut hits);
        assert!(hits.is_empty());
    }
}
