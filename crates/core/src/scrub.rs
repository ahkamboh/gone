//! Metadata removal from live files: EXIF, XMP, IPTC, and C2PA/JUMBF
//! provenance in JPEG, PNG, and PDF containers.
//!
//! Fail-closed, copy-not-in-place, self-verifying output.
//!
//! # How a scrub works
//!
//! 1. [`detect`] sniffs the container format from magic bytes, never the
//!    file extension.
//! 2. [`scrub_file`] refuses to write over its own source, then hands the
//!    container to `prose-sanitiser-media` for byte-level surgery: segment
//!    and chunk filtering for JPEG/PNG, and a full PDF object-graph rewrite
//!    that removes `/Info`, `/Metadata` streams, XMP packets, and C2PA
//!    embedded files. The source file is never modified.
//! 3. Containers the library cannot parse (a forensic reality: CRC-damaged
//!    PNGs, oddly framed JPEGs) fall back to raw segment/chunk filtering
//!    that copies every kept byte verbatim, CRCs included.
//! 4. The output is re-read and re-parsed. If any targeted metadata carrier
//!    survives, the output file is deleted and the scrub reports failure.
//!    A "clean" file that cannot be verified is never left behind.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use prose_sanitiser_media::container::pdf;
use prose_sanitiser_media::image::{CleanImageOptions, clean_image, inspect_bytes};
use serde_json::Value;

/// JPEG start-of-image plus the first marker prefix: `FF D8 FF`.
const JPEG_MAGIC: &[u8] = b"\xff\xd8\xff";
/// JPEG start-of-image alone, where segment walking begins.
const JPEG_SOI: &[u8] = b"\xff\xd8";
/// The eight-byte PNG signature.
const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
/// The PDF header prefix.
const PDF_SIG: &[u8] = b"%PDF";

/// The `iTXt` keyword Adobe uses for an embedded XMP packet, NUL-terminated
/// as it appears at the head of the chunk payload.
const XMP_ITXT_KEYWORD: &[u8] = b"XML:com.adobe.xmp\0";

/// APP1 payload prefixes that mark an XMP packet (standard and extended).
const XMP_APP1_PREFIXES: &[&[u8]] = &[
    b"http://ns.adobe.com/xap/1.0/",
    b"http://ns.adobe.com/xmp/extension/",
];

/// Byte sequences that name a C2PA/JUMBF provenance structure. Matching is
/// case-insensitive, mirroring the surgery library's own marker table.
const PROVENANCE_MARKERS: &[&[u8]] = &[
    b"c2pa",
    b"jumb",
    b"c2ma",
    b"contentcredentials",
    b"contentauth",
    b"cai:",
];

/// PNG chunks that carry image data or rendering intent and are never
/// dropped. Mirrors the surgery library's structural list.
const PNG_STRUCTURAL_CHUNKS: &[&[u8]] = &[
    b"IHDR", b"IDAT", b"IEND", b"PLTE", b"tRNS", b"gAMA", b"pHYs", b"sRGB", b"cHRM", b"iCCP",
];

/// Largest source file the scrubber will load, 256 MiB. The surgery library
/// enforces its own tighter per-format caps; this is the outer guard that
/// keeps a hostile file from exhausting host memory through us.
const MAX_SOURCE_BYTES: u64 = 256 << 20;

/// A container format the scrubber can operate on.
///
/// Detection is by magic bytes only, so a JPEG named `notes.txt` is still
/// [`ScrubFormat::Jpeg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrubFormat {
    /// JPEG image: `FF D8 FF`.
    Jpeg,
    /// PNG image: the eight-byte signature.
    Png,
    /// PDF document: `%PDF`.
    Pdf,
    /// Anything else, including empty or unreadable files.
    Unknown,
}

impl ScrubFormat {
    /// Short name for reports and error messages.
    pub fn label(self) -> &'static str {
        match self {
            ScrubFormat::Jpeg => "JPEG",
            ScrubFormat::Png => "PNG",
            ScrubFormat::Pdf => "PDF",
            ScrubFormat::Unknown => "unknown",
        }
    }
}

/// Sniff the container format from a file's leading magic bytes.
///
/// The extension is never consulted. Unreadable, empty, and unrecognized
/// files all report [`ScrubFormat::Unknown`]; [`scrub_file`] performs its own
/// detection on the bytes it has already read and reports I/O problems
/// properly.
pub fn detect(path: &Path) -> ScrubFormat {
    let mut head = Vec::new();
    let Ok(file) = fs::File::open(path) else {
        return ScrubFormat::Unknown;
    };
    match file.take(16).read_to_end(&mut head) {
        Ok(_) => detect_bytes(&head),
        Err(_) => ScrubFormat::Unknown,
    }
}

/// Magic-byte sniffing shared by [`detect`] and the scrub pipeline.
fn detect_bytes(data: &[u8]) -> ScrubFormat {
    if data.starts_with(JPEG_MAGIC) {
        return ScrubFormat::Jpeg;
    }
    if data.starts_with(PNG_SIG) {
        return ScrubFormat::Png;
    }
    if data.starts_with(PDF_SIG) {
        return ScrubFormat::Pdf;
    }
    ScrubFormat::Unknown
}

/// What a successful scrub did, in plain language.
#[derive(Debug, Clone)]
pub struct ScrubReport {
    /// The detected container format of the source.
    pub format: ScrubFormat,
    /// Source length minus output length, saturating at zero. A PDF rewrite
    /// can in principle grow a pathological file, so this is not signed.
    pub bytes_removed: u64,
    /// One plain-language label per removed metadata carrier, for example
    /// "EXIF camera info" or "XMP edit history".
    pub items_removed: Vec<String>,
    /// Where the scrubbed copy was written.
    pub output_path: PathBuf,
    /// The file that was scrubbed. Guaranteed untouched.
    pub source_path: PathBuf,
}

impl ScrubReport {
    /// A one-line, human-readable summary of the scrub.
    ///
    /// For a file that carried metadata: "Removed 3 hidden metadata blocks
    /// (EXIF camera info, XMP edit history, and IPTC photo captions) from
    /// photo.jpg. Original untouched." For a file that was already clean:
    /// "No hidden metadata found in photo.jpg. Original untouched."
    pub fn summary_line(&self) -> String {
        let name = self
            .source_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "the file".to_string());
        if self.items_removed.is_empty() {
            return format!("No hidden metadata found in {name}. Original untouched.");
        }
        let count = self.items_removed.len();
        let noun = if count == 1 { "block" } else { "blocks" };
        format!(
            "Removed {count} hidden metadata {noun} ({}) from {name}. Original untouched.",
            list_items(&self.items_removed, 3),
        )
    }
}

/// Render up to `max` items as "a, b, and c", folding the rest into
/// ", and N more".
fn list_items(items: &[String], max: usize) -> String {
    if items.len() > max {
        return format!(
            "{}, and {} more",
            items[..max].join(", "),
            items.len() - max
        );
    }
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        2 => format!("{} and {}", items[0], items[1]),
        _ => format!(
            "{}, and {}",
            items[..items.len() - 1].join(", "),
            items[items.len() - 1]
        ),
    }
}

/// Why a scrub did not produce a verified output file.
#[derive(Debug)]
pub enum ScrubError {
    /// Source and output resolve to the same file. Scrubbing never modifies
    /// the original, so this is refused before anything is read.
    SamePath,
    /// The leading bytes match no supported container (JPEG, PNG, PDF).
    UnsupportedFormat,
    /// Reading the source or writing the output failed.
    Io(io::Error),
    /// The container could not be scrubbed: it is malformed beyond what the
    /// surgery library and the salvage filter can handle, or too large.
    Surgery(String),
    /// The output was written but a re-parse still found metadata. The
    /// suspect output has been deleted.
    VerificationFailed(String),
}

impl fmt::Display for ScrubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScrubError::SamePath => write!(
                f,
                "source and output are the same file; scrubbing never modifies the original"
            ),
            ScrubError::UnsupportedFormat => write!(
                f,
                "unsupported format: the leading bytes match neither JPEG, PNG, nor PDF"
            ),
            ScrubError::Io(error) => write!(f, "{error}"),
            ScrubError::Surgery(message) => write!(f, "container surgery failed: {message}"),
            ScrubError::VerificationFailed(message) => {
                write!(f, "scrubbed output failed verification: {message}")
            }
        }
    }
}

impl std::error::Error for ScrubError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScrubError::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ScrubError {
    fn from(error: io::Error) -> Self {
        ScrubError::Io(error)
    }
}

/// Scrub `source` into `output`, leaving the source byte-for-byte untouched.
///
/// The output is written fresh (atomically where the surgery library owns the
/// write), then re-read and re-parsed: if any EXIF, XMP, IPTC, or C2PA/JUMBF
/// carrier survives, the output is deleted and
/// [`ScrubError::VerificationFailed`] is returned.
///
/// # Errors
///
/// * [`ScrubError::SamePath`] when `source` and `output` are the same file
///   after canonicalization (symlinks and `.` segments resolved).
/// * [`ScrubError::UnsupportedFormat`] when the magic bytes are not JPEG,
///   PNG, or PDF.
/// * [`ScrubError::Io`] when the source cannot be read or the output cannot
///   be written.
/// * [`ScrubError::Surgery`] when the container is too damaged to scrub.
pub fn scrub_file(source: &Path, output: &Path) -> Result<ScrubReport, ScrubError> {
    refuse_same_path(source, output)?;
    let source_bytes = read_source(source)?;
    let kind = detect_bytes(&source_bytes);
    if kind == ScrubFormat::Unknown {
        return Err(ScrubError::UnsupportedFormat);
    }

    let (items, salvaged) = match kind {
        ScrubFormat::Jpeg | ScrubFormat::Png => scrub_image(kind, source, output, &source_bytes)?,
        ScrubFormat::Pdf => (scrub_pdf(source, output, &source_bytes)?, false),
        ScrubFormat::Unknown => unreachable!("unknown formats are rejected before surgery"),
    };

    // Self-verification: re-read the output and prove every targeted carrier
    // is gone. A failure deletes the output so an unverified "clean" file is
    // never left behind.
    let out_bytes = read_source(output)?;
    let verification = match kind {
        ScrubFormat::Jpeg | ScrubFormat::Png => verify_image_output(kind, &out_bytes, salvaged),
        ScrubFormat::Pdf => verify_pdf_output(output, &out_bytes),
        ScrubFormat::Unknown => unreachable!("unknown formats are rejected before surgery"),
    };
    if let Err(error) = verification {
        let _ = fs::remove_file(output);
        return Err(error);
    }

    let bytes_removed = (source_bytes.len() as u64).saturating_sub(out_bytes.len() as u64);
    Ok(ScrubReport {
        format: kind,
        bytes_removed,
        items_removed: items,
        output_path: output.to_path_buf(),
        source_path: source.to_path_buf(),
    })
}

/// Scrub a file next to itself, writing `<name>.scrubbed.<ext>` beside the
/// source. The convenience wrapper around [`scrub_file`] for callers that do
/// not want to pick an output path.
///
/// # Errors
///
/// Every error [`scrub_file`] can return, unchanged.
pub fn scrub_in_place_clone(source: &Path) -> Result<ScrubReport, ScrubError> {
    scrub_file(source, &scrubbed_path(source))
}

/// `path/to/photo.jpg` becomes `path/to/photo.scrubbed.jpg`.
fn scrubbed_path(source: &Path) -> PathBuf {
    let stem = source
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut name = stem;
    name.push_str(".scrubbed");
    if let Some(extension) = source.extension() {
        name.push('.');
        name.push_str(&extension.to_string_lossy());
    }
    source.with_file_name(name)
}

/// Refuse to scrub a file onto itself.
///
/// Canonicalization resolves symlinks and `.` segments, so aliases of the
/// source are caught too. An output that does not exist yet is compared by
/// canonicalizing its parent; if the parent cannot be resolved either, the
/// output cannot possibly alias the source and the scrub may proceed.
fn refuse_same_path(source: &Path, output: &Path) -> Result<(), ScrubError> {
    let source_canon = fs::canonicalize(source)?;
    let output_canon = match fs::canonicalize(output) {
        Ok(path) => path,
        Err(_) => {
            let parent = output
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            match output
                .file_name()
                .map(|name| (name, fs::canonicalize(parent)))
            {
                Some((name, Ok(dir))) => dir.join(name),
                _ => return Ok(()),
            }
        }
    };
    if source_canon == output_canon {
        return Err(ScrubError::SamePath);
    }
    Ok(())
}

/// Read a whole source file, refusing directories and anything over the cap.
fn read_source(path: &Path) -> Result<Vec<u8>, ScrubError> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(ScrubError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        )));
    }
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(ScrubError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing input larger than {MAX_SOURCE_BYTES} bytes: {}",
                path.display()
            ),
        )));
    }
    Ok(fs::read(path)?)
}

/// Scrub a JPEG or PNG through the surgery library, salvaging damaged
/// containers with the raw filter when the library cannot parse them.
///
/// Returns the plain-language removal labels plus whether the salvage path
/// was used (verification is stricter about second opinions on that path).
fn scrub_image(
    kind: ScrubFormat,
    source: &Path,
    output: &Path,
    source_bytes: &[u8],
) -> Result<(Vec<String>, bool), ScrubError> {
    let labels = image_carriers(kind, source_bytes).unwrap_or_default();
    match clean_image(source, output, &CleanImageOptions::default()) {
        Ok(report) => {
            let mut items = labels;
            if items.is_empty() {
                // Our scanner labelled nothing but the library still removed
                // a segment: its action log is the honest record of what went.
                if let Some(actions) = report.get("actions").and_then(Value::as_array) {
                    items = actions
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|action| action.starts_with("drop"))
                        .map(str::to_string)
                        .collect();
                }
            }
            Ok((items, false))
        }
        Err(library_error) => {
            // Damaged framing (bad CRCs, odd marker layouts) is everyday
            // material in forensic work. Fall back to raw segment/chunk
            // filtering, which copies kept bytes verbatim.
            let filtered = match kind {
                ScrubFormat::Jpeg => filter_jpeg(source_bytes),
                ScrubFormat::Png => filter_png(source_bytes),
                _ => unreachable!("scrub_image only handles JPEG and PNG"),
            };
            let Some((bytes, items)) = filtered else {
                return Err(ScrubError::Surgery(library_error));
            };
            write_atomic(output, &bytes)?;
            Ok((items, true))
        }
    }
}

/// Scrub a PDF through the library's full object-graph rewrite.
///
/// The library verifies the rewritten document in memory before it is
/// written and refuses a file it cannot parse at all, so any error here is
/// final: there is no byte-level PDF salvage, because a partial edit cannot
/// reach `/Info` without corrupting cross-reference offsets.
fn scrub_pdf(source: &Path, output: &Path, source_bytes: &[u8]) -> Result<Vec<String>, ScrubError> {
    let items = pdf_items(source, source_bytes);
    let (actions, meta) = pdf::clean_pdf(source, output).map_err(ScrubError::Surgery)?;
    if !items.is_empty() {
        return Ok(items);
    }
    // Inspection labelled nothing but a rewrite still happened: report the
    // library's own removal actions rather than claim nothing was found.
    let rewritten = meta.get("mode").and_then(Value::as_str) == Some("lopdf");
    if rewritten {
        return Ok(actions
            .into_iter()
            .filter(|action| action.starts_with("remove ") || action.starts_with("drop "))
            .collect());
    }
    Ok(Vec::new())
}

/// Plain-language labels for the metadata carriers a PDF declares, drawn
/// from the library's inspector plus our own incremental-history check.
fn pdf_items(source: &Path, data: &[u8]) -> Vec<String> {
    let (has_c2pa, _has_ai, findings, details) = pdf::inspect_pdf(source, data);
    let mut items = Vec::new();

    let info_keys: Vec<String> = details
        .get("structure")
        .and_then(|structure| structure.get("info_keys"))
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if !info_keys.is_empty() {
        items.push(format!("PDF document info ({})", info_keys.join(", ")));
    }

    let streams = details
        .get("structure")
        .and_then(|structure| structure.get("metadata_streams"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if streams == 1 {
        items.push("XMP metadata stream (edit history)".to_string());
    } else if streams > 1 {
        items.push(format!("{streams} XMP metadata streams (edit history)"));
    } else if findings
        .iter()
        .any(|finding| finding == "XMP packet present")
    {
        items.push("XMP packet".to_string());
    }

    if has_c2pa {
        items.push("C2PA provenance manifest".to_string());
    }
    if has_incremental_history(data) {
        items.push("an earlier document revision".to_string());
    }
    items
}

/// True when the byte stream holds more than one revision: a PDF is appended
/// to, so extra end-of-file markers or cross-reference pointers mean an
/// earlier document state (possibly with its own `/Info`) is still present.
fn has_incremental_history(data: &[u8]) -> bool {
    count_occurrences(data, b"%%EOF") > 1 || count_occurrences(data, b"startxref") > 1
}

/// Count non-overlapping occurrences of `needle` in `data`.
fn count_occurrences(data: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || data.len() < needle.len() {
        return 0;
    }
    data.windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Verify a scrubbed JPEG or PNG: re-parse it and confirm no metadata
/// carrier survived.
///
/// Two opinions are consulted. Our own framing walk is primary, because it
/// also parses the CRC-damaged files the salvage path produces. The surgery
/// library's inspector runs as a cross-check; its whole-file byte-scan hits
/// are ignored, because a marker byte sequence inside compressed image data
/// is a coincidence and pixel data is never modified. On the salvage path
/// the library cannot parse the file at all, so its "malformed" line is
/// expected and ignored as well.
fn verify_image_output(kind: ScrubFormat, out: &[u8], salvaged: bool) -> Result<(), ScrubError> {
    let residual = image_carriers(kind, out).ok_or_else(|| {
        ScrubError::VerificationFailed(format!(
            "the scrubbed output no longer parses as {}",
            kind.label()
        ))
    })?;
    if !residual.is_empty() {
        return Err(ScrubError::VerificationFailed(format!(
            "metadata survived the scrub: {}",
            residual.join(", ")
        )));
    }

    let (_format, _c2pa, _ai, findings) = inspect_bytes(out);
    let unexplained: Vec<&str> = findings
        .iter()
        .map(String::as_str)
        .filter(|finding| !finding.starts_with("byte-scan"))
        .filter(|finding| !(salvaged && finding.starts_with("malformed")))
        .collect();
    if !unexplained.is_empty() {
        return Err(ScrubError::VerificationFailed(format!(
            "post-scrub inspection still reports: {}",
            unexplained.join("; ")
        )));
    }
    Ok(())
}

/// Verify a scrubbed PDF by re-running the library's inspector on the
/// output: no `/Info` keys, no `/Metadata` streams, no XMP packet, no C2PA
/// manifest. This mirrors the scope of the library's own pre-write check.
fn verify_pdf_output(output: &Path, out: &[u8]) -> Result<(), ScrubError> {
    let (has_c2pa, _has_ai, findings, _details) = pdf::inspect_pdf(output, out);
    let residual: Vec<&str> = findings
        .iter()
        .map(String::as_str)
        .filter(|finding| {
            finding.starts_with("PDF /Info keys")
                || finding.starts_with("PDF /Metadata streams")
                || *finding == "XMP packet present"
                || finding.contains("C2PA")
        })
        .collect();
    if has_c2pa || !residual.is_empty() {
        return Err(ScrubError::VerificationFailed(format!(
            "metadata survived the rewrite: {}",
            residual.join("; ")
        )));
    }
    Ok(())
}

/// Write `bytes` to `path` through a sibling temp file plus rename, so a
/// crash mid-write never leaves a partial output behind. Used by the salvage
/// path; the surgery library writes atomically on its own.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ScrubError> {
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(format!(".gone-tmp-{}", std::process::id()));
    let tmp = PathBuf::from(tmp_name);
    if let Err(error) = fs::write(&tmp, bytes) {
        let _ = fs::remove_file(&tmp);
        return Err(ScrubError::Io(error));
    }
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(ScrubError::Io(error));
    }
    Ok(())
}

/// True when any of `needles` occurs in `haystack`, case-insensitively.
fn contains_any_ci(haystack: &[u8], needles: &[&[u8]]) -> bool {
    let lower = haystack.to_ascii_lowercase();
    needles.iter().any(|needle| {
        let needle = needle.to_ascii_lowercase();
        !needle.is_empty() && lower.windows(needle.len()).any(|window| window == needle)
    })
}

// ---------------------------------------------------------------------------
// JPEG segment walking
//
// The walker below reads marker framing only. It serves three callers: the
// pre-scrub scan that labels what a file carries, the salvage filter that
// rebuilds a damaged container byte-for-byte, and the post-scrub verifier.
// ---------------------------------------------------------------------------

/// One JPEG segment's marker and its whole byte range (prefix included).
struct JpegSegment {
    marker: u8,
    start: usize,
    end: usize,
}

/// Walk JPEG segment framing, stopping where the entropy-coded scan begins.
///
/// Returns the segments before the scan plus the offset of the opaque tail
/// (the SOS segment, scan data, EOI, and any trailing bytes), which callers
/// copy verbatim. `None` means the framing is broken beyond salvage. Noise
/// and fill bytes are skipped the way `img-parts` skips them, so damaged
/// files still walk as far as their markers allow.
fn walk_jpeg(data: &[u8]) -> Option<(Vec<JpegSegment>, usize)> {
    if !data.starts_with(JPEG_SOI) {
        return None;
    }
    let mut segments = Vec::new();
    let mut pos = JPEG_SOI.len();
    loop {
        while pos < data.len() && data[pos] != 0xFF {
            pos += 1; // noise between segments
        }
        let start = pos;
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1; // fill bytes still name one marker
        }
        if pos >= data.len() {
            return None; // ran out of bytes mid-marker: truncated
        }
        let marker = data[pos];
        pos += 1;
        match marker {
            0xD9 => {
                // EOI: keep it as a segment so the filter re-emits it.
                segments.push(JpegSegment {
                    marker,
                    start,
                    end: pos,
                });
                return Some((segments, pos));
            }
            0xDA => return Some((segments, start)), // SOS: opaque tail begins
            0x01 | 0xD0..=0xD8 => {
                // TEM, RSTn, and a stray SOI carry no length field.
                segments.push(JpegSegment {
                    marker,
                    start,
                    end: pos,
                });
            }
            _ => {
                if pos + 2 > data.len() {
                    return None;
                }
                let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                if length < 2 {
                    return None;
                }
                let end = pos.checked_add(length)?;
                if end > data.len() {
                    return None;
                }
                segments.push(JpegSegment { marker, start, end });
                pos = end;
            }
        }
        if pos >= data.len() {
            return None; // ended without a scan or EOI: truncated
        }
    }
}

/// The payload of a length-bearing segment (after marker and length field).
fn jpeg_payload<'a>(data: &'a [u8], segment: &JpegSegment) -> &'a [u8] {
    // Length-bearing segments always have end >= start + 4 by construction.
    &data[(segment.start + 4).min(segment.end)..segment.end]
}

/// The plain-language label for one metadata segment.
fn classify_jpeg_segment(marker: u8, payload: &[u8]) -> String {
    match marker {
        0xE1 if payload.starts_with(b"Exif\0\0") => "EXIF camera info".to_string(),
        0xE1 if XMP_APP1_PREFIXES
            .iter()
            .any(|prefix| payload.starts_with(prefix)) =>
        {
            "XMP edit history".to_string()
        }
        0xE1 => "JPEG APP1 metadata".to_string(),
        0xE2 if payload.starts_with(b"ICC_PROFILE") => "ICC color profile".to_string(),
        0xE2 => "JPEG APP2 metadata".to_string(),
        0xEB if contains_any_ci(payload, PROVENANCE_MARKERS) => {
            "C2PA provenance manifest (JPEG APP11)".to_string()
        }
        0xEB => "JPEG APP11 application data".to_string(),
        0xED if payload.starts_with(b"Photoshop 3.0") => "IPTC photo captions".to_string(),
        0xED => "JPEG APP13 metadata".to_string(),
        0xEE => "Adobe APP14 metadata".to_string(),
        0xFE => "JPEG comment".to_string(),
        other => format!("JPEG APP{} metadata", other - 0xE0),
    }
}

/// True for segments the scrub drops: every APPn except APP0, plus COM.
/// APP0 stays because it carries JFIF decoder compatibility data, matching
/// the surgery library's policy.
fn is_dropped_jpeg_segment(marker: u8) -> bool {
    matches!(marker, 0xE1..=0xEF | 0xFE)
}

/// Labels of every metadata carrier in a JPEG, or `None` when the framing
/// is too broken to walk.
fn jpeg_carriers(data: &[u8]) -> Option<Vec<String>> {
    let (segments, _tail) = walk_jpeg(data)?;
    let mut labels = Vec::new();
    for segment in &segments {
        if is_dropped_jpeg_segment(segment.marker) {
            labels.push(classify_jpeg_segment(
                segment.marker,
                jpeg_payload(data, segment),
            ));
        }
    }
    Some(labels)
}

/// Salvage filter: rebuild a JPEG without its metadata segments, copying
/// every kept byte (APP0, tables, the whole entropy-coded scan) verbatim.
fn filter_jpeg(data: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let (segments, tail_start) = walk_jpeg(data)?;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(JPEG_SOI);
    let mut labels = Vec::new();
    for segment in &segments {
        let whole = &data[segment.start..segment.end];
        if is_dropped_jpeg_segment(segment.marker) {
            labels.push(classify_jpeg_segment(
                segment.marker,
                jpeg_payload(data, segment),
            ));
        } else {
            out.extend_from_slice(whole);
        }
    }
    out.extend_from_slice(&data[tail_start..]);
    Some((out, labels))
}

// ---------------------------------------------------------------------------
// PNG chunk walking
// ---------------------------------------------------------------------------

/// One PNG chunk's type and its whole byte range (length and CRC included).
struct PngChunkSpan {
    kind: [u8; 4],
    start: usize,
    end: usize,
}

/// Walk PNG chunk framing. Returns the chunks plus the offset just past
/// IEND; anything after that offset is trailing data callers copy verbatim.
/// `None` means the framing is broken beyond salvage. CRCs are deliberately
/// not checked: the salvage filter exists for files whose CRCs are damaged,
/// and it copies them through unchanged.
fn walk_png(data: &[u8]) -> Option<(Vec<PngChunkSpan>, usize)> {
    if !data.starts_with(PNG_SIG) {
        return None;
    }
    let mut chunks = Vec::new();
    let mut pos = PNG_SIG.len();
    loop {
        let header_end = pos.checked_add(8)?;
        if header_end > data.len() {
            return None;
        }
        let length = u32::from_be_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        let kind: [u8; 4] = data[pos + 4..pos + 8].try_into().ok()?;
        let end = header_end.checked_add(length)?.checked_add(4)?;
        if end > data.len() {
            return None;
        }
        chunks.push(PngChunkSpan {
            kind,
            start: pos,
            end,
        });
        pos = end;
        if &kind == b"IEND" {
            return Some((chunks, pos));
        }
    }
}

/// True when a chunk type names a JUMBF/C2PA container convention.
fn is_c2pa_chunk_kind(kind: &[u8]) -> bool {
    matches!(kind, b"caBX" | b"juMB" | b"jumb") || kind.starts_with(b"c2")
}

/// True for chunks the scrub drops. Mirrors the surgery library's policy:
/// text and EXIF chunks, the `tIME` timestamp, C2PA containers, and any
/// unknown ancillary chunk whose type or payload names a provenance marker.
fn is_dropped_png_chunk(kind: &[u8; 4], payload: &[u8]) -> bool {
    if matches!(&kind[..], b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"tIME") {
        return true;
    }
    if is_c2pa_chunk_kind(kind) {
        return true;
    }
    if PNG_STRUCTURAL_CHUNKS.contains(&&kind[..]) {
        return false;
    }
    let mut probe = kind.to_vec();
    probe.extend_from_slice(payload);
    contains_any_ci(&probe, PROVENANCE_MARKERS)
}

/// The keyword of a `tEXt`/`zTXt` chunk, for a friendlier label.
fn png_text_keyword(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(payload.len());
    let keyword = &payload[..end];
    if keyword.is_empty() || keyword.len() > 80 {
        return None;
    }
    let text = String::from_utf8_lossy(keyword);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(40).collect())
}

/// The plain-language label for one dropped chunk.
fn classify_png_chunk(kind: &[u8; 4], payload: &[u8]) -> String {
    if &kind[..] == b"tEXt" {
        return match png_text_keyword(payload) {
            Some(keyword) => format!("PNG text metadata (\"{keyword}\")"),
            None => "PNG text metadata".to_string(),
        };
    }
    if &kind[..] == b"zTXt" {
        return match png_text_keyword(payload) {
            Some(keyword) => format!("PNG compressed text metadata (\"{keyword}\")"),
            None => "PNG compressed text metadata".to_string(),
        };
    }
    if &kind[..] == b"iTXt" {
        if payload.starts_with(XMP_ITXT_KEYWORD) {
            return "XMP edit history".to_string();
        }
        return "PNG international text metadata".to_string();
    }
    if &kind[..] == b"eXIf" {
        return "EXIF camera info".to_string();
    }
    if &kind[..] == b"tIME" {
        return "PNG timestamp".to_string();
    }
    if is_c2pa_chunk_kind(kind) {
        return "C2PA provenance manifest".to_string();
    }
    format!("PNG metadata chunk ({})", String::from_utf8_lossy(kind))
}

/// The payload of a chunk (between the type field and the CRC).
fn png_payload<'a>(data: &'a [u8], chunk: &PngChunkSpan) -> &'a [u8] {
    &data[chunk.start + 8..chunk.end - 4]
}

/// Labels of every metadata carrier in a PNG, or `None` when the framing is
/// too broken to walk.
fn png_carriers(data: &[u8]) -> Option<Vec<String>> {
    let (chunks, _tail) = walk_png(data)?;
    let mut labels = Vec::new();
    for chunk in &chunks {
        let payload = png_payload(data, chunk);
        if is_dropped_png_chunk(&chunk.kind, payload) {
            labels.push(classify_png_chunk(&chunk.kind, payload));
        }
    }
    Some(labels)
}

/// Salvage filter: rebuild a PNG without its metadata chunks, copying every
/// kept chunk verbatim, length and (possibly damaged) CRC included.
fn filter_png(data: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let (chunks, tail_start) = walk_png(data)?;
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(PNG_SIG);
    let mut labels = Vec::new();
    for chunk in &chunks {
        let whole = &data[chunk.start..chunk.end];
        let payload = png_payload(data, chunk);
        if is_dropped_png_chunk(&chunk.kind, payload) {
            labels.push(classify_png_chunk(&chunk.kind, payload));
        } else {
            out.extend_from_slice(whole);
        }
    }
    out.extend_from_slice(&data[tail_start..]);
    Some((out, labels))
}

/// Labels of every metadata carrier in a JPEG or PNG, shared by the
/// pre-scrub scan and the post-scrub verifier.
fn image_carriers(kind: ScrubFormat, data: &[u8]) -> Option<Vec<String>> {
    match kind {
        ScrubFormat::Jpeg => jpeg_carriers(data),
        ScrubFormat::Png => png_carriers(data),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // Fixture builders
    // -----------------------------------------------------------------

    /// One length-prefixed JPEG segment.
    fn jpeg_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// SOI + APP0(JFIF) + APP1(EXIF) + DQT + SOF0 + SOS + scan + EOI.
    fn synthetic_jpeg() -> Vec<u8> {
        let mut out = JPEG_SOI.to_vec();
        out.extend_from_slice(&jpeg_segment(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
        out.extend_from_slice(&jpeg_segment(0xE1, b"Exif\0\0Canon EOS 80D, ISO 200"));
        out.extend_from_slice(&jpeg_segment(
            0xDB,
            &[
                0x00, 0x10, 0x0B, 0x0C, 0x0E, 0x0C, 0x0A, 0x10, 0x0E, 0x0D, 0x0E, 0x12, 0x11, 0x10,
                0x13, 0x18,
            ],
        ));
        out.extend_from_slice(&jpeg_segment(
            0xC0,
            b"\x08\x00\x10\x00\x10\x01\x01\x01\x11\x00",
        ));
        out.extend_from_slice(&jpeg_segment(0xDA, b"\x01\x01\x00"));
        out.extend_from_slice(b"scan-data-\x00\x3f\x11");
        out.extend_from_slice(b"\xff\xd9");
        out
    }

    /// The same shape without the APP1 EXIF segment.
    fn clean_jpeg() -> Vec<u8> {
        let mut out = JPEG_SOI.to_vec();
        out.extend_from_slice(&jpeg_segment(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
        out.extend_from_slice(&jpeg_segment(0xDB, &[0x00, 0x10, 0x0B, 0x0C]));
        out.extend_from_slice(&jpeg_segment(
            0xC0,
            b"\x08\x00\x10\x00\x10\x01\x01\x01\x11\x00",
        ));
        out.extend_from_slice(&jpeg_segment(0xDA, b"\x01\x01\x00"));
        out.extend_from_slice(b"scan-data");
        out.extend_from_slice(b"\xff\xd9");
        out
    }

    /// One PNG chunk with an explicit CRC (tests choose valid or dummy).
    fn png_chunk(kind: &[u8; 4], payload: &[u8], crc: u32) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out.extend_from_slice(&crc.to_be_bytes());
        out
    }

    /// The real CRC for a chunk, via the dependency's public helper.
    fn good_crc(kind: &[u8; 4], payload: &[u8]) -> u32 {
        let mut data = kind.to_vec();
        data.extend_from_slice(payload);
        prose_sanitiser_media::image::png::crc32(&data)
    }

    /// Signature + IHDR + tEXt + IDAT + IEND. With `valid_crcs` set, every
    /// chunk carries a correct CRC; otherwise every CRC is a dummy zero,
    /// which the strict parser rejects but the salvage filter walks fine.
    fn synthetic_png(valid_crcs: bool) -> Vec<u8> {
        let ihdr: &[u8] = b"\x00\x00\x00\x02\x00\x00\x00\x02\x08\x02\x00\x00\x00";
        let text: &[u8] = b"Author\0Jane Doe";
        let idat: &[u8] = b"tiny-image-bytes";
        let crc = |kind: &[u8; 4], payload: &[u8]| {
            if valid_crcs {
                good_crc(kind, payload)
            } else {
                0
            }
        };
        let mut out = PNG_SIG.to_vec();
        out.extend_from_slice(&png_chunk(b"IHDR", ihdr, crc(b"IHDR", ihdr)));
        out.extend_from_slice(&png_chunk(b"tEXt", text, crc(b"tEXt", text)));
        out.extend_from_slice(&png_chunk(b"IDAT", idat, crc(b"IDAT", idat)));
        out.extend_from_slice(&png_chunk(b"IEND", b"", crc(b"IEND", b"")));
        out
    }

    /// A minimal one-page PDF with a correct cross-reference table, with or
    /// without an `/Info` dictionary carrying provenance keys.
    fn synthetic_pdf(with_info: bool) -> Vec<u8> {
        let mut objects = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>".to_string(),
        ];
        if with_info {
            objects.push(
                "<< /Title (Secret Title) /Author (Jane Doe) /Creator (SpyApp 1.0) >>".to_string(),
            );
        }
        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (index, body) in objects.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", index + 1).as_bytes());
        }
        let xref_pos = out.len();
        let count = objects.len() + 1;
        out.extend_from_slice(format!("xref\n0 {count}\n").as_bytes());
        out.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        let info_ref = if with_info { " /Info 4 0 R" } else { "" };
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {count} /Root 1 0 R{info_ref} >>\nstartxref\n{xref_pos}\n%%EOF\n"
            )
            .as_bytes(),
        );
        out
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    // -----------------------------------------------------------------
    // Detection
    // -----------------------------------------------------------------

    #[test]
    fn detect_uses_magic_bytes_not_the_extension() {
        let dir = tempfile::tempdir().unwrap();

        let disguised_jpeg = dir.path().join("notes.txt");
        fs::write(&disguised_jpeg, synthetic_jpeg()).unwrap();
        assert_eq!(detect(&disguised_jpeg), ScrubFormat::Jpeg);

        let disguised_png = dir.path().join("photo.jpg");
        fs::write(&disguised_png, synthetic_png(true)).unwrap();
        assert_eq!(detect(&disguised_png), ScrubFormat::Png);

        let disguised_pdf = dir.path().join("image.png");
        fs::write(&disguised_pdf, synthetic_pdf(false)).unwrap();
        assert_eq!(detect(&disguised_pdf), ScrubFormat::Pdf);

        let text = dir.path().join("plain.txt");
        fs::write(&text, b"just some words").unwrap();
        assert_eq!(detect(&text), ScrubFormat::Unknown);

        let empty = dir.path().join("empty.bin");
        fs::write(&empty, b"").unwrap();
        assert_eq!(detect(&empty), ScrubFormat::Unknown);

        let missing = dir.path().join("not-there.jpg");
        assert_eq!(detect(&missing), ScrubFormat::Unknown);
    }

    // -----------------------------------------------------------------
    // JPEG
    // -----------------------------------------------------------------

    #[test]
    fn jpeg_scrub_strips_exif_and_keeps_image_data() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("photo.jpg");
        let output = dir.path().join("clean.jpg");
        let original = synthetic_jpeg();
        fs::write(&source, &original).unwrap();

        let report = scrub_file(&source, &output).unwrap();

        assert_eq!(report.format, ScrubFormat::Jpeg);
        assert_eq!(report.items_removed, vec!["EXIF camera info".to_string()]);
        assert_eq!(
            report.bytes_removed,
            (original.len() - fs::metadata(&output).unwrap().len() as usize) as u64
        );
        assert!(report.bytes_removed > 0);
        assert_eq!(report.output_path, output);

        let cleaned = fs::read(&output).unwrap();
        assert!(cleaned.starts_with(b"\xff\xd8\xff\xe0"), "APP0 stays first");
        assert!(contains(&cleaned, b"JFIF"), "APP0/JFIF is kept");
        assert!(contains(&cleaned, &[0xFF, 0xDB]), "DQT is kept");
        assert!(contains(&cleaned, &[0xFF, 0xC0]), "SOF0 is kept");
        assert!(contains(&cleaned, b"scan-data"), "the scan is untouched");
        assert!(cleaned.ends_with(b"\xff\xd9"), "EOI intact");
        assert!(!contains(&cleaned, b"Exif"), "EXIF segment is gone");
        assert!(!contains(&cleaned, b"Canon"), "EXIF payload is gone");
        assert_eq!(
            fs::read(&source).unwrap(),
            original,
            "the source file must be byte-for-byte untouched"
        );

        let summary = report.summary_line();
        assert!(
            summary.contains("Removed 1 hidden metadata block (EXIF camera info) from photo.jpg"),
            "summary was: {summary}"
        );
        assert!(summary.ends_with("Original untouched."));
    }

    #[test]
    fn jpeg_with_no_metadata_is_copied_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("clean.jpg");
        let output = dir.path().join("out.jpg");
        let original = clean_jpeg();
        fs::write(&source, &original).unwrap();

        let report = scrub_file(&source, &output).unwrap();

        assert!(report.items_removed.is_empty());
        assert_eq!(report.bytes_removed, 0);
        assert_eq!(fs::read(&output).unwrap(), original);
        assert_eq!(
            report.summary_line(),
            "No hidden metadata found in clean.jpg. Original untouched."
        );
    }

    #[test]
    fn jpeg_fallback_filter_drops_metadata_segments_and_keeps_the_scan() {
        // APP13 IPTC and COM ride alongside APP0 and the image tables.
        let mut data = JPEG_SOI.to_vec();
        data.extend_from_slice(&jpeg_segment(0xE0, b"JFIF\0\x01\x02\0\0\x01\0\x01\0\0"));
        data.extend_from_slice(&jpeg_segment(0xED, b"Photoshop 3.0\0caption-by-stringer"));
        data.extend_from_slice(&jpeg_segment(0xFE, b"shot on assignment"));
        data.extend_from_slice(&jpeg_segment(0xDB, &[0x00, 0x10]));
        data.extend_from_slice(&jpeg_segment(0xDA, b"\x01\x01\x00"));
        data.extend_from_slice(b"scan-data");
        data.extend_from_slice(b"\xff\xd9");

        let (filtered, labels) = filter_jpeg(&data).unwrap();
        assert_eq!(
            labels,
            vec![
                "IPTC photo captions".to_string(),
                "JPEG comment".to_string()
            ]
        );
        assert!(contains(&filtered, b"JFIF"));
        assert!(contains(&filtered, &[0xFF, 0xDB]));
        assert!(contains(&filtered, b"scan-data"));
        assert!(filtered.ends_with(b"\xff\xd9"));
        assert!(!contains(&filtered, b"Photoshop"));
        assert!(!contains(&filtered, b"assignment"));
    }

    // -----------------------------------------------------------------
    // PNG
    // -----------------------------------------------------------------

    #[test]
    fn png_scrub_strips_text_chunks_and_keeps_image_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("image.png");
        let output = dir.path().join("clean.png");
        let original = synthetic_png(true);
        fs::write(&source, &original).unwrap();

        let report = scrub_file(&source, &output).unwrap();

        assert_eq!(report.format, ScrubFormat::Png);
        assert_eq!(
            report.items_removed,
            vec!["PNG text metadata (\"Author\")".to_string()]
        );

        let cleaned = fs::read(&output).unwrap();
        assert!(cleaned.starts_with(PNG_SIG));
        assert!(contains(&cleaned, b"IHDR"));
        assert!(contains(&cleaned, b"IDAT"));
        assert!(contains(&cleaned, b"IEND"));
        assert!(contains(&cleaned, b"tiny-image-bytes"));
        assert!(!contains(&cleaned, b"tEXt"), "the text chunk is gone");
        assert!(!contains(&cleaned, b"Jane Doe"), "the text payload is gone");
        assert!(!contains(&cleaned, b"Author"));
        assert_eq!(fs::read(&source).unwrap(), original);
    }

    #[test]
    fn png_with_broken_crcs_is_salvaged_by_raw_chunk_filtering() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("damaged.png");
        let output = dir.path().join("clean.png");
        let original = synthetic_png(false);
        fs::write(&source, &original).unwrap();

        // The strict parser refuses dummy CRCs, so this exercises the
        // salvage filter: it must strip the text chunk and copy every kept
        // chunk verbatim, dummy CRC included.
        let report = scrub_file(&source, &output).unwrap();
        assert_eq!(
            report.items_removed,
            vec!["PNG text metadata (\"Author\")".to_string()]
        );

        let cleaned = fs::read(&output).unwrap();
        assert!(!contains(&cleaned, b"tEXt"));
        assert!(!contains(&cleaned, b"Jane Doe"));

        let (source_chunks, _) = walk_png(&original).unwrap();
        let (cleaned_chunks, _) = walk_png(&cleaned).unwrap();
        assert_eq!(cleaned_chunks.len(), source_chunks.len() - 1);
        let source_ihdr = &original[source_chunks[0].start..source_chunks[0].end];
        let cleaned_ihdr = &cleaned[cleaned_chunks[0].start..cleaned_chunks[0].end];
        assert_eq!(
            source_ihdr, cleaned_ihdr,
            "a kept chunk is copied byte-for-byte, CRC included"
        );
        assert!(
            cleaned_ihdr.ends_with(&[0, 0, 0, 0]),
            "the dummy CRC rides through verbatim"
        );
        assert_eq!(fs::read(&source).unwrap(), original);
    }

    // -----------------------------------------------------------------
    // PDF
    // -----------------------------------------------------------------

    #[test]
    fn pdf_info_dictionary_is_removed_by_full_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("document.pdf");
        let output = dir.path().join("clean.pdf");
        let original = synthetic_pdf(true);
        fs::write(&source, &original).unwrap();

        let report = scrub_file(&source, &output).unwrap();

        assert_eq!(report.format, ScrubFormat::Pdf);
        assert_eq!(
            report.items_removed,
            vec!["PDF document info (Author, Creator, Title)".to_string()]
        );

        let cleaned = fs::read(&output).unwrap();
        assert!(cleaned.starts_with(b"%PDF"));
        assert!(!contains(&cleaned, b"Jane Doe"));
        assert!(!contains(&cleaned, b"Secret Title"));
        assert!(!contains(&cleaned, b"SpyApp"));
        assert!(report.bytes_removed > 0);
        assert_eq!(fs::read(&source).unwrap(), original);

        let summary = report.summary_line();
        assert!(
            summary.contains("PDF document info"),
            "summary was: {summary}"
        );
        assert!(summary.ends_with("Original untouched."));
    }

    #[test]
    fn pdf_without_metadata_is_copied_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("plain.pdf");
        let output = dir.path().join("out.pdf");
        let original = synthetic_pdf(false);
        fs::write(&source, &original).unwrap();

        let report = scrub_file(&source, &output).unwrap();

        assert!(report.items_removed.is_empty());
        assert_eq!(report.bytes_removed, 0);
        assert_eq!(fs::read(&output).unwrap(), original);
    }

    // -----------------------------------------------------------------
    // Refusals and error paths
    // -----------------------------------------------------------------

    #[test]
    fn unknown_format_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.bin");
        for (name, bytes) in [
            ("gif.bin", &b"GIF89a not a real gif"[..]),
            ("text.bin", b"plain words, no magic"),
            ("tiny.bin", b"\xff\xd8"),
            ("empty.bin", b""),
        ] {
            let source = dir.path().join(name);
            fs::write(&source, bytes).unwrap();
            let error = scrub_file(&source, &output).unwrap_err();
            assert!(
                matches!(error, ScrubError::UnsupportedFormat),
                "{name} produced {error}"
            );
            assert!(!output.exists(), "no output may be left behind");
        }
    }

    #[test]
    fn scrubbing_a_file_onto_itself_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("photo.jpg");
        let original = synthetic_jpeg();
        fs::write(&source, &original).unwrap();

        let error = scrub_file(&source, &source).unwrap_err();
        assert!(matches!(error, ScrubError::SamePath));

        // An alias that canonicalizes to the same file is refused too.
        let alias = dir.path().join(".").join("photo.jpg");
        let error = scrub_file(&source, &alias).unwrap_err();
        assert!(matches!(error, ScrubError::SamePath));

        assert_eq!(fs::read(&source).unwrap(), original);
    }

    #[test]
    fn missing_source_is_an_io_error_not_a_format_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.jpg");
        let output = dir.path().join("out.jpg");
        let error = scrub_file(&missing, &output).unwrap_err();
        assert!(matches!(error, ScrubError::Io(_)));
        assert!(!output.exists());
    }

    // -----------------------------------------------------------------
    // The convenience wrapper and the summary line
    // -----------------------------------------------------------------

    #[test]
    fn in_place_clone_writes_a_scrubbed_sibling_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("photo.jpeg");
        let original = synthetic_jpeg();
        fs::write(&source, &original).unwrap();

        let report = scrub_in_place_clone(&source).unwrap();
        let expected = dir.path().join("photo.scrubbed.jpeg");
        assert_eq!(report.output_path, expected);
        assert!(expected.exists());
        assert_eq!(report.items_removed, vec!["EXIF camera info".to_string()]);
        assert_eq!(fs::read(&source).unwrap(), original, "source untouched");

        // Scrubbing the scrubbed copy finds nothing left to remove.
        let second = scrub_in_place_clone(&report.output_path).unwrap();
        assert!(second.items_removed.is_empty());
        assert_eq!(
            fs::read(&report.output_path).unwrap(),
            fs::read(&second.output_path).unwrap()
        );
    }

    #[test]
    fn scrubbed_path_inserts_the_marker_before_the_extension() {
        assert_eq!(
            scrubbed_path(Path::new("a/b/photo.jpg")),
            PathBuf::from("a/b/photo.scrubbed.jpg")
        );
        assert_eq!(
            scrubbed_path(Path::new("README")),
            PathBuf::from("README.scrubbed")
        );
    }

    #[test]
    fn summary_line_pluralizes_and_caps_the_list() {
        let report = ScrubReport {
            format: ScrubFormat::Jpeg,
            bytes_removed: 100,
            items_removed: vec!["one".to_string()],
            output_path: PathBuf::from("out.jpg"),
            source_path: PathBuf::from("x.jpg"),
        };
        assert_eq!(
            report.summary_line(),
            "Removed 1 hidden metadata block (one) from x.jpg. Original untouched."
        );

        let report = ScrubReport {
            items_removed: vec!["a".to_string(), "b".to_string()],
            ..report.clone()
        };
        assert!(
            report
                .summary_line()
                .contains("Removed 2 hidden metadata blocks (a and b)")
        );

        let report = ScrubReport {
            items_removed: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            ..report.clone()
        };
        assert!(report.summary_line().contains("(a, b, and c)"));

        let report = ScrubReport {
            items_removed: (1..=5).map(|n| format!("item{n}")).collect(),
            ..report
        };
        assert!(
            report
                .summary_line()
                .contains("Removed 5 hidden metadata blocks (item1, item2, item3, and 2 more)")
        );
    }
}
