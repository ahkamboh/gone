//! Post-sanitize verification and signed certificates.
//!
//! After an erase, [`rescan`] reads the target again and compares what is
//! left against an optional earlier scan. The result is a [`Verification`]:
//! before and after counters, a media profile, and a plain-language
//! outcome. A [`Certificate`] wraps that verification in a signed,
//! tamper-evident JSON document.
//!
//! ## Tamper evidence
//!
//! The signed payload (schema version, tool name and version, and the
//! verification) is serialized to JSON with serde_json's deterministic key
//! ordering, hashed with BLAKE3, and the 32 hash bytes are signed with
//! ed25519. The certificate embeds the payload, the hash as hex, the
//! signature as base64, and the public key as base64, so anyone can verify
//! the document with [`Certificate::verify_signature`] and nothing else.
//!
//! ## What a certificate proves, and what it does not
//!
//! Certificates are self-signed. A valid signature proves the document was
//! not modified after it was created and that the signer held the matching
//! private key. It does not prove who the signer was, and it does not prove
//! the timestamp, which comes from the local clock. A trusted timestamping
//! service and a public key registry are planned as a phase-2 item.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::io::EvidenceSource;
use crate::report::{Category, ScanSummary};
use crate::scan::scan_source;
use crate::trimdetect::{self, NistCategory};

/// Version of the certificate JSON layout. Bump when the document changes
/// in a way older readers cannot ignore.
pub const SCHEMA_VERSION: u32 = 1;

/// Tool name recorded in every certificate.
const TOOL_NAME: &str = "gone";

/// A serializable snapshot of scan counters, before or after erasure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total bytes read.
    pub bytes_scanned: u64,
    /// Blocks reading as all zero.
    pub blocks_empty: u64,
    /// Blocks reading as a single repeated non-zero byte.
    pub blocks_fill: u64,
    /// Blocks reading as random or encrypted data.
    pub blocks_random: u64,
    /// Blocks reading as structured, potentially recoverable data.
    pub blocks_structured: u64,
    /// Recoverable file signatures found in structured blocks.
    pub hits_total: u64,
    /// Recoverable hits grouped by category: "photo", "document",
    /// "archive", "database", or "other item".
    pub hits_by_category: BTreeMap<String, u64>,
}

impl ScanStats {
    /// Snapshot the counters of a [`ScanSummary`] into a serializable form.
    pub fn from_summary(summary: &ScanSummary) -> Self {
        let hits_by_category = summary
            .hits_by_category()
            .iter()
            .map(|(category, &count)| (category_key(*category).to_string(), count))
            .collect();
        Self {
            bytes_scanned: summary.bytes_scanned,
            blocks_empty: summary.blocks_empty,
            blocks_fill: summary.blocks_fill,
            blocks_random: summary.blocks_random,
            blocks_structured: summary.blocks_structured,
            hits_total: summary.hit_count() as u64,
            hits_by_category,
        }
    }
}

/// The verdict of a before/after comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// No recoverable items remain, and any that were there are gone.
    Clean,
    /// Fewer recoverable items remain than before, but some are left.
    Improved,
    /// The recoverable item count did not change, or no baseline exists
    /// and items remain.
    Unchanged,
    /// More recoverable items were found after the erase than before.
    Worse,
}

impl Outcome {
    /// Capitalized label for headings and banners.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Clean => "Clean",
            Outcome::Improved => "Improved",
            Outcome::Unchanged => "Unchanged",
            Outcome::Worse => "Worse",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The result of a post-erase verification pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    /// Name of the target that was rescanned (path or adapter description).
    pub target: String,
    /// When the rescan ran, in unix seconds.
    pub timestamp: u64,
    /// Block size the rescan used.
    pub block_size: u64,
    /// Counters from the pre-erase scan, when one was supplied.
    pub before: Option<ScanStats>,
    /// Counters from the post-erase rescan.
    pub after: ScanStats,
    /// One-line description of the media under the target.
    pub media_profile: String,
    /// NIST SP 800-88 category the overwrite achieves on this media:
    /// "Clear", "Purge", or "Destroy".
    pub nist_category: String,
    /// Computed verdict of the before/after comparison.
    pub outcome: Outcome,
    /// The verdict as one plain-language sentence.
    pub outcome_sentence: String,
}

/// Rescan `source` after an erase and build the before/after delta.
///
/// `before` is the summary captured before the erase, when one exists.
/// The media profile is a best-effort probe of the storage under the
/// source name: for a device or file path it describes that volume, and
/// for synthetic or in-memory sources it degrades to unknown values.
pub fn rescan(
    source: &mut EvidenceSource,
    block_size: u64,
    before: Option<&ScanSummary>,
) -> io::Result<Verification> {
    let after = scan_source(source, block_size)?;
    let media = trimdetect::profile(Path::new(source.name()));
    let guidance = trimdetect::guidance(&media);
    let before_stats = before.map(ScanStats::from_summary);
    let after_stats = ScanStats::from_summary(&after);
    let (outcome, outcome_sentence) = evaluate(before_stats.as_ref(), &after_stats);
    Ok(Verification {
        target: source.name().to_string(),
        timestamp: unix_now(),
        block_size,
        before: before_stats,
        after: after_stats,
        media_profile: media.to_string(),
        nist_category: nist_category_label(guidance.overwrite_category).to_string(),
        outcome,
        outcome_sentence,
    })
}

/// An ed25519 keypair for signing certificates, generated from operating
/// system randomness. The private key never leaves this value and is
/// zeroized on drop by ed25519-dalek.
pub struct SigningKeypair {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl SigningKeypair {
    /// Generate a fresh keypair from OS randomness.
    ///
    /// Panics only if the operating system has no randomness source, which
    /// cannot happen on any supported platform after boot.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("operating system randomness is unavailable");
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// The public half of the keypair.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The public half of the keypair, base64 encoded for embedding.
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.verifying.to_bytes())
    }
}

/// A signed, tamper-evident JSON certificate for one [`Verification`].
///
/// `payload_hash` is the hex BLAKE3 hash of the canonical payload JSON
/// (schema version, tool name and version, and the verification).
/// `signature` is the base64 ed25519 signature over those 32 hash bytes.
/// `public_key` is the base64 verifying key, so the document verifies
/// itself with no outside input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    /// Certificate JSON layout version, see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Tool name, "gone".
    pub tool: String,
    /// Tool version, from `CARGO_PKG_VERSION`.
    pub tool_version: String,
    /// The verification this certificate attests to.
    pub verification: Verification,
    /// Hex BLAKE3 hash of the canonical payload JSON.
    pub payload_hash: String,
    /// Base64 ed25519 signature over the 32 hash bytes.
    pub signature: String,
    /// Base64 ed25519 public key matching the signature.
    pub public_key: String,
}

/// The signed part of a [`Certificate`]. Serializing this struct is what
/// gets hashed, so field order here is part of the schema.
#[derive(Serialize)]
struct Payload<'a> {
    schema_version: u32,
    tool: &'a str,
    tool_version: &'a str,
    verification: &'a Verification,
}

impl Certificate {
    /// Sign a verification with `key`, producing a self-contained
    /// tamper-evident certificate.
    pub fn sign(verification: &Verification, key: &SigningKeypair) -> Certificate {
        let payload = Payload {
            schema_version: SCHEMA_VERSION,
            tool: TOOL_NAME,
            tool_version: env!("CARGO_PKG_VERSION"),
            verification,
        };
        let canonical =
            serde_json::to_string(&payload).expect("verification payloads always serialize");
        let hash = blake3::hash(canonical.as_bytes());
        let signature = key.signing.sign(hash.as_bytes());
        Certificate {
            schema_version: SCHEMA_VERSION,
            tool: TOOL_NAME.to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            verification: verification.clone(),
            payload_hash: hash.to_hex().to_string(),
            signature: BASE64.encode(signature.to_bytes()),
            public_key: key.public_key_base64(),
        }
    }

    /// The certificate as pretty-printed JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Check the certificate against its own embedded public key.
    ///
    /// Returns true only when the payload still hashes to `payload_hash`
    /// and the signature over those hash bytes verifies. This proves the
    /// document was not modified after signing; because the certificate is
    /// self-signed, it says nothing about who signed it.
    pub fn verify_signature(&self) -> bool {
        let Ok(canonical) = serde_json::to_string(&self.payload()) else {
            return false;
        };
        let hash = blake3::hash(canonical.as_bytes());
        if hash.to_hex().to_string() != self.payload_hash {
            return false;
        }
        let Some(verifying_key) = decode_verifying_key(&self.public_key) else {
            return false;
        };
        let Some(signature) = decode_signature(&self.signature) else {
            return false;
        };
        verifying_key.verify(hash.as_bytes(), &signature).is_ok()
    }

    /// Write `gone-certificate-<timestamp>.json` and
    /// `gone-certificate-<timestamp>.txt` into `dir`, creating it if
    /// needed. Returns the paths written, JSON first.
    pub fn write_files(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        std::fs::create_dir_all(dir)?;
        let stem = format!("gone-certificate-{}", self.verification.timestamp);
        let json_path = dir.join(format!("{stem}.json"));
        let txt_path = dir.join(format!("{stem}.txt"));
        let mut json = self.to_json()?;
        json.push('\n');
        std::fs::write(&json_path, json)?;
        std::fs::write(&txt_path, self.render_text())?;
        Ok(vec![json_path, txt_path])
    }

    /// Render the certificate as plain human-readable text.
    pub fn render_text(&self) -> String {
        let mut text = self.text_lines().join("\n");
        text.push('\n');
        text
    }

    /// Render the certificate summary as a minimal single-page PDF using
    /// only the built-in Helvetica core font. The PDF is a convenience
    /// copy for humans: the JSON file stays the canonical, verifiable
    /// form. Non-ASCII characters are replaced with `?`.
    pub fn to_pdf_bytes(&self) -> Vec<u8> {
        let mut lines = vec!["gone verification certificate".to_string()];
        for line in self.text_lines().into_iter().skip(1) {
            if line.is_empty() {
                lines.push(String::new());
            } else {
                lines.extend(wrap_line(&line, 92));
            }
        }
        build_pdf(&lines)
    }

    /// Write `gone-certificate-<timestamp>.pdf` into `dir`, creating it if
    /// needed. Returns the path written.
    pub fn write_pdf(&self, dir: &Path) -> io::Result<PathBuf> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!(
            "gone-certificate-{}.pdf",
            self.verification.timestamp
        ));
        std::fs::write(&path, self.to_pdf_bytes())?;
        Ok(path)
    }

    /// The signed payload, reconstructed from the certificate fields.
    fn payload(&self) -> Payload<'_> {
        Payload {
            schema_version: self.schema_version,
            tool: &self.tool,
            tool_version: &self.tool_version,
            verification: &self.verification,
        }
    }

    /// The lines shared by the text rendering and the PDF.
    fn text_lines(&self) -> Vec<String> {
        let v = &self.verification;
        let mut lines = vec![
            "gone verification certificate".to_string(),
            String::new(),
            format!("Tool: {} {}", self.tool, self.tool_version),
            format!("Target: {}", v.target),
            format!(
                "Timestamp: {} (unix {})",
                format_unix_utc(v.timestamp),
                v.timestamp
            ),
            format!("Scan block size: {} bytes", commafy(v.block_size)),
            format!("Media: {}", v.media_profile),
            format!("NIST SP 800-88 category: {}", v.nist_category),
            String::new(),
            format!("Outcome: {}", v.outcome.label()),
            v.outcome_sentence.clone(),
            String::new(),
        ];
        if let Some(before) = &v.before {
            lines.push("Before scan:".to_string());
            lines.push(format!(
                "  Bytes scanned: {}",
                commafy(before.bytes_scanned)
            ));
            lines.push(format!("  {}", block_line(before)));
            lines.push(format!("  {}", items_line(before)));
            lines.push(String::new());
        }
        lines.push("After scan:".to_string());
        lines.push(format!(
            "  Bytes scanned: {}",
            commafy(v.after.bytes_scanned)
        ));
        lines.push(format!("  {}", block_line(&v.after)));
        lines.push(format!("  {}", items_line(&v.after)));
        lines.push(String::new());
        lines.push(format!("Payload hash (BLAKE3): {}", self.payload_hash));
        lines.push(format!("Signature (ed25519): {}", self.signature));
        lines.push(format!("Public key (ed25519): {}", self.public_key));
        lines.push(String::new());
        lines.push(
            "This certificate is self-signed. It proves this file was not modified after"
                .to_string(),
        );
        lines.push(
            "creation, not who created it or when. A timestamping and public key registry"
                .to_string(),
        );
        lines.push("service is planned as a phase-2 item.".to_string());
        lines
    }
}

/// Decide the outcome and write the one-sentence verdict.
fn evaluate(before: Option<&ScanStats>, after: &ScanStats) -> (Outcome, String) {
    let a = after.hits_total;
    match before {
        Some(b) if b.hits_total > 0 && a == 0 => {
            let b_total = commafy(b.hits_total);
            (
                Outcome::Clean,
                format!(
                    "Before: {b_total} recoverable items. After: 0. \
                     All recoverable deleted data is gone."
                ),
            )
        }
        Some(b) if b.hits_total == 0 && a == 0 => (
            Outcome::Clean,
            "Before: 0 recoverable items. After: 0. The scanned space was already clean."
                .to_string(),
        ),
        None if a == 0 => (
            Outcome::Clean,
            "After-scan found no recoverable items. The scanned space reads as clean.".to_string(),
        ),
        None => {
            let a_total = commafy(a);
            let breakdown = category_breakdown(after);
            (
                Outcome::Unchanged,
                format!(
                    "{a_total} recoverable items found after erasure ({breakdown}). \
                     No earlier scan was supplied, so no before-and-after comparison \
                     is possible."
                ),
            )
        }
        Some(b) if a < b.hits_total => {
            let b_total = commafy(b.hits_total);
            let a_total = commafy(a);
            let breakdown = category_breakdown(after);
            (
                Outcome::Improved,
                format!(
                    "Before: {b_total} recoverable items. After: {a_total} ({breakdown}). \
                     Fewer recoverable items remain, but some deleted data is still \
                     recoverable."
                ),
            )
        }
        Some(b) if a == b.hits_total => {
            let b_total = commafy(b.hits_total);
            let breakdown = category_breakdown(after);
            (
                Outcome::Unchanged,
                format!(
                    "Before: {b_total} recoverable items. After: {b_total} ({breakdown}). \
                     The erase did not reduce the recoverable data."
                ),
            )
        }
        Some(b) => {
            let b_total = commafy(b.hits_total);
            let a_total = commafy(a);
            let breakdown = category_breakdown(after);
            (
                Outcome::Worse,
                format!(
                    "Before: {b_total} recoverable items. After: {a_total} ({breakdown}). \
                     More recoverable items were found after the erase than before. \
                     Recheck the target and erase again."
                ),
            )
        }
    }
}

/// Stable JSON key for a report category, in singular form.
fn category_key(category: Category) -> &'static str {
    match category {
        Category::Photos => "photo",
        Category::Documents => "document",
        Category::Archives => "archive",
        Category::Databases => "database",
        Category::Other => "other item",
    }
}

/// Display label for a NIST SP 800-88 category.
fn nist_category_label(category: NistCategory) -> &'static str {
    match category {
        NistCategory::Clear => "Clear",
        NistCategory::Purge => "Purge",
        NistCategory::Destroy => "Destroy",
    }
}

/// One line describing the block-class mix of a scan.
fn block_line(stats: &ScanStats) -> String {
    format!(
        "Blocks: {} empty, {} fill-pattern, {} random-or-encrypted, {} structured",
        commafy(stats.blocks_empty),
        commafy(stats.blocks_fill),
        commafy(stats.blocks_random),
        commafy(stats.blocks_structured),
    )
}

/// One line describing the recoverable items of a scan.
fn items_line(stats: &ScanStats) -> String {
    if stats.hits_total == 0 {
        "Recoverable items: 0".to_string()
    } else {
        let total = commafy(stats.hits_total);
        let breakdown = category_breakdown(stats);
        format!("Recoverable items: {total} ({breakdown})")
    }
}

/// "1 photo, 2 documents" style listing of a scan's hits.
fn category_breakdown(stats: &ScanStats) -> String {
    stats
        .hits_by_category
        .iter()
        .map(|(kind, &count)| {
            let n = commafy(count);
            let label = pluralize(kind, count);
            format!("{n} {label}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Naive plural for the fixed category vocabulary.
fn pluralize(kind: &str, count: u64) -> String {
    if count == 1 {
        kind.to_string()
    } else {
        format!("{kind}s")
    }
}

/// Group digits with commas: 1234567 becomes "1,234,567".
fn commafy(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Current unix time in seconds, or 0 if the clock is before the epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format unix seconds as `YYYY-MM-DD HH:MM:SS UTC` without a calendar
/// dependency. Uses Howard Hinnant's civil-from-days algorithm, which is
/// public domain.
fn format_unix_utc(timestamp: u64) -> String {
    let days = (timestamp / 86_400) as i64;
    let secs = timestamp % 86_400;
    let (hour, minute, second) = (secs / 3_600, (secs % 3_600) / 60, secs % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era, [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year, [0, 365]
    let mp = (5 * doy + 2) / 153; // month index, [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Decode a base64 ed25519 public key.
fn decode_verifying_key(encoded: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = BASE64.decode(encoded).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Decode a base64 ed25519 signature.
fn decode_signature(encoded: &str) -> Option<Signature> {
    let bytes: [u8; 64] = BASE64.decode(encoded).ok()?.try_into().ok()?;
    Some(Signature::from_bytes(&bytes))
}

// ---------------------------------------------------------------------------
// Minimal single-page PDF writer (no dependencies)
// ---------------------------------------------------------------------------

/// Wrap text to `max` columns at word boundaries. Empty input yields one
/// empty line so blank lines survive.
fn wrap_line(line: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for word in line.split(' ') {
        if !current.is_empty() && current.len() + word.len() + 1 > max {
            out.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() || out.is_empty() {
        out.push(current);
    }
    out
}

/// Escape a string for a PDF text literal. The core fonts are single-byte,
/// so non-ASCII input degrades to `?`.
fn pdf_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            c if c.is_ascii() => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Assemble a one-page PDF: catalog, page tree, one page, two core fonts,
/// and one text stream. The first line is the bold title; the rest are
/// 10pt body lines, and overflow is truncated with a pointer to the JSON.
fn build_pdf(lines: &[String]) -> Vec<u8> {
    const MAX_BODY_LINES: usize = 47;
    let title = lines
        .first()
        .map(String::as_str)
        .unwrap_or("gone certificate");
    let mut stream = format!("/F2 15 Tf 1 0 0 1 56 756 Tm ({}) Tj\n", pdf_escape(title));
    let mut y: i32 = 756 - 24;
    let mut shown = 0usize;
    for line in lines.iter().skip(1) {
        if shown >= MAX_BODY_LINES || y < 40 {
            break;
        }
        if !line.is_empty() {
            stream.push_str(&format!(
                "/F1 10 Tf 1 0 0 1 56 {y} Tm ({}) Tj\n",
                pdf_escape(line)
            ));
        }
        y -= 14;
        shown += 1;
    }
    if shown < lines.len().saturating_sub(1) {
        stream.push_str(&format!(
            "/F1 10 Tf 1 0 0 1 56 {y} Tm ({}) Tj\n",
            pdf_escape("(truncated: see the JSON certificate for the full document)")
        ));
    }
    let content = stream.into_bytes();

    let objects: Vec<Vec<u8>> = vec![
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
           /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>"
            .to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>".to_vec(),
        [
            format!("<< /Length {} >>\nstream\n", content.len()).into_bytes(),
            content,
            b"endstream".to_vec(),
        ]
        .concat(),
    ];

    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (i, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(object);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_pos = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use crate::report::ScanSummary;
    use crate::scan::scan_source;

    /// Two 1024-byte blocks: structured data with a JPEG and a PDF
    /// signature, then zeros. Yields exactly two hits.
    fn synthetic_before() -> ScanSummary {
        let mut block0: Vec<u8> = b"lorem ipsum dolor sit amet, consectetur adipiscing elit. "
            .iter()
            .cycle()
            .take(1024)
            .copied()
            .collect();
        block0[100..104].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]); // JFIF header
        block0[500..505].copy_from_slice(b"%PDF-");
        let mut image = block0;
        image.extend_from_slice(&[0u8; 1024]);
        let mut src = EvidenceSource::from_reader("synthetic-before", Cursor::new(image)).unwrap();
        scan_source(&mut src, 1024).unwrap()
    }

    /// A stats value with only the hit count set, for outcome tests.
    fn stats(hits: u64) -> ScanStats {
        ScanStats {
            bytes_scanned: 0,
            blocks_empty: 0,
            blocks_fill: 0,
            blocks_random: 0,
            blocks_structured: 0,
            hits_total: hits,
            hits_by_category: BTreeMap::new(),
        }
    }

    /// A verification with a fixed timestamp and no OS probe, so the
    /// certificate tests stay deterministic and fast.
    fn sample_verification() -> Verification {
        let before = ScanStats {
            bytes_scanned: 2048,
            blocks_empty: 1,
            blocks_fill: 0,
            blocks_random: 0,
            blocks_structured: 1,
            hits_total: 2,
            hits_by_category: BTreeMap::from([
                ("photo".to_string(), 1),
                ("document".to_string(), 1),
            ]),
        };
        let after = ScanStats {
            bytes_scanned: 2048,
            blocks_empty: 2,
            blocks_fill: 0,
            blocks_random: 0,
            blocks_structured: 0,
            hits_total: 0,
            hits_by_category: BTreeMap::new(),
        };
        let (outcome, outcome_sentence) = evaluate(Some(&before), &after);
        Verification {
            target: "synthetic-after".to_string(),
            timestamp: 1_760_000_000,
            block_size: 1024,
            before: Some(before),
            after,
            media_profile:
                "unknown media type, unknown filesystem, TRIM unknown, encryption: unknown"
                    .to_string(),
            nist_category: "Clear".to_string(),
            outcome,
            outcome_sentence,
        }
    }

    fn sample_certificate() -> Certificate {
        Certificate::sign(&sample_verification(), &SigningKeypair::generate())
    }

    #[test]
    fn commafy_formats_thousands() {
        assert_eq!(commafy(0), "0");
        assert_eq!(commafy(12), "12");
        assert_eq!(commafy(1234), "1,234");
        assert_eq!(commafy(1_234_567), "1,234,567");
    }

    #[test]
    fn pluralize_category_names() {
        assert_eq!(pluralize("photo", 1), "photo");
        assert_eq!(pluralize("photo", 2), "photos");
        assert_eq!(pluralize("other item", 3), "other items");
    }

    #[test]
    fn format_unix_utc_known_instants() {
        assert_eq!(format_unix_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_unix_utc(1_000_000_000), "2001-09-09 01:46:40 UTC");
        assert_eq!(format_unix_utc(86_400), "1970-01-02 00:00:00 UTC");
    }

    #[test]
    fn wrap_line_wraps_at_word_boundaries() {
        let wrapped = wrap_line("aa bb cc dd ee", 5);
        assert_eq!(wrapped, vec!["aa bb", "cc dd", "ee"]);
        assert_eq!(wrap_line("", 5), vec![""]);
    }

    #[test]
    fn evaluate_covers_the_outcome_matrix() {
        assert_eq!(evaluate(Some(&stats(5)), &stats(0)).0, Outcome::Clean);
        assert_eq!(evaluate(Some(&stats(0)), &stats(0)).0, Outcome::Clean);
        assert_eq!(evaluate(None, &stats(0)).0, Outcome::Clean);
        assert_eq!(evaluate(None, &stats(3)).0, Outcome::Unchanged);
        assert_eq!(evaluate(Some(&stats(5)), &stats(3)).0, Outcome::Improved);
        assert_eq!(evaluate(Some(&stats(3)), &stats(3)).0, Outcome::Unchanged);
        assert_eq!(evaluate(Some(&stats(3)), &stats(5)).0, Outcome::Worse);
        assert_eq!(evaluate(Some(&stats(0)), &stats(2)).0, Outcome::Worse);
    }

    #[test]
    fn clean_sentence_matches_plain_language_style() {
        let mut with_hits = stats(1_240);
        with_hits
            .hits_by_category
            .insert("photo".to_string(), 1_240);
        let (outcome, sentence) = evaluate(Some(&with_hits), &stats(0));
        assert_eq!(outcome, Outcome::Clean);
        assert_eq!(
            sentence,
            "Before: 1,240 recoverable items. After: 0. All recoverable deleted data is gone."
        );
    }

    #[test]
    fn rescan_after_full_erase_is_clean() {
        let before = synthetic_before();
        assert_eq!(before.hit_count(), 2);

        let erased = vec![0u8; 2048];
        let mut after_src =
            EvidenceSource::from_reader("synthetic-after", Cursor::new(erased)).unwrap();
        let v = rescan(&mut after_src, 1024, Some(&before)).unwrap();

        assert_eq!(v.target, "synthetic-after");
        assert_eq!(v.outcome, Outcome::Clean);
        assert_eq!(
            v.outcome_sentence,
            "Before: 2 recoverable items. After: 0. All recoverable deleted data is gone."
        );
        let before_stats = v.before.as_ref().unwrap();
        assert_eq!(before_stats.bytes_scanned, 2048);
        assert_eq!(before_stats.blocks_structured, 1);
        assert_eq!(before_stats.blocks_empty, 1);
        assert_eq!(before_stats.hits_total, 2);
        assert_eq!(before_stats.hits_by_category.get("photo").copied(), Some(1));
        assert_eq!(
            before_stats.hits_by_category.get("document").copied(),
            Some(1)
        );
        assert_eq!(v.after.bytes_scanned, 2048);
        assert_eq!(v.after.blocks_empty, 2);
        assert_eq!(v.after.blocks_structured, 0);
        assert_eq!(v.after.hits_total, 0);
        assert!(!v.media_profile.is_empty());
        assert!(["Clear", "Purge", "Destroy"].contains(&v.nist_category.as_str()));
        assert!(v.timestamp > 0);
    }

    #[test]
    fn rescan_detects_partial_erase_as_improved() {
        let before = synthetic_before();
        // One structured block with a single surviving JPEG, one empty block.
        let mut block0 = vec![0u8; 1024];
        block0[10..14].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
        let mut image = block0;
        image.extend_from_slice(&[0u8; 1024]);
        let mut after_src =
            EvidenceSource::from_reader("synthetic-after", Cursor::new(image)).unwrap();
        let v = rescan(&mut after_src, 1024, Some(&before)).unwrap();

        assert_eq!(v.outcome, Outcome::Improved);
        assert_eq!(v.after.hits_total, 1);
        assert!(v.outcome_sentence.contains("Before: 2 recoverable items"));
        assert!(v.outcome_sentence.contains("After: 1 (1 photo)"));
    }

    #[test]
    fn keypairs_come_from_os_randomness() {
        let a = SigningKeypair::generate();
        let b = SigningKeypair::generate();
        assert_ne!(a.public_key_base64(), b.public_key_base64());
        assert_eq!(
            BASE64.decode(a.public_key_base64()).unwrap().len(),
            32,
            "public key decodes to 32 bytes"
        );
    }

    #[test]
    fn certificate_round_trips_and_verifies() {
        let cert = sample_certificate();
        assert!(cert.verify_signature());
        let json = cert.to_json().unwrap();
        println!("{json}");
        let parsed: Certificate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cert);
        assert!(parsed.verify_signature());
    }

    #[test]
    fn certificate_json_has_expected_schema_keys() {
        let cert = sample_certificate();
        let value: serde_json::Value = serde_json::from_str(&cert.to_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["tool"], "gone");
        assert_eq!(value["tool_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["verification"]["outcome"], "clean");
        assert_eq!(
            value["verification"]["outcome_sentence"],
            "Before: 2 recoverable items. After: 0. All recoverable deleted data is gone."
        );
        assert_eq!(value["payload_hash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let cert = sample_certificate();
        let mut value: serde_json::Value = serde_json::from_str(&cert.to_json().unwrap()).unwrap();
        value["verification"]["after"]["hits_total"] = serde_json::json!(7);
        let tampered: Certificate = serde_json::from_value(value).unwrap();
        assert!(!tampered.verify_signature());
    }

    #[test]
    fn tampered_hash_field_fails_verification() {
        let mut cert = sample_certificate();
        let replacement = if cert.payload_hash.starts_with('f') {
            "0"
        } else {
            "f"
        };
        cert.payload_hash.replace_range(0..1, replacement);
        assert!(!cert.verify_signature());
    }

    #[test]
    fn flipped_signature_byte_fails_verification() {
        let mut cert = sample_certificate();
        let mut raw = BASE64.decode(&cert.signature).unwrap();
        raw[0] ^= 0x01;
        cert.signature = BASE64.encode(raw);
        assert!(!cert.verify_signature());
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let mut cert = sample_certificate();
        cert.public_key = SigningKeypair::generate().public_key_base64();
        assert!(!cert.verify_signature());
    }

    #[test]
    fn malformed_encodings_fail_verification() {
        let mut cert = sample_certificate();
        cert.signature = "not base64 at all".to_string();
        assert!(!cert.verify_signature());
        let mut cert = sample_certificate();
        cert.public_key = BASE64.encode([0u8; 16]); // wrong length
        assert!(!cert.verify_signature());
    }

    #[test]
    fn write_files_emits_json_and_txt() {
        let cert = sample_certificate();
        let dir = tempfile::tempdir().unwrap();
        let paths = cert.write_files(dir.path()).unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths[0].file_name().unwrap(),
            "gone-certificate-1760000000.json"
        );
        assert_eq!(
            paths[1].file_name().unwrap(),
            "gone-certificate-1760000000.txt"
        );
        let parsed: Certificate =
            serde_json::from_str(&std::fs::read_to_string(&paths[0]).unwrap()).unwrap();
        assert!(parsed.verify_signature());
        let text = std::fs::read_to_string(&paths[1]).unwrap();
        assert!(text.contains("gone verification certificate"));
        assert!(text.contains("Outcome: Clean"));
        assert!(text.contains("Recoverable items: 2 (1 document, 1 photo)"));
        assert!(text.contains("2025-10-09"));
        assert!(text.contains("self-signed"));
    }

    /// Check that the xref offsets in a built PDF point at real object
    /// headers, which is what makes the file parse.
    fn assert_pdf_offsets(pdf: &[u8]) {
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        let marker = b"startxref\n";
        let marker_pos = pdf
            .windows(marker.len())
            .rposition(|w| w == marker)
            .expect("startxref present");
        let number_start = marker_pos + marker.len();
        let number_len = pdf[number_start..]
            .iter()
            .position(|&b| b == b'\n')
            .expect("newline after startxref value");
        let xref_pos: usize = std::str::from_utf8(&pdf[number_start..number_start + number_len])
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(&pdf[xref_pos..xref_pos + 4], b"xref");
        for object in 1..=6usize {
            let header = format!("{object} 0 obj\n");
            let pos = pdf
                .windows(header.len())
                .position(|w| w == header.as_bytes())
                .expect("object header present");
            let entry = format!("{pos:010} 00000 n \n");
            assert!(
                pdf.windows(entry.len()).any(|w| w == entry.as_bytes()),
                "xref entry for object {object} records offset {pos}"
            );
        }
    }

    #[test]
    fn pdf_bytes_have_valid_structure() {
        let cert = sample_certificate();
        let pdf = cert.to_pdf_bytes();
        assert_pdf_offsets(&pdf);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("(gone verification certificate)"));
        assert!(text.contains("Outcome: Clean"));
    }

    #[test]
    fn pdf_escapes_and_truncates() {
        assert_eq!(pdf_escape("a(b)\\c"), "a\\(b\\)\\\\c");
        assert_eq!(pdf_escape("caf\u{e9}"), "caf?");
        let lines: Vec<String> = (0..200).map(|i| format!("line {i}")).collect();
        let pdf = build_pdf(&lines);
        assert_pdf_offsets(&pdf);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("truncated"));
    }

    #[test]
    fn write_pdf_creates_file() {
        let cert = sample_certificate();
        let dir = tempfile::tempdir().unwrap();
        let path = cert.write_pdf(dir.path()).unwrap();
        assert_eq!(path.file_name().unwrap(), "gone-certificate-1760000000.pdf");
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"%PDF-1.4\n"));
    }
}
