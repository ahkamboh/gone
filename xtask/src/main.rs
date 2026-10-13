//! xtask: build automation entry point (cargo xtask convention).
//!
//! Validation harness commands:
//!
//!   cargo xtask fetch-fixtures   Download small public forensic test images
//!                                (Digital Corpora) into fixtures/ (gitignored).
//!                                Network failures degrade to a SKIP, never a
//!                                hard error, so CI stays green offline.
//!   cargo xtask synth-corpus     Generate deterministic synthetic images in
//!                                fixtures/ (mixed/zeros/0xFF/random) and
//!                                self-verify them with the real scanner.
//!   cargo xtask oracle           Compare gone's scan against Sleuth Kit
//!                                (fls) / PhotoRec when they are on PATH;
//!                                prints install hints and exits 0 otherwise.
//!   cargo xtask package-rules    (reserved)

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use gone_core::io::EvidenceSource;
use gone_core::scan;

const MIB: usize = 1024 * 1024;
/// Scan block size shared by the synthetic corpus and the integration tests.
const SCAN_BLOCK: u64 = MIB as u64;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fetch-fixtures") => fetch_fixtures(),
        Some("synth-corpus") => synth_corpus(),
        Some("oracle") => oracle(),
        Some("package-rules") => {
            println!("package-rules: not implemented yet");
            ExitCode::SUCCESS
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown task: {other}");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "usage: cargo xtask <task>\n\
         tasks:\n\
         \x20 fetch-fixtures   download public forensic test images into fixtures/\n\
         \x20 synth-corpus     generate deterministic synthetic images into fixtures/\n\
         \x20 oracle           diff gone's scan against Sleuth Kit / PhotoRec\n\
         \x20 package-rules    (reserved)"
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .expect("xtask lives one level below the workspace root")
}

fn fixtures_dir() -> PathBuf {
    workspace_root().join("fixtures")
}

// ---------------------------------------------------------------------------
// fetch-fixtures
// ---------------------------------------------------------------------------

/// One downloadable fixture. `urls` are tried in order (primary, then
/// mirror); at most two per fixture, per the harness's CI-resilience rule.
struct RemoteFixture {
    name: &'static str,
    description: &'static str,
    urls: [&'static str; 2],
}

/// Small public images from Digital Corpora (digitalcorpora.org). All are
/// well under the ~50 MB cap: gen0 is ~1 MB, the DFRWS 2004 zips are 1-2 MB.
const REMOTE_FIXTURES: &[RemoteFixture] = &[
    RemoteFixture {
        name: "ntfs1-gen0.E01",
        description: "NPS NTFS test image, generation 0 (E01)",
        urls: [
            "https://downloads.digitalcorpora.org/corpora/drives/nps-2009-ntfs1/ntfs1-gen0.E01",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/nps-2009-ntfs1/ntfs1-gen0.E01",
        ],
    },
    RemoteFixture {
        name: "8-jpeg-search.zip",
        description: "DFRWS 2004 FAT image with embedded JPEGs (zipped dd)",
        urls: [
            "https://downloads.digitalcorpora.org/corpora/drives/dftt-2004/8-jpeg-search.zip",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/8-jpeg-search.zip",
        ],
    },
    RemoteFixture {
        name: "12-carve-ext2.zip",
        description: "DFRWS 2004 ext2 carving test image (zipped dd)",
        urls: [
            "https://downloads.digitalcorpora.org/corpora/drives/dftt-2004/12-carve-ext2.zip",
            "https://digitalcorpora.s3.amazonaws.com/corpora/drives/dftt-2004/12-carve-ext2.zip",
        ],
    },
];

enum FetchOutcome {
    Cached(u64),
    Downloaded(u64),
    Failed,
}

fn fetch_one(dir: &Path, fixture: &RemoteFixture) -> FetchOutcome {
    let dest = dir.join(fixture.name);
    if let Ok(meta) = fs::metadata(&dest) {
        if meta.len() > 0 {
            return FetchOutcome::Cached(meta.len());
        }
        // Zero-byte leftovers from an interrupted run are not fixtures.
        let _ = fs::remove_file(&dest);
    }
    let tmp = dir.join(format!(".{}.tmp", fixture.name));
    for url in &fixture.urls {
        println!("  trying {url}");
        let status = Command::new("curl")
            .args([
                "-fSL",
                "-sS",
                "--connect-timeout",
                "15",
                "--max-time",
                "600",
            ])
            .arg("-o")
            .arg(&tmp)
            .arg(url)
            .status();
        let ok = matches!(status, Ok(s) if s.success())
            && fs::metadata(&tmp).map(|m| m.len() > 0).unwrap_or(false);
        if ok {
            let size = fs::metadata(&tmp).map(|m| m.len()).unwrap_or(0);
            if fs::rename(&tmp, &dest).is_ok() {
                return FetchOutcome::Downloaded(size);
            }
        }
        let _ = fs::remove_file(&tmp);
    }
    FetchOutcome::Failed
}

/// Best-effort unzip of downloaded archives so the raw images inside are
/// directly usable by `oracle`. Silent no-op when `unzip` is missing.
fn extract_archives(dir: &Path, names: &[&str]) {
    if !on_path("unzip") {
        return;
    }
    for name in names {
        if !name.ends_with(".zip") {
            continue;
        }
        let zip = dir.join(name);
        if !zip.exists() {
            continue;
        }
        let ok = Command::new("unzip")
            .arg("-o")
            .arg("-d")
            .arg(dir)
            .arg(&zip)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            println!("  extracted {name}");
        }
    }
}

fn fetch_fixtures() -> ExitCode {
    println!("== fetch-fixtures ==");
    let dir = fixtures_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let mut downloaded = Vec::new();
    let mut cached = Vec::new();
    let mut failed = Vec::new();
    for fixture in REMOTE_FIXTURES {
        println!("{} ({})", fixture.name, fixture.description);
        match fetch_one(&dir, fixture) {
            FetchOutcome::Cached(size) => {
                println!("  cached ({size} bytes)");
                cached.push(fixture.name);
            }
            FetchOutcome::Downloaded(size) => {
                println!("  downloaded ({size} bytes)");
                downloaded.push(fixture.name);
            }
            FetchOutcome::Failed => {
                println!("  failed on primary and mirror");
                failed.push(fixture.name);
            }
        }
    }
    let present: Vec<&str> = downloaded.iter().chain(cached.iter()).copied().collect();
    extract_archives(&dir, &present);

    println!("\n== SUMMARY ==");
    println!("downloaded: {} {downloaded:?}", downloaded.len());
    println!("cached:     {} {cached:?}", cached.len());
    println!("failed:     {} {failed:?}", failed.len());
    if downloaded.is_empty() && cached.is_empty() {
        println!(
            "SKIP: no fixtures available (network down or site layout changed).\n\
             Integration tests build their corpus in memory and do not need\n\
             fixtures/, so nothing here is a failure."
        );
    }
    // External availability must never hard-fail CI.
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// synth-corpus
// ---------------------------------------------------------------------------
//
// The mixed-image layout below is mirrored by the in-memory builder in
// crates/core/tests/synth_scan.rs. Keep the two in sync: same block order,
// same planted offsets, same PRNG.

/// xorshift64* byte stream. Deterministic, high entropy; NOT for security,
/// only for reproducible fixtures. Seed 0 is a fixed point, never use it.
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
const MIXED_JPEG_OFF: usize = 3 * MIB + 0x100;
const MIXED_PDF_OFF: usize = 3 * MIB + 0x200;
const MIXED_SQLITE_OFF: usize = 4 * MIB + 0x40;
const MIXED_DECOY_GZIP_OFF: usize = 4 * MIB + 0x60;
const MIXED_DECOY_JPEG_OFF: usize = 4 * MIB + 0x70;
const MIXED_RANDOM_BLOCK_JPEG_OFF: usize = 2 * MIB + 0x80;

/// 6 MiB: 2 empty, 1 random (JPEG planted, must be ignored), 3 structured
/// holding exactly 3 real hits (JPEG, PDF, SQLite) plus validator decoys.
fn build_mixed_image() -> Vec<u8> {
    let mut image = vec![0u8; 6 * MIB];
    // Blocks 0-1: zeros (Empty).
    // Block 2: random, with a JPEG signature the scanner must skip because
    // carving is only meaningful on structured space.
    prng_fill(&mut image[2 * MIB..3 * MIB], 0x9E37_79B9_7F4A_7C15);
    image[MIXED_RANDOM_BLOCK_JPEG_OFF..MIXED_RANDOM_BLOCK_JPEG_OFF + 4]
        .copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    // Blocks 3-5: structured.
    for block in 3..6 {
        structured_fill(&mut image[block * MIB..(block + 1) * MIB]);
    }
    image[MIXED_JPEG_OFF..MIXED_JPEG_OFF + 4].copy_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    image[MIXED_PDF_OFF..MIXED_PDF_OFF + 8].copy_from_slice(b"%PDF-1.7");
    image[MIXED_SQLITE_OFF..MIXED_SQLITE_OFF + 16].copy_from_slice(b"SQLite format 3\0");
    // Decoys: valid magics that fail the structural validators.
    image[MIXED_DECOY_GZIP_OFF..MIXED_DECOY_GZIP_OFF + 4]
        .copy_from_slice(&[0x1F, 0x8B, 0x00, 0x00]); // bad compression method
    image[MIXED_DECOY_JPEG_OFF..MIXED_DECOY_JPEG_OFF + 4]
        .copy_from_slice(&[0xFF, 0xD8, 0xFF, 0x6C]); // non-marker 4th byte
    image
}

fn write_image(dir: &Path, name: &str, data: &[u8]) -> std::io::Result<u64> {
    let path = dir.join(name);
    fs::write(&path, data)?;
    Ok(fs::metadata(&path)?.len())
}

fn synth_corpus() -> ExitCode {
    println!("== synth-corpus ==");
    let dir = fixtures_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("cannot create {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }

    let mut random = vec![0u8; 2 * MIB];
    prng_fill(&mut random, 0xC0FF_EE15_600D_F00D);

    let images: Vec<(&str, Vec<u8>)> = vec![
        ("synth-mixed.img", build_mixed_image()),
        ("synth-zeros.img", vec![0u8; MIB]),
        ("synth-ff.img", vec![0xFF; MIB]),
        ("synth-random.img", random),
    ];

    let mut wrote = Vec::new();
    for (name, data) in &images {
        match write_image(&dir, name, data) {
            Ok(size) => {
                println!("wrote {name} ({size} bytes)");
                wrote.push((*name, size));
            }
            Err(e) => {
                eprintln!("failed to write {name}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Self-verify the mixed image with the real scanner: a generator bug is
    // our bug, so it fails loudly (unlike external downloads).
    let mixed_path = dir.join("synth-mixed.img");
    let verify = EvidenceSource::open(&mixed_path)
        .and_then(|mut src| scan::scan_source(&mut src, SCAN_BLOCK));
    match verify {
        Ok(summary) => {
            println!(
                "mixed image scan: {} empty, {} fill, {} random, {} structured, {} hits",
                summary.blocks_empty,
                summary.blocks_fill,
                summary.blocks_random,
                summary.blocks_structured,
                summary.hit_count()
            );
            let ok = summary.blocks_empty == 2
                && summary.blocks_fill == 0
                && summary.blocks_random == 1
                && summary.blocks_structured == 3
                && summary.hit_count() == 3;
            if !ok {
                eprintln!(
                    "MISMATCH: synthetic mixed image does not scan as designed\n\
                     (expected 2 empty / 0 fill / 1 random / 3 structured / 3 hits).\n\
                     The generator and crates/core/tests/synth_scan.rs must be fixed together."
                );
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("verification scan failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    println!("\n== SUMMARY ==");
    for (name, size) in &wrote {
        println!("{name}: {size} bytes");
    }
    println!(
        "synthetic corpus OK: mixed layout verified (2 empty / 1 random / 3 structured, \
         exactly 3 planted hits)"
    );
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// oracle
// ---------------------------------------------------------------------------

fn on_path(tool: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|paths| env::split_paths(&paths).any(|dir| dir.join(tool).is_file()))
}

/// Count deleted entries Sleuth Kit's `fls` sees, or explain why it cannot.
fn fls_deleted_count(image: &Path) -> String {
    let out = Command::new("fls").arg("-r").arg("-d").arg(image).output();
    match out {
        Ok(o) if o.status.success() => {
            let n = String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            format!("{n} deleted entries")
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let first = stderr.lines().next().unwrap_or("unrecognized image");
            format!("n/a ({first})")
        }
        Err(e) => format!("spawn failed ({e})"),
    }
}

/// PhotoRec scripted carving, best-effort: flag syntax varies by version, so
/// any failure degrades to a note rather than an error.
fn photorec_carved_count(image: &Path) -> String {
    let out_dir = env::temp_dir().join(format!("gone-photorec-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out_dir);
    if fs::create_dir_all(&out_dir).is_err() {
        return "n/a (cannot create output dir)".to_string();
    }
    let run = Command::new("photorec")
        .args(["/log", "/d"])
        .arg(&out_dir)
        .arg("/cmd")
        .arg(image)
        .arg("fileopt,everything,enable,search")
        .output();
    let note = match run {
        Ok(o) if o.status.success() => {
            let carved = fs::read_dir(&out_dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                        .count()
                })
                .unwrap_or(0);
            format!("{carved} carved files")
        }
        Ok(_) => "n/a (scripted mode rejected; flags vary by version)".to_string(),
        Err(e) => format!("spawn failed ({e})"),
    };
    let _ = fs::remove_dir_all(&out_dir);
    note
}

/// Recursively gather scannable images under `dir`, skipping archives and
/// the metadata files the DFRWS zips ship alongside the raw images.
fn collect_images(dir: &Path, out: &mut Vec<PathBuf>) {
    const SKIP_EXTS: &[&str] = &["zip", "txt", "html", "md", "xml", "pdf", "json"];
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_images(&path, out);
        } else if path.is_file()
            && !path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| SKIP_EXTS.contains(&ext.to_ascii_lowercase().as_str()))
        {
            out.push(path);
        }
    }
}

fn oracle() -> ExitCode {
    println!("== oracle ==");
    let have_fls = on_path("fls");
    let have_istat = on_path("istat");
    let have_photorec = on_path("photorec");
    if !have_fls && !have_istat && !have_photorec {
        println!(
            "Sleuth Kit (fls/istat) and PhotoRec are not on PATH, so there is\n\
             no oracle to diff against. Install with:\n\
             \x20 brew install sleuthkit   # provides fls and istat\n\
             \x20 brew install testdisk    # provides photorec\n\
             SKIP: oracle comparison unavailable. Exit 0 by design."
        );
        return ExitCode::SUCCESS;
    }

    let dir = fixtures_dir();
    let mut images = Vec::new();
    collect_images(&dir, &mut images);
    images.sort();
    if images.is_empty() {
        println!(
            "fixtures/ holds no raw images. Run `cargo xtask synth-corpus` and/or\n\
             `cargo xtask fetch-fixtures` first.\n\
             SKIP: nothing to compare. Exit 0 by design."
        );
        return ExitCode::SUCCESS;
    }

    println!(
        "{:<22} {:>3} {:>3} {:>3} {:>3} {:>5}  oracle findings",
        "fixture", "E", "F", "R", "S", "hits"
    );
    println!("{}", "-".repeat(88));
    for image in &images {
        let name = image
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let summary = match EvidenceSource::open(image)
            .and_then(|mut src| scan::scan_source(&mut src, SCAN_BLOCK))
        {
            Ok(summary) => summary,
            Err(e) => {
                println!("{name:<22} scan failed: {e}");
                continue;
            }
        };
        let fls = if have_fls {
            fls_deleted_count(image)
        } else {
            "fls not installed".to_string()
        };
        let photorec = if have_photorec {
            photorec_carved_count(image)
        } else {
            "photorec not installed".to_string()
        };
        println!(
            "{name:<22} {:>3} {:>3} {:>3} {:>3} {:>5}  fls: {fls}; photorec: {photorec}",
            summary.blocks_empty,
            summary.blocks_fill,
            summary.blocks_random,
            summary.blocks_structured,
            summary.hit_count()
        );
    }
    println!("{}", "-".repeat(88));
    println!(
        "Columns: E/F/R/S = gone block classes (empty/fill/random/structured).\n\
         Note: the tools measure different things. gone counts signature hits in\n\
         structured space; fls counts filesystem metadata entries; photorec carves\n\
         whole files. Compare direction (found something vs found nothing), not\n\
         exact counts."
    );
    println!("\n== SUMMARY ==");
    println!(
        "compared {} image(s) against the available oracle tools",
        images.len()
    );
    ExitCode::SUCCESS
}
