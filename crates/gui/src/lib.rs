//! gone-gui: the Tauri v2 desktop application.
//!
//! The app links gone-core in-process: no subprocess, no local web
//! server. The commands below are thin wrappers over gone-core APIs,
//! shaped for the plain-language UI in `ui/`.
#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{Emitter, State, Window};

use gone_core::io::EvidenceSource;
use gone_core::report::ScanSummary;
use gone_core::sanitize;
use gone_core::scan;
use gone_core::trimdetect;
use gone_core::verify;

/// Scan block size: 1 MiB, matching the CLI.
const SCAN_BLOCK_SIZE: u64 = 1024 * 1024;

/// Erase progress events go out at most this often, so a fast SSD does
/// not flood the webview with one event per 4 MiB chunk.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(150);

/// Bytes to GiB for display.
fn gib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

/// Media profile plus the plain-language guidance for one path.
#[derive(Serialize)]
pub struct InspectView {
    /// One-line hardware summary, for example "solid-state drive (SSD),
    /// APFS, TRIM enabled, encryption: FileVault (/dev/disk3s5)".
    pub profile_line: String,
    /// The NIST-backed recommendation headline.
    pub headline: String,
    /// Extra notes: snapshots, encryption keys, TRIM hints.
    pub notes: Vec<String>,
    /// NIST SP 800-88 category the overwrite achieves on this media.
    pub nist_category: String,
}

/// One recoverable-item category with its count, for example
/// ("photos", 3).
#[derive(Serialize)]
pub struct CategoryCount {
    pub label: String,
    pub count: u64,
}

/// Read-only scan result for the results screen.
#[derive(Serialize)]
pub struct ScanView {
    pub source: String,
    pub gib_scanned: f64,
    pub blocks_empty: u64,
    pub blocks_fill: u64,
    pub blocks_random: u64,
    pub blocks_structured: u64,
    pub hits: u64,
    pub hits_by_category: Vec<CategoryCount>,
    /// The one-sentence plain-language verdict from gone-core.
    pub verdict: String,
}

/// What an erase run would do, in display-ready numbers.
#[derive(Serialize)]
pub struct PlanView {
    pub target_dir: String,
    pub write_gib: f64,
    pub free_gib: f64,
    pub reserve_gib: f64,
    /// Plain-language description of the plan.
    pub summary: String,
}

/// Payload of the `erase-progress` event.
#[derive(Serialize, Clone)]
pub struct EraseProgress {
    pub percent: f64,
    pub gib_written: f64,
    pub gib_planned: f64,
    pub mib_per_s: f64,
    pub elapsed_secs: f64,
}

/// Shared cancel flag for the erase flow, managed by Tauri.
#[derive(Default)]
pub struct EraseCancel(Arc<AtomicBool>);

/// Run a blocking gone-core call off the async runtime's worker threads
/// so the window stays responsive.
async fn run_blocking<T, F>(job: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|e| format!("background task failed: {e}"))?
}

fn category_counts(summary: &ScanSummary) -> Vec<CategoryCount> {
    summary
        .hits_by_category()
        .into_iter()
        .map(|(category, count)| CategoryCount {
            label: category.label(count).to_string(),
            count,
        })
        .collect()
}

/// Inspect the storage under `path`: media kind, TRIM, encryption, and
/// the plain-language NIST guidance that goes with them. Never fails
/// hard; unknowns come back as "unknown" strings.
#[tauri::command]
async fn inspect(path: String) -> Result<InspectView, String> {
    run_blocking(move || {
        let profile = trimdetect::profile(Path::new(path.trim()));
        let guidance = trimdetect::guidance(&profile);
        Ok(InspectView {
            profile_line: profile.to_string(),
            headline: guidance.headline,
            notes: guidance.notes,
            nist_category: format!("{:?}", guidance.overwrite_category),
        })
    })
    .await
}

/// Read-only scan of a disk image or device for recoverable data. Opens
/// the source read-only and never writes to it.
#[tauri::command]
async fn check(path: String) -> Result<ScanView, String> {
    run_blocking(move || {
        let path = path.trim();
        let mut source = EvidenceSource::open(Path::new(path))
            .map_err(|e| format!("Could not open {path}: {e}"))?;
        let summary = scan::scan_source(&mut source, SCAN_BLOCK_SIZE)
            .map_err(|e| format!("The scan hit a problem: {e}"))?;
        let hits = summary.hit_count() as u64;
        let hits_by_category = category_counts(&summary);
        let verdict = summary.verdict();
        Ok(ScanView {
            source: summary.source,
            gib_scanned: gib(summary.bytes_scanned),
            blocks_empty: summary.blocks_empty,
            blocks_fill: summary.blocks_fill,
            blocks_random: summary.blocks_random,
            blocks_structured: summary.blocks_structured,
            hits,
            hits_by_category,
            verdict,
        })
    })
    .await
}

/// Build the erase plan for the free space on the volume holding `path`.
#[tauri::command]
async fn erase_plan(path: String) -> Result<PlanView, String> {
    run_blocking(move || {
        let plan = sanitize::plan(Path::new(path.trim()))
            .map_err(|e| format!("Could not plan the erase: {e}"))?;
        Ok(PlanView {
            target_dir: plan.target_dir.display().to_string(),
            write_gib: gib(plan.bytes_to_write),
            free_gib: gib(plan.free_bytes),
            reserve_gib: gib(plan.reserve_bytes),
            summary: format!(
                "gone will write about {:.1} GiB of random data over the free space on {}. \
                 This covers what deleted files left behind. Your existing files are not \
                 touched, and about {:.1} GiB stays free as a safety buffer.",
                gib(plan.bytes_to_write),
                plan.target_dir.display(),
                gib(plan.reserve_bytes),
            ),
        })
    })
    .await
}

/// Ask a running erase to stop after the current chunk.
#[tauri::command]
fn erase_cancel(state: State<'_, EraseCancel>) {
    state.0.store(true, Ordering::SeqCst);
}

/// Emit one throttled progress event. A closed window only means the
/// user left; progress delivery is best-effort.
fn emit_progress(window: &Window, progress: sanitize::SanitizeProgress) {
    let percent = if progress.bytes_planned == 0 {
        100.0
    } else {
        (100.0 * progress.bytes_written as f64 / progress.bytes_planned as f64).min(100.0)
    };
    let _ = window.emit(
        "erase-progress",
        EraseProgress {
            percent,
            gib_written: gib(progress.bytes_written),
            gib_planned: gib(progress.bytes_planned),
            mib_per_s: progress.throughput_mibs(),
            elapsed_secs: progress.elapsed.as_secs_f64(),
        },
    );
}

/// Run the free-space overwrite. `confirm` must equal `path`: the UI
/// makes the user type the target path before the button enables, and
/// this check keeps a silent trigger impossible even if the UI is
/// bypassed. Emits `erase-progress` events while running.
#[tauri::command]
async fn erase_run(
    window: Window,
    state: State<'_, EraseCancel>,
    path: String,
    confirm: String,
) -> Result<String, String> {
    let path = path.trim().to_string();
    if path.is_empty() || path != confirm.trim() {
        return Err(
            "The typed path does not match the erase target. Nothing was written.".to_string(),
        );
    }
    let cancel = state.0.clone();
    cancel.store(false, Ordering::SeqCst);
    run_blocking(move || {
        let plan = sanitize::plan(Path::new(&path))
            .map_err(|e| format!("Could not plan the erase: {e}"))?;
        let mut last_emit: Option<Instant> = None;
        let report = sanitize::run(&plan, &cancel, &mut |progress| {
            if last_emit.is_none_or(|t| t.elapsed() >= PROGRESS_INTERVAL) {
                last_emit = Some(Instant::now());
                emit_progress(&window, progress);
            }
        })
        .map_err(|e| format!("The erase failed: {e}"))?;
        // Final tick so the bar lands on the true end state even when
        // the last chunk fell inside the throttle window.
        emit_progress(
            &window,
            sanitize::SanitizeProgress {
                bytes_written: report.bytes_written,
                bytes_planned: plan.bytes_to_write,
                elapsed: report.elapsed,
            },
        );
        Ok(report.summary_line())
    })
    .await
}

/// Post-erase verification for the Done screen: the outcome sentence,
/// whether the certificate's own signature checks out, and where the
/// certificate files landed.
#[derive(Serialize)]
pub struct VerifyView {
    pub outcome_sentence: String,
    pub signature_ok: bool,
    pub cert_paths: Vec<String>,
}

/// Where certificate files go: next to the target when it is a file, or
/// the user's home folder when it is a device or directory (writing into
/// a volume root like / would need privileges we do not ask for).
fn certificate_dir(target: &Path) -> std::path::PathBuf {
    if target.is_file() {
        if let Some(parent) = target.parent() {
            return parent.to_path_buf();
        }
    }
    std::env::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Rescan after erasing, sign a tamper-evident certificate, and write it
/// as JSON, TXT, and PDF. Read-only against the target.
#[tauri::command]
async fn verify_run(path: String) -> Result<VerifyView, String> {
    run_blocking(move || {
        let path = path.trim();
        let mut source = EvidenceSource::open(Path::new(path))
            .map_err(|e| format!("Could not open {path}: {e}"))?;
        let verification = verify::rescan(&mut source, SCAN_BLOCK_SIZE, None)
            .map_err(|e| format!("The verification scan hit a problem: {e}"))?;
        let keypair = verify::SigningKeypair::generate();
        let certificate = verify::Certificate::sign(&verification, &keypair);
        let signature_ok = certificate.verify_signature();
        let dir = certificate_dir(Path::new(path));
        let mut files = certificate
            .write_files(&dir)
            .map_err(|e| format!("Could not write the certificate: {e}"))?;
        files.push(
            certificate
                .write_pdf(&dir)
                .map_err(|e| format!("Could not write the PDF: {e}"))?,
        );
        Ok(VerifyView {
            outcome_sentence: verification.outcome_sentence,
            signature_ok,
            cert_paths: files.iter().map(|p| p.display().to_string()).collect(),
        })
    })
    .await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(EraseCancel::default())
        .invoke_handler(tauri::generate_handler![
            inspect,
            check,
            erase_plan,
            erase_run,
            erase_cancel,
            verify_run
        ])
        .run(tauri::generate_context!())
        .expect("error while running gone");
}
