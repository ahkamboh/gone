//! End-to-end sanitize tests: plan and run a full free-space overwrite
//! cycle on a tempdir, through gone-core's public API only.

use std::sync::atomic::{AtomicBool, Ordering};

use gone_core::sanitize::{DEFAULT_RESERVE_MIB, plan, plan_with_reserve, run};

const MIB: u64 = 1024 * 1024;
/// Cap from the task spec: small enough to run in seconds, large enough to
/// span several 4 MiB chunks.
const MAX_BYTES: u64 = 16 * MIB;
/// Free space on a busy developer machine drifts between two measurements;
/// 32 MiB absorbs that noise. The hard leak checks are the filler-path
/// assertions below; this bound is a coarse sanity check on top.
const FREE_SPACE_EPSILON: u64 = 32 * MIB;

#[test]
fn full_cycle_capped_run_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let free_before = plan_with_reserve(dir.path(), 1).unwrap().free_bytes;

    let sanitize_plan = plan_with_reserve(dir.path(), 1)
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    assert_eq!(
        sanitize_plan.bytes_to_write, MAX_BYTES,
        "test machine has less free space than the 16 MiB cap plus 1 MiB reserve"
    );

    let cancel = AtomicBool::new(false);
    let mut callbacks = 0u64;
    let mut last_progress = None;
    let report = run(&sanitize_plan, &cancel, &mut |progress| {
        callbacks += 1;
        assert!(progress.bytes_written <= MAX_BYTES);
        assert_eq!(progress.bytes_planned, MAX_BYTES);
        last_progress = Some(progress);
    })
    .unwrap();

    assert_eq!(report.bytes_written, MAX_BYTES);
    assert!(!report.canceled);
    assert!(!report.disk_full);
    assert!(report.filler_removed);
    // 16 MiB in 4 MiB chunks: exactly four progress callbacks, the last of
    // which reports completion.
    assert_eq!(callbacks, 4);
    let last = last_progress.unwrap();
    assert_eq!(last.bytes_written, MAX_BYTES);
    assert!(last.throughput_mibs() >= 0.0);

    // The filler is gone and the directory holds nothing after cleanup.
    assert!(!sanitize_plan.filler_path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

    // Free space returns to roughly its pre-run level once the filler is
    // removed; the overwrite borrows blocks, it does not keep them.
    let free_after = plan_with_reserve(dir.path(), 1).unwrap().free_bytes;
    let drift = free_before.abs_diff(free_after);
    assert!(
        drift <= FREE_SPACE_EPSILON,
        "free space moved by {drift} bytes across the run (epsilon {FREE_SPACE_EPSILON})"
    );
}

#[test]
fn cancel_after_first_chunk_still_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let sanitize_plan = plan_with_reserve(dir.path(), 1)
        .unwrap()
        .with_max_bytes(MAX_BYTES);
    let cancel = AtomicBool::new(false);
    let report = run(&sanitize_plan, &cancel, &mut |_| {
        // Simulate Ctrl+C landing after the first chunk completes.
        cancel.store(true, Ordering::Relaxed);
    })
    .unwrap();

    assert!(report.canceled);
    assert!(!report.disk_full);
    // Exactly one chunk landed: cancel is checked between chunks.
    assert_eq!(report.bytes_written, sanitize_plan.chunk_size as u64);
    assert!(report.filler_removed);
    assert!(!sanitize_plan.filler_path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn plan_rejects_a_file_target() {
    let file = tempfile::NamedTempFile::new().unwrap();
    assert!(plan(file.path()).is_err());
}

#[test]
fn default_plan_uses_the_one_gib_reserve() {
    let dir = tempfile::tempdir().unwrap();
    let sanitize_plan = plan(dir.path()).unwrap();
    assert_eq!(sanitize_plan.reserve_bytes, DEFAULT_RESERVE_MIB * MIB);
    assert_eq!(
        sanitize_plan.bytes_to_write,
        sanitize_plan.free_bytes - DEFAULT_RESERVE_MIB * MIB
    );
}
