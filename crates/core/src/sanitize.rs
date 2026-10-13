//! Free-space sanitization: overwrite everything the filesystem has
//! released, without touching a single live file.
//!
//! Strategy, aligned with NIST SP 800-88 Rev. 2 (a single overwrite pass
//! is sufficient; multi-pass patterns are obsolete):
//!
//! 1. Create one filler file inside the target volume and grow it with
//!    AES-256-CTR keystream (CSPRNG-quality bytes from a random key) until
//!    only a safety reserve of free space remains. Every block the
//!    filesystem gives the filler is a block that used to hold deleted
//!    data, so those blocks get overwritten.
//! 2. Flush, sync, delete the filler. The space returns to the volume.
//!
//! The filler never writes outside free space, so live files are safe by
//! construction. Cancel is cooperative: between chunks the engine checks
//! a flag, then removes the filler and reports partial coverage.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

/// AES-256 in counter mode. Encrypting a zeroed buffer yields a
/// cryptographic-strength random stream, the same construction `openssl
/// enc -aes-256-ctr /dev/zero` produces, minus the subprocess.
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Free space left untouched by default so a running system never hits a
/// full disk. Users can lower it; zero means fill until the disk refuses.
pub const DEFAULT_RESERVE_MIB: u64 = 1024;

/// Write chunk size. Large enough for throughput, small enough for
/// responsive cancellation.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// What a sanitize run would do. Produced by [`plan_with_reserve`].
#[derive(Debug, Clone)]
pub struct SanitizePlan {
    /// Directory on the target volume. The filler file lives here, which
    /// is how the overwrite stays inside one filesystem.
    pub target_dir: PathBuf,
    /// Path of the filler file that will be created and later removed.
    pub filler_path: PathBuf,
    /// Free bytes on the volume at planning time.
    pub free_bytes: u64,
    /// Bytes deliberately left untouched.
    pub reserve_bytes: u64,
    /// Bytes the filler will grow to: free minus reserve, capped by any
    /// testing limit.
    pub bytes_to_write: u64,
    /// Per-write chunk size.
    pub chunk_size: usize,
}

impl SanitizePlan {
    /// Cap the total bytes written. Testing escape hatch; also useful to
    /// sanitize only part of a very large volume per invocation.
    pub fn with_max_bytes(mut self, cap: u64) -> Self {
        self.bytes_to_write = self.bytes_to_write.min(cap);
        self
    }
}

/// Build a plan with the default 1 GiB reserve.
pub fn plan(target: &Path) -> io::Result<SanitizePlan> {
    plan_with_reserve(target, DEFAULT_RESERVE_MIB)
}

/// Build a plan with an explicit reserve in MiB.
pub fn plan_with_reserve(target: &Path, reserve_mib: u64) -> io::Result<SanitizePlan> {
    let meta = fs::metadata(target)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a directory on the target volume",
                target.display()
            ),
        ));
    }
    let free_bytes = fs2::free_space(target)?;
    let reserve_bytes = reserve_mib * 1024 * 1024;
    let bytes_to_write = free_bytes.saturating_sub(reserve_bytes);
    if bytes_to_write == 0 {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "free space ({free_bytes} bytes) is at or below the reserve ({reserve_bytes} bytes); nothing to overwrite"
            ),
        ));
    }
    let mut tag = [0u8; 4];
    os_random(&mut tag)?;
    let filler_path = target.join(format!(
        ".gone-fill-{}-{:08x}",
        std::process::id(),
        u32::from_le_bytes(tag)
    ));
    Ok(SanitizePlan {
        target_dir: target.to_path_buf(),
        filler_path,
        free_bytes,
        reserve_bytes,
        bytes_to_write,
        chunk_size: DEFAULT_CHUNK_SIZE,
    })
}

/// Progress snapshot delivered after every chunk.
#[derive(Debug, Clone, Copy)]
pub struct SanitizeProgress {
    pub bytes_written: u64,
    pub bytes_planned: u64,
    pub elapsed: Duration,
}

impl SanitizeProgress {
    /// Average write throughput in MiB/s since the run started.
    pub fn throughput_mibs(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.bytes_written as f64 / (1024.0 * 1024.0) / secs
    }
}

/// Outcome of a sanitize run.
#[derive(Debug)]
pub struct SanitizeReport {
    pub bytes_written: u64,
    pub elapsed: Duration,
    /// True when the cancel flag stopped the run early.
    pub canceled: bool,
    /// True when the disk filled up before the plan completed. With the
    /// default reserve this only happens when other processes consume
    /// space concurrently; the overwrite is still complete for every
    /// block the filler claimed.
    pub disk_full: bool,
    /// False means the filler file could not be removed and the path
    /// needs manual cleanup. The overwrite itself still happened.
    pub filler_removed: bool,
}

impl SanitizeReport {
    /// One plain-language sentence for the CLI and GUI.
    pub fn summary_line(&self) -> String {
        let gib = self.bytes_written as f64 / (1024.0 * 1024.0 * 1024.0);
        let secs = self.elapsed.as_secs_f64();
        let speed = if secs > 0.0 { gib / secs } else { 0.0 };
        let ending = if self.canceled {
            "Stopped early by user. Partial overwrite completed."
        } else if self.disk_full {
            "Disk filled completely. Overwrite finished."
        } else {
            "Planned overwrite finished."
        };
        let cleanup = if self.filler_removed {
            "Temporary filler removed."
        } else {
            "WARNING: temporary filler file could not be removed; delete it by hand."
        };
        format!(
            "Wrote {gib:.1} GiB of random data over free space in {secs:.0}s ({speed:.2} GiB/s). {ending} {cleanup}"
        )
    }
}

/// True for the OS-level "disk is full" errors we treat as a normal end
/// condition rather than a failure.
fn is_disk_full(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::StorageFull {
        return true;
    }
    // ENOSPC on Unix, ERROR_DISK_FULL on Windows.
    matches!(err.raw_os_error(), Some(28) | Some(112))
}

/// Fill `buf` from the OS random source.
fn os_random(buf: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(buf).map_err(|e| io::Error::other(format!("OS random source failed: {e}")))
}

/// Execute a plan, overwriting free space with an AES-256-CTR stream.
///
/// `cancel` is checked between chunks; `on_progress` fires after every
/// successful chunk. The filler file is removed on every exit path:
/// success, disk-full, cancel, and error.
pub fn run(
    plan: &SanitizePlan,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(SanitizeProgress),
) -> io::Result<SanitizeReport> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&plan.filler_path)?;

    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    os_random(&mut key)?;
    os_random(&mut iv)?;
    let mut cipher = Aes256Ctr::new_from_slices(&key, &iv).expect("key and iv sizes are fixed");

    let mut buf = vec![0u8; plan.chunk_size];
    let start = Instant::now();
    let mut written = 0u64;
    let mut canceled = false;
    let mut disk_full = false;

    let write_result = loop {
        if cancel.load(Ordering::Relaxed) {
            canceled = true;
            break Ok(());
        }
        if written >= plan.bytes_to_write {
            break Ok(());
        }
        let want = (plan.bytes_to_write - written).min(plan.chunk_size as u64) as usize;
        buf[..want].fill(0);
        cipher.apply_keystream(&mut buf[..want]);
        match file.write_all(&buf[..want]) {
            Ok(()) => {
                written += want as u64;
                on_progress(SanitizeProgress {
                    bytes_written: written,
                    bytes_planned: plan.bytes_to_write,
                    elapsed: start.elapsed(),
                });
            }
            Err(e) if is_disk_full(&e) => {
                disk_full = true;
                break Ok(());
            }
            Err(e) => break Err(e),
        }
    };

    let sync_result = file.sync_data();
    drop(file);
    let filler_removed = fs::remove_file(&plan.filler_path).is_ok();

    write_result?;
    sync_result?;

    Ok(SanitizeReport {
        bytes_written: written,
        elapsed: start.elapsed(),
        canceled,
        disk_full,
        filler_removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_on_tempdir_reports_free_space() {
        let dir = std::env::temp_dir().join(format!("gone-plan-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let plan = plan_with_reserve(&dir, 1).unwrap();
        assert!(plan.free_bytes > 0);
        assert_eq!(plan.bytes_to_write, plan.free_bytes - 1024 * 1024);
        assert!(plan.filler_path.starts_with(&dir));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plan_rejects_missing_directory() {
        let missing = std::env::temp_dir().join("gone-no-such-dir-xyz");
        assert!(plan(&missing).is_err());
    }

    #[test]
    fn plan_rejects_reserve_larger_than_free_space() {
        let dir = std::env::temp_dir().join(format!("gone-plan2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // Reserve larger than any real disk's free space (in MiB).
        assert!(plan_with_reserve(&dir, u64::MAX / 1024 / 1024).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_writes_capped_bytes_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("gone-run-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let plan = plan_with_reserve(&dir, 1)
            .unwrap()
            .with_max_bytes(8 * 1024 * 1024);
        let cancel = AtomicBool::new(false);
        let mut callbacks = 0u64;
        let report = run(&plan, &cancel, &mut |p| {
            callbacks += 1;
            assert!(p.bytes_written <= 8 * 1024 * 1024);
        })
        .unwrap();
        assert_eq!(report.bytes_written, 8 * 1024 * 1024);
        assert!(!report.canceled);
        assert!(!report.disk_full);
        assert!(report.filler_removed);
        assert!(callbacks >= 2); // 8 MiB in 4 MiB chunks
        assert!(!plan.filler_path.exists());
        // The directory holds nothing after cleanup.
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_honors_cancel_and_still_cleans_up() {
        let dir = std::env::temp_dir().join(format!("gone-cancel-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let plan = plan_with_reserve(&dir, 1)
            .unwrap()
            .with_max_bytes(64 * 1024 * 1024);
        let cancel = AtomicBool::new(false);
        let report = run(&plan, &cancel, &mut |_| {
            // Simulate Ctrl+C after the first chunk lands.
            cancel.store(true, Ordering::Relaxed);
        })
        .unwrap();
        assert!(report.canceled);
        assert!(report.bytes_written <= 64 * 1024 * 1024);
        assert!(report.filler_removed);
        assert!(!plan.filler_path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keystream_is_deterministic_per_key_and_not_zero() {
        let key = [7u8; 32];
        let iv = [3u8; 16];
        let mut a = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
        let mut b = Aes256Ctr::new_from_slices(&key, &iv).unwrap();
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        a.apply_keystream(&mut buf_a);
        b.apply_keystream(&mut buf_b);
        assert_eq!(buf_a, buf_b);
        assert!(buf_a.iter().any(|&x| x != 0));
    }
}
