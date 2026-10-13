//! gone: see what deleted data can still be recovered, erase it for good,
//! and prove it. Power-user interface; the GUI is the primary client.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "gone",
    version,
    about = "See what deleted data can still be recovered. Erase it for good. Prove it.",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a drive or disk image and show what is still recoverable.
    /// Always read-only; never changes anything on the target.
    Check {
        /// Drive, partition, or disk image to scan
        target: String,
    },
    /// Overwrite every deleted byte sitting in a volume's free space.
    /// Live files are never touched: the engine grows one filler file,
    /// then removes it. Aligned with NIST SP 800-88 Rev. 2.
    Erase {
        /// Directory on the volume to sanitize, for example / or /Volumes/USB
        target: String,
        /// Show the plan (free space, reserve, bytes to overwrite) and stop
        #[arg(long)]
        dry_run: bool,
        /// Skip the interactive type-the-path confirmation
        #[arg(long)]
        yes: bool,
        /// Overwrite at most this many MiB. Testing escape hatch.
        #[arg(long, hide = true)]
        max_mib: Option<u64>,
    },
    /// Rescan after erasing and produce a signed verification certificate
    /// (JSON + human-readable TXT + PDF) proving what is still recoverable
    Verify {
        /// Drive, partition, or disk image to verify
        target: String,
        /// Directory to write certificate files into
        #[arg(long, default_value = ".")]
        out: String,
    },
    /// Show what kind of storage sits under a path: SSD or HDD, TRIM,
    /// encryption, filesystem, and what an overwrite achieves on it
    Inspect {
        /// Directory on the volume to inspect
        target: String,
    },
    /// Strip hidden metadata (EXIF, XMP, IPTC, C2PA) from a photo or
    /// document. Always writes a NEW file; the original is never touched
    #[cfg(unix)]
    Scrub {
        /// JPEG, PNG, or PDF file to scrub
        target: String,
        /// Output path. Default: <name>.scrubbed.<ext> next to the original
        #[arg(long)]
        out: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check { target } => {
            check(&target)?;
        }
        Commands::Erase {
            target,
            dry_run,
            yes,
            max_mib,
        } => {
            erase(&target, dry_run, yes, max_mib)?;
        }
        Commands::Verify { target, out } => {
            verify(&target, &out)?;
        }
        #[cfg(unix)]
        Commands::Scrub { target, out } => {
            let source = std::path::PathBuf::from(&target);
            if !source.is_file() {
                bail!("no such file: {target}");
            }
            let report = match &out {
                Some(path) => gone_core::scrub::scrub_file(&source, std::path::Path::new(path)),
                None => gone_core::scrub::scrub_in_place_clone(&source),
            }
            .map_err(|e| anyhow::anyhow!(e))
            .with_context(|| format!("cannot scrub {target}"))?;
            println!("{}", report.summary_line());
            for item in &report.items_removed {
                println!("  - {item}");
            }
            println!("Clean copy: {}", report.output_path.display());
        }
        Commands::Inspect { target } => {
            let profile = gone_core::trimdetect::profile(std::path::Path::new(&target));
            println!("{profile}");
            let guidance = gone_core::trimdetect::guidance(&profile);
            let category = match guidance.overwrite_category {
                gone_core::trimdetect::NistCategory::Clear => "Clear",
                gone_core::trimdetect::NistCategory::Purge => "Purge",
                gone_core::trimdetect::NistCategory::Destroy => "Destroy",
            };
            println!("NIST 800-88 category of an overwrite here: {category}");
            println!("{}", guidance.headline);
            for note in &guidance.notes {
                println!("Note: {note}");
            }
        }
    }
    Ok(())
}

fn check(target: &str) -> anyhow::Result<()> {
    let mut source = open_target(target)?;
    let summary = gone_core::scan::scan_source(&mut source, 1024 * 1024)
        .with_context(|| format!("scan failed on {target}"))?;
    println!("{summary}");
    Ok(())
}

/// Open a disk image, or a device the OS lists, read-only.
///
/// A listed device is opened with the size the OS reported. Anything else
/// is sized by seeking, and a device node can report 0 that way. A source
/// of 0 bytes is refused: scanning nothing must not read as a clean result.
fn open_target(target: &str) -> anyhow::Result<gone_core::io::EvidenceSource> {
    let path = std::path::Path::new(target);
    if !path.is_file() && looks_like_device(target) {
        if let Ok(devices) = gone_core::devices::enumerate() {
            if let Some(device) = devices.iter().find(|device| device_matches(device, target)) {
                return gone_core::devices::open_for_scan(device).map_err(|err| {
                    if gone_core::devices::is_permission_error(&err) {
                        anyhow::anyhow!("{}", gone_core::devices::access_denied_message())
                    } else {
                        anyhow::anyhow!("cannot open {}: {err}", device.device_node)
                    }
                });
            }
        }
    }
    let source = gone_core::io::EvidenceSource::open(path)
        .with_context(|| format!("cannot open {target}"))?;
    if source.size() == 0 {
        bail!(
            "{target} reports a size of 0 bytes, so nothing was read and there is no result. \
             For a disk, pass a whole disk (for example /dev/disk4) or a mounted volume."
        );
    }
    Ok(source)
}

fn looks_like_device(target: &str) -> bool {
    target.starts_with("/dev/")
        || target.starts_with(r"\\.\")
        || target.starts_with("disk")
        || target.starts_with("rdisk")
}

fn device_matches(device: &gone_core::devices::Device, target: &str) -> bool {
    device.device_node == target
        || device.raw_node.as_deref() == Some(target)
        || device.identifier == target
        || target == format!("/dev/{}", device.identifier)
        || target == format!("/dev/r{}", device.identifier)
}

fn verify(target: &str, out: &str) -> anyhow::Result<()> {
    let mut source = open_target(target)?;
    let verification = gone_core::verify::rescan(&mut source, 1024 * 1024, None)
        .with_context(|| format!("verify scan failed on {target}"))?;
    println!("{}", verification.outcome_sentence);
    println!("Media: {}", verification.media_profile);
    println!("NIST 800-88 category here: {}", verification.nist_category);

    let keypair = gone_core::verify::SigningKeypair::generate();
    let certificate = gone_core::verify::Certificate::sign(&verification, &keypair);
    if !certificate.verify_signature() {
        bail!("internal error: freshly signed certificate failed verification");
    }
    let out_dir = std::path::Path::new(out);
    let mut files = certificate
        .write_files(out_dir)
        .context("cannot write certificate files")?;
    files.push(certificate.write_pdf(out_dir).context("cannot write PDF")?);
    for file in &files {
        println!("wrote {}", file.display());
    }
    println!("Signature checks out. Keep the JSON: any later edit to it is detectable.");
    Ok(())
}

fn erase(target: &str, dry_run: bool, yes: bool, max_mib: Option<u64>) -> anyhow::Result<()> {
    let path = std::path::PathBuf::from(target);
    let mut plan = gone_core::sanitize::plan_adaptive(&path)
        .with_context(|| format!("cannot plan erase on {target}"))?;
    if let Some(cap) = max_mib {
        plan = plan.with_max_bytes(cap * 1024 * 1024);
    }

    let free_gib = plan.free_bytes as f64 / 2f64.powi(30);
    let write_gib = plan.bytes_to_write as f64 / 2f64.powi(30);
    println!("Target volume directory: {}", plan.target_dir.display());
    println!(
        "Free space: {free_gib:.1} GiB, reserve kept: {} MiB",
        plan.reserve_bytes / 1024 / 1024
    );
    println!("Will overwrite {write_gib:.1} GiB of free space with random data.");
    println!(
        "Live files are never touched. Temporary filler: {}",
        plan.filler_path.display()
    );

    if dry_run {
        println!("Dry run: nothing was written.");
        return Ok(());
    }

    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("refusing to erase without confirmation; re-run with --yes or use --dry-run");
        }
        print!(
            "Type the target path to confirm ({}): ",
            plan.target_dir.display()
        );
        std::io::stdout().flush()?;
        let mut typed = String::new();
        std::io::stdin().read_line(&mut typed)?;
        if typed.trim() != plan.target_dir.to_string_lossy().as_ref() {
            bail!("path did not match; nothing was written");
        }
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    ctrlc::set_handler(move || {
        if flag.swap(true, Ordering::SeqCst) {
            eprintln!("\nForced quit.");
            std::process::exit(130);
        }
        eprintln!("\nStopping after the current chunk... press Ctrl+C again to force quit");
    })
    .context("cannot install Ctrl+C handler")?;

    let start = Instant::now();
    let show_progress = std::io::stdout().is_terminal();
    let mut last_print = Instant::now() - std::time::Duration::from_secs(1);
    let report = gone_core::sanitize::run(&plan, &cancel, &mut |p| {
        if show_progress && last_print.elapsed().as_millis() >= 300 {
            last_print = Instant::now();
            let pct = 100.0 * p.bytes_written as f64 / p.bytes_planned.max(1) as f64;
            print!(
                "\r{pct:5.1}%  {written:.1} / {planned:.1} GiB  at {rate:.0} MiB/s   ",
                written = p.bytes_written as f64 / 2f64.powi(30),
                planned = p.bytes_planned as f64 / 2f64.powi(30),
                rate = p.throughput_mibs(),
            );
            let _ = std::io::stdout().flush();
        }
    })
    .with_context(|| format!("erase failed on {target}"))?;

    println!();
    println!("{}", report.summary_line());
    println!("Elapsed: {:.1}s", start.elapsed().as_secs_f64());
    if path.is_file() {
        println!("Next step: run `gone verify {target}` to rescan and get a certificate.");
    } else {
        println!(
            "Folder erase is recorded above. A byte rescan needs a disk image: gone verify image.img"
        );
    }
    Ok(())
}
