//! gone: see what deleted data can still be recovered, erase it for good,
//! and prove it. Power-user interface; the GUI is the primary client.

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
    /// Erase recoverable deleted data from free space.
    /// Touches only unallocated space, never live files.
    Erase {
        /// Drive or partition to sanitize
        target: String,
        /// Show exactly what would happen, without writing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Rescan after erasing and produce a signed verification certificate
    Verify {
        /// Drive, partition, or disk image to verify
        target: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check { target } => {
            println!("check: {target} (engine not wired yet)");
        }
        Commands::Erase { target, dry_run } => {
            println!("erase: {target} dry_run={dry_run} (engine not wired yet)");
        }
        Commands::Verify { target } => {
            println!("verify: {target} (engine not wired yet)");
        }
    }
    Ok(())
}
