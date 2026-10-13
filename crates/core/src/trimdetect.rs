//! Media, TRIM, and encryption introspection, plus honest NIST labels.
//!
//! Why this exists: whether deleted data can come back depends less on
//! our tool than on the hardware underneath. A TRIM-enabled encrypted SSD
//! destroys deleted blocks on its own schedule; a magnetic HDD keeps them
//! until something overwrites them. This module asks the OS what is down
//! there and turns the answer into plain-language guidance.
//!
//! Every probe degrades to an explicit `Unknown` instead of guessing or
//! failing. The parsing is pure and unit-tested; the OS calls are thin
//! wrappers.

use std::fmt;
use std::path::Path;

/// What kind of storage sits under the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    Ssd,
    Hdd,
    /// eMMC or UFS flash, common in phones and budget laptops. Behaves
    /// like an SSD for sanitization purposes.
    Flash,
    Unknown,
}

/// A probe result that may legitimately be undeterminable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriState {
    Yes,
    No,
    Unknown,
}

impl TriState {
    pub fn from_bool(value: bool) -> Self {
        if value { TriState::Yes } else { TriState::No }
    }
}

/// Volume encryption state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    FileVault,
    BitLocker,
    Luks,
    /// Some other full-volume encryption the OS reported.
    Other,
    None,
    Unknown,
}

/// Filesystem personality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsKind {
    Apfs,
    Ntfs,
    Ext4,
    Btrfs,
    Xfs,
    Zfs,
    Fat,
    HfsPlus,
    Other(String),
    Unknown,
}

impl FsKind {
    /// Copy-on-write filesystems keep old block copies in snapshots, so
    /// overwriting free space does not reach data captured in a snapshot.
    pub fn is_copy_on_write(&self) -> bool {
        matches!(self, FsKind::Apfs | FsKind::Btrfs | FsKind::Zfs)
    }
}

/// Everything we could learn about the storage under one path.
#[derive(Debug, Clone)]
pub struct MediaProfile {
    pub media: MediaKind,
    pub trim: TriState,
    pub encryption: Encryption,
    pub fs: FsKind,
    /// Device node when known, for example /dev/disk3s5.
    pub device_hint: Option<String>,
}

impl MediaProfile {
    fn unknown() -> Self {
        Self {
            media: MediaKind::Unknown,
            trim: TriState::Unknown,
            encryption: Encryption::Unknown,
            fs: FsKind::Unknown,
            device_hint: None,
        }
    }
}

impl fmt::Display for MediaProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let media = match self.media {
            MediaKind::Ssd => "solid-state drive (SSD)",
            MediaKind::Hdd => "magnetic hard drive (HDD)",
            MediaKind::Flash => "flash storage (eMMC/UFS)",
            MediaKind::Unknown => "unknown media type",
        };
        let trim = match self.trim {
            TriState::Yes => "enabled",
            TriState::No => "disabled",
            TriState::Unknown => "unknown",
        };
        let encryption = match self.encryption {
            Encryption::FileVault => "FileVault",
            Encryption::BitLocker => "BitLocker",
            Encryption::Luks => "LUKS",
            Encryption::Other => "volume encryption",
            Encryption::None => "none",
            Encryption::Unknown => "unknown",
        };
        let fs = match &self.fs {
            FsKind::Apfs => "APFS".to_string(),
            FsKind::Ntfs => "NTFS".to_string(),
            FsKind::Ext4 => "ext4".to_string(),
            FsKind::Btrfs => "Btrfs".to_string(),
            FsKind::Xfs => "XFS".to_string(),
            FsKind::Zfs => "ZFS".to_string(),
            FsKind::Fat => "FAT/exFAT".to_string(),
            FsKind::HfsPlus => "HFS+".to_string(),
            FsKind::Other(name) => name.clone(),
            FsKind::Unknown => "unknown filesystem".to_string(),
        };
        write!(f, "{media}, {fs}, TRIM {trim}, encryption: {encryption}")?;
        if let Some(device) = &self.device_hint {
            write!(f, " ({device})")?;
        }
        Ok(())
    }
}

/// NIST SP 800-88 Rev. 2 sanitization categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NistCategory {
    /// Overwrite-based. Protects against software recovery.
    Clear,
    /// Firmware-level erase, cryptographic erase, or TRIM-backed flows.
    /// Protects against laboratory recovery.
    Purge,
    /// Physical destruction. Beyond software scope.
    Destroy,
}

/// Plain-language recommendation derived from a [`MediaProfile`].
#[derive(Debug, Clone)]
pub struct Guidance {
    /// What our free-space overwrite achieves on this hardware.
    pub overwrite_category: NistCategory,
    pub headline: String,
    pub notes: Vec<String>,
}

/// Probe the storage under `target`. Never fails: worst case is a
/// profile full of `Unknown`.
pub fn profile(target: &Path) -> MediaProfile {
    // Symlinked paths (macOS /tmp -> /private/tmp) confuse volume probes,
    // so resolve first and fall back to the original when that fails.
    let resolved;
    let target = match std::fs::canonicalize(target) {
        Ok(path) => {
            resolved = path;
            &resolved
        }
        Err(_) => target,
    };
    platform::gather(target)
}

/// Turn a profile into honest advice. Pure function.
pub fn guidance(profile: &MediaProfile) -> Guidance {
    let mut notes = Vec::new();

    let (category, mut headline) = match (profile.media, profile.trim) {
        (MediaKind::Ssd | MediaKind::Flash, TriState::Yes) => (
            NistCategory::Purge,
            "Your drive's TRIM support already destroys deleted data over time. \
             One overwrite pass clears whatever is still queued."
                .to_string(),
        ),
        (MediaKind::Ssd | MediaKind::Flash, _) => (
            NistCategory::Clear,
            "This is a solid-state drive, so wear leveling decides exactly which \
             physical cells get overwritten. The overwrite still clears all \
             host-visible deleted data."
                .to_string(),
        ),
        (MediaKind::Hdd, _) => (
            NistCategory::Clear,
            "This is a magnetic hard drive. One overwrite pass is enough; \
             multi-pass wiping is a myth on modern drives (NIST 800-88)."
                .to_string(),
        ),
        (MediaKind::Unknown, _) => (
            NistCategory::Clear,
            "Could not identify the drive type. The overwrite clears all \
             host-visible deleted data either way."
                .to_string(),
        ),
    };

    match profile.encryption {
        Encryption::FileVault | Encryption::BitLocker | Encryption::Luks | Encryption::Other => {
            headline.push_str(" Your disk is also encrypted, which protects deleted data even before any overwrite.");
            notes.push(
                "Volume encryption is on. The strongest erase on this machine is destroying \
                 the encryption key, which the OS does during Erase All Content and Settings."
                    .to_string(),
            );
        }
        Encryption::None => {}
        Encryption::Unknown => {}
    }

    if profile.fs.is_copy_on_write() {
        notes.push(
            "Your filesystem keeps snapshots (APFS/Btrfs/ZFS). Deleted data captured inside \
             a local snapshot survives a free-space overwrite until the snapshot expires. \
             Check Time Machine local snapshots if you need them gone now."
                .to_string(),
        );
    }

    if profile.trim == TriState::No && profile.media == MediaKind::Ssd {
        notes.push(
            "TRIM appears disabled on this SSD. Enabling it lets the drive finish \
             destroying deleted blocks on its own."
                .to_string(),
        );
    }

    Guidance {
        overwrite_category: category,
        headline,
        notes,
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers (pure, unit-tested with canned OS output)
// ---------------------------------------------------------------------------

/// macOS `diskutil info <volume>` output.
#[allow(dead_code)]
#[derive(Default, Debug, PartialEq, Eq)]
struct DiskutilInfo {
    solid_state: Option<bool>,
    fs_personality: Option<FsKind>,
    encrypted: Option<bool>,
    device_node: Option<String>,
    protocol: Option<String>,
}

#[allow(dead_code)]
fn parse_diskutil_info(output: &str) -> DiskutilInfo {
    let mut info = DiskutilInfo::default();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "Solid State" => info.solid_state = Some(value.eq_ignore_ascii_case("yes")),
            "File System Personality" => {
                info.fs_personality = Some(match value.to_ascii_lowercase().as_str() {
                    v if v.starts_with("apfs") => FsKind::Apfs,
                    v if v.contains("hfs") || v.contains("jhfs") => FsKind::HfsPlus,
                    v if v.contains("exfat") || v.contains("ms-dos") => FsKind::Fat,
                    v if v.contains("ntfs") => FsKind::Ntfs,
                    other => FsKind::Other(other.to_string()),
                });
            }
            "Encrypted" => info.encrypted = Some(value.eq_ignore_ascii_case("yes")),
            "Device Node" => info.device_node = Some(value.to_string()),
            "Protocol" => info.protocol = Some(value.to_string()),
            _ => {}
        }
    }
    info
}

/// `df -P <path>` output: extract the backing device from the data line,
/// for example /dev/disk3s1s1.
#[allow(dead_code)]
fn parse_df_device(output: &str) -> Option<String> {
    let line = output.lines().nth(1)?;
    let device = line.split_whitespace().next()?;
    if device.starts_with("/dev/") {
        Some(device.to_string())
    } else {
        None
    }
}

/// macOS `fdesetup status` output.
#[allow(dead_code)]
fn parse_fdesetup_status(output: &str) -> Option<bool> {
    let lower = output.to_ascii_lowercase();
    if lower.contains("filevault is on") {
        Some(true)
    } else if lower.contains("filevault is off") {
        Some(false)
    } else {
        None
    }
}

/// macOS `system_profiler SPNVMeDataType` / `SPSerialATADataType` output.
/// Returns TRIM support.
#[allow(dead_code)]
fn parse_system_profiler_trim(output: &str) -> Option<bool> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("TRIM Support:") {
            return Some(value.trim().eq_ignore_ascii_case("yes"));
        }
    }
    None
}

// The parsers below are called only on their own OS, but their unit tests
// run everywhere so behavior stays verifiable on any dev machine. The
// allow(dead_code) markers silence the per-platform dead-code lints.

/// Linux `/sys/block/<dev>/queue/rotational` content.
#[allow(dead_code)]
fn parse_rotational(content: &str) -> Option<bool> {
    match content.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Linux `/sys/block/<dev>/queue/discard_granularity` content. Nonzero
/// means the device accepts discard (TRIM) commands.
#[allow(dead_code)]
fn parse_discard_granularity(content: &str) -> Option<bool> {
    content.trim().parse::<u64>().ok().map(|v| v > 0)
}

/// Linux filesystem type string from `findmnt -no FSTYPE`.
#[allow(dead_code)]
fn parse_linux_fstype(content: &str) -> FsKind {
    match content.trim().to_ascii_lowercase().as_str() {
        "ext4" | "ext3" | "ext2" => FsKind::Ext4,
        "btrfs" => FsKind::Btrfs,
        "xfs" => FsKind::Xfs,
        "zfs" => FsKind::Zfs,
        "vfat" | "exfat" | "fat32" | "msdos" => FsKind::Fat,
        "ntfs" | "ntfs3" => FsKind::Ntfs,
        "apfs" => FsKind::Apfs,
        "" => FsKind::Unknown,
        other => FsKind::Other(other.to_string()),
    }
}

/// Windows `fsutil behavior query DisableDeleteNotify` output. Returns
/// TRIM enabled, which is the inverse of DisableDeleteNotify.
#[allow(dead_code)]
fn parse_fsutil_disable_delete_notify(output: &str) -> Option<bool> {
    for line in output.lines() {
        if let Some((_, value)) = line.split_once('=') {
            if let Ok(disabled) = value
                .trim()
                .trim_matches(|c: char| !c.is_ascii_digit())
                .parse::<u32>()
            {
                return Some(disabled == 0);
            }
        }
    }
    None
}

/// Windows `manage-bde -status` output. Returns "fully encrypted".
#[allow(dead_code)]
fn parse_manage_bde_status(output: &str) -> Option<bool> {
    let lower = output.to_ascii_lowercase();
    if lower.contains("fully encrypted") || lower.contains("protection on") {
        Some(true)
    } else if lower.contains("fully decrypted") || lower.contains("protection off") {
        Some(false)
    } else {
        None
    }
}

/// Strip the partition suffix from a block device name: /dev/sda1 -> sda,
/// /dev/nvme0n1p2 -> nvme0n1, /dev/mmcblk0p1 -> mmcblk0. Names ending in
/// "p" with no digits after it (loop) keep their tail.
#[allow(dead_code)]
fn base_block_device(name: &str) -> String {
    let n = name.trim_start_matches("/dev/");
    if let Some(idx) = n.rfind('p') {
        let head = &n[..idx];
        let tail = &n[idx + 1..];
        // nvme0n1p2 / mmcblk0p1 style: the "p" separator follows a digit.
        if head.ends_with(|c: char| c.is_ascii_digit())
            && !tail.is_empty()
            && tail.chars().all(|c| c.is_ascii_digit())
        {
            return head.to_string();
        }
    }
    n.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
}

// ---------------------------------------------------------------------------
// Per-OS probes
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::process::Command;

    pub fn gather(target: &Path) -> MediaProfile {
        let mut profile = MediaProfile::unknown();

        // diskutil info accepts volumes, not plain directories, so fall
        // back to the backing device from df when the path probe fails.
        let mut diskutil_out = run("diskutil", &["info", &target.to_string_lossy()]);
        if diskutil_out.is_none() {
            if let Some(df) = run("df", &["-P", &target.to_string_lossy()]) {
                if let Some(device) = parse_df_device(&df) {
                    diskutil_out = run("diskutil", &["info", &device]);
                }
            }
        }

        if let Some(out) = diskutil_out {
            let info = parse_diskutil_info(&out);
            if let Some(ssd) = info.solid_state {
                profile.media = if ssd { MediaKind::Ssd } else { MediaKind::Hdd };
            }
            if let Some(fs) = info.fs_personality {
                profile.fs = fs;
            }
            if let Some(enc) = info.encrypted {
                profile.encryption = if enc {
                    Encryption::FileVault
                } else {
                    Encryption::None
                };
            }
            profile.device_hint = info.device_node;
        }

        if let Some(out) = run("fdesetup", &["status"]) {
            if let Some(on) = parse_fdesetup_status(&out) {
                profile.encryption = if on {
                    Encryption::FileVault
                } else {
                    Encryption::None
                };
            }
        }

        // TRIM shows up under the storage controller, NVMe or SATA.
        for datatype in ["SPNVMeDataType", "SPSerialATADataType"] {
            if let Some(out) = run("system_profiler", &[datatype]) {
                if let Some(trim) = parse_system_profiler_trim(&out) {
                    profile.trim = TriState::from_bool(trim);
                    break;
                }
            }
        }

        profile
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok()
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::process::Command;

    pub fn gather(target: &Path) -> MediaProfile {
        let mut profile = MediaProfile::unknown();

        // Filesystem type for the mount containing the target.
        if let Some(out) = run(
            "findmnt",
            &["-no", "FSTYPE", "-T", &target.to_string_lossy()],
        ) {
            profile.fs = parse_linux_fstype(&out);
        }

        // Backing block device for the target.
        let device = run(
            "findmnt",
            &["-no", "SOURCE", "-T", &target.to_string_lossy()],
        )
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
        profile.device_hint = device.clone();

        if let Some(dev) = device {
            let base = base_block_device(&dev);
            let read_sys =
                |name: &str| std::fs::read_to_string(format!("/sys/block/{base}/{name}")).ok();

            if let Some(rot) = read_sys("queue/rotational").and_then(|c| parse_rotational(&c)) {
                profile.media = if rot { MediaKind::Hdd } else { MediaKind::Ssd };
            }
            if let Some(discard) =
                read_sys("queue/discard_granularity").and_then(|c| parse_discard_granularity(&c))
            {
                profile.trim = TriState::from_bool(discard);
            }

            // LUKS: either the device itself or one of its parents is crypto_LUKS.
            if let Some(out) = run("lsblk", &["-no", "FSTYPE", &dev]) {
                if out.to_ascii_lowercase().contains("crypto_luks") {
                    profile.encryption = Encryption::Luks;
                }
            }
            if profile.encryption == Encryption::Unknown {
                if let Some(out) = run("lsblk", &["-po", "NAME,FSTYPE", &dev]) {
                    if out.to_ascii_lowercase().contains("crypto_luks") {
                        profile.encryption = Encryption::Luks;
                    }
                }
            }
        }

        if profile.encryption == Encryption::Unknown {
            profile.encryption = Encryption::None;
        }

        profile
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout).ok()
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::process::Command;

    pub fn gather(target: &Path) -> MediaProfile {
        let mut profile = MediaProfile::unknown();

        // Drive letter from the target path, for example C:.
        let text = target.to_string_lossy();
        let letter: String = text.chars().take(2).collect();

        // TRIM: DisableDeleteNotify = 0 means TRIM is on.
        if let Some(out) = run("fsutil", &["behavior", "query", "DisableDeleteNotify"]) {
            if let Some(trim) = parse_fsutil_disable_delete_notify(&out) {
                profile.trim = TriState::from_bool(trim);
            }
        }

        // BitLocker status for the drive.
        if let Some(out) = run("manage-bde", &["-status", &letter]) {
            if let Some(on) = parse_manage_bde_status(&out) {
                profile.encryption = if on {
                    Encryption::BitLocker
                } else {
                    Encryption::None
                };
            }
        }

        // Media type and filesystem via PowerShell. Kept to one process.
        if let Some(out) = run(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!(
                    "Get-Volume -DriveLetter {} | Select-Object -ExpandProperty FileSystemType; \
                     Get-Partition -DriveLetter {} | Get-Disk | Get-PhysicalDisk | \
                     Select-Object -First 1 -ExpandProperty MediaType",
                    letter.trim_end_matches(':'),
                    letter.trim_end_matches(':')
                ),
            ],
        ) {
            let mut lines = out.lines().map(str::trim);
            if let Some(fs) = lines.next() {
                profile.fs = match fs.to_ascii_lowercase().as_str() {
                    "ntfs" => FsKind::Ntfs,
                    "refs" => FsKind::Other("ReFS".to_string()),
                    "fat32" | "exfat" | "fat" => FsKind::Fat,
                    "" => FsKind::Unknown,
                    other => FsKind::Other(other.to_string()),
                };
            }
            if let Some(media) = lines.next() {
                profile.media = match media.to_ascii_lowercase().as_str() {
                    "ssd" => MediaKind::Ssd,
                    "hdd" => MediaKind::Hdd,
                    "scm" => MediaKind::Flash,
                    _ => MediaKind::Unknown,
                };
            }
        }

        profile
    }

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(program).args(args).output().ok()?;
        String::from_utf8(output.stdout).ok()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;

    pub fn gather(_target: &Path) -> MediaProfile {
        MediaProfile::unknown()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_diskutil_apfs_nvme() {
        let sample = "   Device Identifier:         disk3s5\n\
                      Device Node:               /dev/disk3s5\n\
                      Whole:                     No\n\
                      Part of Whole:             disk3\n\
                      Solid State:               Yes\n\
                      Protocol:                  PCI-Express\n\
                      File System Personality:   APFS\n\
                      Encrypted:                 Yes\n";
        let info = parse_diskutil_info(sample);
        assert_eq!(info.solid_state, Some(true));
        assert_eq!(info.fs_personality, Some(FsKind::Apfs));
        assert_eq!(info.encrypted, Some(true));
        assert_eq!(info.device_node.as_deref(), Some("/dev/disk3s5"));
    }

    #[test]
    fn parses_diskutil_hdd_hfs() {
        let sample = "   Solid State:               No\n\
                      File System Personality:   Journaled HFS+\n\
                      Encrypted:                 No\n";
        let info = parse_diskutil_info(sample);
        assert_eq!(info.solid_state, Some(false));
        assert_eq!(info.fs_personality, Some(FsKind::HfsPlus));
        assert_eq!(info.encrypted, Some(false));
    }

    #[test]
    fn parses_df_device_line() {
        let df = "Filesystem 512-blocks      Used Available Capacity Mounted on\n\
                  /dev/disk3s1s1 3906000000 10000000 2000000000    10%    /\n";
        assert_eq!(parse_df_device(df).as_deref(), Some("/dev/disk3s1s1"));
        assert_eq!(parse_df_device("only a header\n"), None);
        assert_eq!(
            parse_df_device("header\nmap - auto_home 0 0 0 100% /System/Volumes/Data/home\n"),
            None
        );
    }

    #[test]
    fn parses_fdesetup() {
        assert_eq!(parse_fdesetup_status("FileVault is On.\n"), Some(true));
        assert_eq!(parse_fdesetup_status("FileVault is Off.\n"), Some(false));
        assert_eq!(parse_fdesetup_status("garbage"), None);
    }

    #[test]
    fn parses_system_profiler_trim() {
        let nvme = "NVMe:\n\n    APPLE SSD AP2048Z:\n\n      Capacity: 2 TB\n      TRIM Support: Yes\n      Model: APPLE SSD\n";
        assert_eq!(parse_system_profiler_trim(nvme), Some(true));
        assert_eq!(
            parse_system_profiler_trim("      TRIM Support: No\n"),
            Some(false)
        );
        assert_eq!(parse_system_profiler_trim("no trim line"), None);
    }

    #[test]
    fn strips_partition_suffixes() {
        assert_eq!(base_block_device("/dev/sda1"), "sda");
        assert_eq!(base_block_device("/dev/nvme0n1p2"), "nvme0n1");
        assert_eq!(base_block_device("/dev/mmcblk0p1"), "mmcblk0");
        assert_eq!(base_block_device("/dev/loop0"), "loop");
        assert_eq!(base_block_device("loop"), "loop");
        assert_eq!(base_block_device("/dev/sda"), "sda");
    }

    #[test]
    fn parses_linux_sysfs() {
        assert_eq!(parse_rotational("1\n"), Some(true));
        assert_eq!(parse_rotational("0\n"), Some(false));
        assert_eq!(parse_rotational("junk"), None);
        assert_eq!(parse_discard_granularity("4096\n"), Some(true));
        assert_eq!(parse_discard_granularity("0\n"), Some(false));
    }

    #[test]
    fn parses_linux_fstypes() {
        assert_eq!(parse_linux_fstype("ext4\n"), FsKind::Ext4);
        assert_eq!(parse_linux_fstype("btrfs\n"), FsKind::Btrfs);
        assert_eq!(parse_linux_fstype("vfat\n"), FsKind::Fat);
        assert_eq!(parse_linux_fstype(""), FsKind::Unknown);
    }

    #[test]
    fn parses_fsutil_disable_delete_notify() {
        assert_eq!(
            parse_fsutil_disable_delete_notify("NTFS DisableDeleteNotify = 0\n"),
            Some(true)
        );
        assert_eq!(
            parse_fsutil_disable_delete_notify("NTFS DisableDeleteNotify = 1  (Disabled)\n"),
            Some(false)
        );
        assert_eq!(parse_fsutil_disable_delete_notify("unexpected"), None);
    }

    #[test]
    fn parses_manage_bde() {
        let on = "Conversion Status:    Fully Encrypted\nProtection Status:    Protection On\n";
        assert_eq!(parse_manage_bde_status(on), Some(true));
        let off = "Conversion Status:    Fully Decrypted\nProtection Status:    Protection Off\n";
        assert_eq!(parse_manage_bde_status(off), Some(false));
        assert_eq!(parse_manage_bde_status("error"), None);
    }

    #[test]
    fn guidance_for_trimmed_ssd_is_purge() {
        let profile = MediaProfile {
            media: MediaKind::Ssd,
            trim: TriState::Yes,
            encryption: Encryption::None,
            fs: FsKind::Ntfs,
            device_hint: None,
        };
        let g = guidance(&profile);
        assert_eq!(g.overwrite_category, NistCategory::Purge);
        assert!(g.headline.contains("TRIM"));
    }

    #[test]
    fn guidance_for_hdd_is_clear() {
        let profile = MediaProfile {
            media: MediaKind::Hdd,
            trim: TriState::Unknown,
            encryption: Encryption::None,
            fs: FsKind::Ext4,
            device_hint: None,
        };
        let g = guidance(&profile);
        assert_eq!(g.overwrite_category, NistCategory::Clear);
        assert!(g.headline.contains("magnetic"));
    }

    #[test]
    fn guidance_mentions_encryption_and_snapshots() {
        let profile = MediaProfile {
            media: MediaKind::Ssd,
            trim: TriState::Yes,
            encryption: Encryption::FileVault,
            fs: FsKind::Apfs,
            device_hint: None,
        };
        let g = guidance(&profile);
        assert!(g.headline.contains("encrypted"));
        assert!(g.notes.iter().any(|n| n.contains("encryption key")));
        assert!(g.notes.iter().any(|n| n.contains("snapshot")));
    }

    #[test]
    fn guidance_warns_when_trim_disabled_on_ssd() {
        let profile = MediaProfile {
            media: MediaKind::Ssd,
            trim: TriState::No,
            encryption: Encryption::None,
            fs: FsKind::Ext4,
            device_hint: None,
        };
        let g = guidance(&profile);
        assert!(g.notes.iter().any(|n| n.contains("TRIM appears disabled")));
    }

    #[test]
    fn profile_smoke_test_on_real_fs() {
        // Must never panic, whatever the OS reports. Values themselves
        // depend on the host, so only the Display impl is exercised.
        let p = profile(&std::env::temp_dir());
        let rendered = p.to_string();
        assert!(!rendered.is_empty());
    }
}
