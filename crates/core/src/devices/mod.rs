//! Physical disks and mounted volumes.
//!
//! Listing is read-only. Opening a device for a scan is read-only.
//! Nothing in this module writes to a device node.

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
mod linux;
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
mod macos;
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
mod plist;
#[cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]
mod windows;

use std::io::{self, ErrorKind};
use std::path::Path;

use serde::Serialize;

use crate::io::EvidenceSource;

/// A whole disk, or a mounted volume on one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Device {
    /// Name to show: the media name for a disk, the volume name for a volume.
    pub name: String,
    /// OS identifier, for example `disk0` or `nvme0n1`.
    pub identifier: String,
    /// Block device path, for example `/dev/disk0`.
    pub device_node: String,
    /// Raw device path when the OS has one. On macOS this is `/dev/rdiskN`.
    pub raw_node: Option<String>,
    pub size_bytes: u64,
    /// Logical sector size in bytes. Reads of a raw node must be a multiple of this.
    pub sector_size: u64,
    pub kind: DeviceKind,
    /// `Some(true)` for an SSD, `Some(false)` for a spinning disk, unknown otherwise.
    pub solid_state: Option<bool>,
    /// `Some(true)` internal, `Some(false)` external, unknown otherwise.
    pub internal: Option<bool>,
    pub volume_name: Option<String>,
    pub mount_point: Option<String>,
    /// Bus or transport, for example "Apple Fabric", "nvme", "usb".
    pub protocol: Option<String>,
    /// macOS `VirtualOrPhysical`, when diskutil reported it.
    pub virtual_or_physical: Option<String>,
}

/// Whole disk or mounted volume. Bare partitions without a mount point are not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Disk,
    Volume,
}

impl Device {
    /// Bytes that can be read as whole sectors. A raw device rejects a short tail.
    pub fn scan_len(&self) -> u64 {
        let sector = self.sector_size.max(512);
        self.size_bytes - (self.size_bytes % sector)
    }

    pub fn is_disk_image(&self) -> bool {
        self.protocol
            .as_deref()
            .is_some_and(|protocol| protocol.eq_ignore_ascii_case("Disk Image"))
    }

    /// One line for the results screen: media, where it sits, and the path.
    pub fn media_line(&self) -> String {
        let mut parts = Vec::new();
        match self.solid_state {
            Some(true) => parts.push("solid-state drive (SSD)".to_string()),
            Some(false) => parts.push("magnetic hard drive (HDD)".to_string()),
            None => {}
        }
        match self.internal {
            Some(true) => parts.push("internal".to_string()),
            Some(false) => parts.push("external".to_string()),
            None => {}
        }
        if let Some(protocol) = &self.protocol {
            parts.push(protocol.clone());
        }
        match self.kind {
            DeviceKind::Volume => parts.push("volume".to_string()),
            DeviceKind::Disk => parts.push("whole disk".to_string()),
        }
        if let Some(mount) = &self.mount_point {
            parts.push(mount.clone());
        } else {
            parts.push(self.device_node.clone());
        }
        parts.join(", ")
    }
}

/// Heading for the device list on this operating system.
pub fn host_heading() -> &'static str {
    if cfg!(target_os = "macos") {
        "This Mac"
    } else if cfg!(target_os = "windows") {
        "This PC"
    } else if cfg!(target_os = "linux") {
        "This computer"
    } else {
        "Disks"
    }
}

/// Sentence shown when the OS refuses a read. No password prompt, no sudo.
pub fn access_denied_message() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS blocked this. Run gone from an admin terminal, or grant Full Disk Access to the app."
    } else if cfg!(target_os = "windows") {
        "Windows blocked this. Run gone from an administrator terminal."
    } else if cfg!(target_os = "linux") {
        "Linux blocked this. Run gone as a user who can read the disk, or from an admin terminal."
    } else {
        "The system blocked reading this disk."
    }
}

pub fn is_permission_error(err: &io::Error) -> bool {
    err.kind() == ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(1) | Some(5) | Some(13))
}

/// Every disk and volume the OS reported, before the calm display filter.
pub fn enumerate() -> io::Result<Vec<Device>> {
    #[cfg(target_os = "macos")]
    {
        macos::list_live()
    }
    #[cfg(target_os = "linux")]
    {
        linux::list_live()
    }
    #[cfg(target_os = "windows")]
    {
        windows::list_live()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "Listing disks is not supported on this operating system.",
        ))
    }
}

/// Disks and volumes to show in the app.
///
/// Disk images are omitted (check those as files). Virtual containers are
/// omitted when the physical disk is the real device. Helper mounts such as
/// Preboot and VM are omitted because they are slices of a disk already listed.
pub fn list() -> io::Result<Vec<Device>> {
    Ok(for_display(enumerate()?))
}

pub fn for_display(mut devices: Vec<Device>) -> Vec<Device> {
    devices.retain(device_is_shown);
    devices.sort_by(|left, right| {
        let rank = |device: &Device| {
            let kind = match device.kind {
                DeviceKind::Disk => 0,
                DeviceKind::Volume => 1,
            };
            let place = match device.internal {
                Some(true) => 0,
                None => 1,
                Some(false) => 2,
            };
            (kind, place, device.name.to_lowercase())
        };
        rank(left).cmp(&rank(right))
    });
    devices
}

fn device_is_shown(device: &Device) -> bool {
    if device.is_disk_image() || device.size_bytes == 0 || device.device_node.is_empty() {
        return false;
    }
    match device.kind {
        DeviceKind::Disk => device.virtual_or_physical.as_deref() != Some("Virtual"),
        DeviceKind::Volume => device
            .mount_point
            .as_deref()
            .is_some_and(volume_mount_is_shown),
    }
}

fn volume_mount_is_shown(mount: &str) -> bool {
    if mount.is_empty() {
        return false;
    }
    if mount == "/" || mount == "/System/Volumes/Data" {
        return true;
    }
    if let Some(name) = mount.strip_prefix("/Volumes/") {
        return !name.is_empty() && name != "Recovery";
    }
    if mount.starts_with("/System/") || mount.starts_with("/private/") {
        return false;
    }
    // Windows drive roots and other mounts stay visible.
    true
}

/// Open `device` read-only for a scan.
///
/// Tries the raw node first (`/dev/rdiskN` on macOS) and falls back to the
/// block node when that open fails for a reason other than permission.
/// A permission error is returned as-is so the caller can show
/// [`access_denied_message`]. This function never writes.
pub fn open_for_scan(device: &Device) -> io::Result<EvidenceSource> {
    let size = device.scan_len();
    if size == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "this disk reported a size of zero",
        ));
    }
    let sector = device.sector_size.max(512);
    let mut fallback = None;
    if let Some(raw) = &device.raw_node {
        match open_probed(Path::new(raw), size, sector) {
            Ok(source) => return Ok(source),
            Err(err) if is_permission_error(&err) => return Err(err),
            Err(err) => fallback = Some(err),
        }
    }
    match open_probed(Path::new(&device.device_node), size, sector) {
        Ok(source) => Ok(source),
        Err(err) if is_permission_error(&err) => Err(err),
        Err(err) => Err(fallback.unwrap_or(err)),
    }
}

fn open_probed(path: &Path, size: u64, sector: u64) -> io::Result<EvidenceSource> {
    let mut source = EvidenceSource::open_with_size(path, size)?;
    let probe = probe_len(size, sector);
    let mut buf = vec![0u8; probe];
    let n = source.read_at(0, &mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "the disk read returned no bytes",
        ));
    }
    Ok(source)
}

fn probe_len(size: u64, sector: u64) -> usize {
    let sector = sector.max(512);
    let mut len = sector.max(4096).min(size);
    len -= len % sector;
    if len == 0 {
        len = sector.min(size);
    }
    len as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::scan_source_with;

    fn device(
        name: &str,
        kind: DeviceKind,
        protocol: Option<&str>,
        virtual_kind: Option<&str>,
        mount: Option<&str>,
        internal: Option<bool>,
    ) -> Device {
        Device {
            name: name.to_string(),
            identifier: name.to_string(),
            device_node: format!("/dev/{name}"),
            raw_node: None,
            size_bytes: 4096,
            sector_size: 512,
            kind,
            solid_state: Some(true),
            internal,
            volume_name: None,
            mount_point: mount.map(str::to_string),
            protocol: protocol.map(str::to_string),
            virtual_or_physical: virtual_kind.map(str::to_string),
        }
    }

    #[test]
    fn display_filter_keeps_real_disks_and_user_volumes() {
        let devices = vec![
            device(
                "disk0",
                DeviceKind::Disk,
                Some("Apple Fabric"),
                Some("Unknown"),
                None,
                Some(true),
            ),
            device(
                "disk3",
                DeviceKind::Disk,
                Some("Apple Fabric"),
                Some("Virtual"),
                None,
                Some(true),
            ),
            device(
                "disk5",
                DeviceKind::Disk,
                Some("Disk Image"),
                Some("Virtual"),
                None,
                Some(false),
            ),
            device(
                "preboot",
                DeviceKind::Volume,
                Some("Apple Fabric"),
                None,
                Some("/System/Volumes/Preboot"),
                Some(true),
            ),
            device(
                "data",
                DeviceKind::Volume,
                Some("Apple Fabric"),
                None,
                Some("/System/Volumes/Data"),
                Some(true),
            ),
            device(
                "hd",
                DeviceKind::Volume,
                Some("Apple Fabric"),
                None,
                Some("/"),
                Some(true),
            ),
            device(
                "usb",
                DeviceKind::Volume,
                Some("USB"),
                None,
                Some("/Volumes/Photos"),
                Some(false),
            ),
            device(
                "gone",
                DeviceKind::Volume,
                Some("Disk Image"),
                None,
                Some("/Volumes/gone-test"),
                Some(false),
            ),
        ];
        let shown = for_display(devices);
        let names: Vec<_> = shown.iter().map(|device| device.name.as_str()).collect();
        assert_eq!(names, vec!["disk0", "data", "hd", "usb"]);
    }

    #[test]
    fn access_denied_message_does_not_ask_for_a_password() {
        let message = access_denied_message();
        let lower = message.to_lowercase();
        assert!(!lower.contains("password"));
        assert!(!message.contains("sudo"));
        assert!(!message.contains('\u{2014}'));
        if cfg!(target_os = "macos") {
            assert_eq!(
                message,
                "macOS blocked this. Run gone from an admin terminal, or grant Full Disk Access to the app."
            );
        }
    }

    #[test]
    fn permission_errors_match_eperm_and_eacces() {
        assert!(is_permission_error(&io::Error::from_raw_os_error(1)));
        assert!(is_permission_error(&io::Error::from_raw_os_error(13)));
        assert!(!is_permission_error(&io::Error::from_raw_os_error(2)));
    }

    #[test]
    fn open_for_scan_reads_a_file_with_a_known_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, vec![0u8; 8192]).unwrap();
        let mut sample = device("img", DeviceKind::Disk, None, None, None, None);
        sample.device_node = path.display().to_string();
        sample.size_bytes = 8192;
        sample.sector_size = 512;
        let mut source = open_for_scan(&sample).unwrap();
        let mut ticks = 0u64;
        let run = scan_source_with(&mut source, 4096, None, |progress| {
            ticks += 1;
            assert_eq!(progress.bytes_total, 8192);
            assert_eq!(progress.bytes_read, ticks * 4096);
        })
        .unwrap();
        assert!(!run.canceled);
        assert_eq!(run.summary.bytes_scanned, 8192);
        assert_eq!(run.summary.blocks_empty, 2);
    }

    #[test]
    fn media_line_names_an_internal_ssd() {
        let mut sample = device(
            "disk0",
            DeviceKind::Disk,
            Some("Apple Fabric"),
            Some("Unknown"),
            None,
            Some(true),
        );
        sample.device_node = "/dev/disk0".to_string();
        assert_eq!(
            sample.media_line(),
            "solid-state drive (SSD), internal, Apple Fabric, whole disk, /dev/disk0"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_list_on_this_machine() {
        if !std::path::Path::new("/usr/sbin/diskutil").exists() {
            eprintln!("diskutil is missing; skipping live list");
            return;
        }
        let devices = list().expect("list disks");
        for device in &devices {
            eprintln!(
                "{} | {} | {} bytes | {:?} | ssd={:?} internal={:?} mount={:?}",
                device.name,
                device.device_node,
                device.size_bytes,
                device.kind,
                device.solid_state,
                device.internal,
                device.mount_point
            );
        }
        assert!(
            devices
                .iter()
                .any(|device| device.kind == DeviceKind::Disk && device.size_bytes > 1_000_000_000),
            "expected a real whole disk larger than 1 GB"
        );
        assert!(
            devices.iter().all(|device| !device.is_disk_image()),
            "disk images stay out of the display list"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_scan_small_readable_device_when_present() {
        if !std::path::Path::new("/usr/sbin/diskutil").exists() {
            return;
        }
        let Ok(mut devices) = enumerate() else {
            return;
        };
        devices
            .retain(|device| device.size_bytes > 0 && device.size_bytes < 2 * 1024 * 1024 * 1024);
        devices.sort_by_key(|device| device.size_bytes);
        let Some(device) = devices
            .into_iter()
            .find(|device| open_for_scan(device).is_ok())
        else {
            eprintln!("no readable device under 2 GiB; skipping live device scan");
            return;
        };
        eprintln!(
            "scanning {} ({}) {} bytes",
            device.name,
            device.device_node,
            device.scan_len()
        );
        let mut source = open_for_scan(&device).unwrap();
        let expected = device.scan_len();
        let run = scan_source_with(&mut source, 1024 * 1024, None, |_| {}).unwrap();
        assert!(!run.canceled);
        assert_eq!(run.summary.bytes_scanned, expected);
    }
}
