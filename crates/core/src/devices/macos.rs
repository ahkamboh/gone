//! macOS disk enumeration via `diskutil list -plist` and `diskutil info -plist`.
//!
//! Parsing is pure. The live command runs only in [`list_live`].

use super::plist::{self, Plist};
use super::{Device, DeviceKind};

#[cfg(target_os = "macos")]
const DISKUTIL: &str = "/usr/sbin/diskutil";

/// Identifiers worth an `info` call: whole disks, and anything with a mount point.
pub fn candidate_ids(list_xml: &str) -> Result<Vec<String>, String> {
    let plist = plist::parse_plist(list_xml).map_err(|err| err.to_string())?;
    let root = plist
        .as_dict()
        .ok_or("diskutil list was not a dictionary")?;
    let disks = plist::dict_get(root, "AllDisksAndPartitions")
        .and_then(Plist::as_array)
        .ok_or("diskutil list has no AllDisksAndPartitions")?;
    let mut ids = Vec::new();
    for disk in disks {
        walk(disk, true, &mut ids);
    }
    Ok(ids)
}

fn walk(node: &Plist, top: bool, ids: &mut Vec<String>) {
    let Some(dict) = node.as_dict() else {
        return;
    };
    let identifier = plist::dict_get(dict, "DeviceIdentifier").and_then(Plist::as_str);
    let mount = plist::dict_get(dict, "MountPoint")
        .and_then(Plist::as_str)
        .filter(|mount| !mount.is_empty());
    if let Some(identifier) = identifier {
        if top || mount.is_some() {
            push_unique(ids, identifier);
        }
    }
    for key in ["Partitions", "APFSVolumes"] {
        if let Some(children) = plist::dict_get(dict, key).and_then(Plist::as_array) {
            for child in children {
                walk(child, false, ids);
            }
        }
    }
}

fn push_unique(ids: &mut Vec<String>, identifier: &str) {
    if !ids.iter().any(|existing| existing == identifier) {
        ids.push(identifier.to_string());
    }
}

/// Build one device from a `diskutil info -plist` document.
pub fn device_from_info_plist(xml: &str) -> Result<Device, String> {
    let plist = plist::parse_plist(xml).map_err(|err| err.to_string())?;
    let dict = plist
        .as_dict()
        .ok_or("diskutil info was not a dictionary")?;
    let identifier =
        dict_string(dict, "DeviceIdentifier").ok_or("diskutil info is missing DeviceIdentifier")?;
    let device_node =
        dict_string(dict, "DeviceNode").unwrap_or_else(|| format!("/dev/{identifier}"));
    let whole = plist::dict_get(dict, "WholeDisk")
        .and_then(Plist::as_bool)
        .unwrap_or(false);
    let mount_point = dict_string(dict, "MountPoint");
    let volume_name = dict_string(dict, "VolumeName");
    let media_name = dict_string(dict, "MediaName");
    let protocol = dict_string(dict, "BusProtocol");
    let virtual_or_physical = dict_string(dict, "VirtualOrPhysical");
    let internal = plist::dict_get(dict, "Internal").and_then(Plist::as_bool);
    let solid_state = plist::dict_get(dict, "SolidState").and_then(Plist::as_bool);
    let size_bytes = plist::dict_get(dict, "Size")
        .and_then(Plist::as_u64)
        .or_else(|| plist::dict_get(dict, "TotalSize").and_then(Plist::as_u64))
        .unwrap_or(0);
    let sector_size = plist::dict_get(dict, "DeviceBlockSize")
        .and_then(Plist::as_u64)
        .filter(|size| *size > 0)
        .unwrap_or(512);
    let kind = if whole {
        DeviceKind::Disk
    } else {
        DeviceKind::Volume
    };
    let name = choose_name(
        kind,
        media_name.as_deref(),
        volume_name.as_deref(),
        &identifier,
    );
    Ok(Device {
        name,
        identifier,
        raw_node: macos_raw_node(&device_node),
        device_node,
        size_bytes,
        sector_size,
        kind,
        solid_state,
        internal,
        volume_name,
        mount_point,
        protocol,
        virtual_or_physical,
    })
}

fn dict_string(dict: &[(String, Plist)], key: &str) -> Option<String> {
    plist::dict_get(dict, key)
        .and_then(Plist::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn choose_name(
    kind: DeviceKind,
    media_name: Option<&str>,
    volume_name: Option<&str>,
    identifier: &str,
) -> String {
    if kind == DeviceKind::Volume {
        if let Some(name) = volume_name {
            return name.to_string();
        }
    }
    if let Some(name) = media_name.filter(|name| *name != "Disk Image") {
        return name.to_string();
    }
    if let Some(name) = volume_name {
        return name.to_string();
    }
    identifier.to_string()
}

/// `/dev/disk0` to `/dev/rdisk0`. The raw node is faster when the OS allows it.
pub fn macos_raw_node(device_node: &str) -> Option<String> {
    let rest = device_node.strip_prefix("/dev/disk")?;
    if rest.is_empty() {
        return None;
    }
    Some(format!("/dev/rdisk{rest}"))
}

/// Keep info documents whose identifier was selected from the list.
pub fn devices_from_plists(list_xml: &str, info_xmls: &[String]) -> Result<Vec<Device>, String> {
    let ids = candidate_ids(list_xml)?;
    let mut devices = Vec::new();
    for xml in info_xmls {
        let device = device_from_info_plist(xml)?;
        if ids.iter().any(|id| id == &device.identifier) {
            devices.push(device);
        }
    }
    Ok(devices)
}

/// Query diskutil. Read-only commands only.
#[cfg(target_os = "macos")]
pub fn list_live() -> std::io::Result<Vec<Device>> {
    use std::io::ErrorKind;
    let list_xml = run_diskutil(&["list", "-plist"])?;
    let ids =
        candidate_ids(&list_xml).map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))?;
    let info_xmls = fetch_infos(&ids)?;
    devices_from_plists(&list_xml, &info_xmls)
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidData, err))
}

#[cfg(target_os = "macos")]
fn fetch_infos(ids: &[String]) -> std::io::Result<Vec<String>> {
    use std::thread;
    thread::scope(|scope| {
        let mut joins = Vec::with_capacity(ids.len());
        for id in ids {
            joins.push(scope.spawn(|| run_diskutil(&["info", "-plist", id])));
        }
        let mut xmls = Vec::with_capacity(joins.len());
        for join in joins {
            match join.join() {
                Ok(Ok(xml)) => xmls.push(xml),
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(std::io::Error::other("diskutil info thread stopped"));
                }
            }
        }
        Ok(xmls)
    })
}

#[cfg(target_os = "macos")]
fn run_diskutil(args: &[&str]) -> std::io::Result<String> {
    use std::process::Command;
    let output = Command::new(DISKUTIL).args(args).output().map_err(|err| {
        std::io::Error::other(format!(
            "could not run {DISKUTIL}: {err}. Disk listing needs diskutil."
        ))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        let detail = if detail.is_empty() {
            format!("exit status {}", output.status)
        } else {
            detail.to_string()
        };
        return Err(std::io::Error::other(format!("diskutil failed: {detail}")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>AllDisksAndPartitions</key>
  <array>
    <dict>
      <key>DeviceIdentifier</key>
      <string>disk0</string>
      <key>Content</key>
      <string>GUID_partition_scheme</string>
      <key>Size</key>
      <integer>2001111162880</integer>
      <key>Partitions</key>
      <array>
        <dict>
          <key>DeviceIdentifier</key>
          <string>disk0s2</string>
          <key>Content</key>
          <string>Apple_APFS</string>
          <key>Size</key>
          <integer>1995218165760</integer>
        </dict>
      </array>
    </dict>
    <dict>
      <key>DeviceIdentifier</key>
      <string>disk3</string>
      <key>Content</key>
      <string>Apple_APFS_Container</string>
      <key>Size</key>
      <integer>1995218165760</integer>
      <key>APFSVolumes</key>
      <array>
        <dict>
          <key>DeviceIdentifier</key>
          <string>disk3s1s1</string>
          <key>VolumeName</key>
          <string>Macintosh HD</string>
          <key>MountPoint</key>
          <string>/</string>
          <key>Size</key>
          <integer>1995218165760</integer>
        </dict>
        <dict>
          <key>DeviceIdentifier</key>
          <string>disk3s2</string>
          <key>VolumeName</key>
          <string>Preboot</string>
          <key>MountPoint</key>
          <string>/System/Volumes/Preboot</string>
          <key>Size</key>
          <integer>1995218165760</integer>
        </dict>
        <dict>
          <key>DeviceIdentifier</key>
          <string>disk3s5</string>
          <key>VolumeName</key>
          <string>Macintosh HD - Data</string>
          <key>MountPoint</key>
          <string>/System/Volumes/Data</string>
          <key>Size</key>
          <integer>1995218165760</integer>
        </dict>
      </array>
    </dict>
    <dict>
      <key>DeviceIdentifier</key>
      <string>disk5</string>
      <key>Content</key>
      <string>Apple_APFS_Container</string>
      <key>Size</key>
      <integer>268394496</integer>
      <key>APFSVolumes</key>
      <array>
        <dict>
          <key>DeviceIdentifier</key>
          <string>disk5s1</string>
          <key>VolumeName</key>
          <string>gone-test</string>
          <key>MountPoint</key>
          <string>/Volumes/gone-test</string>
          <key>Size</key>
          <integer>268394496</integer>
        </dict>
      </array>
    </dict>
  </array>
</dict>
</plist>"#;

    #[allow(clippy::too_many_arguments)]
    fn info(
        id: &str,
        node: &str,
        whole: bool,
        size: u64,
        sector: u64,
        internal: bool,
        solid: Option<bool>,
        protocol: &str,
        virtual_kind: &str,
        media: &str,
        volume: &str,
        mount: &str,
    ) -> String {
        let solid_xml = match solid {
            Some(true) => "<key>SolidState</key><true/>",
            Some(false) => "<key>SolidState</key><false/>",
            None => "",
        };
        let whole_xml = if whole { "<true/>" } else { "<false/>" };
        let internal_xml = if internal { "<true/>" } else { "<false/>" };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>DeviceIdentifier</key><string>{id}</string>
  <key>DeviceNode</key><string>{node}</string>
  <key>WholeDisk</key>{whole_xml}
  <key>Size</key><integer>{size}</integer>
  <key>DeviceBlockSize</key><integer>{sector}</integer>
  <key>Internal</key>{internal_xml}
  {solid_xml}
  <key>BusProtocol</key><string>{protocol}</string>
  <key>VirtualOrPhysical</key><string>{virtual_kind}</string>
  <key>MediaName</key><string>{media}</string>
  <key>VolumeName</key><string>{volume}</string>
  <key>MountPoint</key><string>{mount}</string>
  <key>SMARTDeviceSpecificKeysMayVaryNotGuaranteed</key>
  <dict><key>AVAILABLE_SPARE</key><integer>100</integer></dict>
</dict></plist>"#
        )
    }

    #[test]
    fn candidates_are_whole_disks_and_mounts() {
        let ids = candidate_ids(LIST).unwrap();
        assert_eq!(
            ids,
            vec![
                "disk0",
                "disk3",
                "disk3s1s1",
                "disk3s2",
                "disk3s5",
                "disk5",
                "disk5s1",
            ]
        );
    }

    #[test]
    fn info_plist_becomes_a_physical_disk() {
        let xml = info(
            "disk0",
            "/dev/disk0",
            true,
            2001111162880,
            4096,
            true,
            Some(true),
            "Apple Fabric",
            "Unknown",
            "APPLE SSD AP2048R",
            "",
            "",
        );
        let device = device_from_info_plist(&xml).unwrap();
        assert_eq!(device.name, "APPLE SSD AP2048R");
        assert_eq!(device.device_node, "/dev/disk0");
        assert_eq!(device.raw_node.as_deref(), Some("/dev/rdisk0"));
        assert_eq!(device.size_bytes, 2001111162880);
        assert_eq!(device.sector_size, 4096);
        assert_eq!(device.kind, DeviceKind::Disk);
        assert_eq!(device.solid_state, Some(true));
        assert_eq!(device.internal, Some(true));
        assert_eq!(device.protocol.as_deref(), Some("Apple Fabric"));
        assert_eq!(device.mount_point, None);
        assert_eq!(device.scan_len(), 2001111162880);
    }

    #[test]
    fn assemble_keeps_only_listed_identifiers() {
        let infos = vec![
            info(
                "disk0",
                "/dev/disk0",
                true,
                2001111162880,
                4096,
                true,
                Some(true),
                "Apple Fabric",
                "Unknown",
                "APPLE SSD AP2048R",
                "",
                "",
            ),
            info(
                "disk3s5",
                "/dev/disk3s5",
                false,
                1995218165760,
                4096,
                true,
                Some(true),
                "Apple Fabric",
                "Virtual",
                "",
                "Macintosh HD - Data",
                "/System/Volumes/Data",
            ),
            info(
                "disk9",
                "/dev/disk9",
                true,
                100,
                512,
                false,
                None,
                "USB",
                "Physical",
                "Not In The List",
                "",
                "",
            ),
        ];
        let devices = devices_from_plists(LIST, &infos).unwrap();
        let names: Vec<_> = devices.iter().map(|device| device.name.as_str()).collect();
        assert_eq!(names, vec!["APPLE SSD AP2048R", "Macintosh HD - Data"]);
        assert_eq!(devices[1].kind, DeviceKind::Volume);
        assert_eq!(
            devices[1].mount_point.as_deref(),
            Some("/System/Volumes/Data")
        );
    }
}
