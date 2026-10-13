//! Linux disk enumeration via `lsblk -Jb`.
//!
//! [`parse_lsblk`] is pure and tested with canned JSON. [`list_live`] runs
//! the command.

use serde_json::Value;

use super::{Device, DeviceKind};

/// Parse `lsblk -Jb -o NAME,PATH,SIZE,TYPE,MOUNTPOINT,ROTA,TRAN,MODEL,LABEL` JSON.
pub fn parse_lsblk(json: &str) -> Result<Vec<Device>, String> {
    let value: Value = serde_json::from_str(json).map_err(|err| format!("lsblk JSON: {err}"))?;
    let mut devices = Vec::new();
    if let Some(blocks) = value.get("blockdevices").and_then(Value::as_array) {
        for block in blocks {
            walk(block, &mut devices);
        }
    }
    Ok(devices)
}

fn walk(node: &Value, devices: &mut Vec<Device>) {
    if let Some(device) = device_from_node(node) {
        devices.push(device);
    }
    if let Some(children) = node.get("children").and_then(Value::as_array) {
        for child in children {
            walk(child, devices);
        }
    }
}

fn device_from_node(node: &Value) -> Option<Device> {
    let kind_name = node.get("type").and_then(Value::as_str).unwrap_or("");
    if matches!(kind_name, "loop" | "rom" | "") {
        return None;
    }
    let name = node.get("name").and_then(Value::as_str).unwrap_or("");
    let device_node = node
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if name.is_empty() {
                String::new()
            } else {
                format!("/dev/{name}")
            }
        });
    if device_node.is_empty() {
        return None;
    }
    let size_bytes = node.get("size").and_then(json_u64).unwrap_or(0);
    let mount_point = node
        .get("mountpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|mount| !mount.is_empty())
        .map(str::to_string);
    // lsblk also reports an array under "mountpoints" on newer util-linux.
    let mount_point = mount_point.or_else(|| first_mountpoint(node.get("mountpoints")));
    let kind = match kind_name {
        "disk" => DeviceKind::Disk,
        "part" | "lvm" | "crypt" | "raid" | "md" => {
            mount_point.as_ref()?;
            DeviceKind::Volume
        }
        _ => return None,
    };
    let model = node
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let label = node
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let display = match kind {
        DeviceKind::Volume => label.or(mount_point.as_deref()).unwrap_or(name).to_string(),
        DeviceKind::Disk => model.unwrap_or(name).to_string(),
    };
    let protocol = node
        .get("tran")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    let solid_state = node
        .get("rota")
        .and_then(json_rota)
        .map(|spinning| !spinning);
    let internal = match protocol.as_deref() {
        Some("usb" | "firewire" | "sdio") => Some(false),
        _ => None,
    };
    Some(Device {
        name: display,
        identifier: name.to_string(),
        device_node,
        raw_node: None,
        size_bytes,
        sector_size: 512,
        kind,
        solid_state,
        internal,
        volume_name: label.map(str::to_string),
        mount_point,
        protocol,
        virtual_or_physical: None,
    })
}

fn first_mountpoint(value: Option<&Value>) -> Option<String> {
    let array = value?.as_array()?;
    array.iter().find_map(|item| {
        item.as_str()
            .map(str::trim)
            .filter(|mount| !mount.is_empty())
            .map(str::to_string)
    })
}

fn json_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_f64()
                .filter(|value| *value >= 0.0)
                .map(|value| value as u64)
        }),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

/// `rota` is true when the medium spins (an HDD). JSON may use a bool, 0/1, or "0"/"1".
fn json_rota(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(spinning) => Some(*spinning),
        Value::Number(number) => number.as_u64().map(|value| value != 0),
        Value::String(text) => match text.trim() {
            "0" | "false" => Some(false),
            "1" | "true" => Some(true),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub fn list_live() -> std::io::Result<Vec<Device>> {
    use std::io::{Error, ErrorKind};
    use std::process::Command;
    let output = Command::new("lsblk")
        .args([
            "-Jb",
            "-o",
            "NAME,PATH,SIZE,TYPE,MOUNTPOINT,MOUNTPOINTS,ROTA,TRAN,MODEL,LABEL",
        ])
        .output()
        .map_err(|err| Error::other(format!("could not run lsblk: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!("lsblk failed: {}", stderr.trim())));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_lsblk(&text).map_err(|err| Error::new(ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canned_lsblk() {
        let json = r#"{
          "blockdevices": [
            {
              "name": "nvme0n1",
              "path": "/dev/nvme0n1",
              "size": "512110190592",
              "type": "disk",
              "rota": false,
              "tran": "nvme",
              "model": "Samsung SSD 980 ",
              "mountpoint": null,
              "children": [
                {
                  "name": "nvme0n1p2",
                  "path": "/dev/nvme0n1p2",
                  "size": 511000000000,
                  "type": "part",
                  "rota": 0,
                  "tran": "nvme",
                  "mountpoint": "/home",
                  "label": "home"
                },
                {
                  "name": "nvme0n1p1",
                  "path": "/dev/nvme0n1p1",
                  "size": 500000000,
                  "type": "part",
                  "rota": "0",
                  "tran": "nvme",
                  "mountpoint": null
                }
              ]
            },
            {
              "name": "sda",
              "path": "/dev/sda",
              "size": 1000204886016,
              "type": "disk",
              "rota": true,
              "tran": "usb",
              "model": "Backup HDD",
              "mountpoint": null
            },
            {
              "name": "loop0",
              "path": "/dev/loop0",
              "size": 4096,
              "type": "loop",
              "rota": false,
              "mountpoint": "/snap/demo"
            }
          ]
        }"#;
        let devices = parse_lsblk(json).unwrap();
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].name, "Samsung SSD 980");
        assert_eq!(devices[0].device_node, "/dev/nvme0n1");
        assert_eq!(devices[0].kind, DeviceKind::Disk);
        assert_eq!(devices[0].solid_state, Some(true));
        assert_eq!(devices[0].internal, None);
        assert_eq!(devices[0].size_bytes, 512110190592);
        assert_eq!(devices[0].raw_node, None);
        assert_eq!(devices[1].name, "home");
        assert_eq!(devices[1].kind, DeviceKind::Volume);
        assert_eq!(devices[1].mount_point.as_deref(), Some("/home"));
        assert_eq!(devices[1].solid_state, Some(true));
        assert_eq!(devices[2].name, "Backup HDD");
        assert_eq!(devices[2].solid_state, Some(false));
        assert_eq!(devices[2].internal, Some(false));
        assert_eq!(devices[2].protocol.as_deref(), Some("usb"));
    }
}
