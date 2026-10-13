//! Windows disk enumeration via PowerShell `Get-Disk` and `Get-Partition`.
//!
//! [`parse_powershell_json`] is pure and tested with canned JSON.
//! [`list_live`] runs PowerShell. If that cannot run, the error is returned
//! as-is. Nothing here invents disks.

use serde_json::Value;

use super::{Device, DeviceKind};

#[cfg(target_os = "windows")]
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$disks = @(Get-Disk | ForEach-Object {
  [PSCustomObject]@{
    number = $_.Number
    friendlyName = [string]$_.FriendlyName
    size = $_.Size
    busType = [string]$_.BusType
    mediaType = $(if ($_.PSObject.Properties.Name -contains 'MediaType') { [string]$_.MediaType } else { '' })
  }
})
$parts = @(Get-Partition | ForEach-Object {
  $label = ''
  try {
    $vol = Get-Volume -Partition $_
    if ($vol) { $label = [string]$vol.FileSystemLabel }
  } catch {}
  $letter = ''
  if ($_.DriveLetter) { $letter = [string]$_.DriveLetter }
  [PSCustomObject]@{
    diskNumber = $_.DiskNumber
    partitionNumber = $_.PartitionNumber
    size = $_.Size
    driveLetter = $letter
    label = $label
  }
})
@{ disks = $disks; partitions = $parts } | ConvertTo-Json -Depth 4 -Compress
"#;

/// Parse the JSON object produced by [`SCRIPT`].
pub fn parse_powershell_json(text: &str) -> Result<Vec<Device>, String> {
    let json = text.trim().trim_start_matches('\u{feff}');
    let start = json
        .find('{')
        .ok_or("PowerShell did not return a JSON object")?;
    let value: Value =
        serde_json::from_str(&json[start..]).map_err(|err| format!("PowerShell JSON: {err}"))?;
    let mut devices = Vec::new();
    for disk in as_list(value.get("disks")) {
        if let Some(device) = disk_from_json(disk) {
            devices.push(device);
        }
    }
    for part in as_list(value.get("partitions")) {
        if let Some(device) = partition_from_json(part) {
            devices.push(device);
        }
    }
    Ok(devices)
}

fn as_list(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(_)) => vec![value.unwrap()],
        _ => Vec::new(),
    }
}

fn disk_from_json(value: &Value) -> Option<Device> {
    let number = value.get("number").and_then(json_u64)?;
    let size_bytes = value.get("size").and_then(json_u64).unwrap_or(0);
    let friendly = value
        .get("friendlyName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let protocol = value
        .get("busType")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty() && *text != "0")
        .map(str::to_string);
    let media = value.get("mediaType").and_then(Value::as_str).unwrap_or("");
    let solid_state = match media {
        "SSD" | "SCM" => Some(true),
        "HDD" => Some(false),
        _ => None,
    };
    // Bus type is not a reliable internal/external flag. USB is external.
    // Anything else stays unknown rather than a guess.
    let internal = match protocol.as_deref() {
        Some("USB") => Some(false),
        _ => None,
    };
    Some(Device {
        name: friendly.unwrap_or("Disk").to_string(),
        identifier: format!("disk{number}"),
        device_node: format!(r"\\.\PhysicalDrive{number}"),
        raw_node: None,
        size_bytes,
        sector_size: 512,
        kind: DeviceKind::Disk,
        solid_state,
        internal,
        volume_name: None,
        mount_point: None,
        protocol,
        virtual_or_physical: None,
    })
}

fn partition_from_json(value: &Value) -> Option<Device> {
    let disk_number = value.get("diskNumber").and_then(json_u64)?;
    let partition_number = value.get("partitionNumber").and_then(json_u64)?;
    let letter = value
        .get("driveLetter")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let label = value
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let mount_point = letter.map(|letter| format!("{letter}:\\"));
    mount_point.as_ref()?;
    let size_bytes = value.get("size").and_then(json_u64).unwrap_or(0);
    let name = label
        .map(str::to_string)
        .or_else(|| letter.map(|letter| format!("Drive {letter}")))
        .unwrap_or_else(|| format!("Partition {partition_number}"));
    Some(Device {
        name,
        identifier: format!("disk{disk_number}p{partition_number}"),
        device_node: format!(r"\\.\Harddisk{disk_number}Partition{partition_number}"),
        raw_node: None,
        size_bytes,
        sector_size: 512,
        kind: DeviceKind::Volume,
        solid_state: None,
        internal: None,
        volume_name: label.map(str::to_string),
        mount_point,
        protocol: None,
        virtual_or_physical: None,
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

#[cfg(target_os = "windows")]
pub fn list_live() -> std::io::Result<Vec<Device>> {
    use std::io::{Error, ErrorKind};
    use std::process::Command;
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .output()
        .map_err(|err| Error::other(format!("Listing disks on Windows needs PowerShell. {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        return Err(Error::other(if detail.is_empty() {
            "PowerShell could not list disks.".to_string()
        } else {
            format!("PowerShell could not list disks. {detail}")
        }));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_powershell_json(&text).map_err(|err| Error::new(ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canned_powershell_json() {
        let json = r#"{
          "disks": {
            "number": 0,
            "friendlyName": "Samsung SSD",
            "size": 512110190592,
            "busType": "NVMe",
            "mediaType": "SSD"
          },
          "partitions": [
            {
              "diskNumber": 0,
              "partitionNumber": 1,
              "size": 100000000,
              "driveLetter": "",
              "label": ""
            },
            {
              "diskNumber": 0,
              "partitionNumber": 3,
              "size": 511000000000,
              "driveLetter": "C",
              "label": "Windows"
            }
          ]
        }"#;
        let devices = parse_powershell_json(json).unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name, "Samsung SSD");
        assert_eq!(devices[0].device_node, r"\\.\PhysicalDrive0");
        assert_eq!(devices[0].kind, DeviceKind::Disk);
        assert_eq!(devices[0].solid_state, Some(true));
        assert_eq!(devices[0].internal, None);
        assert_eq!(devices[0].protocol.as_deref(), Some("NVMe"));
        assert_eq!(devices[1].name, "Windows");
        assert_eq!(devices[1].kind, DeviceKind::Volume);
        assert_eq!(devices[1].mount_point.as_deref(), Some("C:\\"));
        assert_eq!(devices[1].device_node, r"\\.\Harddisk0Partition3");
    }

    #[test]
    fn empty_powershell_object_is_an_empty_list() {
        let devices = parse_powershell_json(r#"{"disks":[],"partitions":[]}"#).unwrap();
        assert!(devices.is_empty());
    }
}
