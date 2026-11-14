use serde_json::Value;

use super::{command_output, command_with_args};

/// Simulator selection for install and launch commands.
#[derive(Debug, Clone, Default)]
pub struct SimulatorTarget {
    /// Explicit simulator UDID.
    pub udid: Option<String>,
    /// Booted simulator name.
    pub device: Option<String>,
}

pub(super) fn simulator_udid(target: &SimulatorTarget) -> Result<String, String> {
    if let Some(udid) = &target.udid {
        let udid = udid.trim();
        if udid.is_empty() {
            return Err("simulator UDID cannot be empty".into());
        }
        return Ok(udid.to_string());
    }
    if let Some(device) = &target.device
        && device.trim().is_empty()
    {
        return Err("simulator device name cannot be empty".into());
    }
    first_booted_simulator_udid(target.device.as_deref())
}

fn first_booted_simulator_udid(device_name: Option<&str>) -> Result<String, String> {
    let output = command_output(command_with_args(
        "/usr/bin/xcrun",
        &["simctl", "list", "--json", "-e", "devices"],
    ))?;
    find_booted_simulator_udid(&output, device_name)
}

fn find_booted_simulator_udid(output: &str, device_name: Option<&str>) -> Result<String, String> {
    let json: Value =
        serde_json::from_str(output).map_err(|e| format!("failed to parse simctl JSON: {e}"))?;
    let devices = json
        .get("devices")
        .and_then(Value::as_object)
        .ok_or("simctl JSON did not contain devices")?;

    for runtime_devices in devices.values().filter_map(Value::as_array) {
        for device in runtime_devices {
            if device.get("state").and_then(Value::as_str) == Some("Booted")
                && device_name
                    .is_none_or(|name| device.get("name").and_then(Value::as_str) == Some(name))
                && let Some(udid) = device.get("udid").and_then(Value::as_str)
            {
                return Ok(udid.to_string());
            }
        }
    }

    match device_name {
        Some(name) => Err(format!("no booted Simulator named {name:?} found")),
        None => Err("no booted Simulator found".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulator_udid_rejects_empty_udid() {
        let target = SimulatorTarget {
            udid: Some("  ".into()),
            device: None,
        };

        assert!(simulator_udid(&target).unwrap_err().contains("UDID"));
    }

    #[test]
    fn simulator_udid_rejects_empty_device_name() {
        let target = SimulatorTarget {
            udid: None,
            device: Some("  ".into()),
        };

        assert!(simulator_udid(&target).unwrap_err().contains("device"));
    }

    #[test]
    fn explicit_simulator_udid_is_trimmed_without_running_xcrun() {
        let target = SimulatorTarget {
            udid: Some("  SIM-123  ".into()),
            device: None,
        };

        assert_eq!(simulator_udid(&target).as_deref(), Ok("SIM-123"));
    }

    #[test]
    fn booted_simulator_lookup_filters_by_name_and_reports_missing_devices() {
        let output = r#"{"devices":{"runtime-a":[{"name":"Phone A","udid":"A","state":"Shutdown"},{"name":"Phone B","udid":"B","state":"Booted"}],"runtime-b":[{"name":"Phone C","udid":"C","state":"Booted"}]}}"#;

        assert_eq!(find_booted_simulator_udid(output, None).as_deref(), Ok("B"));
        assert_eq!(
            find_booted_simulator_udid(output, Some("Phone C")).as_deref(),
            Ok("C")
        );
        assert!(
            find_booted_simulator_udid(output, Some("Missing"))
                .unwrap_err()
                .contains("Missing")
        );
    }

    #[test]
    fn booted_simulator_lookup_rejects_invalid_simctl_json_shapes() {
        assert!(
            find_booted_simulator_udid("not json", None)
                .unwrap_err()
                .contains("parse")
        );
        assert!(
            find_booted_simulator_udid("{}", None)
                .unwrap_err()
                .contains("did not contain devices")
        );
        assert!(
            find_booted_simulator_udid(r#"{"devices":{}}"#, None)
                .unwrap_err()
                .contains("no booted Simulator found")
        );
    }
}
