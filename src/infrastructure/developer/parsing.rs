//! Pure parsers for Apple Developer Services plist responses.
//!
//! `post_plist` decodes the response into `serde_json::Value`, with plist `Data`
//! fields rendered as base64 strings. These helpers extract the pieces the
//! provisioning flow needs and surface Apple's `resultCode`/`userString` errors.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

/// A development team.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Team {
    /// Team identifier (`teamId`).
    pub id: String,
    /// Human-readable team name.
    pub name: String,
}

/// A registered device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Device {
    /// Internal device id.
    pub id: String,
    /// The device UDID (`deviceNumber`).
    pub udid: String,
}

/// An issued development certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Certificate serial number.
    pub serial: String,
    /// DER-encoded certificate bytes.
    pub der: Vec<u8>,
}

/// Apple signals success with `resultCode == 0`; otherwise surface its message.
pub(super) fn check_result(resp: &Value) -> Result<(), String> {
    match resp.get("resultCode").and_then(Value::as_i64) {
        Some(0) | None => Ok(()),
        Some(code) => {
            let message = resp
                .get("userString")
                .or_else(|| resp.get("resultString"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            Err(format!("Apple Developer Services error {code}: {message}"))
        }
    }
}

/// Parse `listTeams.action`.
pub(super) fn parse_teams(resp: &Value) -> Result<Vec<Team>, String> {
    check_result(resp)?;
    Ok(array(resp, "teams")
        .iter()
        .filter_map(|t| {
            Some(Team {
                id: string(t, "teamId")?,
                name: string(t, "name").unwrap_or_default(),
            })
        })
        .collect())
}

/// Parse `ios/listDevices.action`.
pub(super) fn parse_devices(resp: &Value) -> Result<Vec<Device>, String> {
    check_result(resp)?;
    Ok(array(resp, "devices")
        .iter()
        .filter_map(|d| {
            Some(Device {
                id: string(d, "deviceId").unwrap_or_default(),
                udid: string(d, "deviceNumber")?,
            })
        })
        .collect())
}

/// Parse a certificate out of `submitDevelopmentCSR.action`.
pub(super) fn parse_certificate(resp: &Value) -> Result<Certificate, String> {
    check_result(resp)?;
    let cert = resp
        .get("certRequest")
        .or_else(|| resp.get("certificate"))
        .ok_or("response has no certRequest")?;
    let der = decode_data(cert, "certContent")
        .or_else(|| decode_data(cert, "certificateContent"))
        .ok_or("certificate has no DER content")?;
    Ok(Certificate {
        serial: string(cert, "serialNumber").unwrap_or_default(),
        der,
    })
}

/// Parse the `.mobileprovision` bytes from `downloadTeamProvisioningProfile.action`.
pub(super) fn parse_profile(resp: &Value) -> Result<Vec<u8>, String> {
    check_result(resp)?;
    let profile = resp
        .get("provisioningProfile")
        .ok_or("response has no provisioningProfile")?;
    decode_data(profile, "encodedProfile").ok_or_else(|| "profile has no encodedProfile".into())
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], |v| v.as_slice())
}

fn string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn decode_data(value: &Value, key: &str) -> Option<Vec<u8>> {
    let encoded = value.get(key).and_then(Value::as_str)?;
    BASE64.decode(encoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn surfaces_apple_errors() {
        let resp = json!({"resultCode": 7460, "userString": "bad device"});
        assert!(check_result(&resp).unwrap_err().contains("bad device"));
        assert!(check_result(&json!({"resultCode": 0})).is_ok());
    }

    #[test]
    fn parses_teams_and_devices() {
        let teams = parse_teams(&json!({"resultCode": 0, "teams": [
            {"teamId": "ABC", "name": "Me"}
        ]}))
        .unwrap();
        assert_eq!(
            teams,
            vec![Team {
                id: "ABC".into(),
                name: "Me".into()
            }]
        );

        let devices = parse_devices(&json!({"devices": [
            {"deviceId": "1", "deviceNumber": "UDID-1"}
        ]}))
        .unwrap();
        assert_eq!(devices[0].udid, "UDID-1");
    }

    #[test]
    fn parses_certificate_and_profile_data() {
        let der = BASE64.encode([1, 2, 3, 4]);
        let cert = parse_certificate(&json!({
            "certRequest": {"serialNumber": "S1", "certContent": der}
        }))
        .unwrap();
        assert_eq!(cert.serial, "S1");
        assert_eq!(cert.der, vec![1, 2, 3, 4]);

        let prof = BASE64.encode(b"MOBILEPROVISION");
        let bytes = parse_profile(&json!({
            "provisioningProfile": {"encodedProfile": prof}
        }))
        .unwrap();
        assert_eq!(bytes, b"MOBILEPROVISION");
    }
}
