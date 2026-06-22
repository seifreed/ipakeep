//! Request bodies and headers for the Apple Developer Services plist protocol.
//!
//! The protocol is undocumented by Apple; the field/header names mirror the
//! open-source reference implementations (`AltSign`/`SideStore`). All builders
//! here are pure so they can be unit-tested without the network.

use crate::infrastructure::grandslam::AnisetteData;
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// `AltSign`'s well-known client id / protocol version for the iOS team API.
pub(super) const CLIENT_ID: &str = "XABBG36SBA";
pub(super) const PROTOCOL_VERSION: &str = "QH65B2";

/// Common request envelope shared by every `*.action` call.
pub(super) fn base_body(team_id: Option<&str>) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("clientId".into(), json!(CLIENT_ID));
    body.insert("protocolVersion".into(), json!(PROTOCOL_VERSION));
    body.insert("requestId".into(), json!(request_id()));
    body.insert("userLocale".into(), json!(["en_US"]));
    if let Some(team_id) = team_id {
        body.insert("teamId".into(), json!(team_id));
    }
    body
}

/// Body for `ios/addDevice.action`.
pub(super) fn add_device_body(team_id: &str, udid: &str, name: &str) -> Value {
    let mut body = base_body(Some(team_id));
    body.insert("deviceNumber".into(), json!(udid));
    body.insert("name".into(), json!(name));
    Value::Object(body)
}

/// Body for `ios/submitDevelopmentCSR.action`.
pub(super) fn submit_csr_body(team_id: &str, csr_pem: &str, machine_name: &str) -> Value {
    let mut body = base_body(Some(team_id));
    body.insert("csrContent".into(), json!(csr_pem));
    body.insert("machineId".into(), json!(machine_name));
    body.insert("machineName".into(), json!(machine_name));
    Value::Object(body)
}

/// Body for `ios/downloadTeamProvisioningProfile.action`.
pub(super) fn download_profile_body(team_id: &str, app_id_id: &str) -> Value {
    let mut body = base_body(Some(team_id));
    body.insert("appIdId".into(), json!(app_id_id));
    Value::Object(body)
}

/// HTTP headers authenticating a Developer Services request.
pub(super) fn headers(
    identity_id: &str,
    gs_token: &str,
    anisette: &AnisetteData,
) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());
    headers.insert("Accept".into(), "text/x-xml-plist".into());
    headers.insert("User-Agent".into(), "Xcode".into());
    headers.insert("X-Xcode-Version".into(), "14.2 (14C18)".into());
    headers.insert("X-Apple-I-Identity-Id".into(), identity_id.to_string());
    headers.insert("X-Apple-GS-Token".into(), gs_token.to_string());
    for key in [
        "X-Apple-I-MD",
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Apple-I-SRL-NO",
        "X-Apple-I-Client-Time",
        "X-Apple-I-TimeZone",
        "X-Mme-Device-Id",
    ] {
        if let Some(value) = anisette.headers.get(key) {
            headers.insert(key.to_string(), value.clone());
        }
    }
    headers
}

/// A best-effort unique request id (no `uuid`/random crate needed).
fn request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("ipakeep-{:x}-{:x}", std::process::id(), nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_body_has_protocol_envelope() {
        let body = base_body(Some("TEAM123"));
        assert_eq!(body["clientId"], json!(CLIENT_ID));
        assert_eq!(body["protocolVersion"], json!(PROTOCOL_VERSION));
        assert_eq!(body["teamId"], json!("TEAM123"));
        assert!(body["requestId"].as_str().unwrap().starts_with("ipakeep-"));
    }

    #[test]
    fn bodies_carry_their_fields() {
        assert_eq!(
            add_device_body("T", "UDID", "iPhone")["deviceNumber"],
            json!("UDID")
        );
        assert_eq!(
            submit_csr_body("T", "-----CSR-----", "mac")["csrContent"],
            json!("-----CSR-----")
        );
        assert_eq!(
            download_profile_body("T", "APPID")["appIdId"],
            json!("APPID")
        );
    }

    #[test]
    fn headers_include_auth_and_anisette() {
        let a = AnisetteData {
            headers: HashMap::from([("X-Apple-I-MD".to_string(), "md".to_string())]),
            cpd: Value::Null,
        };
        let h = headers("ADSID", "TOKEN", &a);
        assert_eq!(h["X-Apple-I-Identity-Id"], "ADSID");
        assert_eq!(h["X-Apple-GS-Token"], "TOKEN");
        assert_eq!(h["X-Apple-I-MD"], "md");
    }
}
