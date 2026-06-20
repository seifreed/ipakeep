//! Parsing of the decrypted SPD account payload returned by `GrandSlam`.

use crate::domain::entity::Account;
use serde_json::Value as JsonValue;

/// Parse an [`Account`] from decrypted SPD plist data.
pub(super) fn parse_spd_account(spd: &JsonValue) -> Account {
    // The numeric account DSID (`DsPrsId`) is what MZFinance commerce expects in
    // X-Dsid. It is a plist integer, so it must be read number-aware; reading it
    // as a string only would fall through to `adsid` (the long GrandSlam identity
    // id), which MZFinance rejects with failureType 2001 ("account could not be
    // found"). `adsid` is deliberately not a fallback here.
    let dsid = string_or_number_from_keys(spd, &["dsid", "DsPrsId", "DirectoryServicesID"]);
    let idms_token = optional_string_from_keys(spd, &["idms-token", "IDMSToken", "GsIdmsToken"]);
    let adsid = optional_string_from_keys(spd, &["adsid"]);
    let grandslam_session_key = optional_string_from_keys(spd, &["sk"]);
    let grandslam_continuation = optional_string_from_keys(spd, &["c"]);
    let email = string_from_keys(spd, &["accountName", "acname", "primaryEmail"]);
    let first_name = string_from_keys(spd, &["firstName", "fn"]);
    let last_name = string_from_keys(spd, &["lastName", "ln"]);
    let name = format!("{first_name} {last_name}").trim().to_string();

    tracing::debug!(
        spd_keys = ?spd
            .as_object()
            .map(|o| o.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default(),
        service_tokens = ?spd
            .get("t")
            .and_then(JsonValue::as_object)
            .map(|o| o.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default(),
        dsid_len = dsid.len(),
        dsid_numeric = !dsid.is_empty() && dsid.bytes().all(|b| b.is_ascii_digit()),
        "parsed GrandSlam SPD account fields"
    );

    // GrandSlam service tokens are not MZFinance passwordToken values.
    let password_token = string_from_keys(spd, &["token", "passwordToken"]);

    let store_front = string_from_keys(spd, &["storeFront", "store-front"]);
    let pod = string_from_keys(spd, &["pod"]);

    let dsid_opt = if dsid.is_empty() {
        None
    } else {
        Some(dsid.clone())
    };

    Account {
        email,
        name,
        password_token,
        directory_services_id: dsid,
        store_front,
        pod,
        idms_token,
        dsid: dsid_opt,
        adsid,
        grandslam_session_key,
        grandslam_continuation,
        cookies: Vec::new(),
    }
}

fn string_from_keys(value: &JsonValue, keys: &[&str]) -> String {
    optional_string_from_keys(value, keys).unwrap_or_default()
}

/// Like [`string_from_keys`] but also accepts numeric plist values (decoded as
/// JSON numbers), returning their decimal string form. Used for `DsPrsId`, which
/// Apple sends as an integer.
fn string_or_number_from_keys(value: &JsonValue, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            let field = value.get(*key)?;
            if let Some(text) = field.as_str() {
                return (!text.is_empty()).then(|| text.to_string());
            }
            field.as_i64().map(|number| number.to_string())
        })
        .unwrap_or_default()
}

fn optional_string_from_keys(value: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(std::string::ToString::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    #[test]
    fn parse_spd_account_extracts_fields() {
        let spd = serde_json::json!({
            "dsid": "12345",
            "idms-token": "tok-abc",
            "adsid": "adsid-abc",
            "accountName": "test@example.com",
            "firstName": "Test",
            "lastName": "User",
            "token": "ptok",
            "storeFront": "143441-2,26",
            "pod": "3",
            "sk": BASE64.encode([1_u8; 32]),
            "c": BASE64.encode([2_u8; 16]),
        });

        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "test@example.com");
        assert_eq!(account.name, "Test User");
        assert_eq!(account.directory_services_id, "12345");
        assert_eq!(account.password_token, "ptok");
        assert_eq!(account.store_front, "143441-2,26");
        assert_eq!(account.pod, "3");
        assert_eq!(account.idms_token, Some("tok-abc".into()));
        assert_eq!(account.dsid, Some("12345".into()));
        assert_eq!(account.adsid, Some("adsid-abc".into()));
        assert!(account.grandslam_session_key.is_some());
        assert!(account.grandslam_continuation.is_some());
    }

    #[test]
    fn parse_spd_account_extracts_grandslam_fields_without_password_token() {
        let spd = serde_json::json!({
            "DsPrsId": "67890",
            "GsIdmsToken": "idms-token",
            "adsid": "adsid-def",
            "sk": BASE64.encode([3_u8; 32]),
            "c": BASE64.encode([4_u8; 16]),
            "acname": "test@example.com",
            "fn": "Test",
            "ln": "User",
            "t": {
                "com.apple.gs.itunes.mu.invite": {
                    "token": "gs-token"
                }
            }
        });

        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "test@example.com");
        assert_eq!(account.name, "Test User");
        assert_eq!(account.directory_services_id, "67890");
        assert_eq!(account.password_token, "");
        assert_eq!(account.idms_token, Some("idms-token".into()));
        assert_eq!(account.dsid, Some("67890".into()));
        assert_eq!(account.adsid, Some("adsid-def".into()));
        assert!(account.grandslam_session_key.is_some());
        assert!(account.grandslam_continuation.is_some());
    }

    #[test]
    fn parse_spd_account_reads_numeric_dsprsid_not_adsid() {
        // Regression: Apple sends DsPrsId as a plist integer (JSON number). It
        // must become the numeric DSID (X-Dsid) rather than falling through to
        // the long adsid, which MZFinance rejects with failureType 2001.
        let spd = serde_json::json!({
            "DsPrsId": 1_234_567_890_i64,
            "adsid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE-FFFFGGG",
            "GsIdmsToken": "idms",
        });

        let account = parse_spd_account(&spd);
        assert_eq!(account.directory_services_id, "1234567890");
        assert_eq!(account.dsid.as_deref(), Some("1234567890"));
        assert_eq!(
            account.adsid.as_deref(),
            Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE-FFFFGGG")
        );
    }

    #[test]
    fn parse_spd_account_empty_defaults() {
        let spd = serde_json::json!({});
        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "");
        assert_eq!(account.name, "");
        assert_eq!(account.directory_services_id, "");
        assert!(account.idms_token.is_none());
        assert!(account.dsid.is_none());
        assert!(account.adsid.is_none());
        assert!(account.grandslam_session_key.is_none());
        assert!(account.grandslam_continuation.is_none());
    }
}
