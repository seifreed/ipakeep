//! `GrandSlam` response parsing helpers.

use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::response_snippet;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value as JsonValue;

/// Extract the inner `Response` dictionary from a `GrandSlam` plist response.
pub(super) fn extract_response(response: &JsonValue) -> Result<&JsonValue, AppStoreError> {
    response.get("Response").ok_or_else(|| {
        AppStoreError::AuthenticationFailed("missing Response wrapper in GrandSlam response".into())
    })
}

/// Read the `Status` value from a `GrandSlam` response.
///
/// Returns `(hsc, ec)`:
/// - `hsc` defaults to `200` if the `Status` dict or `hsc` key is missing.
/// - `ec`  defaults to `0` if the `Status` dict or `ec` key is missing.
/// - Also handles legacy string `Status` values (e.g. `"-21669"`).
pub(super) fn read_status(response: &JsonValue) -> (u64, i64) {
    let Some(status) = response.get("Status") else {
        return (200, 0);
    };

    if let Some(hsc) = status.get("hsc").and_then(serde_json::Value::as_u64) {
        let ec = status
            .get("ec")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        return (hsc, ec);
    }

    if let Some(s) = status.as_str() {
        if s == "-21669" {
            return (200, -21669);
        }
        if let Ok(code) = s.parse::<i64>() {
            return (200, code);
        }
    }

    (200, 0)
}

/// Verify the `GrandSlam` HTTP status code, returning the error code (`ec`).
///
/// `context` labels the operation in error messages (e.g. `"SRP init"`).
pub(super) fn check_grandslam_status(
    inner: &JsonValue,
    context: &str,
) -> Result<i64, AppStoreError> {
    let (hsc, ec) = read_status(inner);
    if hsc != 200 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "{context} failed: HTTP {hsc} (error code {ec}): {}",
            status_message(inner)
        )));
    }
    Ok(ec)
}

pub(super) fn two_factor_status_error(
    operation: &str,
    status: reqwest::StatusCode,
    body: &[u8],
) -> AppStoreError {
    AppStoreError::AuthenticationFailed(format!(
        "{operation} failed with HTTP {status}: {}",
        response_snippet(body)
    ))
}

/// Parse the `trustedPhoneNumbers` array from Apple's HSA2 auth-options JSON.
///
/// Each entry must carry a numeric `id`; entries without one are skipped. The
/// display string prefers `numberWithDialCode`, then `obfuscatedNumber`, then
/// `lastTwoDigits`. A missing or non-array key yields an empty list.
pub(super) fn parse_trusted_phone_numbers(value: &JsonValue) -> Vec<TrustedPhoneNumber> {
    let Some(entries) = value
        .get("trustedPhoneNumbers")
        .and_then(JsonValue::as_array)
    else {
        return Vec::new();
    };

    entries
        .iter()
        .filter_map(|entry| {
            let id = entry.get("id").and_then(JsonValue::as_i64)?;
            let number = ["numberWithDialCode", "obfuscatedNumber", "lastTwoDigits"]
                .iter()
                .find_map(|key| entry.get(*key).and_then(JsonValue::as_str))
                .filter(|s| !s.is_empty())
                .unwrap_or("(unknown)")
                .to_string();
            Some(TrustedPhoneNumber { id, number })
        })
        .collect()
}

/// Extract a base64-encoded field from a JSON value.
pub(super) fn extract_base64(value: &JsonValue, key: &str) -> Result<Vec<u8>, String> {
    let s = value
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing field: {key}"))?;
    BASE64
        .decode(s)
        .map_err(|e| format!("base64 decode failed for {key}: {e}"))
}

/// Read the `Status.em` error message from a `GrandSlam` response.
fn status_message(inner: &JsonValue) -> &str {
    inner
        .get("Status")
        .and_then(|s| s.get("em"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_response_requires_wrapper() {
        assert_eq!(
            extract_response(&json!({"Response": {"ok": true}})).unwrap()["ok"],
            true
        );
        assert!(
            extract_response(&json!({}))
                .unwrap_err()
                .to_string()
                .contains("missing Response")
        );
    }

    #[test]
    fn read_status_handles_missing_dict_and_legacy_strings() {
        assert_eq!(read_status(&json!({})), (200, 0));
        assert_eq!(
            read_status(&json!({"Status": {"hsc": 409, "ec": -1}})),
            (409, -1)
        );
        assert_eq!(read_status(&json!({"Status": "-21669"})), (200, -21669));
        assert_eq!(read_status(&json!({"Status": "123"})), (200, 123));
        assert_eq!(read_status(&json!({"Status": "ok"})), (200, 0));
    }

    #[test]
    fn check_grandslam_status_returns_error_code_or_message() {
        assert_eq!(
            check_grandslam_status(&json!({"Status": {"hsc": 200, "ec": -21669}}), "SRP").unwrap(),
            -21669
        );

        let error = check_grandslam_status(
            &json!({"Status": {"hsc": 500, "ec": 7, "em": "broken"}}),
            "SRP",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("HTTP 500"));
        assert!(error.contains("broken"));
    }
}
