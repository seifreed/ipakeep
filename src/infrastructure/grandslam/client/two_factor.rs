//! Trusted-device and SMS 2FA endpoints for `GrandSlam`.

use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::client::http::{
    build_header_map, ensure_success_status, identity_token,
};
use crate::infrastructure::grandslam::client::response::parse_trusted_phone_numbers;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

const AUTH_OPTIONS_URL: &str = "https://gsa.apple.com/auth";
const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
const PHONE_URL: &str = "https://gsa.apple.com/auth/verify/phone";
const PHONE_SECURITY_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";
const VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";

pub(super) async fn request_trusted_device_notification(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
) -> Result<(), AppStoreError> {
    let mut headers = identity_headers(dsid, idms_token);
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());

    let response = client
        .get(TRUSTED_DEVICE_URL)
        .headers(build_header_map(&headers)?)
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("trusted device request failed: {e}")))?;
    ensure_success_status(response, "trusted device request").await
}

pub(super) async fn list_trusted_phone_numbers(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
    let mut headers = identity_headers(dsid, idms_token);
    headers.insert("Accept".into(), "application/json".into());

    let value: JsonValue = client
        .get(AUTH_OPTIONS_URL)
        .headers(build_header_map(&headers)?)
        .send()
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("trusted phone list request failed: {e}"))
        })?
        .error_for_status()
        .map_err(|e| {
            AppStoreError::NetworkError(format!("trusted phone list request failed: {e}"))
        })?
        .json()
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("trusted phone list decode failed: {e}"))
        })?;

    Ok(parse_trusted_phone_numbers(&value))
}

pub(super) async fn validate_trusted_device_code(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
    code: &str,
) -> Result<(), AppStoreError> {
    let mut headers = identity_headers(dsid, idms_token);
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());
    headers.insert("security-code".into(), code.into());

    client
        .get(VALIDATE_URL)
        .headers(build_header_map(&headers)?)
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("validate code request failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("invalid 2FA code: {e}")))?;

    Ok(())
}

pub(super) async fn request_sms(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
    phone_id: i64,
) -> Result<(), AppStoreError> {
    let mut headers = identity_headers(dsid, idms_token);
    headers.insert("Content-Type".into(), "application/json".into());

    let body = serde_json::json!({
        "phoneNumber": { "id": phone_id },
        "mode": "sms",
    });

    let response = client
        .put(PHONE_URL)
        .headers(build_header_map(&headers)?)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("SMS request failed: {e}")))?;
    ensure_success_status(response, "SMS request").await
}

pub(super) async fn validate_sms_code(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
    phone_id: i64,
    code: &str,
) -> Result<(), AppStoreError> {
    let headers = sms_headers(dsid, idms_token);
    let body = serde_json::json!({
        "phoneNumber": { "id": phone_id },
        "securityCode": { "code": code },
        "mode": "sms",
    });

    client
        .post(PHONE_SECURITY_CODE_URL)
        .headers(build_header_map(&headers)?)
        .json(&body)
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("SMS validation request failed: {e}")))?
        .error_for_status()
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("invalid SMS code: {e}")))?;

    Ok(())
}

fn identity_headers(dsid: &str, idms_token: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "X-Apple-Identity-Token".into(),
        identity_token(dsid, idms_token),
    );
    headers
}

fn sms_headers(dsid: &str, idms_token: &str) -> HashMap<String, String> {
    let mut headers = identity_headers(dsid, idms_token);
    headers.insert("Content-Type".into(), "application/json".into());
    headers
}
