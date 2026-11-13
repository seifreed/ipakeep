//! Trusted-device and SMS 2FA endpoints for `GrandSlam`.

use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::client::http::{
    build_header_map, ensure_success_status, identity_token,
};
use crate::infrastructure::grandslam::client::response::parse_trusted_phone_numbers;
use crate::infrastructure::grandslam::resolve_anisette;
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
    let mut headers = identity_headers(client, dsid, idms_token).await?;
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
    let mut headers = identity_headers(client, dsid, idms_token).await?;
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
    let mut headers = identity_headers(client, dsid, idms_token).await?;
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
    let mut headers = identity_headers(client, dsid, idms_token).await?;
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
    let mut headers = identity_headers(client, dsid, idms_token).await?;
    headers.insert("Content-Type".into(), "application/json".into());
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

async fn identity_headers(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
) -> Result<HashMap<String, String>, AppStoreError> {
    let mut headers = resolve_anisette(client).await?.headers;
    add_identity_token(&mut headers, dsid, idms_token);
    Ok(headers)
}

fn add_identity_token(headers: &mut HashMap<String, String>, dsid: &str, idms_token: &str) {
    headers.insert(
        "X-Apple-Identity-Token".into(),
        identity_token(dsid, idms_token),
    );
}

#[cfg(test)]
mod tests {
    use super::add_identity_token;
    use crate::infrastructure::grandslam::client::http::identity_token;
    use std::collections::HashMap;

    #[test]
    fn identity_token_is_added_without_dropping_anisette_headers() {
        let mut headers = HashMap::from([("X-Apple-I-MD".into(), "anisette-md".into())]);

        add_identity_token(&mut headers, "123", "token");

        assert_eq!(
            headers.get("X-Apple-I-MD").map(String::as_str),
            Some("anisette-md")
        );
        assert_eq!(
            headers.get("X-Apple-Identity-Token").map(String::as_str),
            Some(identity_token("123", "token").as_str())
        );
    }
}
