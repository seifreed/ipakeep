//! Trusted-device and SMS 2FA endpoints for `GrandSlam`.

use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::client::http::{
    build_header_map, ensure_success_status, identity_token,
};
use crate::infrastructure::grandslam::client::response::parse_trusted_phone_numbers;
use crate::infrastructure::grandslam::resolve_anisette;
use crate::infrastructure::http::{decode_plist, response_snippet};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

const AUTH_OPTIONS_URL: &str = "https://gsa.apple.com/auth";
const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
const PHONE_URL: &str = "https://gsa.apple.com/auth/verify/phone";
const PHONE_SECURITY_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";
const VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
const XCODE_VERSION: &str = "11.2 (11B41)";
const SMS_ACCEPT: &str = "application/json, text/javascript, */*; q=0.01";

pub(super) async fn request_trusted_device_notification(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
) -> Result<(), AppStoreError> {
    let mut headers = identity_headers(client, dsid, idms_token).await?;
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());
    headers.insert("Accept".into(), "text/x-xml-plist".into());

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
    headers.insert("Accept".into(), "text/x-xml-plist".into());
    headers.insert("security-code".into(), code.into());

    let response = client
        .get(VALIDATE_URL)
        .headers(build_header_map(&headers)?)
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("validate code request failed: {e}")))?;
    let status = response.status();
    let body = response.bytes().await.map_err(|e| {
        AppStoreError::NetworkError(format!("validate code response read failed: {e}"))
    })?;
    validate_trusted_device_response(status, &body)
}

pub(super) async fn request_sms(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
    phone_id: i64,
) -> Result<(), AppStoreError> {
    let mut headers = identity_headers(client, dsid, idms_token).await?;
    headers.insert("Content-Type".into(), "application/json".into());
    headers.insert("Accept".into(), SMS_ACCEPT.into());

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
    headers.insert("Accept".into(), SMS_ACCEPT.into());
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
    add_auth_headers(&mut headers, dsid, idms_token);
    Ok(headers)
}

fn add_auth_headers(headers: &mut HashMap<String, String>, dsid: &str, idms_token: &str) {
    headers.insert(
        "X-Apple-Identity-Token".into(),
        identity_token(dsid, idms_token),
    );
    headers.insert("User-Agent".into(), "Xcode".into());
    headers.insert("Accept-Language".into(), "en-us".into());
    headers.insert("X-Apple-App-Info".into(), "com.apple.gs.xcode.auth".into());
    headers.insert("X-Xcode-Version".into(), XCODE_VERSION.into());
}

fn validate_trusted_device_response(
    status: reqwest::StatusCode,
    body: &[u8],
) -> Result<(), AppStoreError> {
    if !status.is_success() {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "trusted-device code validation failed with HTTP {status}: {}",
            response_snippet(body)
        )));
    }

    let response = decode_plist(body).map_err(|error| {
        AppStoreError::NetworkError(format!(
            "trusted-device response plist decode failed: {error}"
        ))
    })?;
    let error_code = response
        .get("ec")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppStoreError::NetworkError(
                "trusted-device response plist is missing error code".into(),
            )
        })?;
    if error_code != 0 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "trusted-device code validation failed with error code {error_code}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::add_auth_headers;
    use super::validate_trusted_device_response;
    use crate::domain::error::AppStoreError;
    use crate::infrastructure::grandslam::client::http::identity_token;
    use crate::infrastructure::http::encode_plist;
    use std::collections::HashMap;

    #[test]
    fn identity_token_is_added_without_dropping_anisette_headers() {
        let mut headers = HashMap::from([("X-Apple-I-MD".into(), "anisette-md".into())]);

        add_auth_headers(&mut headers, "123", "token");

        assert_eq!(
            headers.get("X-Apple-I-MD").map(String::as_str),
            Some("anisette-md")
        );
        assert_eq!(
            headers.get("X-Apple-Identity-Token").map(String::as_str),
            Some(identity_token("123", "token").as_str())
        );
        assert_eq!(headers.get("User-Agent").map(String::as_str), Some("Xcode"));
        assert_eq!(
            headers.get("X-Apple-App-Info").map(String::as_str),
            Some("com.apple.gs.xcode.auth")
        );
    }

    #[test]
    fn trusted_device_validation_requires_success_error_code() {
        let success = encode_plist(&serde_json::json!({ "ec": 0 })).expect("success plist");
        let invalid_code =
            encode_plist(&serde_json::json!({ "ec": -21669 })).expect("invalid-code plist");

        assert!(validate_trusted_device_response(reqwest::StatusCode::OK, &success).is_ok());
        assert!(matches!(
            validate_trusted_device_response(reqwest::StatusCode::OK, &invalid_code),
            Err(AppStoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            validate_trusted_device_response(reqwest::StatusCode::OK, b"not a plist"),
            Err(AppStoreError::NetworkError(_))
        ));
    }
}
