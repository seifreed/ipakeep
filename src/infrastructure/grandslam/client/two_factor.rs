//! Trusted-device and SMS 2FA endpoints for `GrandSlam`.

use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::client::http::{
    build_header_map, ensure_success_status, identity_token,
};
use crate::infrastructure::grandslam::client::response::parse_trusted_phone_numbers;
use crate::infrastructure::grandslam::resolve_anisette;
use crate::infrastructure::http::decode_plist;
use crate::infrastructure::http::telemetry::{
    read_response_bytes, read_response_json, send_with_observability,
};
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
    let headers = identity_headers(dsid, idms_token).await?;
    request_trusted_device_notification_with_headers(client, TRUSTED_DEVICE_URL, headers).await
}

async fn request_trusted_device_notification_with_headers(
    client: &reqwest::Client,
    url: &str,
    mut headers: HashMap<String, String>,
) -> Result<(), AppStoreError> {
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());
    headers.insert("Accept".into(), "text/x-xml-plist".into());

    let request = client.get(url).headers(build_header_map(&headers)?);
    let response = send_with_observability(client, request)
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("trusted device request failed: {e}")))?;
    ensure_success_status(response, "trusted device request").await
}

pub(super) async fn list_trusted_phone_numbers(
    client: &reqwest::Client,
    dsid: &str,
    idms_token: &str,
) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
    let headers = identity_headers(dsid, idms_token).await?;
    list_trusted_phone_numbers_with_headers(client, AUTH_OPTIONS_URL, headers).await
}

async fn list_trusted_phone_numbers_with_headers(
    client: &reqwest::Client,
    url: &str,
    mut headers: HashMap<String, String>,
) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
    headers.insert("Accept".into(), "application/json".into());

    let request = client.get(url).headers(build_header_map(&headers)?);
    let response = send_with_observability(client, request)
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("trusted phone list request failed: {e}"))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(AppStoreError::NetworkError(format!(
            "trusted phone list request failed with HTTP {status}"
        )));
    }
    let value: JsonValue = read_response_json(response).await.map_err(|e| {
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
    let headers = identity_headers(dsid, idms_token).await?;
    validate_trusted_device_code_with_headers(client, VALIDATE_URL, headers, code).await
}

async fn validate_trusted_device_code_with_headers(
    client: &reqwest::Client,
    url: &str,
    mut headers: HashMap<String, String>,
    code: &str,
) -> Result<(), AppStoreError> {
    headers.insert("Content-Type".into(), "text/x-xml-plist".into());
    headers.insert("Accept".into(), "text/x-xml-plist".into());
    headers.insert("security-code".into(), code.into());

    let request = client.get(url).headers(build_header_map(&headers)?);
    let response = send_with_observability(client, request)
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("validate code request failed: {e}")))?;
    let status = response.status();
    let body = read_response_bytes(response).await.map_err(|e| {
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
    let headers = identity_headers(dsid, idms_token).await?;
    request_sms_with_headers(client, PHONE_URL, headers, phone_id).await
}

async fn request_sms_with_headers(
    client: &reqwest::Client,
    url: &str,
    mut headers: HashMap<String, String>,
    phone_id: i64,
) -> Result<(), AppStoreError> {
    headers.insert("Content-Type".into(), "application/json".into());
    headers.insert("Accept".into(), SMS_ACCEPT.into());

    let body = serde_json::json!({
        "phoneNumber": { "id": phone_id },
        "mode": "sms",
    });

    let request = client
        .put(url)
        .headers(build_header_map(&headers)?)
        .json(&body);
    let response = send_with_observability(client, request)
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
    let headers = identity_headers(dsid, idms_token).await?;
    validate_sms_code_with_headers(client, PHONE_SECURITY_CODE_URL, headers, phone_id, code).await
}

async fn validate_sms_code_with_headers(
    client: &reqwest::Client,
    url: &str,
    mut headers: HashMap<String, String>,
    phone_id: i64,
    code: &str,
) -> Result<(), AppStoreError> {
    headers.insert("Content-Type".into(), "application/json".into());
    headers.insert("Accept".into(), SMS_ACCEPT.into());
    let body = serde_json::json!({
        "phoneNumber": { "id": phone_id },
        "securityCode": { "code": code },
        "mode": "sms",
    });

    let request = client
        .post(url)
        .headers(build_header_map(&headers)?)
        .json(&body);
    let response = send_with_observability(client, request)
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("SMS validation request failed: {e}")))?;
    if !response.status().is_success() {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "invalid SMS code: HTTP {}",
            response.status()
        )));
    }

    Ok(())
}

async fn identity_headers(
    dsid: &str,
    idms_token: &str,
) -> Result<HashMap<String, String>, AppStoreError> {
    let mut headers = resolve_anisette().await?.headers;
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
            "trusted-device code validation failed with HTTP {status}"
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
    use super::*;
    use crate::domain::error::AppStoreError;
    use crate::infrastructure::grandslam::client::http::identity_token;
    use crate::infrastructure::http::encode_plist;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn anisette_headers() -> HashMap<String, String> {
        HashMap::from([("X-Apple-I-MD".into(), "local-test-token".into())])
    }

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
        assert!(matches!(
            validate_trusted_device_response(reqwest::StatusCode::BAD_REQUEST, b"ignored"),
            Err(AppStoreError::AuthenticationFailed(_))
        ));
        let missing_code = encode_plist(&serde_json::json!({})).expect("missing-code plist");
        assert!(matches!(
            validate_trusted_device_response(reqwest::StatusCode::OK, &missing_code),
            Err(AppStoreError::NetworkError(_))
        ));
    }

    #[tokio::test]
    async fn trusted_device_and_sms_endpoints_accept_successful_responses() {
        let server = MockServer::start().await;
        let success_plist = encode_plist(&serde_json::json!({ "ec": 0 })).expect("success plist");
        for (verb, route, response) in [
            ("GET", "/trusteddevice", ResponseTemplate::new(204)),
            (
                "GET",
                "/auth",
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "trustedPhoneNumbers": [
                        { "id": 7, "numberWithDialCode": "+1 ••••42" }
                    ]
                })),
            ),
            (
                "GET",
                "/validate",
                ResponseTemplate::new(200)
                    .set_body_raw(success_plist.clone(), "application/x-apple-plist"),
            ),
            ("PUT", "/phone", ResponseTemplate::new(204)),
            ("POST", "/phone/securitycode", ResponseTemplate::new(204)),
        ] {
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(response)
                .mount(&server)
                .await;
        }

        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let url = |route: &str| format!("{}{route}", server.uri());
        assert!(
            request_trusted_device_notification_with_headers(
                &client,
                &url("/trusteddevice"),
                anisette_headers()
            )
            .await
            .is_ok()
        );
        let phones =
            list_trusted_phone_numbers_with_headers(&client, &url("/auth"), anisette_headers())
                .await
                .expect("trusted phones");
        assert_eq!(phones.len(), 1);
        assert_eq!(phones[0].id, 7);
        assert!(
            validate_trusted_device_code_with_headers(
                &client,
                &url("/validate"),
                anisette_headers(),
                "123456"
            )
            .await
            .is_ok()
        );
        assert!(
            request_sms_with_headers(&client, &url("/phone"), anisette_headers(), 7)
                .await
                .is_ok()
        );
        assert!(
            validate_sms_code_with_headers(
                &client,
                &url("/phone/securitycode"),
                anisette_headers(),
                7,
                "123456"
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn trusted_device_and_sms_endpoints_map_http_and_decode_errors() {
        let server = MockServer::start().await;
        for (verb, route) in [
            ("GET", "/trusteddevice"),
            ("GET", "/auth"),
            ("GET", "/validate"),
            ("PUT", "/phone"),
            ("POST", "/phone/securitycode"),
        ] {
            Mock::given(method(verb))
                .and(path(route))
                .respond_with(ResponseTemplate::new(401).set_body_string("private"))
                .mount(&server)
                .await;
        }
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let url = |route: &str| format!("{}{route}", server.uri());
        assert!(
            request_trusted_device_notification_with_headers(
                &client,
                &url("/trusteddevice"),
                anisette_headers()
            )
            .await
            .is_err()
        );
        assert!(
            list_trusted_phone_numbers_with_headers(&client, &url("/auth"), anisette_headers())
                .await
                .is_err()
        );
        assert!(
            validate_trusted_device_code_with_headers(
                &client,
                &url("/validate"),
                anisette_headers(),
                "000000"
            )
            .await
            .is_err()
        );
        assert!(
            request_sms_with_headers(&client, &url("/phone"), anisette_headers(), 7)
                .await
                .is_err()
        );
        assert!(
            validate_sms_code_with_headers(
                &client,
                &url("/phone/securitycode"),
                anisette_headers(),
                7,
                "000000"
            )
            .await
            .is_err()
        );

        let invalid_json = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&invalid_json)
            .await;
        assert!(
            list_trusted_phone_numbers_with_headers(
                &client,
                &format!("{}/auth", invalid_json.uri()),
                anisette_headers()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn trusted_device_and_sms_endpoints_map_request_errors() {
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let url = "not a valid URL";

        assert!(
            request_trusted_device_notification_with_headers(&client, url, anisette_headers())
                .await
                .is_err()
        );
        assert!(
            list_trusted_phone_numbers_with_headers(&client, url, anisette_headers())
                .await
                .is_err()
        );
        assert!(
            validate_trusted_device_code_with_headers(&client, url, anisette_headers(), "123456")
                .await
                .is_err()
        );
        assert!(
            request_sms_with_headers(&client, url, anisette_headers(), 7)
                .await
                .is_err()
        );
        assert!(
            validate_sms_code_with_headers(&client, url, anisette_headers(), 7, "123456")
                .await
                .is_err()
        );
    }
}
