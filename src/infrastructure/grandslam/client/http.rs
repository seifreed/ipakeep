//! HTTP helpers for the `GrandSlam` client.

use crate::domain::error::AppStoreError;
use crate::infrastructure::http::plist_codec::{decode_plist, encode_plist};
use crate::infrastructure::http::response_snippet;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// POST a plist XML body and decode the plist response.
pub(super) async fn post_plist(
    client: &reqwest::Client,
    url: &str,
    body: &JsonValue,
    extra_headers: Option<&HashMap<String, String>>,
) -> Result<JsonValue, AppStoreError> {
    let plist_xml = encode_plist(body)
        .map_err(|e| AppStoreError::NetworkError(format!("plist encode failed: {e}")))?;

    let mut request = client
        .post(url)
        .header("Content-Type", "application/x-apple-plist")
        .header("Accept", "*/*")
        .body(plist_xml);

    if let Some(h) = extra_headers {
        for (k, v) in h {
            request = request.header(k.as_str(), v.as_str());
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("HTTP POST failed: {e}")))?;

    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("failed to read response: {e}")))?;

    if !status.is_success() {
        return Err(AppStoreError::NetworkError(format!(
            "GrandSlam request failed with HTTP {status}: {}",
            response_snippet(&bytes)
        )));
    }

    decode_plist(&bytes)
        .map_err(|e| AppStoreError::NetworkError(format!("plist decode failed: {e}")))
}

/// Build the `X-Apple-Identity-Token` header value: base64 of `dsid:idms_token`.
pub(super) fn identity_token(dsid: &str, idms_token: &str) -> String {
    BASE64.encode(format!("{dsid}:{idms_token}").as_bytes())
}

/// Build a `reqwest::header::HeaderMap` from a `HashMap<String, String>`.
pub(super) fn build_header_map(
    headers: &HashMap<String, String>,
) -> Result<reqwest::header::HeaderMap, AppStoreError> {
    let mut map = reqwest::header::HeaderMap::new();
    for (k, v) in headers {
        let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| AppStoreError::NetworkError(format!("invalid header name: {e}")))?;
        let value = reqwest::header::HeaderValue::from_str(v)
            .map_err(|e| AppStoreError::NetworkError(format!("invalid header value: {e}")))?;
        map.insert(name, value);
    }
    Ok(map)
}

pub(super) async fn ensure_success_status(
    response: reqwest::Response,
    operation: &str,
) -> Result<(), AppStoreError> {
    let status = response.status();
    let body = response.bytes().await.map_err(|e| {
        AppStoreError::NetworkError(format!("{operation} response read failed: {e}"))
    })?;

    if !status.is_success() {
        return Err(super::response::two_factor_status_error(
            operation, status, &body,
        ));
    }

    Ok(())
}
