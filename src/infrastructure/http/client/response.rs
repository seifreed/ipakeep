//! HTTP response decoding and status errors.

use crate::domain::error::AppStoreError;
use crate::infrastructure::http::{plist_codec, response_snippet};
use reqwest::StatusCode;

/// An HTTP response with typed body, status code, and headers.
pub struct HttpResponse<T> {
    /// The HTTP status code.
    pub status: StatusCode,
    /// The response headers.
    pub headers: reqwest::header::HeaderMap,
    /// The deserialized response body.
    pub body: T,
}

pub(super) fn ensure_success_status(
    operation: &str,
    status: StatusCode,
    body: &[u8],
) -> Result<(), AppStoreError> {
    if status.is_success() {
        return Ok(());
    }
    Err(http_status_error(operation, status, body))
}

pub(super) fn http_status_error(operation: &str, status: StatusCode, body: &[u8]) -> AppStoreError {
    AppStoreError::NetworkError(format!(
        "{operation} failed with HTTP {status}: {}",
        response_snippet(body)
    ))
}

pub(super) fn decode_json_or_plist(text: &str) -> Result<serde_json::Value, String> {
    if let Ok(value) = serde_json::from_str(text) {
        return Ok(value);
    }

    if let Ok(value) = plist_codec::decode_plist(text.as_bytes()) {
        return Ok(value);
    }

    let plist = extract_embedded_plist(text)?;
    plist_codec::decode_plist(plist.as_bytes())
}

fn extract_embedded_plist(text: &str) -> Result<&str, String> {
    let start = text
        .find("<plist")
        .ok_or_else(|| "missing embedded plist".to_string())?;
    let end = text
        .rfind("</plist>")
        .ok_or_else(|| "missing embedded plist terminator".to_string())?
        + "</plist>".len();
    Ok(&text[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::http::encode_plist;
    use serde_json::json;

    #[test]
    fn ensure_success_status_accepts_success_and_formats_error() {
        assert!(ensure_success_status("op", StatusCode::OK, b"ok").is_ok());

        let error = ensure_success_status("op", StatusCode::BAD_GATEWAY, b"bad\nbody")
            .unwrap_err()
            .to_string();

        assert!(error.contains("op failed with HTTP 502 Bad Gateway"));
        assert!(error.contains("bad body"));
    }

    #[test]
    fn decode_json_or_plist_reads_json_xml_and_embedded_plist() {
        assert_eq!(
            decode_json_or_plist(r#"{"key":"value"}"#).unwrap()["key"],
            "value"
        );

        let plist = String::from_utf8(encode_plist(&json!({"key": "plist"})).unwrap()).unwrap();
        assert_eq!(decode_json_or_plist(&plist).unwrap()["key"], "plist");

        let wrapped = format!("prefix {plist} suffix");
        assert_eq!(decode_json_or_plist(&wrapped).unwrap()["key"], "plist");
    }

    #[test]
    fn decode_json_or_plist_rejects_missing_embedded_plist_parts() {
        assert!(
            decode_json_or_plist("not plist")
                .unwrap_err()
                .contains("missing embedded plist")
        );
        assert!(
            extract_embedded_plist("<plist><dict></dict>")
                .unwrap_err()
                .contains("missing embedded plist terminator")
        );
    }
}
