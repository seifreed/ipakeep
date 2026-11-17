//! Field mapping for Anisette headers and CPD.

use crate::domain::error::AppStoreError;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

use super::time::iso8601_now;
use super::{CLIENT_INFO, DEVICE_MODEL, DEVICE_OS, FALLBACK_DEVICE_ID, RINFO, SYSTEM_VERSION};

/// The fully-resolved field values shared by the headers and CPD projections.
pub(super) struct AnisetteFields {
    pub(super) time: String,
    pub(super) timezone: String,
    pub(super) locale: String,
    pub(super) md: String,
    pub(super) md_lu: String,
    pub(super) md_m: String,
    pub(super) rinfo: String,
    pub(super) client_info: String,
    pub(super) device_id: String,
    pub(super) serial: String,
}

impl AnisetteFields {
    /// Build fields from an anisette header set (names matched ignoring
    /// ASCII case), requiring the cryptographic OTP tokens.
    pub(super) fn from_headers(headers: &HashMap<String, String>) -> Result<Self, AppStoreError> {
        let get = |keys: &[&str]| -> Option<String> {
            keys.iter()
                .find_map(|key| {
                    headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(key))
                        .map(|(_, value)| value.clone())
                })
                .filter(|value| !value.is_empty())
        };
        let missing = |field: &str| {
            AppStoreError::AuthenticationFailed(format!(
                "anisette headers are missing the required OTP field {field}"
            ))
        };

        Ok(Self {
            time: get(&["X-Apple-I-Client-Time"]).unwrap_or_else(iso8601_now),
            timezone: get(&["X-Apple-I-TimeZone"]).unwrap_or_else(|| "UTC".to_string()),
            locale: get(&["X-Apple-I-Locale", "X-Apple-Locale"]).unwrap_or_else(current_locale),
            md: get(&["X-Apple-I-MD"]).ok_or_else(|| missing("X-Apple-I-MD"))?,
            md_lu: get(&["X-Apple-I-MD-LU"]).unwrap_or_default(),
            md_m: get(&["X-Apple-I-MD-M"]).ok_or_else(|| missing("X-Apple-I-MD-M"))?,
            rinfo: get(&["X-Apple-I-MD-RINFO"]).unwrap_or_else(|| RINFO.to_string()),
            client_info: get(&["X-MMe-Client-Info"]).unwrap_or_else(|| CLIENT_INFO.to_string()),
            device_id: get(&["X-Mme-Device-Id"]).unwrap_or_else(|| FALLBACK_DEVICE_ID.to_string()),
            serial: get(&["X-Apple-I-SRL-NO"]).unwrap_or_else(|| "0".to_string()),
        })
    }
}

/// Locale reported when `LANG` does not provide one.
const DEFAULT_LOCALE: &str = "en_US";

/// Resolve the request locale from the `LANG` environment variable.
fn current_locale() -> String {
    locale_from_lang(std::env::var("LANG"))
}

/// Strip the encoding suffix from a `LANG` value, falling back to
/// [`DEFAULT_LOCALE`] when the variable is unset or not valid Unicode.
fn locale_from_lang(lang: Result<String, std::env::VarError>) -> String {
    lang.unwrap_or_else(|_| DEFAULT_LOCALE.into())
        .split('.')
        .next()
        .unwrap_or(DEFAULT_LOCALE)
        .to_string()
}

pub(super) fn build_headers(fields: &AnisetteFields) -> HashMap<String, String> {
    HashMap::from([
        ("X-Apple-I-Client-Time".into(), fields.time.clone()),
        ("X-Apple-I-TimeZone".into(), fields.timezone.clone()),
        ("X-Apple-Locale".into(), fields.locale.clone()),
        ("X-Apple-I-MD".into(), fields.md.clone()),
        ("X-Apple-I-MD-LU".into(), fields.md_lu.clone()),
        ("X-Apple-I-MD-M".into(), fields.md_m.clone()),
        ("X-Apple-I-MD-RINFO".into(), fields.rinfo.clone()),
        ("X-Mme-Device-Id".into(), fields.device_id.clone()),
        ("X-Apple-I-SRL-NO".into(), fields.serial.clone()),
        ("X-MMe-Client-Info".into(), fields.client_info.clone()),
    ])
}

pub(super) fn build_cpd(fields: &AnisetteFields) -> JsonValue {
    serde_json::json!({
        "ak": "anisette-v3",
        "bootstrap": "true",
        "cl": fields.locale,
        "dt": DEVICE_MODEL,
        "icscrec": "true",
        "loc": fields.timezone,
        "os": DEVICE_OS,
        "p": "api",
        "pbe": "false",
        "prkgen": "true",
        "sv": SYSTEM_VERSION,
        "svct": "iCloud",
        "tk": "01",
        "v": "2",
        "X-Apple-I-Client-Time": fields.time,
        "X-Apple-I-TimeZone": fields.timezone,
        "X-Apple-I-Locale": fields.locale,
        "X-Apple-I-MD": fields.md,
        "X-Apple-I-MD-LU": fields.md_lu,
        "X-Apple-I-MD-M": fields.md_m,
        "X-Apple-I-MD-RINFO": fields.rinfo,
        "X-Mme-Device-Id": fields.device_id,
        "X-Apple-I-SRL-NO": fields.serial,
        "X-MMe-Client-Info": fields.client_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_headers() -> HashMap<String, String> {
        [
            ("X-Apple-I-Client-Time", "2026-01-02T03:04:05Z"),
            ("X-Apple-I-MD", "AAAA-one-time-password"),
            ("X-Apple-I-MD-M", "BBBB-machine-identifier"),
            ("X-Apple-I-MD-RINFO", "17106176"),
            ("X-Apple-I-MD-LU", "CCCC-local-user"),
            ("X-Apple-I-SRL-NO", "0"),
            (
                "X-MMe-Client-Info",
                "<MacBookPro13,3> <Mac OS X;10.12.6;16G29>",
            ),
            ("X-Apple-I-TimeZone", "Local"),
            ("X-Apple-Locale", "en_US"),
            ("X-Mme-Device-Id", "11112222-3333-4444-5555-666677778888"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    }

    #[test]
    fn maps_native_headers_into_canonical_headers() {
        let fields = AnisetteFields::from_headers(&native_headers()).expect("headers parse");
        let headers = build_headers(&fields);

        assert_eq!(headers.len(), 10);
        assert_eq!(headers["X-Apple-I-MD"], "AAAA-one-time-password");
        assert_eq!(headers["X-Apple-I-MD-M"], "BBBB-machine-identifier");
        assert_eq!(headers["X-Apple-I-TimeZone"], "Local");
        assert_eq!(
            headers["X-Mme-Device-Id"],
            "11112222-3333-4444-5555-666677778888"
        );
    }

    #[test]
    fn missing_otp_field_reports_required_field() {
        let headers = HashMap::from([("X-Apple-I-TimeZone".to_string(), "UTC".to_string())]);
        let Err(error) = AnisetteFields::from_headers(&headers) else {
            panic!("headers without an OTP must be rejected");
        };
        assert!(error.to_string().contains("X-Apple-I-MD"), "{error}");
    }

    #[test]
    fn unset_lang_falls_back_to_default_locale() {
        assert_eq!(
            locale_from_lang(Err(std::env::VarError::NotPresent)),
            DEFAULT_LOCALE
        );
    }

    #[test]
    fn lang_encoding_suffix_is_stripped() {
        assert_eq!(locale_from_lang(Ok("es_ES.UTF-8".to_string())), "es_ES");
    }

    #[test]
    fn headers_and_cpd_share_one_stable_identity() {
        let fields = AnisetteFields::from_headers(&native_headers()).expect("headers parse");
        let headers = build_headers(&fields);
        let cpd = build_cpd(&fields);

        for key in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id"] {
            assert_eq!(
                headers[key].as_str(),
                cpd[key].as_str().expect("CPD string"),
                "header and CPD diverge for {key}"
            );
        }
    }
}
