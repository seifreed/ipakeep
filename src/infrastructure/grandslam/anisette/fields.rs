//! Field mapping for Anisette headers and CPD.

use crate::domain::error::AppStoreError;
use serde_json::Value as JsonValue;
use std::collections::HashMap;

use super::time::iso8601_now;
use super::{CLIENT_INFO, DEVICE_MODEL, FALLBACK_DEVICE_ID, RINFO};

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
    /// Build fields from a remote anisette server JSON payload, validating that
    /// the cryptographic OTP tokens are present.
    ///
    /// Accepts both anisette-v3 response shapes: the flat `GET /` payload (the
    /// full `X-Apple-*` header set) and the `result`-wrapped `/v3/get_headers`
    /// payload (`{"result": "Headers", "X-Apple-I-MD", ...}`). Any other
    /// `result` value is surfaced as a clear, actionable error.
    pub(super) fn from_remote(
        obj: &serde_json::Map<String, JsonValue>,
    ) -> Result<Self, AppStoreError> {
        ensure_successful_result(obj)?;

        let get = |keys: &[&str]| -> Option<String> {
            keys.iter()
                .find_map(|key| {
                    obj.iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(key))
                        .map(|(_, value)| value_to_string(value))
                })
                .filter(|value| !value.is_empty())
        };

        let missing = |field: &str| {
            AppStoreError::AuthenticationFailed(format!(
                "anisette server response is missing the required OTP field {field}; point \
                 IPAKEEP_ANISETTE_URL at a provisioned anisette-v3 server (one whose GET / returns \
                 X-Apple-I-MD and X-Apple-I-MD-M)"
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

/// Detect the anisette-v3 `result` envelope and reject unsuccessful outcomes.
///
/// The `/v3/get_headers` endpoint wraps its reply in a `result` discriminant
/// (`Headers` on success, `GetHeadersError`/`ProvisioningNeeded`/… otherwise),
/// while a plain `GET /` response carries no `result` field. A response without
/// the envelope, or one reporting `Headers`, passes through; anything else is
/// turned into an actionable error quoting the server's own message.
fn ensure_successful_result(obj: &serde_json::Map<String, JsonValue>) -> Result<(), AppStoreError> {
    let Some(result) = obj
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("result"))
        .and_then(|(_, value)| value.as_str())
    else {
        return Ok(());
    };

    if result.eq_ignore_ascii_case("Headers") {
        return Ok(());
    }

    let detail = obj
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("message"))
        .and_then(|(_, value)| value.as_str())
        .unwrap_or("no detail provided");

    Err(AppStoreError::AuthenticationFailed(format!(
        "anisette v3 server returned result={result} ({detail}); it is not provisioned or rejected \
         the request. Point IPAKEEP_ANISETTE_URL at a provisioned anisette-v3 server."
    )))
}

/// Resolve the request locale from the `LANG` environment variable.
pub(super) fn current_locale() -> String {
    std::env::var("LANG")
        .unwrap_or_else(|_| "en_US".into())
        .split('.')
        .next()
        .unwrap_or("en_US")
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
        "os": "macOS 15.2",
        "p": "api",
        "pbe": "false",
        "prkgen": "true",
        "sv": "24C5089c",
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

fn value_to_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of the exact flat payload `anisette-v3-server` returns from
    /// `GET /` (see Dadoum/anisette-v3-server `source/app.d`).
    fn v3_root_payload() -> serde_json::Map<String, JsonValue> {
        serde_json::json!({
            "X-Apple-I-Client-Time": "2026-01-02T03:04:05Z",
            "X-Apple-I-MD": "AAAA-one-time-password",
            "X-Apple-I-MD-M": "BBBB-machine-identifier",
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": "CCCC-local-user",
            "X-Apple-I-SRL-NO": "0",
            "X-MMe-Client-Info": "<iPhone> <iOS;18.0> <com.apple.AuthKit/1>",
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
            "X-Mme-Device-Id": "11112222-3333-4444-5555-666677778888"
        })
        .as_object()
        .expect("object fixture")
        .clone()
    }

    #[test]
    fn parses_flat_v3_root_response_into_canonical_headers() {
        let fields = AnisetteFields::from_remote(&v3_root_payload()).expect("v3 root parses");
        let headers = build_headers(&fields);

        for key in [
            "X-Apple-I-Client-Time",
            "X-Apple-I-TimeZone",
            "X-Apple-Locale",
            "X-Apple-I-MD",
            "X-Apple-I-MD-LU",
            "X-Apple-I-MD-M",
            "X-Apple-I-MD-RINFO",
            "X-Mme-Device-Id",
            "X-Apple-I-SRL-NO",
            "X-MMe-Client-Info",
        ] {
            assert!(headers.contains_key(key), "missing canonical header {key}");
        }
        assert_eq!(headers["X-Apple-I-MD"], "AAAA-one-time-password");
        assert_eq!(headers["X-Apple-I-MD-M"], "BBBB-machine-identifier");
        assert_eq!(
            headers["X-Mme-Device-Id"],
            "11112222-3333-4444-5555-666677778888"
        );
    }

    #[test]
    fn accepts_v3_get_headers_result_envelope() {
        let obj = serde_json::json!({
            "result": "Headers",
            "X-Apple-I-MD": "otp",
            "X-Apple-I-MD-M": "machine",
            "X-Apple-I-MD-RINFO": "17106176"
        });
        let fields =
            AnisetteFields::from_remote(obj.as_object().unwrap()).expect("Headers envelope parses");
        assert_eq!(fields.md, "otp");
        assert_eq!(fields.md_m, "machine");
    }

    /// Parse `obj` expecting rejection, returning the error's message.
    /// `AnisetteFields` holds OTP secrets and is deliberately not `Debug`, so we
    /// destructure instead of using `Result::expect_err`.
    fn expect_remote_error(obj: &serde_json::Value) -> String {
        match AnisetteFields::from_remote(obj.as_object().unwrap()) {
            Ok(_) => panic!("expected the anisette payload to be rejected"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn rejects_v3_provisioning_needed_with_actionable_error() {
        let obj = serde_json::json!({ "result": "ProvisioningNeeded" });
        let message = expect_remote_error(&obj);
        assert!(message.contains("ProvisioningNeeded"), "message: {message}");
        assert!(
            message.contains("provisioned anisette-v3 server"),
            "message: {message}"
        );
    }

    #[test]
    fn rejects_v3_get_headers_error_quoting_server_message() {
        let obj = serde_json::json!({
            "result": "GetHeadersError",
            "message": "std.base64.Base64Exception: Invalid character"
        });
        let message = expect_remote_error(&obj);
        assert!(
            message.contains("Invalid character"),
            "server message should be surfaced: {message}"
        );
    }

    #[test]
    fn missing_otp_field_reports_required_field() {
        let obj = serde_json::json!({ "X-Apple-I-TimeZone": "UTC" });
        let message = expect_remote_error(&obj);
        assert!(message.contains("X-Apple-I-MD"), "message: {message}");
        assert!(
            message.contains("missing the required OTP field"),
            "message: {message}"
        );
    }

    #[test]
    fn headers_and_cpd_share_one_stable_identity() {
        // A single resolved identity must project consistently into both the
        // request headers and the CPD plist so that the same anisette data is
        // presented across the SRP init+complete exchange.
        let fields = AnisetteFields::from_remote(&v3_root_payload()).expect("v3 root parses");
        let headers = build_headers(&fields);
        let cpd = build_cpd(&fields);

        for key in ["X-Apple-I-MD", "X-Apple-I-MD-M", "X-Mme-Device-Id"] {
            assert_eq!(
                headers[key].as_str(),
                cpd[key].as_str().unwrap(),
                "header and CPD diverge for {key}"
            );
        }
    }
}
