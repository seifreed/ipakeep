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
    pub(super) device_id: String,
    pub(super) serial: String,
}

impl AnisetteFields {
    /// Build fields from a remote anisette server JSON payload, validating that
    /// the cryptographic OTP tokens are present.
    pub(super) fn from_remote(
        obj: &serde_json::Map<String, JsonValue>,
    ) -> Result<Self, AppStoreError> {
        let get = |keys: &[&str]| -> Option<String> {
            keys.iter()
                .find_map(|key| obj.get(*key).map(value_to_string))
                .filter(|value| !value.is_empty())
        };

        let missing = |field: &str| {
            AppStoreError::AuthenticationFailed(format!(
                "anisette server did not return {field}; is it provisioned?"
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
            device_id: get(&["X-Mme-Device-Id"]).unwrap_or_else(|| FALLBACK_DEVICE_ID.to_string()),
            serial: get(&["X-Apple-I-SRL-NO"]).unwrap_or_else(|| "0".to_string()),
        })
    }
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
        ("X-Apple-I-Locale".into(), fields.locale.clone()),
        ("X-Apple-I-MD".into(), fields.md.clone()),
        ("X-Apple-I-MD-LU".into(), fields.md_lu.clone()),
        ("X-Apple-I-MD-M".into(), fields.md_m.clone()),
        ("X-Apple-I-MD-RINFO".into(), fields.rinfo.clone()),
        ("X-Mme-Device-Id".into(), fields.device_id.clone()),
        ("X-Apple-I-SRL-NO".into(), fields.serial.clone()),
        ("X-MMe-Client-Info".into(), CLIENT_INFO.into()),
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
        "X-MMe-Client-Info": CLIENT_INFO,
    })
}

fn value_to_string(value: &JsonValue) -> String {
    match value {
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    }
}
