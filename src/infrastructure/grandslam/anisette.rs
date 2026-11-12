//! Anisette / Client Provisioning Data (CPD) for Apple `GrandSlam`.
//!
//! Apple's `GrandSlam` authentication requires device metadata (CPD) embedded
//! in the SRP request plist. This module maps local or remote device data into
//! the request headers and plist.

mod fields;
mod time;

#[cfg(not(ipakeep_modern_adi))]
mod remote;

use crate::domain::error::AppStoreError;
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
use fields::current_locale;
use fields::{AnisetteFields, build_cpd, build_headers};
#[cfg(not(ipakeep_modern_adi))]
use remote::fetch_remote;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
use time::iso8601_now;

#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
use super::aoskit::{machine_serial_number, machine_udid, retrieve_otp_headers};

/// Device provisioning data bundled with HTTP headers.
#[derive(Debug, Clone)]
pub struct AnisetteData {
    /// Extra HTTP headers to attach to `GrandSlam` requests.
    pub headers: HashMap<String, String>,
    /// The `cpd` plist dictionary to embed in SRP request bodies.
    pub cpd: JsonValue,
}

/// Returns the local user's `GeneratedUID` on macOS, if available.
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
fn get_local_user_uuid() -> Option<String> {
    let username = std::env::var("USER").ok()?;
    let output = std::process::Command::new("dscl")
        .args([
            "/Search",
            "-read",
            &format!("/Users/{username}"),
            "GeneratedUID",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    // Parse "GeneratedUID: AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    stdout
        .split_whitespace()
        .nth(1)
        .map(|s| s.trim().to_string())
}

const DEVICE_MODEL: &str = "MacBookPro18,3";
const RINFO: &str = "17106176";
const CLIENT_INFO: &str = "<MacBookPro18,3> <Mac OS X;15.2;24C5089c> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>";
const FALLBACK_DEVICE_ID: &str = "FEDCBA09-8765-4321-0FED-CBA987654321";

/// Cryptographic OTP tokens (`X-Apple-I-MD*`) bundled together.
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
struct OtpTokens {
    md: String,
    md_lu: String,
    md_m: String,
}

/// Obtain Anisette data for the current platform/configuration.
///
/// Resolution order:
/// 1. `IPAKEEP_ANISETTE_URL` — fetch from an explicit remote anisette server.
/// 2. macOS — generate locally via `AOSKit` (real OTP tokens).
/// 3. Other platforms — auto-launch the bundled Docker anisette server and
///    fetch from it (`AOSKit` is unavailable, so placeholder tokens would be
///    rejected by Apple).
///
/// # Errors
///
/// Returns an error if a configured/launched anisette server cannot be reached
/// or returns an incomplete payload.
#[cfg(ipakeep_modern_adi)]
pub async fn resolve_anisette(_client: &reqwest::Client) -> Result<AnisetteData, AppStoreError> {
    super::modern_adi::generate().await
}

#[cfg(not(ipakeep_modern_adi))]
pub async fn resolve_anisette(client: &reqwest::Client) -> Result<AnisetteData, AppStoreError> {
    if let Ok(url) = std::env::var("IPAKEEP_ANISETTE_URL") {
        let url = url.trim();
        if !url.is_empty() {
            return fetch_remote(client, url).await;
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS can generate valid OTP tokens locally via AOSKit.
        generate_anisette()
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Other platforms lack AOSKit; fetch from the Docker anisette server.
        let url = super::anisette_docker::ensure_local_server(client).await?;
        fetch_remote(client, &url).await
    }
}

pub(super) fn from_headers(
    headers: HashMap<String, String>,
) -> Result<AnisetteData, AppStoreError> {
    let fields = headers
        .into_iter()
        .map(|(key, value)| (key, JsonValue::String(value)))
        .collect();
    let fields = AnisetteFields::from_remote(&fields)?;
    Ok(AnisetteData {
        headers: build_headers(&fields),
        cpd: build_cpd(&fields),
    })
}

/// Generate Anisette / CPD data locally (macOS `AOSKit` path).
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
fn generate_anisette() -> Result<AnisetteData, AppStoreError> {
    let tokens = otp_tokens()?;
    let (device_id, serial) = machine_identifiers();

    let fields = AnisetteFields {
        time: iso8601_now(),
        timezone: "UTC".to_string(),
        locale: current_locale(),
        md: tokens.md,
        md_lu: get_local_user_uuid().unwrap_or(tokens.md_lu),
        md_m: tokens.md_m,
        rinfo: RINFO.to_string(),
        client_info: CLIENT_INFO.to_string(),
        device_id,
        serial,
    };

    Ok(AnisetteData {
        headers: build_headers(&fields),
        cpd: build_cpd(&fields),
    })
}

/// Resolve the OTP tokens from native macOS `AOSKit`.
///
/// `X-Apple-I-MD` and `X-Apple-I-MD-M` are cryptographic tokens generated by
/// Apple's proprietary CoreADI/AOSKit libraries. Missing values are an error;
/// fabricated tokens cannot authenticate.
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
fn otp_tokens() -> Result<OtpTokens, AppStoreError> {
    otp_tokens_from_headers(retrieve_otp_headers("-2"), get_local_user_uuid())
}

#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
fn otp_tokens_from_headers(
    headers: Option<HashMap<String, String>>,
    local_user_uuid: Option<String>,
) -> Result<OtpTokens, AppStoreError> {
    let missing = |field: &str| {
        AppStoreError::AuthenticationFailed(format!(
            "macOS AOSKit did not provide {field}; refusing to send placeholder Anisette data"
        ))
    };
    let headers = headers.ok_or_else(|| missing("OTP headers"))?;
    // AOSUtilities may return keys with or without the `-I-` segment.
    let pick = |primary: &str, fallback: &str| {
        headers
            .get(primary)
            .or_else(|| headers.get(fallback))
            .cloned()
            .filter(|value| !value.is_empty())
    };
    Ok(OtpTokens {
        md: pick("X-Apple-I-MD", "X-Apple-MD").ok_or_else(|| missing("X-Apple-I-MD"))?,
        md_lu: pick("X-Apple-I-MD-LU", "X-Apple-MD-LU")
            .or(local_user_uuid)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| missing("X-Apple-I-MD-LU"))?,
        md_m: pick("X-Apple-I-MD-M", "X-Apple-MD-M").ok_or_else(|| missing("X-Apple-I-MD-M"))?,
    })
}

/// Resolve the `(device_id, serial)` pair, using real identifiers on macOS to
/// avoid Apple error 433.
#[cfg(all(target_os = "macos", not(ipakeep_modern_adi)))]
fn machine_identifiers() -> (String, String) {
    (
        machine_udid().unwrap_or_else(|| FALLBACK_DEVICE_ID.to_string()),
        machine_serial_number().unwrap_or_else(|| "0".to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_header_casing_builds_anisette_cpd() {
        let headers = HashMap::from([
            ("X-Apple-I-Md".into(), "otp".into()),
            ("X-Apple-I-Md-M".into(), "machine".into()),
            ("X-Mme-Client-Info".into(), "Mac client".into()),
        ]);

        let anisette = from_headers(headers).expect("anisette headers");

        assert_eq!(anisette.headers["X-Apple-I-MD"], "otp");
        assert_eq!(anisette.headers["X-Apple-I-MD-M"], "machine");
        assert_eq!(anisette.cpd["X-Apple-I-MD"], "otp");
        assert_eq!(anisette.cpd["X-MMe-Client-Info"], "Mac client");
    }
}

#[cfg(all(test, target_os = "macos", not(ipakeep_modern_adi)))]
mod legacy_tests {
    use super::*;

    #[test]
    fn otp_tokens_require_real_headers() {
        let result = otp_tokens_from_headers(None, None);
        assert!(result.err().unwrap().to_string().contains("OTP headers"));

        let result = otp_tokens_from_headers(Some(HashMap::new()), None);
        assert!(result.err().unwrap().to_string().contains("X-Apple-I-MD"));
    }

    #[test]
    fn otp_tokens_map_aoskit_header_aliases() {
        let headers = HashMap::from([
            ("X-Apple-MD".into(), "otp".into()),
            ("X-Apple-MD-M".into(), "machine".into()),
        ]);

        let tokens = otp_tokens_from_headers(Some(headers), Some("local-uuid".into())).unwrap();

        assert_eq!(tokens.md, "otp");
        assert_eq!(tokens.md_m, "machine");
        assert_eq!(tokens.md_lu, "local-uuid");
    }
}
