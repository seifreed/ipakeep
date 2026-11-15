//! Anisette / Client Provisioning Data (CPD) for Apple `GrandSlam`.
//!
//! Apple's `GrandSlam` authentication requires device metadata (CPD) embedded
//! in the SRP request plist. The headers come from the in-process Apple SAP
//! service ([`SapService::anisette_headers`]) on every platform; this module
//! maps them into the request headers and the CPD dictionary.

mod fields;
mod time;

use crate::domain::error::AppStoreError;
use crate::infrastructure::apple_sap::storeauth::SapService;
use fields::{AnisetteFields, build_cpd, build_headers};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

/// Device provisioning data bundled with HTTP headers.
#[derive(Debug, Clone)]
pub struct AnisetteData {
    /// Extra HTTP headers to attach to `GrandSlam` requests.
    pub headers: HashMap<String, String>,
    /// The `cpd` plist dictionary to embed in SRP request bodies.
    pub cpd: JsonValue,
}

/// Device model the emulated `akd` reports (matches its `X-MMe-Client-Info`).
const DEVICE_MODEL: &str = "MacBookPro13,3";
/// Operating system the emulated `akd` reports.
const DEVICE_OS: &str = "Mac OS X 10.12.6";
/// Build of [`DEVICE_OS`].
const SYSTEM_VERSION: &str = "16G29";
const RINFO: &str = "17106176";
const CLIENT_INFO: &str =
    "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const FALLBACK_DEVICE_ID: &str = "FEDCBA09-8765-4321-0FED-CBA987654321";

/// Obtain Anisette data from the process-wide native Apple SAP service.
///
/// The first call reuses (or creates) the persisted machine provisioning;
/// later calls return the same headers for the rest of the process, because
/// Apple binds the `GrandSlam` session to the `X-Apple-I-MD-M` it saw.
///
/// # Errors
///
/// Returns an error when the Apple assets, the emulated machine, GSA
/// provisioning or the state file fail.
pub async fn resolve_anisette() -> Result<AnisetteData, AppStoreError> {
    #[cfg(test)]
    if let Some(data) = test_anisette() {
        return Ok(data);
    }
    let headers = SapService::shared()?.anisette_headers().await?;
    from_headers(&headers.to_map())
}

#[cfg(test)]
thread_local! {
    static TEST_ANISETTE: std::cell::RefCell<Option<AnisetteData>> = const { std::cell::RefCell::new(None) };
}

/// Make [`resolve_anisette`] return `data` on this thread (tests only).
#[cfg(test)]
pub(crate) fn set_test_anisette(data: Option<AnisetteData>) {
    TEST_ANISETTE.with(|cell| cell.replace(data));
}

#[cfg(test)]
fn test_anisette() -> Option<AnisetteData> {
    TEST_ANISETTE.with(|cell| cell.borrow().clone())
}

/// Map an anisette header set to request headers and CPD.
///
/// # Errors
///
/// Returns [`AppStoreError::AuthenticationFailed`] when the one-time password
/// or machine identifier is missing.
pub(crate) fn from_headers(
    headers: &HashMap<String, String>,
) -> Result<AnisetteData, AppStoreError> {
    let fields = AnisetteFields::from_headers(headers)?;
    Ok(AnisetteData {
        headers: build_headers(&fields),
        cpd: build_cpd(&fields),
    })
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

        let anisette = from_headers(&headers).expect("anisette headers");

        assert_eq!(anisette.headers["X-Apple-I-MD"], "otp");
        assert_eq!(anisette.headers["X-Apple-I-MD-M"], "machine");
        assert_eq!(anisette.cpd["X-Apple-I-MD"], "otp");
        assert_eq!(anisette.cpd["X-MMe-Client-Info"], "Mac client");
    }

    #[test]
    fn cpd_matches_the_native_akd_client_identity() {
        let headers = HashMap::from([
            ("X-Apple-I-MD".into(), "otp".into()),
            ("X-Apple-I-MD-M".into(), "machine".into()),
        ]);

        let data = from_headers(&headers).expect("Anisette data");

        assert_eq!(data.cpd["dt"], DEVICE_MODEL);
        assert_eq!(data.cpd["os"], DEVICE_OS);
        assert_eq!(data.cpd["sv"], SYSTEM_VERSION);
        assert_eq!(data.headers["X-MMe-Client-Info"], CLIENT_INFO);
    }

    #[tokio::test]
    async fn resolve_returns_the_test_override() {
        let data = from_headers(&HashMap::from([
            ("X-Apple-I-MD".into(), "override".into()),
            ("X-Apple-I-MD-M".into(), "machine".into()),
        ]))
        .expect("Anisette data");
        set_test_anisette(Some(data));

        let resolved = resolve_anisette().await;
        set_test_anisette(None);

        assert_eq!(
            resolved.expect("override").headers["X-Apple-I-MD"],
            "override"
        );
    }
}
