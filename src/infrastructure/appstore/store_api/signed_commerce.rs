//! App Store commerce through the bundled ipatool helper.
//!
//! Accounts signed in with the Store login only work when every `MZFinance`
//! request carries the Store AMD proof, kbsync and the session cookies of that
//! login, which only the helper can produce. The helper stages downloaded
//! packages on disk and reports them with their path as the item URL.

use super::parsing::parse_download_item;
use crate::domain::entity::{Account, AppVersion, DownloadItem};
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::store_request;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const PASSWORD_TOKEN_EXPIRED: &str = "passwordTokenExpired";
const LICENSE_REQUIRED: &str = "licenseRequired";
const STAGING_DIRECTORY: &str = "downloads";

pub(super) async fn purchase(account: &Account, app_id: i64) -> Result<(), AppStoreError> {
    let response = store_request("purchase", &request(account, app_id, None)).await?;
    check_failure(&response, app_id, AppStoreError::PurchaseFailed)
}

pub(super) async fn list_versions(
    account: &Account,
    app_id: i64,
) -> Result<Vec<AppVersion>, AppStoreError> {
    let response = store_request("list-versions", &request(account, app_id, None)).await?;
    check_failure(&response, app_id, AppStoreError::DownloadFailed)?;
    Ok(parse_versions(&response))
}

pub(super) async fn download(
    account: &Account,
    app_id: i64,
    version_id: Option<&str>,
) -> Result<Vec<DownloadItem>, AppStoreError> {
    let response = store_request("download", &request(account, app_id, version_id)).await?;
    check_failure(&response, app_id, AppStoreError::DownloadFailed)?;
    Ok(vec![staged_item(&response)?])
}

/// Read and discard a package the helper staged, or `None` when `url` does
/// not name one.
pub(super) fn take_staged_package(url: &str) -> Option<Result<Vec<u8>, AppStoreError>> {
    let staging = dirs::config_dir()?.join("ipakeep").join(STAGING_DIRECTORY);
    let directory = staged_package_directory(&staging, Path::new(url))?;
    let bytes = std::fs::read(url)
        .map_err(|error| AppStoreError::NetworkError(format!("read staged package: {error}")));
    if let Err(error) = std::fs::remove_dir_all(&directory) {
        tracing::warn!(
            service = "ipakeep",
            component = "appstore",
            operation = "download",
            event_name = "appstore.download.staging_cleanup_failed",
            outcome = "failure",
            error_type = ?error.kind(),
            "failed to remove staged package"
        );
    }
    Some(bytes)
}

/// The per-download directory holding `package`, when it lies directly inside
/// `staging` without symlinks redirecting it elsewhere.
fn staged_package_directory(staging: &Path, package: &Path) -> Option<PathBuf> {
    let staging = staging.canonicalize().ok()?;
    let package = package.canonicalize().ok()?;
    let directory = package.parent()?;
    (directory.parent()? == staging).then(|| directory.to_path_buf())
}

fn request(account: &Account, app_id: i64, version_id: Option<&str>) -> Value {
    json!({
        "account": {
            "email": account.email,
            "name": account.name,
            "passwordToken": account.password_token,
            "directoryServicesIdentifier": account.directory_services_id,
            "storeFront": account.store_front,
            "pod": account.pod,
        },
        "appId": app_id,
        "externalVersionId": version_id.unwrap_or_default(),
    })
}

fn check_failure(
    response: &Value,
    app_id: i64,
    failure: fn(String) -> AppStoreError,
) -> Result<(), AppStoreError> {
    let Some(error) = response.get("error") else {
        return Ok(());
    };
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown App Store error")
        .to_string();
    Err(match error.get("code").and_then(Value::as_str) {
        Some(PASSWORD_TOKEN_EXPIRED) => {
            AppStoreError::AuthenticationFailed(format!("{message}; run auth login again"))
        }
        Some(LICENSE_REQUIRED) => AppStoreError::NoLicense(app_id),
        _ => failure(message),
    })
}

/// Label every identifier with the catalog's current version, matching the
/// direct download response, which only describes the latest build.
fn parse_versions(response: &Value) -> Vec<AppVersion> {
    let version_string = response
        .get("latestVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    response
        .get("externalVersionIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|id| AppVersion {
            external_version_id: id.to_string(),
            version_string: version_string.to_string(),
        })
        .collect()
}

fn staged_item(response: &Value) -> Result<DownloadItem, AppStoreError> {
    response
        .get("item")
        .map(parse_download_item)
        .transpose()?
        .flatten()
        .ok_or_else(|| AppStoreError::Unexpected("missing item in download response".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_helper_failures_to_domain_errors() {
        let expired = json!({"error": {"code": PASSWORD_TOKEN_EXPIRED, "message": "x"}});
        let unlicensed = json!({"error": {"code": LICENSE_REQUIRED, "message": "x"}});
        let other = json!({"error": {"message": "item is temporarily unavailable"}});

        assert!(matches!(
            check_failure(&expired, 7, AppStoreError::DownloadFailed),
            Err(AppStoreError::AuthenticationFailed(_))
        ));
        assert!(matches!(
            check_failure(&unlicensed, 7, AppStoreError::DownloadFailed),
            Err(AppStoreError::NoLicense(7))
        ));
        assert!(matches!(
            check_failure(&other, 7, AppStoreError::PurchaseFailed),
            Err(AppStoreError::PurchaseFailed(message)) if message == "item is temporarily unavailable"
        ));
        assert!(check_failure(&json!({}), 7, AppStoreError::PurchaseFailed).is_ok());
    }

    #[test]
    fn labels_versions_with_the_catalog_version() {
        let versions = parse_versions(&json!({
            "externalVersionIds": ["894490049", "895038260"],
            "latestExternalVersionId": "895038260",
            "latestVersion": "1.377",
        }));

        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].external_version_id, "894490049");
        assert_eq!(versions[1].version_string, "1.377");
    }

    #[test]
    fn parses_a_staged_item_like_a_download_response() {
        let item = staged_item(&json!({"item": {
            "URL": "/tmp/download-1/package.ipa",
            "sinfs": [{"id": 0, "sinf": "AQID"}],
            "metadata": {"softwareVersionBundleId": "com.example"},
        }}))
        .expect("staged item");

        assert_eq!(item.url, "/tmp/download-1/package.ipa");
        assert_eq!(item.sinfs[0].data, [1, 2, 3]);
        assert_eq!(item.metadata["softwareVersionBundleId"], "com.example");
        assert!(staged_item(&json!({})).is_err());
    }

    #[test]
    fn only_accepts_packages_staged_by_the_helper() {
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join(STAGING_DIRECTORY);
        let download = staging.join("download-1");
        std::fs::create_dir_all(&download).expect("download directory");
        let package = download.join("package.ipa");
        std::fs::write(&package, b"ipa").expect("package");
        let outside = root.path().join("package.ipa");
        std::fs::write(&outside, b"ipa").expect("outside package");

        assert_eq!(
            staged_package_directory(&staging, &package),
            Some(download.canonicalize().expect("canonical download"))
        );
        assert_eq!(staged_package_directory(&staging, &outside), None);
        assert_eq!(
            staged_package_directory(
                &staging,
                Path::new("https://iosapps.itunes.apple.com/a.ipa")
            ),
            None
        );
    }
}
