//! App Store commerce through the bundled ipatool helper.
//!
//! Accounts signed in with the Store login only work when every `MZFinance`
//! request carries the Store AMD proof, kbsync and the session cookies of that
//! login, which only the helper can produce. The helper stages downloaded
//! packages on disk and reports them with their path as the item URL.

use super::parsing::parse_download_item;
use crate::domain::entity::{Account, AppVersion, DownloadItem, OwnedApp};
use crate::domain::error::AppStoreError;
use serde_json::{Value, json};
use std::future::Future;
use std::path::{Path, PathBuf};

const PASSWORD_TOKEN_EXPIRED: &str = "passwordTokenExpired";
const LICENSE_REQUIRED: &str = "licenseRequired";
const STAGING_DIRECTORY: &str = "downloads";

pub(super) async fn purchase<F, Fut>(
    account: &Account,
    app_id: i64,
    store_request: F,
) -> Result<(), AppStoreError>
where
    F: FnOnce(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, AppStoreError>>,
{
    let response = store_request("purchase", request(account, app_id, None)).await?;
    check_failure(&response, app_id, AppStoreError::PurchaseFailed)
}

pub(super) async fn list_versions<F, Fut>(
    account: &Account,
    app_id: i64,
    store_request: F,
) -> Result<Vec<AppVersion>, AppStoreError>
where
    F: FnOnce(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, AppStoreError>>,
{
    let response = store_request("list-versions", request(account, app_id, None)).await?;
    check_failure(&response, app_id, AppStoreError::DownloadFailed)?;
    Ok(parse_versions(&response))
}

pub(super) async fn download<F, Fut>(
    account: &Account,
    app_id: i64,
    version_id: Option<&str>,
    store_request: F,
) -> Result<Vec<DownloadItem>, AppStoreError>
where
    F: FnOnce(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, AppStoreError>>,
{
    let response = store_request("download", request(account, app_id, version_id)).await?;
    check_failure(&response, app_id, AppStoreError::DownloadFailed)?;
    Ok(vec![staged_item(&response)?])
}

pub(super) async fn owned_apps<F, Fut>(
    account: &Account,
    limit: u32,
    store_request: F,
) -> Result<Vec<OwnedApp>, AppStoreError>
where
    F: FnOnce(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value, AppStoreError>>,
{
    let response = store_request("owned-apps", owned_apps_request(account, limit)).await?;
    check_failure(&response, 0, AppStoreError::Unexpected)?;
    Ok(parse_owned_apps(&response))
}

/// Read and discard a package the helper staged, or `None` when `url` does
/// not name one.
pub(super) fn take_staged_package(url: &str) -> Option<Result<Vec<u8>, AppStoreError>> {
    let staging = dirs::config_dir()?.join("ipakeep").join(STAGING_DIRECTORY);
    take_staged_package_at(&staging, Path::new(url))
}

fn take_staged_package_at(
    staging: &Path,
    package: &Path,
) -> Option<Result<Vec<u8>, AppStoreError>> {
    let directory = staged_package_directory(staging, package)?;
    let bytes = std::fs::read(package)
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

fn account_json(account: &Account) -> Value {
    json!({
        "email": account.email,
        "name": account.name,
        "passwordToken": account.password_token,
        "directoryServicesIdentifier": account.directory_services_id,
        "storeFront": account.store_front,
        "pod": account.pod,
    })
}

fn request(account: &Account, app_id: i64, version_id: Option<&str>) -> Value {
    json!({
        "account": account_json(account),
        "appId": app_id,
        "externalVersionId": version_id.unwrap_or_default(),
    })
}

fn owned_apps_request(account: &Account, limit: u32) -> Value {
    json!({
        "account": account_json(account),
        "limit": limit,
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

/// Parse the owned-apps listing the helper returns, mapping each `apps` entry
/// to an [`OwnedApp`]. Entries without a numeric `trackId` are skipped so a
/// single malformed row never drops the whole listing.
fn parse_owned_apps(response: &Value) -> Vec<OwnedApp> {
    response
        .get("apps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(parse_owned_app)
        .collect()
}

fn parse_owned_app(item: &Value) -> Option<OwnedApp> {
    Some(OwnedApp {
        id: item.get("trackId").and_then(Value::as_i64)?,
        bundle_id: item
            .get("bundleId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        name: item
            .get("trackName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        version: item
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        platforms: item
            .get("platforms")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        purchase_date: item
            .get("purchaseDate")
            .and_then(Value::as_str)
            .filter(|date| !date.is_empty())
            .map(str::to_string),
    })
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

    fn account() -> Account {
        Account {
            email: "user@example.com".into(),
            name: "User".into(),
            password_token: "token".into(),
            directory_services_id: "123".into(),
            store_front: "143441-1".into(),
            pod: "48".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    #[tokio::test]
    async fn commerce_operations_map_helper_responses() {
        let account = account();
        assert!(
            purchase(&account, 7, |operation, request| async move {
                assert_eq!(operation, "purchase");
                assert_eq!(request["appId"], 7);
                Ok(json!({}))
            })
            .await
            .is_ok()
        );
        assert_eq!(
            list_versions(&account, 7, |operation, _| async move {
                assert_eq!(operation, "list-versions");
                Ok(json!({"latestVersion":"1.2", "externalVersionIds":["9"]}))
            })
            .await
            .expect("versions")[0]
                .version_string,
            "1.2"
        );
        assert_eq!(
            download(&account, 7, Some("9"), |operation, request| async move {
                assert_eq!(operation, "download");
                assert_eq!(request["externalVersionId"], "9");
                Ok(json!({"item":{"URL":"/tmp/package.ipa"}}))
            })
            .await
            .expect("download")
            .len(),
            1
        );
        assert!(
            owned_apps(&account, 25, |operation, request| async move {
                assert_eq!(operation, "owned-apps");
                assert_eq!(request["limit"], 25);
                Ok(json!({"apps":[{"trackId":7}]}))
            })
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn commerce_operations_propagate_helper_and_response_errors() {
        let account = account();
        assert!(matches!(
            purchase(&account, 7, |_, _| async {
                Err(AppStoreError::NetworkError("offline".into()))
            })
            .await,
            Err(AppStoreError::NetworkError(_))
        ));
        assert!(matches!(
            list_versions(&account, 7, |_, _| async {
                Ok(json!({"error":{"message":"unavailable"}}))
            })
            .await,
            Err(AppStoreError::DownloadFailed(_))
        ));
        assert!(matches!(
            download(&account, 7, None, |_, _| async { Ok(json!({})) }).await,
            Err(AppStoreError::Unexpected(_))
        ));
        assert!(matches!(
            owned_apps(&account, 25, |_, _| async {
                Ok(json!({"error":{"message":"failed"}}))
            })
            .await,
            Err(AppStoreError::Unexpected(_))
        ));
    }

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
        assert!(matches!(
            check_failure(
                &json!({"error": {"code": 7}}),
                7,
                AppStoreError::PurchaseFailed
            ),
            Err(AppStoreError::PurchaseFailed(message)) if message == "unknown App Store error"
        ));
        assert!(check_failure(&json!({}), 7, AppStoreError::PurchaseFailed).is_ok());
    }

    #[test]
    fn commerce_requests_serialize_account_and_version_fields() {
        let account = Account {
            email: "user@example.com".into(),
            name: "User".into(),
            password_token: "password-token".into(),
            directory_services_id: "123".into(),
            store_front: "143441-1".into(),
            pod: "48".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        };
        let payload = request(&account, 42, Some("9"));

        assert_eq!(payload["appId"], 42);
        assert_eq!(payload["externalVersionId"], "9");
        assert_eq!(payload["account"]["directoryServicesIdentifier"], "123");
        assert_eq!(payload["account"]["storeFront"], "143441-1");
        assert_eq!(owned_apps_request(&account, 25)["limit"], 25);
        assert_eq!(request(&account, 42, None)["externalVersionId"], "");
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
        assert!(parse_versions(&json!({})).is_empty());
    }

    #[test]
    fn parses_owned_apps_from_the_helper_listing() {
        let apps = parse_owned_apps(&json!({
            "totalCount": 2,
            "apps": [
                {
                    "trackId": 894_490_049_i64,
                    "bundleId": "com.example.ludostar",
                    "trackName": "Ludo Star",
                    "version": "1.376",
                    "platforms": ["iphone", "ipad"],
                    "purchaseDate": "2021-01-01T00:00:00Z",
                },
                {
                    "trackId": 1_234_i64,
                    "bundleId": "com.example.other",
                    "trackName": "Other",
                    "version": "2.0",
                },
            ],
        }));

        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].id, 894_490_049);
        assert_eq!(apps[0].bundle_id, "com.example.ludostar");
        assert_eq!(apps[0].platforms, vec!["iphone", "ipad"]);
        assert_eq!(
            apps[0].purchase_date.as_deref(),
            Some("2021-01-01T00:00:00Z")
        );
        assert!(apps[1].platforms.is_empty());
        assert!(apps[1].purchase_date.is_none());
    }

    #[test]
    fn skips_owned_apps_without_a_track_id() {
        let apps = parse_owned_apps(&json!({
            "apps": [
                {"bundleId": "com.example.missingid"},
                {"trackId": 7_i64, "bundleId": "com.example.kept"},
            ],
        }));

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, 7);
        assert!(parse_owned_apps(&json!({})).is_empty());
    }

    #[test]
    fn owned_app_optional_fields_default_and_filter_invalid_values() {
        let apps = parse_owned_apps(&json!({
            "apps": [
                {"trackId": 8},
                {"trackId": 9, "platforms": ["iphone", 7], "purchaseDate": ""},
                {"trackId": 10, "platforms": "iphone", "purchaseDate": 7}
            ]
        }));

        assert_eq!(apps[0].bundle_id, "");
        assert_eq!(apps[0].name, "");
        assert_eq!(apps[0].version, "");
        assert!(apps[0].platforms.is_empty());
        assert_eq!(apps[1].platforms, ["iphone"]);
        assert!(apps[1].purchase_date.is_none());
        assert!(apps[2].platforms.is_empty());
        assert!(apps[2].purchase_date.is_none());
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
        assert!(staged_item(&json!({"item": {}})).is_err());
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

    #[test]
    fn reads_and_removes_a_staged_package() {
        let root = tempfile::tempdir().expect("temporary directory");
        let staging = root.path().join(STAGING_DIRECTORY);
        let download = staging.join("download-2");
        std::fs::create_dir_all(&download).expect("download directory");
        let package = download.join("package.ipa");
        std::fs::write(&package, b"staged IPA").expect("package");

        assert_eq!(
            take_staged_package_at(&staging, &package)
                .expect("package is staged")
                .expect("package can be read"),
            b"staged IPA"
        );
        assert!(!download.exists());
        assert!(take_staged_package("https://example.test/package.ipa").is_none());
    }
}
