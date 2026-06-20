//! Commerce operations for Apple's `MZFinance` App Store endpoints.

use super::AppleAppStoreRepository;
use super::commerce_auth::auth_headers;
use super::parsing::{external_version_ids, parse_download_item};
use crate::domain::entity::{Account, AppVersion, DownloadItem, metadata_string};
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::plist_codec::build_plist_dict;

const BUY_PRODUCT_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
const DOWNLOAD_PRODUCT_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
const PURCHASE_SUCCESS_DOC_TYPE: &str = "purchaseSuccess";
const ALREADY_OWNED_FAILURE_TYPE: &str = "5002";

pub(super) async fn purchase(
    store: &AppleAppStoreRepository,
    account: &Account,
    app_id: i64,
    guid: &str,
) -> Result<(), AppStoreError> {
    let headers = auth_headers(&store.client, account)?;
    let plist_body = build_plist_dict(&[
        ("appExtVrsId", "0"),
        ("hasAskedToFulfillPreorder", "true"),
        ("buyWithoutAuthorization", "true"),
        ("hasDoneAgeCheck", "true"),
        ("guid", guid),
        ("needDiv", "0"),
        ("origPage", &format!("Software-{app_id}")),
        ("origPageLocation", "Buy"),
        ("price", "0"),
        ("pricingParameters", "STDQ"),
        ("productType", "C"),
        ("salableAdamId", &app_id.to_string()),
    ]);

    let response = store
        .post_store_plist(account, BUY_PRODUCT_PATH, "", &plist_body, &headers)
        .await?;

    let jingle_type = response
        .body
        .get("jingleDocType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let failure_type = response
        .body
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if jingle_type == PURCHASE_SUCCESS_DOC_TYPE || failure_type == ALREADY_OWNED_FAILURE_TYPE {
        return Ok(());
    }

    let message = response
        .body
        .get("customerMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown purchase error");
    let server_store_front = response
        .headers
        .get("x-set-apple-store-front")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sent_store_front = headers
        .get("X-Apple-Store-Front")
        .map_or("", String::as_str);
    tracing::debug!(
        %failure_type,
        %sent_store_front,
        %server_store_front,
        sent_dsid_len = headers.get("X-Dsid").map_or(0, String::len),
        auth_scheme = "password-token",
        body_keys = ?response.body.as_object().map(|body| body.keys().collect::<Vec<_>>()),
        "purchase rejected by store"
    );

    let detail = purchase_error_detail(message, failure_type);
    if server_store_front.is_empty() {
        return Err(AppStoreError::PurchaseFailed(detail));
    }
    Err(AppStoreError::PurchaseFailed(format!(
        "{detail} [store front sent: {sent_store_front}; Apple expects: {server_store_front}]"
    )))
}

pub(super) async fn download(
    store: &AppleAppStoreRepository,
    account: &Account,
    app_id: i64,
    guid: &str,
    version_id: Option<String>,
) -> Result<Vec<DownloadItem>, AppStoreError> {
    let headers = auth_headers(&store.client, account)?;
    let app_id_str = app_id.to_string();
    let mut plist_pairs = vec![
        ("creditDisplay", ""),
        ("guid", guid),
        ("salableAdamId", app_id_str.as_str()),
    ];

    if let Some(ref vid) = version_id {
        plist_pairs.push(("externalVersionId", vid.as_str()));
    }

    let plist_body = build_plist_dict(&plist_pairs);
    let response = store
        .post_store_plist(
            account,
            DOWNLOAD_PRODUCT_PATH,
            &format!("?guid={guid}"),
            &plist_body,
            &headers,
        )
        .await?;

    let failure_type = response
        .body
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !failure_type.is_empty() {
        let message = response
            .body
            .get("customerMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown download error");
        return Err(AppStoreError::DownloadFailed(message.to_string()));
    }

    let song_list = response
        .body
        .get("songList")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppStoreError::Unexpected("missing songList in download response".into()))?;

    let mut items = Vec::new();
    for item in song_list {
        if let Some(item) = parse_download_item(item)? {
            items.push(item);
        }
    }
    Ok(items)
}

pub(super) async fn list_versions(
    store: &AppleAppStoreRepository,
    account: &Account,
    app_id: i64,
    guid: &str,
) -> Result<Vec<AppVersion>, AppStoreError> {
    let items = download(store, account, app_id, guid, None).await?;
    let mut versions = Vec::new();
    for item in &items {
        let version_string =
            metadata_string(&item.metadata, "bundleShortVersionString").unwrap_or_default();
        if let Some(ext_ids) = item.metadata.get("softwareVersionExternalIdentifiers") {
            for vid in external_version_ids(ext_ids) {
                versions.push(AppVersion {
                    external_version_id: vid,
                    version_string: version_string.clone(),
                });
            }
        }
    }
    Ok(versions)
}

fn purchase_error_detail(message: &str, failure_type: &str) -> String {
    if failure_type.is_empty() {
        message.to_string()
    } else {
        format!("{message} (failureType {failure_type})")
    }
}
