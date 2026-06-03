//! App Store API implementation — search, purchase, download, list-versions.

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, Sinf};
use crate::domain::error::AppStoreError;
use crate::domain::repository::AppStoreRepository;
use crate::infrastructure::appstore::config::AppleApiConfig;
use crate::infrastructure::grandslam::GrandSlamClient;
use crate::infrastructure::http::AppleHttpClient;
use crate::infrastructure::http::plist_codec::build_plist_dict;
use async_trait::async_trait;
use base64::Engine;
use reqwest::Url;
use std::collections::HashMap;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Purchase endpoint path.
const BUY_PRODUCT_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";

/// Download endpoint path.
const DOWNLOAD_PRODUCT_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";

/// US App Store storefront used when `GrandSlam` does not provide legacy store metadata.
const DEFAULT_US_STORE_FRONT: &str = "143441-1";

/// `GrandSlam` service token Apple exposes for iTunes/App Store commerce.
const APP_STORE_GS_TOKEN_APP: &str = "itunes.mu.invite";

/// Apple Configurator user agent expected by `MZFinance` commerce endpoints.
const CONFIGURATOR_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

/// Origin used to replay cookies captured from native Apple authentication.
const AUTH_COOKIE_ORIGIN: &str = "https://auth.itunes.apple.com/";

/// `AppStoreRepository` implementation using Apple's private APIs.
#[derive(Clone)]
pub struct AppleAppStoreRepository {
    client: AppleHttpClient,
    config: AppleApiConfig,
}

impl AppleAppStoreRepository {
    /// Create a new Apple App Store repository with default configuration.
    pub fn new(client: AppleHttpClient) -> Self {
        Self::with_config(client, AppleApiConfig::default())
    }

    /// Create a new Apple App Store repository with custom configuration.
    pub fn with_config(client: AppleHttpClient, config: AppleApiConfig) -> Self {
        Self { client, config }
    }

    /// Build the store URL with optional pod prefix.
    fn store_url(&self, account: &Account, path: &str) -> String {
        if account.pod.is_empty() {
            format!("{}{path}", self.config.store_base_url)
        } else {
            format!("https://p{}-buy.itunes.apple.com{path}", account.pod)
        }
    }

    fn seed_account_cookies(&self, account: &Account) -> Result<(), AppStoreError> {
        if account.cookies.is_empty() {
            return Ok(());
        }
        self.client
            .seed_cookies(&account.cookies, AUTH_COOKIE_ORIGIN)
    }

    fn identity_headers(account: &Account) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".into(), CONFIGURATOR_USER_AGENT.into());
        headers.insert("X-Dsid".into(), account.directory_services_id.clone());
        headers.insert("iCloud-DSID".into(), account.directory_services_id.clone());
        headers
    }

    /// Build legacy purchase authentication headers from an account.
    fn legacy_purchase_headers(account: &Account) -> HashMap<String, String> {
        let mut headers = Self::identity_headers(account);
        headers.insert("X-Token".into(), account.password_token.clone());
        let store_front = if account.store_front.is_empty() {
            DEFAULT_US_STORE_FRONT
        } else {
            &account.store_front
        };
        headers.insert("X-Apple-Store-Front".into(), store_front.to_string());
        headers
    }

    /// Build authentication headers, falling back to `GrandSlam` app tokens.
    async fn auth_headers(
        &self,
        account: &Account,
    ) -> Result<HashMap<String, String>, AppStoreError> {
        self.seed_account_cookies(account)?;
        let mut headers = Self::legacy_purchase_headers(account);
        if !account.password_token.is_empty() {
            return Ok(headers);
        }

        if account.idms_token.is_some() {
            let gs_client = GrandSlamClient::new(self.client.client().clone());
            let token = gs_client
                .request_app_token(account, APP_STORE_GS_TOKEN_APP)
                .await?;
            Self::insert_grandslam_headers(&mut headers, account, &token);
        }

        Ok(headers)
    }

    fn insert_grandslam_headers(
        headers: &mut HashMap<String, String>,
        account: &Account,
        token: &str,
    ) {
        headers.insert("X-Apple-GS-Token".into(), token.to_string());
        headers.insert("X-Token".into(), token.to_string());

        if let Some(identity_id) = account
            .adsid
            .as_deref()
            .or(account.dsid.as_deref())
            .filter(|s| !s.is_empty())
        {
            headers.insert("X-Apple-I-Identity-Id".into(), identity_id.to_string());
        }

        for (key, value) in crate::infrastructure::grandslam::generate_anisette().headers {
            headers.entry(key).or_insert(value);
        }
    }
}

#[async_trait]
impl AppStoreRepository for AppleAppStoreRepository {
    async fn authenticate(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let auth_url = crate::infrastructure::appstore::bag::resolve_auth_endpoint(
            &self.client,
            &self.config.bag_url,
            guid,
        )
        .await?;
        crate::infrastructure::appstore::authentication::authenticate(
            &self.client,
            &auth_url,
            email,
            password,
            guid,
        )
        .await
    }

    async fn authenticate_with_2fa(
        &self,
        email: &str,
        password: &str,
        code: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let auth_url = crate::infrastructure::appstore::bag::resolve_auth_endpoint(
            &self.client,
            &self.config.bag_url,
            guid,
        )
        .await?;
        crate::infrastructure::appstore::authentication::authenticate_with_2fa(
            &self.client,
            &auth_url,
            email,
            password,
            code,
            guid,
        )
        .await
    }

    async fn authenticate_grandslam(
        &self,
        email: &str,
        password: &str,
        _guid: &str,
    ) -> Result<Account, AppStoreError> {
        let gs_client = GrandSlamClient::new(self.client.client().clone());
        let init = gs_client.srp_init(email).await?;
        let result = gs_client.srp_complete(email, password, &init).await?;
        match result {
            crate::infrastructure::grandslam::client::SrpCompleteResult::Success(account) => {
                Ok(*account)
            }
            crate::infrastructure::grandslam::client::SrpCompleteResult::TwoFactorRequired {
                dsid,
                idms_token,
            } => Err(AppStoreError::AuthCodeRequired { dsid, idms_token }),
        }
    }

    async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        let gs_client = GrandSlamClient::new(self.client.client().clone());
        gs_client
            .request_trusted_device_notification(dsid, idms_token)
            .await
    }

    async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let gs_client = GrandSlamClient::new(self.client.client().clone());
        gs_client
            .validate_trusted_device_code(dsid, idms_token, code)
            .await
    }

    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        let gs_client = GrandSlamClient::new(self.client.client().clone());
        gs_client.request_sms(dsid, idms_token, phone_id).await
    }

    async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let gs_client = GrandSlamClient::new(self.client.client().clone());
        gs_client
            .validate_sms_code(dsid, idms_token, phone_id, code)
            .await
    }

    async fn search(
        &self,
        term: &str,
        country: &str,
        limit: u32,
    ) -> Result<Vec<App>, AppStoreError> {
        let limit = limit.to_string();
        let url = appstore_query_url(
            &self.config.itunes_search_url,
            &[
                ("entity", "software,iPadSoftware"),
                ("limit", &limit),
                ("media", "software"),
                ("term", term),
                ("country", country),
            ],
        )?;

        let response = self
            .client
            .get_json::<serde_json::Value>(&url)
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;

        let results = response
            .body
            .get("results")
            .and_then(|v| v.as_array())
            .ok_or_else(|| AppStoreError::Unexpected("missing results array".into()))?;

        let apps = results
            .iter()
            .filter_map(|item| {
                Some(App {
                    id: item.get("trackId")?.as_i64()?,
                    bundle_id: item.get("bundleId")?.as_str()?.to_string(),
                    name: item.get("trackName")?.as_str()?.to_string(),
                    version: item.get("version")?.as_str()?.to_string(),
                    price: item.get("price")?.as_f64()?,
                })
            })
            .collect();

        Ok(apps)
    }

    async fn lookup(&self, bundle_id: &str, country: &str) -> Result<Option<App>, AppStoreError> {
        let url = appstore_query_url(
            &self.config.itunes_lookup_url,
            &[
                ("entity", "software,iPadSoftware"),
                ("limit", "1"),
                ("media", "software"),
                ("bundleId", bundle_id),
                ("country", country),
            ],
        )?;

        let response = self
            .client
            .get_json::<serde_json::Value>(&url)
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;

        let results = response.body.get("results").and_then(|v| v.as_array());

        match results {
            Some(arr) if !arr.is_empty() => {
                let item = &arr[0];
                Ok(Some(App {
                    id: item
                        .get("trackId")
                        .and_then(serde_json::Value::as_i64)
                        .unwrap_or(0),
                    bundle_id: item
                        .get("bundleId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: item
                        .get("trackName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    version: item
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    price: item
                        .get("price")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(0.0),
                }))
            }
            _ => Ok(None),
        }
    }

    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        let url = self.store_url(account, BUY_PRODUCT_PATH);
        let headers = self.auth_headers(account).await?;

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

        let response = self
            .client
            .post_plist(&url, &plist_body, Some(&headers))
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

        if jingle_type == "purchaseSuccess" {
            return Ok(());
        }

        if failure_type == "5002" {
            return Ok(()); // Already purchased
        }

        let message = response
            .body
            .get("customerMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown purchase error");

        Err(AppStoreError::PurchaseFailed(message.to_string()))
    }

    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        let url = format!(
            "{}?guid={guid}",
            self.store_url(account, DOWNLOAD_PRODUCT_PATH)
        );
        let headers = self.auth_headers(account).await?;

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

        let response = self
            .client
            .post_plist(&url, &plist_body, Some(&headers))
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
            .ok_or_else(|| {
                AppStoreError::Unexpected("missing songList in download response".into())
            })?;

        let mut items = Vec::new();
        for item in song_list {
            if let Some(item) = parse_download_item(item)? {
                items.push(item);
            }
        }

        Ok(items)
    }

    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError> {
        self.client
            .download_file(url, None)
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))
    }

    async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError> {
        // First download to get metadata containing version info
        let items = self.download(account, app_id, guid, None).await?;

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
}

fn appstore_query_url(base: &str, pairs: &[(&str, &str)]) -> Result<String, AppStoreError> {
    let mut url = Url::parse(base)
        .map_err(|e| AppStoreError::NetworkError(format!("invalid App Store URL: {e}")))?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}

fn parse_download_item(item: &serde_json::Value) -> Result<Option<DownloadItem>, AppStoreError> {
    let Some(url) = item
        .get("URL")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
        return Ok(None);
    };

    let md5 = item
        .get("md5")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let sinfs = parse_download_sinfs(item.get("sinfs"))?;

    let metadata = item
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    Ok(Some(DownloadItem {
        url,
        md5,
        sinfs,
        metadata,
    }))
}

fn metadata_string(
    metadata: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn external_version_ids(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(ids) => ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect(),
        serde_json::Value::Array(ids) => ids
            .iter()
            .filter_map(external_version_id)
            .collect::<Vec<_>>(),
        other => external_version_id(other).into_iter().collect(),
    }
}

fn external_version_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(id) => {
            let id = id.trim();
            if id.is_empty() {
                None
            } else {
                Some(id.to_string())
            }
        }
        serde_json::Value::Number(id) => Some(id.to_string()),
        _ => None,
    }
}

fn parse_download_sinfs(value: Option<&serde_json::Value>) -> Result<Vec<Sinf>, AppStoreError> {
    let Some(arr) = value.and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut sinfs = Vec::new();
    for sinf in arr {
        let Some(id) = sinf.get("id").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let data = match sinf.get("sinf").and_then(serde_json::Value::as_str) {
            Some(encoded) if !encoded.is_empty() => BASE64.decode(encoded).map_err(|e| {
                AppStoreError::Unexpected(format!("invalid sinf base64 for id {id}: {e}"))
            })?,
            _ => Vec::new(),
        };
        sinfs.push(Sinf { id, data });
    }

    Ok(sinfs)
}
