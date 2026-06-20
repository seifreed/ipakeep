//! App Store API implementation — search, purchase, download, list-versions.

mod commerce;
mod commerce_auth;
mod grandslam_auth;
mod parsing;
mod transport;

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
use crate::domain::repository::AppStoreRepository;
use crate::infrastructure::appstore::config::AppleApiConfig;
use crate::infrastructure::http::AppleHttpClient;
use crate::infrastructure::http::client::HttpResponse;
use async_trait::async_trait;
use parsing::parse_app;
use std::collections::HashMap;
use transport::{appstore_query_url, pod_from_cookies, response_is_store_error};

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

    /// POST a plist to a store endpoint, retrying on the account's pod-specific
    /// host when the account has no pod yet and the first (generic-host) response
    /// is an error that sets an `itspod` affinity cookie. Apple's generic
    /// `buy.itunes.apple.com` answers "account could not be found" until the
    /// request lands on the right pod (e.g. `p48-buy.itunes.apple.com`); the
    /// `GrandSlam` SPD does not provide the pod, so it is discovered here.
    async fn post_store_plist(
        &self,
        account: &Account,
        path: &str,
        query: &str,
        plist_body: &serde_json::Value,
        headers: &HashMap<String, String>,
    ) -> Result<HttpResponse<serde_json::Value>, AppStoreError> {
        let url = format!("{}{query}", self.store_url(account, path));
        let response = self
            .client
            .post_plist(&url, plist_body, Some(headers))
            .await?;

        if !account.pod.is_empty() || !response_is_store_error(&response.body) {
            return Ok(response);
        }
        let Some(pod) = pod_from_cookies(&response.headers) else {
            return Ok(response);
        };

        let pod_url = format!("https://p{pod}-buy.itunes.apple.com{path}{query}");
        tracing::debug!(%pod, "retrying store request on pod-specific host");
        self.client
            .post_plist(&pod_url, plist_body, Some(headers))
            .await
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
        grandslam_auth::authenticate(&self.client, email, password).await
    }

    async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        grandslam_auth::request_trusted_device_notification(&self.client, dsid, idms_token).await
    }

    async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError> {
        grandslam_auth::validate_trusted_device_code(&self.client, dsid, idms_token, code).await
    }

    async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
        grandslam_auth::list_trusted_phone_numbers(&self.client, dsid, idms_token).await
    }

    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        grandslam_auth::request_sms(&self.client, dsid, idms_token, phone_id).await
    }

    async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError> {
        grandslam_auth::validate_sms_code(&self.client, dsid, idms_token, phone_id, code).await
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

        let apps = results.iter().filter_map(parse_app).collect();

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
            Some(arr) => Ok(arr.first().and_then(parse_app)),
            None => Ok(None),
        }
    }

    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        commerce::purchase(self, account, app_id, guid).await
    }

    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        commerce::download(self, account, app_id, guid, version_id).await
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
        commerce::list_versions(self, account, app_id, guid).await
    }
}

#[cfg(test)]
mod tests;
