//! App Store API implementation — search, purchase, download, list-versions.

mod grandslam_auth;
pub mod native_commerce;
mod parsing;
mod store_cookies;
pub mod store_machine;
mod store_session;
mod transport;

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, OwnedApp, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
use crate::domain::repository::{
    AuthenticationRepository, CatalogRepository, DownloadRepository, PurchaseRepository,
    VersionRepository,
};
use crate::infrastructure::apple_sap::storeauth::SapService;
use crate::infrastructure::appstore::config::AppleApiConfig;
use crate::infrastructure::http::AppleHttpClient;
use async_trait::async_trait;
use native_commerce::bag::machine_guid;
use native_commerce::login::Credentials;
use parsing::parse_app;
use std::path::PathBuf;
use std::sync::Arc;
use store_machine::StoreMachine;
use store_session::{StoreSession, StoreSessionConfig};
use tokio::sync::OnceCell;
use transport::appstore_query_url;

const APP_DIRECTORY: &str = "ipakeep";
/// GUID sent when the machine has no readable MAC address.
const FALLBACK_HARDWARE_ID: [u8; 6] = [0; 6];

/// The machine GUID Apple sees: the uppercase hex MAC address, or zeros when
/// none is readable.
#[must_use]
pub fn device_guid() -> String {
    let address = mac_address::get_mac_address().ok().flatten();
    machine_guid(&address.map_or(FALLBACK_HARDWARE_ID, mac_address::MacAddress::bytes))
}

/// `AppStoreRepository` implementation using Apple's private APIs.
#[derive(Clone)]
pub struct AppleAppStoreRepository {
    client: AppleHttpClient,
    config: AppleApiConfig,
    machine: Option<Arc<dyn StoreMachine>>,
    session: Arc<OnceCell<StoreSession>>,
}

impl AppleAppStoreRepository {
    /// Create a new Apple App Store repository with default configuration.
    pub fn new(client: AppleHttpClient) -> Self {
        Self::with_config(client, AppleApiConfig::default())
    }

    /// Create a new Apple App Store repository with custom configuration,
    /// over the process-wide native Apple SAP service.
    pub fn with_config(client: AppleHttpClient, config: AppleApiConfig) -> Self {
        Self {
            client,
            config,
            machine: None,
            session: Arc::new(OnceCell::new()),
        }
    }

    /// Create a repository whose Store session uses `machine` for anisette,
    /// Store AMD, kbsync and SAP signing.
    pub fn with_store_machine(
        client: AppleHttpClient,
        config: AppleApiConfig,
        machine: Arc<dyn StoreMachine>,
    ) -> Self {
        Self {
            machine: Some(machine),
            ..Self::with_config(client, config)
        }
    }

    /// The native Store session, opened on first use.
    async fn store(&self) -> Result<&StoreSession, AppStoreError> {
        self.session
            .get_or_try_init(|| async {
                let machine = match &self.machine {
                    Some(machine) => Arc::clone(machine),
                    None => Arc::new(SapService::shared()?),
                };
                StoreSession::open(machine, self.session_config()?)
            })
            .await
    }

    fn session_config(&self) -> Result<StoreSessionConfig, AppStoreError> {
        let state_directory = match &self.config.state_directory {
            Some(directory) => directory.clone(),
            None => default_state_directory()?,
        };
        Ok(StoreSessionConfig {
            bag_url: self.config.bag_url.clone(),
            purchase_history_url: self.config.purchase_history_url.clone(),
            origin: self.config.store_origin.clone(),
            state_directory,
        })
    }
}

fn default_state_directory() -> Result<PathBuf, AppStoreError> {
    dirs::config_dir()
        .map(|directory| directory.join(APP_DIRECTORY))
        .ok_or_else(|| AppStoreError::NetworkError("cannot find user config directory".into()))
}

#[async_trait]
impl AuthenticationRepository for AppleAppStoreRepository {
    async fn authenticate(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        store_authenticate(self, email, password, None, guid).await
    }

    async fn authenticate_with_2fa(
        &self,
        email: &str,
        password: &str,
        code: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        store_authenticate(self, email, password, Some(code), guid).await
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
}

#[async_trait]
impl CatalogRepository for AppleAppStoreRepository {
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
}

#[async_trait]
impl PurchaseRepository for AppleAppStoreRepository {
    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        self.store().await?.purchase(account, app_id, guid).await
    }

    async fn list_purchases(
        &self,
        account: &Account,
        limit: u32,
    ) -> Result<Vec<OwnedApp>, AppStoreError> {
        let guid = device_guid();
        self.store().await?.owned_apps(account, limit, &guid).await
    }
}

#[async_trait]
impl DownloadRepository for AppleAppStoreRepository {
    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        self.store()
            .await?
            .download(account, app_id, guid, version_id.as_deref())
            .await
    }

    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError> {
        self.client
            .download_file(url, None)
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))
    }
}

#[async_trait]
impl VersionRepository for AppleAppStoreRepository {
    async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError> {
        self.store()
            .await?
            .list_versions(account, app_id, guid)
            .await
    }
}

async fn store_authenticate(
    repository: &AppleAppStoreRepository,
    email: &str,
    password: &str,
    code: Option<&str>,
    guid: &str,
) -> Result<Account, AppStoreError> {
    let credentials = Credentials {
        email,
        password,
        auth_code: code,
    };
    repository.store().await?.login(credentials, guid).await
}

#[cfg(test)]
mod tests;
