//! Native Store session: sign-in, purchase, version listing, download
//! tickets and purchase history over the in-process Apple SAP machine.
//!
//! Port of the orchestration upstream ipatool's `nativeLogin` and the former
//! `tools/modern-anisette` helper performed: one URL bag, one SAP session,
//! one persistent cookie jar and one kbsync cache per process.

use super::native_commerce::bag::{StoreBag, fetch_bag, store_client};
use super::native_commerce::download_product::NativeDownloader;
use super::native_commerce::kbsync_cache::KbsyncCache;
use super::native_commerce::login::{Credentials, LoginContext, login, phone_number_country_code};
use super::native_commerce::owned_apps::{DaapClock, OwnedAppsContext, owned_apps};
use super::native_commerce::purchase::{PurchaseContext, purchase, purchase_url};
use super::native_commerce::storefront::{
    AVAILABLE_STOREFRONTS_URL, STOREFRONT_GENRE_URL, StorefrontResolver,
};
use super::native_commerce::telemetry::error_type;
use super::store_cookies::{PersistentCookies, STORE_COOKIES_FILE};
use super::store_machine::{StoreAmd, StoreMachine, amd_headers};
use crate::domain::entity::{Account, AppVersion, DownloadItem, OwnedApp};
use crate::domain::error::AppStoreError;
use crate::infrastructure::apple_sap::signer::SignerConfig;
use crate::infrastructure::apple_sap::storeauth::StoreProvisioningRequest;
use crate::infrastructure::apple_sap::storeauth::store_provisioning::{
    STORE_AUTHENTICATION_USER_AGENT, STORE_PROVISIONING_URL,
};
use crate::infrastructure::observability::elapsed_ms;
use base64::Engine;
use reqwest::Url;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::OnceCell;
use tracing::Instrument;

/// Account the Store "SP" provisioning kbsync is generated for (upstream
/// `^uint64(1)`, i.e. DSID -2).
const PROVISIONING_DSID: u64 = u64::MAX - 1;
const KBSYNC_CACHE_FILE: &str = "kbsync-v1.json";

type KbsyncSource<'a> = Box<dyn Fn(u64) -> Result<Vec<u8>, AppStoreError> + Send + Sync + 'a>;
type AmdSource<'a> = Box<dyn Fn() -> Result<StoreAmd, AppStoreError> + Send + Sync + 'a>;
type Downloader<'a> = NativeDownloader<'a, KbsyncSource<'a>, AmdSource<'a>>;

/// Where a [`StoreSession`] sends its requests and keeps its files.
#[derive(Debug, Clone)]
pub struct StoreSessionConfig {
    /// URL bag endpoint.
    pub bag_url: String,
    /// `MZPurchaseDaap` base URL for purchase history.
    pub purchase_history_url: String,
    /// When set, every Store request goes to this origin instead of Apple's
    /// hosts (path and query kept); for proxies and tests.
    pub origin: Option<String>,
    /// Directory of `store-cookies.json` and `kbsync-v1.json`.
    pub state_directory: PathBuf,
}

/// One process-wide native Store session.
pub struct StoreSession {
    machine: Arc<dyn StoreMachine>,
    config: StoreSessionConfig,
    client: reqwest::Client,
    storefronts: StorefrontResolver,
    kbsync_cache: KbsyncCache,
    bag: OnceCell<StoreBag>,
}

impl StoreSession {
    /// Open the session over `machine`, loading the persisted cookie jar.
    ///
    /// # Errors
    ///
    /// Returns [`AppStoreError::NetworkError`] when the HTTP client cannot be
    /// built.
    pub fn open(
        machine: Arc<dyn StoreMachine>,
        config: StoreSessionConfig,
    ) -> Result<Self, AppStoreError> {
        let cookies = PersistentCookies::load(config.state_directory.join(STORE_COOKIES_FILE));
        let client = store_client(Arc::new(cookies))?;
        let storefronts = StorefrontResolver::with_urls(
            client.clone(),
            &reroute(AVAILABLE_STOREFRONTS_URL, config.origin.as_deref()),
            &reroute(STOREFRONT_GENRE_URL, config.origin.as_deref()),
        );
        let kbsync_cache = KbsyncCache::new(config.state_directory.join(KBSYNC_CACHE_FILE));
        Ok(Self {
            machine,
            config,
            client,
            storefronts,
            kbsync_cache,
            bag: OnceCell::new(),
        })
    }

    /// The URL bag fetched once for commerce requests.
    async fn bag(&self, guid: &str) -> Result<&StoreBag, AppStoreError> {
        self.bag.get_or_try_init(|| self.fresh_bag(guid)).await
    }

    /// A newly fetched URL bag with its sign-in endpoint rerouted.
    async fn fresh_bag(&self, guid: &str) -> Result<StoreBag, AppStoreError> {
        let mut bag = fetch_bag(&self.client, &self.config.bag_url, guid).await?;
        bag.authenticate_account = self.reroute(&bag.authenticate_account);
        Ok(bag)
    }

    fn reroute(&self, url: &str) -> String {
        reroute(url, self.config.origin.as_deref())
    }

    async fn connect_sap(&self, bag: &StoreBag, guid: &str) -> Result<(), AppStoreError> {
        let config = SignerConfig {
            setup_url: bag.sap_setup.clone(),
            certificate_url: bag.sap_setup_cert.clone(),
            version: bag.sap_version,
            hardware_id: hardware_id(guid)?,
        };
        self.machine.connect_sap(config).await
    }

    /// Sign in to the Store with a fresh bag and SAP session, like every
    /// upstream attempt. Without `code`, Apple pushes a 2FA code to the
    /// trusted devices and this returns [`AppStoreError::AuthCodeRequired`];
    /// the coded attempt reuses the persisted cookie session.
    ///
    /// # Errors
    ///
    /// Authentication, provisioning and network failures.
    pub async fn login(
        &self,
        credentials: Credentials<'_>,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        observed("login", None, self.sign_in(credentials, guid)).await
    }

    async fn sign_in(
        &self,
        credentials: Credentials<'_>,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let bag = self.fresh_bag(guid).await?;
        self.connect_sap(&bag, guid).await?;
        let machine_headers = self.login_headers().await?;
        let storefront_hint = self.storefront_hint(credentials.email).await?;
        let machine = Arc::clone(&self.machine);
        let mut sign = move |body: &[u8]| machine.sign_blocking(body);
        let mut context = LoginContext {
            client: &self.client,
            endpoint: &bag.authenticate_account,
            guid,
            sign: &mut sign,
            machine_headers,
            storefront_hint,
            validate_redirect: LoginContext::DEFAULT_REDIRECT_POLICY,
        };
        let hardware_id = hardware_id(guid)?;
        login(&mut context, credentials, |challenge| {
            self.provision_store(challenge, hardware_id)
        })
        .await
    }

    /// The stored Store AMD proof once the Store provisioning exists,
    /// otherwise the GSA anisette headers (upstream `nativeLogin`).
    async fn login_headers(&self) -> Result<HashMap<String, String>, AppStoreError> {
        match self.machine.store_amd().await {
            Ok(amd) => Ok(amd_headers(amd)),
            Err(error) => {
                tracing::debug!(
                    service = "ipakeep",
                    component = "appstore",
                    operation = "login",
                    event_name = "appstore.login.store_amd_unavailable",
                    error_type = error_type(&error),
                    "no Store AMD proof yet; signing in with anisette headers"
                );
                self.machine.anisette_headers().await
            }
        }
    }

    async fn storefront_hint(&self, email: &str) -> Result<Option<String>, AppStoreError> {
        match phone_number_country_code(email) {
            Some(country) => Ok(Some(self.storefronts.storefront_id(country).await?)),
            None => Ok(None),
        }
    }

    /// The Store "SP" action: kbsync for DSID -2, `otp/1.5/finish`, then the
    /// fresh Store AMD proof for the retried sign-in.
    async fn provision_store(
        &self,
        challenge: String,
        hardware_id: Vec<u8>,
    ) -> Result<HashMap<String, String>, AppStoreError> {
        let started = Instant::now();
        tracing::info!(
            service = "ipakeep",
            component = "appstore",
            operation = "login",
            event_name = "appstore.login.store_provisioning_started",
            "Apple requested Store provisioning"
        );
        let kbsync = self.machine.kbsync(&hardware_id, PROVISIONING_DSID).await?;
        let kbsync = base64::engine::general_purpose::STANDARD.encode(kbsync);
        let identity: Vec<(String, String)> =
            self.machine.anisette_headers().await?.into_iter().collect();
        let endpoint = self.reroute(STORE_PROVISIONING_URL);
        let request = StoreProvisioningRequest {
            client: &self.client,
            challenge: &challenge,
            endpoint: &endpoint,
            user_agent: STORE_AUTHENTICATION_USER_AGENT,
            kbsync: &kbsync,
            hardware_id: &hardware_id,
            identity: &identity,
        };
        self.machine.provision_store(&request).await?;
        let headers = amd_headers(self.machine.store_amd().await?);
        tracing::info!(
            service = "ipakeep",
            component = "appstore",
            operation = "login",
            event_name = "appstore.login.store_provisioned",
            outcome = "success",
            duration_ms = elapsed_ms(started),
            "Store provisioning completed"
        );
        Ok(headers)
    }

    /// Acquire the free license for `app_id`. Apple answers "sign in again"
    /// (2034) even for owned apps, so that answer counts as owned whenever
    /// the version listing succeeds.
    ///
    /// # Errors
    ///
    /// Purchase, authentication and network failures.
    pub async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        let purchasing = self.acquire_license(account, app_id, guid);
        observed("purchase", Some(app_id), purchasing).await
    }

    async fn acquire_license(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        require_signed_in(account)?;
        let url = self.reroute(&purchase_url(&account.pod));
        let context = PurchaseContext {
            client: &self.client,
            url: &url,
            guid,
        };
        purchase(&context, account, app_id, || async {
            self.list_versions(account, app_id, guid).await.map(|_| ())
        })
        .await
    }

    /// External version identifiers of `app_id`, labelled with the catalog
    /// version.
    ///
    /// # Errors
    ///
    /// Download-ticket, authentication and network failures.
    pub async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError> {
        let listing = async {
            require_signed_in(account)?;
            let bag = self.bag(guid).await?;
            let hardware_id = hardware_id(guid)?;
            let downloader = self.downloader(bag, &hardware_id);
            downloader.list_versions(account, app_id, guid).await
        };
        observed("list_versions", Some(app_id), listing).await
    }

    /// The songList item of `app_id` (optionally pinned to a version) for the
    /// download and patch pipeline.
    ///
    /// # Errors
    ///
    /// Download-ticket, license, authentication and network failures.
    pub async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<&str>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        let ticket = async {
            require_signed_in(account)?;
            let bag = self.bag(guid).await?;
            let hardware_id = hardware_id(guid)?;
            let downloader = self.downloader(bag, &hardware_id);
            downloader.download(account, app_id, guid, version_id).await
        };
        observed("download", Some(app_id), ticket).await
    }

    fn downloader<'a>(&'a self, bag: &'a StoreBag, hardware_id: &'a [u8]) -> Downloader<'a> {
        let kbsync: KbsyncSource<'a> =
            Box::new(move |dsid| self.machine.kbsync_blocking(hardware_id, dsid));
        let amd: AmdSource<'a> = Box::new(move || self.machine.store_amd_blocking());
        let downloader = NativeDownloader::new(
            &self.client,
            bag,
            &self.storefronts,
            &self.kbsync_cache,
            kbsync,
            amd,
        );
        match &self.config.origin {
            Some(origin) => downloader.with_origin(origin.clone()),
            None => downloader,
        }
    }

    /// Up to `limit` owned apps, newest purchase first.
    ///
    /// # Errors
    ///
    /// SAP, purchase-history and network failures.
    pub async fn owned_apps(
        &self,
        account: &Account,
        limit: u32,
        guid: &str,
    ) -> Result<Vec<OwnedApp>, AppStoreError> {
        observed(
            "owned_apps",
            None,
            self.purchase_history(account, limit, guid),
        )
        .await
    }

    async fn purchase_history(
        &self,
        account: &Account,
        limit: u32,
        guid: &str,
    ) -> Result<Vec<OwnedApp>, AppStoreError> {
        require_signed_in(account)?;
        let bag = self.bag(guid).await?;
        self.connect_sap(bag, guid).await?;
        let machine = Arc::clone(&self.machine);
        let mut sign = move |body: &[u8]| machine.sign_blocking(body);
        let mut context = OwnedAppsContext {
            client: &self.client,
            base_url: &self.config.purchase_history_url,
            guid,
            sign: &mut sign,
            clock: DaapClock::now_utc(),
        };
        owned_apps(&mut context, account, limit).await
    }
}

/// Run one Store operation inside an `appstore_operation` span (so the
/// commerce events it emits carry the operation and app id) and record its
/// start, outcome and duration. Only the error variant is logged: messages
/// can quote Apple's free text.
async fn observed<T>(
    operation: &'static str,
    app_id: Option<i64>,
    future: impl Future<Output = Result<T, AppStoreError>>,
) -> Result<T, AppStoreError> {
    let span = tracing::info_span!(
        "appstore_operation",
        operation,
        app_id = tracing::field::Empty
    );
    if let Some(app_id) = app_id {
        span.record("app_id", app_id);
    }
    span.in_scope(log_started);
    let started = Instant::now();
    let result = future.instrument(span.clone()).await;
    let duration_ms = elapsed_ms(started);
    span.in_scope(|| log_outcome(operation, result.as_ref().err(), duration_ms));
    result
}

fn log_started() {
    tracing::debug!(
        service = "ipakeep",
        component = "appstore",
        event_name = "appstore.operation.started",
        "Store operation started"
    );
}

/// A pending 2FA code is the expected first sign-in answer, not a failure.
fn log_outcome(operation: &'static str, error: Option<&AppStoreError>, duration_ms: u64) {
    match error {
        None => {
            tracing::info!(
                service = "ipakeep",
                component = "appstore",
                operation,
                event_name = "appstore.operation.completed",
                outcome = "success",
                duration_ms,
                "Store operation completed"
            );
        }
        Some(error @ AppStoreError::AuthCodeRequired { .. }) => {
            tracing::info!(
                service = "ipakeep",
                component = "appstore",
                operation,
                event_name = "appstore.operation.completed",
                outcome = "auth_code_required",
                error_type = error_type(error),
                duration_ms,
                "Store operation needs a 2FA code"
            );
        }
        Some(error) => {
            tracing::warn!(
                service = "ipakeep",
                component = "appstore",
                operation,
                event_name = "appstore.operation.failed",
                outcome = "failure",
                error_type = error_type(error),
                duration_ms,
                "Store operation failed"
            );
        }
    }
}

/// Commerce needs the `MZFinance` purchase token of a Store sign-in.
fn require_signed_in(account: &Account) -> Result<(), AppStoreError> {
    if account.password_token.is_empty() || account.directory_services_id.is_empty() {
        return Err(AppStoreError::AuthenticationFailed(
            "account is missing the MZFinance passwordToken; run auth login".into(),
        ));
    }
    Ok(())
}

/// The hardware identifier bytes of an uppercase hex machine GUID.
fn hardware_id(guid: &str) -> Result<Vec<u8>, AppStoreError> {
    hex::decode(guid)
        .map_err(|_| AppStoreError::Unexpected("machine GUID is not a hex hardware id".into()))
}

/// `url` with its scheme, host and port replaced by `origin`, when given.
fn reroute(url: &str, origin: Option<&str>) -> String {
    let (Some(origin), Ok(parsed)) = (origin, Url::parse(url)) else {
        return url.to_string();
    };
    let query = parsed.query().map(|query| format!("?{query}"));
    format!(
        "{}{}{}",
        origin.trim_end_matches('/'),
        parsed.path(),
        query.unwrap_or_default()
    )
}

#[cfg(test)]
#[path = "store_session_tests.rs"]
mod tests;
