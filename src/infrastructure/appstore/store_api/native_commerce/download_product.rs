//! Native Store download ticket: `ent/download` with kbsync, then the legacy
//! `volumeStoreDownloadProduct` → `redownload` → `updateProduct` chain.
//!
//! Ported from ipatool v2.8.1 `pkg/appstore`: `appstore_download_product.go`,
//! `appstore_kbsync.go`, `appstore_amd.go`, `appstore_platform_version_lookup.go`,
//! `appstore_ios_version_lookup.go`, `appstore_list_versions.go` and
//! `appstore_lookup.go`. Requests go out directly instead of through the
//! emulated `AppleMediaServices` session, carrying what upstream sends.
//!
//! Wire notes (no live capture yet):
//! - Upstream hands the payload to `AMSURLRequestEncoder` with
//!   `requestEncoding = 2`; in the pinned framework that is an XML property
//!   list (`+[AMSData dataWithObject:encoding:error:]`, format 100). So every
//!   body here is an XML plist, even for `ent/download`, whose Content-Type
//!   upstream overrides to `application/x-www-form-urlencoded`.
//! - Dictionary keys are written sorted, as `CFPropertyList` does.
//! - The AMS session may add headers of its own (locale, client versions);
//!   only the headers upstream sets explicitly are sent.
//! - Session cookies come from the caller's client (`bag::store_client`).
//! - Only the iOS (iPhone) platform is ported; ipakeep has no other.

use super::bag::{STORE_USER_AGENT, StoreBag, decode_store_plist};
use super::kbsync_cache::KbsyncCache;
use super::storefront::{DEFAULT_USER_AGENT, StorefrontResolver};
use crate::domain::entity::{Account, AppVersion, DownloadItem};
use crate::domain::error::AppStoreError;
use crate::infrastructure::appstore::store_api::parsing::parse_download_item;
use crate::infrastructure::http::plist_codec::decode_plist;
use base64::Engine;
use reqwest::Url;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const DOWNLOAD_DISPATCH_DOMAIN: &str = "downloaddispatch.itunes.apple.com";
const BUY_DOMAIN: &str = "buy.itunes.apple.com";
const ENT_DOWNLOAD_PATH: &str = "/WebObjects/DownloadDispatch.woa/wa/ent/download";
const REDOWNLOAD_PATH: &str = "/r/redownload";
const UPDATE_PRODUCT_PATH: &str = "/up/updateProduct";
const VOLUME_STORE_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
const VERSION_KEY_VOLUME_STORE: &str = "externalVersionId";
const VERSION_KEY_REDOWNLOAD: &str = "appExtVrsId";
const PLATFORM_LOOKUP_URL: &str =
    "https://uclient-api.itunes.apple.com/WebObjects/MZStorePlatform.woa/wa/lookup";
const IOS_CATALOG_URL: &str = "https://apps.apple.com/api/apps/v1/catalog";
const ITUNES_LOOKUP_URL: &str = "https://itunes.apple.com/lookup";
const PLATFORM_CATALOGS: [&str; 3] = ["enterprisestore", "iphone", "ipad"];
const IOS_PLATFORM: &str = "iphone";
const LOOKUP_ENTITY_QUERY: &str = "software%2CiPadSoftware";
const CONTENT_TYPE_PLIST: &str = "application/x-apple-plist";
const CONTENT_TYPE_FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";
const SERIAL_PREFIX: [u8; 5] = [0x54, 0xc8, 0xb0, 0xa9, 0x88];
const SERIAL_HARDWARE_OFFSET: usize = 2;
const HARDWARE_ID_LEN: usize = 6;
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(30);
const HTTPS_PORT: u16 = 443;
const FAILURE_PASSWORD_TOKEN_EXPIRED: &str = "2034";
const FAILURE_SIGN_IN_REQUIRED: &str = "2042";
const FAILURE_LICENSE_NOT_FOUND: &str = "9610";
const FAILURE_LICENSE_ALREADY_EXISTS: &str = "5002";
const FAILURE_DEVICE_VERIFICATION_FAILED: &str = "1008";
const DOWNLOAD_EXPIRED_FAILURES: [&str; 4] = [
    FAILURE_PASSWORD_TOKEN_EXPIRED,
    FAILURE_SIGN_IN_REQUIRED,
    FAILURE_DEVICE_VERIFICATION_FAILED,
    FAILURE_LICENSE_ALREADY_EXISTS,
];
const LIST_EXPIRED_FAILURES: [&str; 2] = [FAILURE_PASSWORD_TOKEN_EXPIRED, FAILURE_SIGN_IN_REQUIRED];
const REDOWNLOAD_UNAVAILABLE: &str = "Redownload Unavailable with This Apple Account";
const REDOWNLOAD_UNAVAILABLE_EXPLANATION: &str = "This redownload is not available for this Apple Account either because it was bought by a different user or the item was refunded or cancelled.";

/// One decoded Store response: HTTP status and its plist body as JSON
/// (`Null` for redirects, which are never followed).
#[derive(Debug, Clone)]
struct StoreResponse {
    status: u16,
    body: Value,
}

/// A failed attempt, keeping the response Apple sent, if any.
#[derive(Debug)]
struct Failure {
    response: Option<StoreResponse>,
    error: AppStoreError,
    empty_server_error: bool,
}

type Attempt = Result<StoreResponse, Failure>;

enum VersionLookupError {
    CatalogNotFound(AppStoreError),
    Failed(AppStoreError),
}

/// Request identity shared by every step of one download.
struct Ticket<'a> {
    account: &'a Account,
    app_id: i64,
    guid: &'a str,
    hardware_id: Vec<u8>,
}

/// A validated `downloaddispatch` endpoint and the key it expects the
/// version under.
struct Endpoint {
    url: String,
    version_key: &'static str,
}

/// Native download-ticket client.
///
/// `kbsync(dsid)` returns a raw kbsync blob for the account; `amd()` returns
/// `(X-Apple-AMD, X-Apple-AMD-M)`: base64 ADI OTP for DSID -1 and its MID.
pub struct NativeDownloader<'a, K, A> {
    client: &'a reqwest::Client,
    bag: &'a StoreBag,
    storefronts: &'a StorefrontResolver,
    kbsync_cache: &'a KbsyncCache,
    kbsync: K,
    amd: A,
    origin: Option<String>,
}

impl<'a, K, A> NativeDownloader<'a, K, A>
where
    K: Fn(u64) -> Result<Vec<u8>, AppStoreError>,
    A: Fn() -> Result<(String, String), AppStoreError>,
{
    /// Downloader over `client`, which must carry the Store session cookies and
    /// never follow redirects (see `bag::store_client`).
    pub fn new(
        client: &'a reqwest::Client,
        bag: &'a StoreBag,
        storefronts: &'a StorefrontResolver,
        kbsync_cache: &'a KbsyncCache,
        kbsync: K,
        amd: A,
    ) -> Self {
        Self {
            client,
            bag,
            storefronts,
            kbsync_cache,
            kbsync,
            amd,
            origin: None,
        }
    }

    #[cfg(test)]
    fn with_origin(mut self, origin: String) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Download ticket for `app_id`, as the songList item the existing
    /// download pipeline consumes. `guid` is the uppercase hex hardware id.
    ///
    /// # Errors
    ///
    /// [`AppStoreError::AuthenticationFailed`] when Apple wants a new sign-in,
    /// [`AppStoreError::NoLicense`] without a license, and download, network
    /// or response errors otherwise.
    pub async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        external_version_id: Option<&str>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        let ticket = Ticket::new(account, app_id, guid)?;
        let version = external_version_id.filter(|id| !id.is_empty());
        let response = self
            .send_download_product(&ticket, version.map(str::to_string))
            .await
            .map_err(|failure| failure.error)?;
        let item = first_item(&response, app_id, &DOWNLOAD_EXPIRED_FAILURES)?;
        let item = parse_download_item(item)?
            .ok_or_else(|| AppStoreError::DownloadFailed("download item has no URL".into()))?;
        Ok(vec![item])
    }

    /// External version identifiers of `app_id`, each labelled with the
    /// catalog's current version string.
    ///
    /// # Errors
    ///
    /// As [`Self::download`], plus missing version metadata.
    pub async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError> {
        let ticket = Ticket::new(account, app_id, guid)?;
        let response = self
            .send_download_product(&ticket, None)
            .await
            .map_err(|failure| failure.error)?;
        let item = first_item(&response, app_id, &LIST_EXPIRED_FAILURES)?;
        let identifiers = version_identifiers(item)?;
        let label = self
            .catalog_version(account, app_id)
            .await
            .unwrap_or_default();
        Ok(identifiers
            .into_iter()
            .map(|external_version_id| AppVersion {
                external_version_id,
                version_string: label.clone(),
            })
            .collect())
    }

    async fn send_download_product(&self, ticket: &Ticket<'_>, version: Option<String>) -> Attempt {
        if let Some(ent) = self.bag.volume_store_download_product.as_deref()
            && let Ok(response) = self.preferred_download(ticket, ent, version.clone()).await
        {
            return Ok(response);
        }
        let volume = volume_store_endpoint(&ticket.account.pod);
        let response = self
            .send_legacy(ticket, &volume, version.as_deref(), None)
            .await?;
        if !is_empty_response(&response) && !is_unavailable_response(&response) {
            return Ok(response);
        }
        let Some(redownload) = self.bag.redownload_product.as_deref() else {
            return Ok(response);
        };
        let redownload = download_endpoint(redownload, REDOWNLOAD_PATH)
            .map_err(|error| failure(Some(response.clone()), error))?;
        self.redownload_chain(ticket, &redownload, version, response)
            .await
    }

    async fn redownload_chain(
        &self,
        ticket: &Ticket<'_>,
        redownload: &Endpoint,
        version: Option<String>,
        volume: StoreResponse,
    ) -> Attempt {
        let version = match version {
            Some(version) => version,
            None => match self.latest_version_id(ticket).await {
                Ok(version) => version,
                Err(VersionLookupError::CatalogNotFound(_)) => {
                    return self.delisted_download(ticket, redownload).await;
                }
                Err(VersionLookupError::Failed(error)) => return Err(failure(Some(volume), error)),
            },
        };
        let response = self
            .send_legacy(ticket, redownload, Some(&version), None)
            .await;
        if self.bag.update_product.is_some() && update_eligible(&response) {
            return self.update_product(ticket, &version).await;
        }
        response
    }

    async fn update_product(&self, ticket: &Ticket<'_>, version: &str) -> Attempt {
        let url = self.bag.update_product.as_deref().unwrap_or_default();
        let endpoint =
            download_endpoint(url, UPDATE_PRODUCT_PATH).map_err(|error| failure(None, error))?;
        let response = self
            .send_legacy(ticket, &endpoint, Some(version), None)
            .await?;
        validated(response, ticket.app_id, Some(version), "update")
    }

    async fn delisted_download(&self, ticket: &Ticket<'_>, redownload: &Endpoint) -> Attempt {
        let unpinned = self.unpinned_redownload(ticket, redownload).await;
        if unpinned
            .as_ref()
            .is_ok_and(|response| failure_type(&response.body) != FAILURE_LICENSE_NOT_FOUND)
        {
            return unpinned;
        }
        let Some(ent) = self.bag.volume_store_download_product.as_deref() else {
            return unpinned;
        };
        let ent = match download_endpoint(ent, ENT_DOWNLOAD_PATH) {
            Ok(ent) => ent,
            Err(error) => return Err(failure(attempt_response(&unpinned), error)),
        };
        let ent_attempt = self.ent_download(ticket, &ent, None).await;
        resolve_delisted(unpinned, ent_attempt, ticket.app_id)
    }

    async fn unpinned_redownload(&self, ticket: &Ticket<'_>, redownload: &Endpoint) -> Attempt {
        let mut response = self
            .send_legacy(ticket, redownload, None, Some(AUTHENTICATION_TIMEOUT))
            .await?;
        normalize_failure(&mut response.body);
        let response = validated(response, ticket.app_id, None, "redownload")?;
        if failure_type(&response.body).is_empty() && item_url(&response).is_empty() {
            return Err(failure(
                Some(response),
                AppStoreError::DownloadFailed("redownload response has no package URL".into()),
            ));
        }
        Ok(response)
    }

    async fn preferred_download(
        &self,
        ticket: &Ticket<'_>,
        ent_url: &str,
        version: Option<String>,
    ) -> Attempt {
        let endpoint =
            download_endpoint(ent_url, ENT_DOWNLOAD_PATH).map_err(|error| failure(None, error))?;
        let version = match version {
            Some(version) => version,
            None => self
                .latest_version_id(ticket)
                .await
                .map_err(|error| failure(None, error.into_error()))?,
        };
        self.ent_download(ticket, &endpoint, Some(&version)).await
    }

    async fn ent_download(
        &self,
        ticket: &Ticket<'_>,
        endpoint: &Endpoint,
        version: Option<&str>,
    ) -> Attempt {
        let dsid = ticket.dsid().map_err(|error| failure(None, error))?;
        if let Some(cached) = self.kbsync_cache.cached(dsid, ticket.guid) {
            let attempt = self.ent_request(ticket, endpoint, version, &cached).await;
            if attempt.is_ok() {
                return attempt;
            }
            self.kbsync_cache.invalidate(dsid, ticket.guid, &cached);
        }
        let blob = self
            .generate_kbsync(dsid)
            .map_err(|error| failure(None, error))?;
        let attempt = self.ent_request(ticket, endpoint, version, &blob).await;
        if attempt.is_ok() {
            self.kbsync_cache.store(dsid, ticket.guid, &blob);
        }
        attempt
    }

    fn generate_kbsync(&self, dsid: u64) -> Result<String, AppStoreError> {
        let data = (self.kbsync)(dsid)?;
        if data.is_empty() {
            return Err(AppStoreError::DownloadFailed(
                "generated download kbsync is empty".into(),
            ));
        }
        Ok(base64::engine::general_purpose::STANDARD.encode(data))
    }

    async fn ent_request(
        &self,
        ticket: &Ticket<'_>,
        endpoint: &Endpoint,
        version: Option<&str>,
        blob: &str,
    ) -> Attempt {
        let body = ent_body(ticket, version, blob);
        let mut response = self
            .post(
                ticket,
                endpoint,
                CONTENT_TYPE_FORM,
                &body,
                Some(AUTHENTICATION_TIMEOUT),
            )
            .await?;
        normalize_failure(&mut response.body);
        let failure_code = failure_type(&response.body);
        if !failure_code.is_empty() {
            let error = AppStoreError::DownloadFailed(format!(
                "received ent/download error: {failure_code}"
            ));
            return Err(failure(Some(response), error));
        }
        let response = validated(response, ticket.app_id, version, "ent/download")?;
        if item_url(&response).is_empty() {
            let error =
                AppStoreError::DownloadFailed("ent/download response has no package URL".into());
            return Err(failure(Some(response), error));
        }
        Ok(response)
    }

    async fn send_legacy(
        &self,
        ticket: &Ticket<'_>,
        endpoint: &Endpoint,
        version: Option<&str>,
        timeout: Option<Duration>,
    ) -> Attempt {
        let body = legacy_body(ticket, endpoint.version_key, version);
        self.post(ticket, endpoint, CONTENT_TYPE_PLIST, &body, timeout)
            .await
    }

    async fn post(
        &self,
        ticket: &Ticket<'_>,
        endpoint: &Endpoint,
        content_type: &str,
        body: &plist::Dictionary,
        timeout: Option<Duration>,
    ) -> Attempt {
        let url = format!("{}?guid={}", endpoint.url, ticket.guid);
        let headers = self
            .commerce_headers(ticket.account, &url, content_type)
            .map_err(|error| failure(None, error))?;
        let mut request = self
            .client
            .post(self.wire_url(&url))
            .body(encode_body(body)?);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|error| failure(None, network("send Store commerce request", &error)))?;
        read_store_response(response).await
    }

    fn commerce_headers(
        &self,
        account: &Account,
        url: &str,
        content_type: &str,
    ) -> Result<Vec<(&'static str, String)>, AppStoreError> {
        if !is_store_amd_commerce_url(url) {
            return Err(AppStoreError::Unexpected(
                "store AMD proof endpoint is not allowlisted".into(),
            ));
        }
        let (amd, machine_id) = (self.amd)()?;
        let dsid = account.directory_services_id.clone();
        Ok(vec![
            ("Content-Type", content_type.to_string()),
            ("User-Agent", STORE_USER_AGENT.to_string()),
            ("iCloud-DSID", dsid.clone()),
            ("X-Apple-Store-Front", account.store_front.clone()),
            ("X-Dsid", dsid),
            ("X-Token", account.password_token.clone()),
            ("X-Apple-AMD", amd),
            ("X-Apple-AMD-M", machine_id),
        ])
    }

    async fn latest_version_id(&self, ticket: &Ticket<'_>) -> Result<String, VersionLookupError> {
        let country = self
            .storefronts
            .country_code(&ticket.account.store_front)
            .await
            .map_err(VersionLookupError::Failed)?;
        let mut last_error = None;
        for catalog in PLATFORM_CATALOGS {
            match self
                .platform_lookup(ticket.app_id, &country, catalog)
                .await?
            {
                Ok(version) => return Ok(version),
                Err(error) => last_error = Some(error),
            }
        }
        let missing = last_error
            .map(|error| error.to_string())
            .unwrap_or_default();
        let context = format!("app {} in storefront {country}: {missing}", ticket.app_id);
        match self.ios_catalog_lookup(ticket.app_id, &country).await {
            Ok(version) => Ok(version),
            Err(VersionLookupError::CatalogNotFound(error)) => Err(
                VersionLookupError::CatalogNotFound(lookup_error(&context, &error)),
            ),
            Err(VersionLookupError::Failed(error)) => {
                Err(VersionLookupError::Failed(lookup_error(&context, &error)))
            }
        }
    }

    /// `Ok(Err(_))` means this catalog lacks the app; try the next one.
    async fn platform_lookup(
        &self,
        app_id: i64,
        country: &str,
        catalog: &str,
    ) -> Result<Result<String, AppStoreError>, VersionLookupError> {
        let url = platform_lookup_url(app_id, country, catalog);
        let (status, body) = self
            .get_json(&url)
            .await
            .map_err(VersionLookupError::Failed)?;
        if status != reqwest::StatusCode::OK.as_u16() {
            return Err(VersionLookupError::Failed(AppStoreError::NetworkError(
                format!("platform version lookup request failed (HTTP {status})"),
            )));
        }
        let Some(item) = body.pointer(&format!("/results/{app_id}")) else {
            return Ok(Err(AppStoreError::AppNotFound(
                "platform version lookup returned no app".into(),
            )));
        };
        let Some(offer) = item
            .get("offers")
            .and_then(Value::as_array)
            .and_then(|offers| offers.first())
        else {
            return Ok(Err(AppStoreError::VersionNotAvailable(
                "platform version lookup returned no offers".into(),
            )));
        };
        offer_version_id(offer)
            .map(Ok)
            .map_err(VersionLookupError::Failed)
    }

    async fn ios_catalog_lookup(
        &self,
        app_id: i64,
        country: &str,
    ) -> Result<String, VersionLookupError> {
        let url = format!(
            "{IOS_CATALOG_URL}/{}/apps/{app_id}?platform={IOS_PLATFORM}",
            country.to_ascii_lowercase()
        );
        let (status, body) = self
            .get_json(&url)
            .await
            .map_err(VersionLookupError::Failed)?;
        if status == reqwest::StatusCode::NOT_FOUND.as_u16() {
            return Err(VersionLookupError::CatalogNotFound(
                AppStoreError::AppNotFound("iOS catalog lookup returned HTTP 404".into()),
            ));
        }
        if status != reqwest::StatusCode::OK.as_u16() {
            return Err(VersionLookupError::Failed(AppStoreError::NetworkError(
                format!("iOS catalog lookup returned HTTP {status}"),
            )));
        }
        catalog_version_id(&body, app_id).map_err(VersionLookupError::Failed)
    }

    async fn catalog_version(&self, account: &Account, app_id: i64) -> Option<String> {
        let country = self
            .storefronts
            .country_code(&account.store_front)
            .await
            .ok()?;
        let url = itunes_lookup_url(app_id, &country);
        let (status, body) = self.get_json(&url).await.ok()?;
        if status != reqwest::StatusCode::OK.as_u16() {
            return None;
        }
        body.pointer("/results/0/version")
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    async fn get_json(&self, url: &str) -> Result<(u16, Value), AppStoreError> {
        let response = self
            .client
            .get(self.wire_url(url))
            .header(reqwest::header::USER_AGENT, DEFAULT_USER_AGENT)
            .send()
            .await
            .map_err(|error| network("Store lookup request failed", &error))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| network("read Store lookup response", &error))?;
        if status == reqwest::StatusCode::NOT_FOUND.as_u16() {
            return Ok((status, Value::Null));
        }
        let body = serde_json::from_slice(&bytes).map_err(|error| {
            AppStoreError::Unexpected(format!("failed to unmarshal json: {error}"))
        })?;
        Ok((status, body))
    }

    /// Apple URL as sent; tests reroute its origin to a mock server while
    /// keeping the allowlisted Apple URL for validation.
    fn wire_url(&self, url: &str) -> String {
        let Some(origin) = &self.origin else {
            return url.to_string();
        };
        Url::parse(url).map_or_else(
            |_| url.to_string(),
            |parsed| {
                let query = parsed
                    .query()
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default();
                format!("{origin}{}{query}", parsed.path())
            },
        )
    }
}

impl<'a> Ticket<'a> {
    fn new(account: &'a Account, app_id: i64, guid: &'a str) -> Result<Self, AppStoreError> {
        let hardware_id = hex::decode(guid)
            .ok()
            .filter(|bytes| bytes.len() == HARDWARE_ID_LEN)
            .ok_or_else(|| {
                AppStoreError::Unexpected("store download requires a six-byte device GUID".into())
            })?;
        Ok(Self {
            account,
            app_id,
            guid,
            hardware_id,
        })
    }

    fn dsid(&self) -> Result<u64, AppStoreError> {
        self.account
            .directory_services_id
            .parse::<u64>()
            .ok()
            .filter(|dsid| *dsid != 0)
            .ok_or_else(|| {
                AppStoreError::AuthenticationFailed(
                    "ent/download requires a nonzero numeric account DSID".into(),
                )
            })
    }

    fn serial_number(&self) -> String {
        let mut serial = SERIAL_PREFIX.to_vec();
        serial.extend_from_slice(&self.hardware_id[SERIAL_HARDWARE_OFFSET..]);
        base64::engine::general_purpose::STANDARD.encode(serial)
    }
}

impl VersionLookupError {
    fn into_error(self) -> AppStoreError {
        match self {
            Self::CatalogNotFound(error) | Self::Failed(error) => error,
        }
    }
}

fn failure(response: Option<StoreResponse>, error: AppStoreError) -> Failure {
    Failure {
        response,
        error,
        empty_server_error: false,
    }
}

fn attempt_response(attempt: &Attempt) -> Option<StoreResponse> {
    match attempt {
        Ok(response) => Some(response.clone()),
        Err(failure) => failure.response.clone(),
    }
}

fn resolve_delisted(unpinned: Attempt, ent: Attempt, app_id: i64) -> Attempt {
    let ent_failure = match ent {
        Ok(response) => return Ok(response),
        Err(failure) => failure,
    };
    if let Some(response) = ent_failure.response.as_ref().filter(|response| {
        let code = failure_type(&response.body);
        code == FAILURE_PASSWORD_TOKEN_EXPIRED || code == FAILURE_LICENSE_NOT_FOUND
    }) {
        return Ok(response.clone());
    }
    if let Some(response) = attempt_response(&unpinned)
        .filter(|response| failure_type(&response.body) == FAILURE_LICENSE_NOT_FOUND)
    {
        return Ok(response);
    }
    let unpinned_error = unpinned
        .err()
        .map(|failure| failure.error.to_string())
        .unwrap_or_default();
    Err(failure(
        ent_failure.response,
        AppStoreError::DownloadFailed(format!(
            "app {app_id} has no offer in the account's App Store catalog and the kbsync fallback failed: {unpinned_error}; {}",
            ent_failure.error
        )),
    ))
}

fn update_eligible(attempt: &Attempt) -> bool {
    match attempt {
        Ok(response) => is_unavailable_response(response),
        Err(failure) => failure.empty_server_error,
    }
}

fn volume_store_endpoint(pod: &str) -> Endpoint {
    let prefix = if pod.is_empty() {
        String::new()
    } else {
        format!("p{pod}-")
    };
    Endpoint {
        url: format!("https://{prefix}{BUY_DOMAIN}{VOLUME_STORE_PATH}"),
        version_key: VERSION_KEY_VOLUME_STORE,
    }
}

fn download_endpoint(url: &str, path: &str) -> Result<Endpoint, AppStoreError> {
    let valid = Url::parse(url).is_ok_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str() == Some(DOWNLOAD_DISPATCH_DOMAIN)
            && parsed.port().is_none()
            && parsed.path() == path
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && !url.contains('?')
    });
    if !valid {
        return Err(AppStoreError::Unexpected(
            "invalid download endpoint in bag".into(),
        ));
    }
    Ok(Endpoint {
        url: url.to_string(),
        version_key: VERSION_KEY_REDOWNLOAD,
    })
}

/// Upstream's allowlist of the commerce URLs that may carry the AMD proof
/// (`appstore_amd.go:51-91`).
fn is_store_amd_commerce_url(url: &str) -> bool {
    if url.contains('#') {
        return false;
    }
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    let plain = parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.port().is_none_or(|port| port == HTTPS_PORT);
    plain && has_only_guid_query(&parsed) && allowlisted_path(&parsed)
}

fn has_only_guid_query(url: &Url) -> bool {
    let pairs: Vec<_> = url.query_pairs().collect();
    pairs.len() == 1 && pairs[0].0 == "guid" && !pairs[0].1.is_empty()
}

fn allowlisted_path(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host == DOWNLOAD_DISPATCH_DOMAIN {
        return [ENT_DOWNLOAD_PATH, REDOWNLOAD_PATH, UPDATE_PRODUCT_PATH].contains(&url.path());
    }
    is_store_buy_host(&host) && url.path() == VOLUME_STORE_PATH
}

fn is_store_buy_host(host: &str) -> bool {
    if host == BUY_DOMAIN {
        return true;
    }
    host.strip_suffix(&format!("-{BUY_DOMAIN}"))
        .and_then(|pod| pod.strip_prefix('p'))
        .is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn legacy_body(ticket: &Ticket<'_>, version_key: &str, version: Option<&str>) -> plist::Dictionary {
    let mut fields = BTreeMap::from([
        ("creditDisplay", plist::Value::from("")),
        ("guid", plist::Value::from(ticket.guid)),
        ("salableAdamId", plist::Value::from(ticket.app_id)),
        ("serialNumber", plist::Value::from("0")),
    ]);
    if let Some(version) = version {
        fields.insert(version_key, plist::Value::from(version));
    }
    sorted_dictionary(fields)
}

fn ent_body(ticket: &Ticket<'_>, version: Option<&str>, blob: &str) -> plist::Dictionary {
    let mut fields = BTreeMap::from([
        ("creditDisplay", plist::Value::from("")),
        ("guid", plist::Value::from(ticket.guid)),
        ("kbsync", plist::Value::from(blob)),
        (
            "salableAdamId",
            plist::Value::from(ticket.app_id.to_string()),
        ),
        ("serialNumber", plist::Value::from(ticket.serial_number())),
    ]);
    if let Some(version) = version {
        fields.insert(VERSION_KEY_VOLUME_STORE, plist::Value::from(version));
    }
    sorted_dictionary(fields)
}

fn sorted_dictionary(fields: BTreeMap<&str, plist::Value>) -> plist::Dictionary {
    fields
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

fn encode_body(body: &plist::Dictionary) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    plist::Value::Dictionary(body.clone())
        .to_writer_xml(&mut bytes)
        .map_err(|error| {
            failure(
                None,
                AppStoreError::Unexpected(format!("encode Store request: {error}")),
            )
        })?;
    Ok(bytes)
}

async fn read_store_response(response: reqwest::Response) -> Attempt {
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| failure(None, network("read Store commerce response", &error)))?;
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let text = String::from_utf8_lossy(&bytes).trim().to_string();
        let error =
            AppStoreError::NetworkError(format!("rate limited by Apple (HTTP 429): {text}"));
        return Err(failure(None, error));
    }
    let status = status.as_u16();
    if (300..400).contains(&status) {
        return Ok(StoreResponse {
            status,
            body: Value::Null,
        });
    }
    match decode_body(&bytes) {
        Ok(body) => Ok(StoreResponse { status, body }),
        Err(error) => Err(Failure {
            response: None,
            error,
            empty_server_error: status == reqwest::StatusCode::INTERNAL_SERVER_ERROR.as_u16()
                && bytes.trim_ascii().is_empty(),
        }),
    }
}

fn decode_body(bytes: &[u8]) -> Result<Value, AppStoreError> {
    let dictionary = decode_store_plist(bytes)?;
    let mut xml = Vec::new();
    plist::Value::Dictionary(dictionary)
        .to_writer_xml(&mut xml)
        .map_err(|error| AppStoreError::Unexpected(format!("re-encode Store plist: {error}")))?;
    decode_plist(&xml).map_err(AppStoreError::Unexpected)
}

fn value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

fn failure_type(body: &Value) -> String {
    value_text(body.get("failureType"))
}

fn customer_message(body: &Value) -> String {
    value_text(body.get("customerMessage"))
}

fn items(body: &Value) -> &[Value] {
    body.get("songList")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn item_url(response: &StoreResponse) -> String {
    value_text(
        items(&response.body)
            .first()
            .and_then(|item| item.get("URL")),
    )
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Port of upstream `normalizeDownloadFailure`.
fn normalize_failure(body: &mut Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let has_items = object
        .get("songList")
        .and_then(Value::as_array)
        .is_some_and(|list| !list.is_empty());
    let mut code = value_text(object.get("failureType"));
    if !has_items
        && code.is_empty()
        && let Some(message_code) = object
            .get("metrics")
            .and_then(|metrics| metrics.get("messageCode"))
    {
        code = value_text(Some(message_code)).trim().to_string();
    }
    if code == FAILURE_SIGN_IN_REQUIRED || code == FAILURE_DEVICE_VERIFICATION_FAILED {
        code = FAILURE_PASSWORD_TOKEN_EXPIRED.to_string();
    }
    if !has_items {
        code = classify_message_failure(object, code);
    }
    if !code.is_empty() {
        object.insert("failureType".into(), Value::String(code));
    }
}

fn classify_message_failure(object: &serde_json::Map<String, Value>, code: String) -> String {
    let message = collapse_whitespace(&value_text(object.get("customerMessage")));
    if message.eq_ignore_ascii_case("sign in to the itunes store")
        || message.eq_ignore_ascii_case("sign-in required")
    {
        return FAILURE_PASSWORD_TOKEN_EXPIRED.to_string();
    }
    if code == FAILURE_PASSWORD_TOKEN_EXPIRED {
        return code;
    }
    let dialog = |key: &str| {
        collapse_whitespace(&value_text(
            object.get("dialog").and_then(|dialog| dialog.get(key)),
        ))
    };
    if message == REDOWNLOAD_UNAVAILABLE
        || (dialog("message") == REDOWNLOAD_UNAVAILABLE
            && dialog("explanation") == REDOWNLOAD_UNAVAILABLE_EXPLANATION)
    {
        return FAILURE_LICENSE_NOT_FOUND.to_string();
    }
    code
}

fn is_unavailable_response(response: &StoreResponse) -> bool {
    let message = customer_message(&response.body).trim().to_lowercase();
    response.status == reqwest::StatusCode::OK.as_u16()
        && failure_type(&response.body).is_empty()
        && items(&response.body).is_empty()
        && (message == "no longer available" || message.ends_with(" no longer available"))
}

fn is_empty_response(response: &StoreResponse) -> bool {
    response.status == reqwest::StatusCode::OK.as_u16()
        && failure_type(&response.body).is_empty()
        && customer_message(&response.body).is_empty()
        && items(&response.body).is_empty()
}

/// Port of upstream `validateDownloadResponse`.
fn validated(response: StoreResponse, app_id: i64, version: Option<&str>, source: &str) -> Attempt {
    match validation_error(&response, app_id, version, source) {
        Some(error) => Err(failure(Some(response), error)),
        None => Ok(response),
    }
}

fn validation_error(
    response: &StoreResponse,
    app_id: i64,
    version: Option<&str>,
    source: &str,
) -> Option<AppStoreError> {
    let body = &response.body;
    if !failure_type(body).is_empty() {
        return None;
    }
    let message = customer_message(body);
    let error = |text: String| Some(AppStoreError::DownloadFailed(text));
    if !message.is_empty() {
        return error(format!("received {source} error: {message}"));
    }
    if response.status != reqwest::StatusCode::OK.as_u16() {
        return error(format!(
            "received unexpected {source} status code: {}",
            response.status
        ));
    }
    let [item] = items(body) else {
        return error(format!("{source} response must contain exactly one item"));
    };
    metadata_mismatch(item, app_id, version)
        .map(|mismatch| AppStoreError::DownloadFailed(format!("{source} {mismatch}")))
}

fn metadata_mismatch(item: &Value, app_id: i64, version: Option<&str>) -> Option<&'static str> {
    let metadata = item.get("metadata");
    let field = |key: &str| value_text(metadata.and_then(|metadata| metadata.get(key)));
    if field("itemId") != app_id.to_string()
        || version.is_some_and(|version| field("softwareVersionExternalIdentifier") != version)
    {
        return Some("response does not match the requested app or version");
    }
    field("softwareVersionBundleId")
        .is_empty()
        .then_some("response does not match the requested bundle identifier")
}

/// Port of the failure mapping in upstream `Download` / `ListVersions`.
fn first_item<'r>(
    response: &'r StoreResponse,
    app_id: i64,
    expired: &[&str],
) -> Result<&'r Value, AppStoreError> {
    let code = failure_type(&response.body);
    let message = customer_message(&response.body);
    let list = items(&response.body);
    if expired.contains(&code.as_str()) {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "Apple rejected the Store session (failureType {code}); run auth login again"
        )));
    }
    if code == FAILURE_LICENSE_NOT_FOUND {
        return Err(AppStoreError::NoLicense(app_id));
    }
    if !message.is_empty() && (!code.is_empty() || list.is_empty()) {
        return Err(AppStoreError::DownloadFailed(format!(
            "received error: {message}"
        )));
    }
    if !code.is_empty() {
        return Err(AppStoreError::DownloadFailed(format!(
            "received error: {code}"
        )));
    }
    list.first()
        .ok_or_else(|| AppStoreError::Unexpected("invalid download response".into()))
}

fn version_identifiers(item: &Value) -> Result<Vec<String>, AppStoreError> {
    let metadata = item.get("metadata");
    let identifiers = metadata
        .and_then(|metadata| metadata.get("softwareVersionExternalIdentifiers"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppStoreError::Unexpected("failed to get version identifiers from item metadata".into())
        })?;
    if metadata
        .and_then(|metadata| metadata.get("softwareVersionExternalIdentifier"))
        .is_none()
    {
        return Err(AppStoreError::Unexpected(
            "failed to get latest version from item metadata".into(),
        ));
    }
    Ok(identifiers
        .iter()
        .map(|value| value_text(Some(value)))
        .collect())
}

fn offer_version_id(offer: &Value) -> Result<String, AppStoreError> {
    let direct = value_text(offer.pointer("/version/externalId"));
    if !direct.is_empty() {
        return Ok(direct);
    }
    let buy_params = value_text(offer.get("buyParams"));
    let from_params = url_query_value(&buy_params, "appExtVrsId");
    if from_params.is_empty() {
        return Err(AppStoreError::VersionNotAvailable(
            "platform version lookup returned no external version id".into(),
        ));
    }
    Ok(from_params)
}

fn url_query_value(query: &str, key: &str) -> String {
    Url::parse(&format!("https://query.invalid/?{query}"))
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.into_owned())
        })
        .unwrap_or_default()
}

fn catalog_version_id(body: &Value, app_id: i64) -> Result<String, AppStoreError> {
    let unexpected = |text: &str| AppStoreError::Unexpected(format!("iOS catalog lookup {text}"));
    let [item] = body
        .get("data")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    else {
        return Err(unexpected("must return exactly one app"));
    };
    if value_text(item.get("id")) != app_id.to_string() || value_text(item.get("type")) != "apps" {
        return Err(unexpected("returned a different app"));
    }
    let families = item
        .pointer("/attributes/deviceFamilies")
        .and_then(Value::as_array);
    let attributes = item.pointer("/attributes/platformAttributes/ios");
    let supported =
        families.is_some_and(|families| families.iter().any(|family| family == IOS_PLATFORM));
    let Some(attributes) = attributes.filter(|_| supported) else {
        return Err(unexpected(
            "returned no metadata for the requested platform",
        ));
    };
    let version = value_text(attributes.get("externalVersionId"));
    if version.parse::<u64>().map_or(true, |id| id == 0) {
        return Err(unexpected("returned no valid external version id"));
    }
    Ok(version)
}

fn platform_lookup_url(app_id: i64, country: &str, catalog: &str) -> String {
    format!(
        "{PLATFORM_LOOKUP_URL}?caller=MDM&cc={}&id={app_id}&l=en&p=mdm-lockup&platform={catalog}&version=2",
        country.to_ascii_lowercase()
    )
}

fn itunes_lookup_url(app_id: i64, country: &str) -> String {
    format!("{ITUNES_LOOKUP_URL}?country={country}&entity={LOOKUP_ENTITY_QUERY}&id={app_id}")
}

fn lookup_error(context: &str, error: &AppStoreError) -> AppStoreError {
    AppStoreError::VersionNotAvailable(format!("{context}; iOS catalog fallback failed: {error}"))
}

fn network(context: &str, error: &reqwest::Error) -> AppStoreError {
    AppStoreError::NetworkError(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::appstore::store_api::native_commerce::storefront::tests::{
        mount_available, resolver,
    };
    use std::cell::Cell;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const GUID: &str = "001122334455";
    const DSID: u64 = 123_456_789_012;
    const VERSION: &str = "123456789";
    const APP_ID: i64 = 42;
    const KBSYNC: &[u8] = b"kbsync blob";
    const ENT_URL: &str =
        "https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download";
    const REDOWNLOAD_URL: &str = "https://downloaddispatch.itunes.apple.com/r/redownload";
    const UPDATE_URL: &str = "https://downloaddispatch.itunes.apple.com/up/updateProduct";
    const PLATFORM_LOOKUP_PATH: &str = "/WebObjects/MZStorePlatform.woa/wa/lookup";
    const CATALOG_PATH: &str = "/api/apps/v1/catalog/us/apps/42";

    fn account() -> Account {
        Account {
            email: "user@example.com".into(),
            name: "User".into(),
            password_token: "test-token".into(),
            directory_services_id: DSID.to_string(),
            store_front: "143441-1,29".into(),
            pod: String::new(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    fn bag(ent: bool) -> StoreBag {
        StoreBag {
            authenticate_account:
                "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate/".into(),
            sap_setup: String::new(),
            sap_setup_cert: String::new(),
            sap_version: 200,
            volume_store_download_product: ent.then(|| ENT_URL.to_string()),
            redownload_product: Some(REDOWNLOAD_URL.into()),
            update_product: Some(UPDATE_URL.into()),
            values: plist::Dictionary::new(),
        }
    }

    type TestDownloader<'h> = NativeDownloader<
        'h,
        Box<dyn Fn(u64) -> Result<Vec<u8>, AppStoreError> + 'h>,
        Box<dyn Fn() -> Result<(String, String), AppStoreError>>,
    >;

    struct Harness {
        server: MockServer,
        bag: StoreBag,
        storefronts: StorefrontResolver,
        cache: KbsyncCache,
        client: reqwest::Client,
        generated: Cell<u32>,
        _directory: tempfile::TempDir,
    }

    impl Harness {
        async fn new(ent: bool) -> Self {
            let server = MockServer::start().await;
            mount_available(&server, &[(143_441, "US")]).await;
            let directory = tempfile::tempdir().expect("temporary directory");
            Self {
                storefronts: resolver(&server),
                server,
                bag: bag(ent),
                cache: KbsyncCache::new(directory.path().join("kbsync-v1.json")),
                client: reqwest::Client::new(),
                generated: Cell::new(0),
                _directory: directory,
            }
        }

        fn downloader(&self) -> TestDownloader<'_> {
            let kbsync: Box<dyn Fn(u64) -> Result<Vec<u8>, AppStoreError> + '_> =
                Box::new(move |dsid: u64| {
                    assert_eq!(dsid, DSID);
                    self.generated.set(self.generated.get() + 1);
                    Ok(KBSYNC.to_vec())
                });
            let amd: Box<dyn Fn() -> Result<(String, String), AppStoreError>> =
                Box::new(|| Ok(("amd-otp".to_string(), "amd-mid".to_string())));
            NativeDownloader::new(
                &self.client,
                &self.bag,
                &self.storefronts,
                &self.cache,
                kbsync,
                amd,
            )
            .with_origin(self.server.uri())
        }

        async fn mount(&self, route: &str, response: ResponseTemplate) {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(response)
                .mount(&self.server)
                .await;
        }

        async fn commerce_requests(&self) -> Vec<Request> {
            self.server
                .received_requests()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|request| request.method.as_str() == "POST")
                .collect()
        }
    }

    fn plist_body(inner: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>{inner}</dict></plist>"#
        ))
    }

    fn success(version: &str) -> ResponseTemplate {
        plist_body(&format!(
            "<key>songList</key><array><dict>\
             <key>URL</key><string>https://iosapps.itunes.apple.com/app.ipa</string>\
             <key>md5</key><string>abc</string>\
             <key>sinfs</key><array><dict><key>id</key><integer>0</integer><key>sinf</key><data>AQID</data></dict></array>\
             <key>metadata</key><dict>\
             <key>itemId</key><integer>42</integer>\
             <key>softwareVersionBundleId</key><string>com.example.app</string>\
             <key>softwareVersionExternalIdentifier</key><integer>{version}</integer>\
             <key>softwareVersionExternalIdentifiers</key><array><integer>876660700</integer><integer>876660716</integer></array>\
             </dict></dict></array>"
        ))
    }

    fn body(request: &Request) -> plist::Dictionary {
        plist::from_bytes(&request.body).expect("plist request body")
    }

    fn header<'r>(request: &'r Request, name: &str) -> &'r str {
        request
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn assert_session_headers(request: &Request, content_type: &str) {
        assert_eq!(request.url.query(), Some("guid=001122334455"));
        assert_eq!(header(request, "content-type"), content_type);
        assert_eq!(header(request, "user-agent"), STORE_USER_AGENT);
        assert_eq!(header(request, "x-token"), "test-token");
        assert_eq!(header(request, "x-dsid"), "123456789012");
        assert_eq!(header(request, "icloud-dsid"), "123456789012");
        assert_eq!(header(request, "x-apple-store-front"), "143441-1,29");
        assert_eq!(header(request, "x-apple-amd"), "amd-otp");
        assert_eq!(header(request, "x-apple-amd-m"), "amd-mid");
    }

    #[tokio::test]
    async fn sends_kbsync_to_ent_download_for_a_pinned_version() {
        let harness = Harness::new(true).await;
        harness.mount(ENT_DOWNLOAD_PATH, success(VERSION)).await;

        let items = harness
            .downloader()
            .download(&account(), APP_ID, GUID, Some(VERSION))
            .await
            .expect("download");

        let requests = harness.commerce_requests().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), ENT_DOWNLOAD_PATH);
        assert_session_headers(&requests[0], CONTENT_TYPE_FORM);
        let expected: plist::Dictionary = [
            ("creditDisplay", plist::Value::from("")),
            ("externalVersionId", plist::Value::from(VERSION)),
            ("guid", plist::Value::from(GUID)),
            ("kbsync", plist::Value::from(b64(KBSYNC))),
            ("salableAdamId", plist::Value::from("42")),
            (
                "serialNumber",
                plist::Value::from(b64(&[0x54, 0xc8, 0xb0, 0xa9, 0x88, 0x22, 0x33, 0x44, 0x55])),
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect();
        assert_eq!(body(&requests[0]), expected);
        assert_eq!(items[0].url, "https://iosapps.itunes.apple.com/app.ipa");
        assert_eq!(items[0].sinfs[0].data, [1, 2, 3]);
        assert_eq!(harness.generated.get(), 1);
        assert_eq!(harness.cache.cached(DSID, GUID), Some(b64(KBSYNC)));
    }

    #[tokio::test]
    async fn retries_a_rejected_cached_kbsync_once_with_a_fresh_blob() {
        let harness = Harness::new(true).await;
        harness.cache.store(DSID, GUID, "c3RhbGU=");
        Mock::given(path(ENT_DOWNLOAD_PATH))
            .and(|request: &Request| {
                body(request)
                    .get("kbsync")
                    .and_then(plist::Value::as_string)
                    == Some("c3RhbGU=")
            })
            .respond_with(plist_body("<key>failureType</key><string>2034</string>"))
            .mount(&harness.server)
            .await;
        harness.mount(ENT_DOWNLOAD_PATH, success(VERSION)).await;

        harness
            .downloader()
            .download(&account(), APP_ID, GUID, Some(VERSION))
            .await
            .expect("download");

        let requests = harness.commerce_requests().await;
        let blobs: Vec<_> = requests
            .iter()
            .map(|request| {
                body(request)
                    .get("kbsync")
                    .and_then(plist::Value::as_string)
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(blobs, [Some("c3RhbGU=".to_string()), Some(b64(KBSYNC))]);
        assert_eq!(harness.generated.get(), 1);
        assert_eq!(harness.cache.cached(DSID, GUID), Some(b64(KBSYNC)));
    }

    #[tokio::test]
    async fn never_retries_a_fresh_kbsync_and_falls_back_to_volume_store() {
        let harness = Harness::new(true).await;
        harness
            .mount(
                ENT_DOWNLOAD_PATH,
                plist_body("<key>failureType</key><string>2034</string>"),
            )
            .await;
        harness.mount(VOLUME_STORE_PATH, success(VERSION)).await;

        harness
            .downloader()
            .download(&account(), APP_ID, GUID, Some(VERSION))
            .await
            .expect("download");

        let paths: Vec<_> = harness
            .commerce_requests()
            .await
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert_eq!(paths, [ENT_DOWNLOAD_PATH, VOLUME_STORE_PATH]);
        assert_eq!(harness.cache.cached(DSID, GUID), None);
    }

    fn assert_legacy_requests(requests: &[Request]) {
        for request in requests {
            assert_session_headers(request, CONTENT_TYPE_PLIST);
            let fields = body(request);
            assert_eq!(
                fields.get("salableAdamId"),
                Some(&plist::Value::from(APP_ID))
            );
            assert_eq!(fields.get("serialNumber"), Some(&plist::Value::from("0")));
            assert_eq!(fields.get("creditDisplay"), Some(&plist::Value::from("")));
        }
        assert_eq!(
            body(&requests[0]).get("externalVersionId"),
            Some(&plist::Value::from(VERSION))
        );
        assert_eq!(
            body(&requests[1]).get("appExtVrsId"),
            Some(&plist::Value::from(VERSION))
        );
        assert_eq!(
            body(&requests[2]).get("appExtVrsId"),
            Some(&plist::Value::from(VERSION))
        );
    }

    #[tokio::test]
    async fn walks_volume_store_redownload_and_update_in_order() {
        let harness = Harness::new(true).await;
        harness
            .mount(
                ENT_DOWNLOAD_PATH,
                ResponseTemplate::new(500).set_body_string("<html>down</html>"),
            )
            .await;
        harness.mount(VOLUME_STORE_PATH, plist_body("")).await;
        harness
            .mount(REDOWNLOAD_PATH, ResponseTemplate::new(500))
            .await;
        harness.mount(UPDATE_PRODUCT_PATH, success(VERSION)).await;

        let items = harness
            .downloader()
            .download(&account(), APP_ID, GUID, Some(VERSION))
            .await
            .expect("download");

        let requests = harness.commerce_requests().await;
        let paths: Vec<_> = requests.iter().map(|r| r.url.path()).collect();
        assert_eq!(
            paths,
            [
                ENT_DOWNLOAD_PATH,
                VOLUME_STORE_PATH,
                REDOWNLOAD_PATH,
                UPDATE_PRODUCT_PATH
            ]
        );
        assert_legacy_requests(&requests[1..]);
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn resolves_the_latest_version_before_ent_download() {
        let harness = Harness::new(true).await;
        Mock::given(method("GET"))
            .and(path(PLATFORM_LOOKUP_PATH))
            .and(|request: &Request| {
                request.url.query()
                    == Some("caller=MDM&cc=us&id=42&l=en&p=mdm-lockup&platform=enterprisestore&version=2")
            })
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"results":{"42":{"offers":[{"version":{"externalId":123456789}}]}}}"#,
            ))
            .mount(&harness.server)
            .await;
        harness.mount(ENT_DOWNLOAD_PATH, success(VERSION)).await;

        harness
            .downloader()
            .download(&account(), APP_ID, GUID, None)
            .await
            .expect("download");

        let requests = harness.commerce_requests().await;
        assert_eq!(
            body(&requests[0]).get("externalVersionId"),
            Some(&plist::Value::from(VERSION))
        );
    }

    #[tokio::test]
    async fn redownloads_a_delisted_app_unpinned() {
        let harness = Harness::new(true).await;
        Mock::given(path(PLATFORM_LOOKUP_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"results":{}}"#))
            .mount(&harness.server)
            .await;
        Mock::given(path(CATALOG_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&harness.server)
            .await;
        harness.mount(VOLUME_STORE_PATH, plist_body("")).await;
        harness.mount(REDOWNLOAD_PATH, success("7")).await;

        harness
            .downloader()
            .download(&account(), APP_ID, GUID, None)
            .await
            .expect("download");

        let requests = harness.commerce_requests().await;
        let paths: Vec<_> = requests.iter().map(|r| r.url.path()).collect();
        assert_eq!(paths, [VOLUME_STORE_PATH, REDOWNLOAD_PATH]);
        assert!(body(&requests[1]).get("appExtVrsId").is_none());
    }

    #[tokio::test]
    async fn lists_versions_labelled_with_the_catalog_version() {
        let harness = Harness::new(false).await;
        harness.mount(VOLUME_STORE_PATH, success(VERSION)).await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .and(|request: &Request| {
                request.url.query() == Some("country=US&entity=software%2CiPadSoftware&id=42")
            })
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"results":[{"version":"1.2.3"}]}"#),
            )
            .mount(&harness.server)
            .await;

        let versions = harness
            .downloader()
            .list_versions(&account(), APP_ID, GUID)
            .await
            .expect("versions");

        let ids: Vec<_> = versions
            .iter()
            .map(|v| v.external_version_id.as_str())
            .collect();
        assert_eq!(ids, ["876660700", "876660716"]);
        assert!(versions.iter().all(|v| v.version_string == "1.2.3"));
    }

    #[tokio::test]
    async fn maps_store_failures_to_domain_errors() {
        for (inner, check) in [
            (
                "<key>failureType</key><string>9610</string>",
                (|e: &AppStoreError| matches!(e, AppStoreError::NoLicense(42)))
                    as fn(&AppStoreError) -> bool,
            ),
            ("<key>failureType</key><string>2034</string>", |e| {
                matches!(e, AppStoreError::AuthenticationFailed(_))
            }),
            (
                "<key>failureType</key><string>2059</string><key>customerMessage</key><string>Busy</string>",
                |e| matches!(e, AppStoreError::DownloadFailed(m) if m.contains("Busy")),
            ),
        ] {
            let harness = Harness::new(false).await;
            harness.mount(VOLUME_STORE_PATH, plist_body(inner)).await;
            let error = harness
                .downloader()
                .download(&account(), APP_ID, GUID, Some(VERSION))
                .await
                .expect_err("failure");
            assert!(check(&error), "{error:?}");
        }
    }

    #[test]
    fn allowlists_only_commerce_urls_for_the_amd_proof() {
        for url in [
            "https://downloaddispatch.itunes.apple.com/WebObjects/DownloadDispatch.woa/wa/ent/download?guid=A",
            "https://downloaddispatch.itunes.apple.com/r/redownload?guid=A",
            "https://downloaddispatch.itunes.apple.com/up/updateProduct?guid=A",
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A",
            "https://p48-buy.itunes.apple.com:443/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A",
        ] {
            assert!(is_store_amd_commerce_url(url), "{url}");
        }
        for url in [
            "http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A",
            "https://px-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A",
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=",
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=A&x=1",
            "https://buy.itunes.apple.com/r/redownload?guid=A",
            "https://downloaddispatch.itunes.apple.com/r/redownload?guid=A#f",
            "https://user@downloaddispatch.itunes.apple.com/r/redownload?guid=A",
            "https://downloaddispatch.itunes.apple.com:8443/r/redownload?guid=A",
        ] {
            assert!(!is_store_amd_commerce_url(url), "{url}");
        }
    }

    #[test]
    fn validates_bag_download_endpoints() {
        assert!(download_endpoint(REDOWNLOAD_URL, REDOWNLOAD_PATH).is_ok());
        assert!(download_endpoint(REDOWNLOAD_URL, UPDATE_PRODUCT_PATH).is_err());
        assert!(download_endpoint("https://evil.example/r/redownload", REDOWNLOAD_PATH).is_err());
        assert!(download_endpoint(&format!("{REDOWNLOAD_URL}?x=1"), REDOWNLOAD_PATH).is_err());
        assert!(download_endpoint(&format!("{REDOWNLOAD_URL}?"), REDOWNLOAD_PATH).is_err());
        assert_eq!(
            volume_store_endpoint("48").url,
            "https://p48-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
        );
        assert!(Ticket::new(&account(), APP_ID, "0011").is_err());
        assert!(Ticket::new(&account(), APP_ID, "zz1122334455").is_err());
    }

    #[test]
    fn normalizes_download_failures_like_upstream() {
        let normalized = |mut body: Value| {
            normalize_failure(&mut body);
            failure_type(&body)
        };
        assert_eq!(
            normalized(serde_json::json!({"metrics": {"messageCode": " 2042 "}})),
            "2034"
        );
        assert_eq!(
            normalized(serde_json::json!({"failureType": "1008"})),
            "2034"
        );
        assert_eq!(
            normalized(serde_json::json!({"customerMessage": "Sign  In to the iTunes Store"})),
            "2034"
        );
        assert_eq!(
            normalized(serde_json::json!({"customerMessage": REDOWNLOAD_UNAVAILABLE})),
            "9610"
        );
        assert_eq!(
            normalized(
                serde_json::json!({"dialog": {"message": REDOWNLOAD_UNAVAILABLE, "explanation": REDOWNLOAD_UNAVAILABLE_EXPLANATION}})
            ),
            "9610"
        );
        assert_eq!(
            normalized(
                serde_json::json!({"songList": [{}], "customerMessage": REDOWNLOAD_UNAVAILABLE})
            ),
            ""
        );
        assert_eq!(normalized(serde_json::json!({"failureType": 5002})), "5002");
    }

    #[test]
    fn parses_offer_and_catalog_version_ids() {
        assert_eq!(
            offer_version_id(&serde_json::json!({"version": {"externalId": "9"}})).expect("id"),
            "9"
        );
        assert_eq!(
            offer_version_id(&serde_json::json!({"buyParams": "productType=C&appExtVrsId=77"}))
                .expect("id"),
            "77"
        );
        assert!(offer_version_id(&serde_json::json!({})).is_err());
        let catalog = serde_json::json!({"data": [{"id": "42", "type": "apps", "attributes": {
            "deviceFamilies": ["iphone"], "platformAttributes": {"ios": {"externalVersionId": 88}}}}]});
        assert_eq!(catalog_version_id(&catalog, 42).expect("id"), "88");
        assert!(catalog_version_id(&catalog, 43).is_err());
        assert!(catalog_version_id(&serde_json::json!({"data": []}), 42).is_err());
    }

    #[test]
    fn requires_version_metadata_for_listings() {
        assert!(version_identifiers(&serde_json::json!({"metadata": {}})).is_err());
        assert!(
            version_identifiers(
                &serde_json::json!({"metadata": {"softwareVersionExternalIdentifiers": [1]}})
            )
            .is_err()
        );
        assert_eq!(
            version_identifiers(&serde_json::json!({"metadata": {
                "softwareVersionExternalIdentifiers": [1, "2"], "softwareVersionExternalIdentifier": 2}}))
            .expect("ids"),
            ["1", "2"]
        );
    }
}
