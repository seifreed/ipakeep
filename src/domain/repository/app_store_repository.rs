//! Ports for App Store authentication, catalog, purchasing, and downloads.

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, OwnedApp, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;

/// Repository operations required by Apple account authentication and 2FA.
#[async_trait::async_trait]
pub trait AuthenticationRepository: Send + Sync {
    /// Authenticate with Apple using email and password.
    async fn authenticate(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError>;

    /// Authenticate with Apple using email, password, and a 2FA code.
    async fn authenticate_with_2fa(
        &self,
        email: &str,
        password: &str,
        code: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError>;

    /// Authenticate with Apple's `GrandSlam` SRP flow.
    async fn authenticate_grandslam(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError>;

    /// Send a trusted-device verification notification.
    async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError>;

    /// Validate a trusted-device verification code.
    async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError>;

    /// List trusted phone numbers available for SMS verification.
    async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError>;

    /// Request an SMS verification code for a trusted phone.
    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError>;

    /// Validate an SMS verification code.
    async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError>;
}

/// Repository operations for searching and resolving App Store apps.
#[async_trait::async_trait]
pub trait CatalogRepository: Send + Sync {
    /// Search apps by term and country.
    async fn search(
        &self,
        term: &str,
        country: &str,
        limit: u32,
    ) -> Result<Vec<App>, AppStoreError>;

    /// Look up an app by its bundle identifier.
    async fn lookup(&self, bundle_id: &str, country: &str) -> Result<Option<App>, AppStoreError>;
}

/// Repository operations for acquiring apps and listing owned apps.
#[async_trait::async_trait]
pub trait PurchaseRepository: Send + Sync {
    /// Purchase (acquire a license for) an app.
    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError>;

    /// List apps the authenticated account already owns.
    async fn list_purchases(
        &self,
        account: &Account,
        limit: u32,
    ) -> Result<Vec<OwnedApp>, AppStoreError>;
}

/// Repository operations for requesting app packages and their bytes.
#[async_trait::async_trait]
pub trait DownloadRepository: Send + Sync {
    /// Request the download items for an app.
    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError>;

    /// Download raw bytes from a URL.
    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError>;
}

/// Repository operations for listing available app versions.
#[async_trait::async_trait]
pub trait VersionRepository: Send + Sync {
    /// List available versions for an app.
    async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError>;
}

/// Aggregate App Store port for adapters that compose multiple capabilities.
pub trait AppStoreRepository:
    AuthenticationRepository
    + CatalogRepository
    + PurchaseRepository
    + DownloadRepository
    + VersionRepository
{
}

impl<T> AppStoreRepository for T where
    T: AuthenticationRepository
        + CatalogRepository
        + PurchaseRepository
        + DownloadRepository
        + VersionRepository
{
}
