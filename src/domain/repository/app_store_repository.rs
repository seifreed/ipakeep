//! App Store repository trait — the port for all Apple App Store operations.

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;

/// Repository trait for Apple App Store operations.
///
/// This trait defines the contract for all interactions with Apple's
/// private App Store APIs. Implementations handle HTTP communication,
/// plist encoding/decoding, and response parsing.
#[async_trait::async_trait]
pub trait AppStoreRepository: Send + Sync {
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

    /// Authenticate with Apple using `GrandSlam` SRP (supports trusted-device 2FA).
    ///
    /// This is the modern authentication flow used by Xcode and other Apple tools.
    async fn authenticate_grandslam(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError>;

    /// Request a trusted-device 2FA notification to be sent.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError>;

    /// Validate a trusted-device 2FA code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError>;

    /// List the account's trusted phone numbers for SMS 2FA.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError>;

    /// Request an SMS code to be sent to a trusted phone number.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError>;

    /// Validate an SMS 2FA code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError>;

    /// Search for apps on the App Store by term.
    async fn search(
        &self,
        term: &str,
        country: &str,
        limit: u32,
    ) -> Result<Vec<App>, AppStoreError>;

    /// Look up an app by its bundle identifier.
    async fn lookup(&self, bundle_id: &str, country: &str) -> Result<Option<App>, AppStoreError>;

    /// Purchase (acquire a license for) an app.
    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError>;

    /// Download an app, returning the download items with URLs and sinf data.
    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError>;

    /// Download raw bytes from a URL.
    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError>;

    /// List available versions for an app.
    async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError>;
}
