//! Domain-specific error types.

use thiserror::Error;

/// Errors that can occur during App Store operations.
#[derive(Debug, Clone, Error)]
pub enum AppStoreError {
    /// Authentication failed with a specific reason.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// A 2FA code is required to continue authentication.
    #[error("2FA code required")]
    AuthCodeRequired {
        /// Directory Services ID for continuing the 2FA flow.
        dsid: String,
        /// IDMS token for continuing the 2FA flow.
        idms_token: String,
    },

    /// The Apple account is disabled.
    #[error("account is disabled")]
    AccountDisabled,

    /// Invalid credentials provided.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// The app was not found on the App Store.
    #[error("app not found: {0}")]
    AppNotFound(String),

    /// The app requires purchase but is not free.
    #[error("app is not free (price: {0})")]
    AppNotFree(f64),

    /// License for the app does not exist.
    #[error("no license for app {0}")]
    NoLicense(i64),

    /// The requested app version is not available.
    #[error("version not available: {0}")]
    VersionNotAvailable(String),

    /// The purchase was not successful.
    #[error("purchase failed: {0}")]
    PurchaseFailed(String),

    /// The download failed.
    #[error("download failed: {0}")]
    DownloadFailed(String),

    /// IPA patching (sinf replication) failed.
    #[error("IPA patching failed: {0}")]
    IpaPatchingFailed(String),

    /// A network or infrastructure error occurred.
    #[error("network error: {0}")]
    NetworkError(String),

    /// An unexpected error with a descriptive message.
    #[error("{0}")]
    Unexpected(String),
}

/// Errors related to two-factor authentication flows.
#[derive(Debug, Clone, Error)]
pub enum TwoFactorError {
    /// Two-factor authentication is required but no method was selected.
    #[error("2FA required")]
    Required,

    /// A trusted-device notification was sent; waiting for user approval.
    #[error("trusted device notification sent")]
    TrustedDeviceNotificationSent,

    /// An SMS code was sent to the given phone number ID.
    #[error("SMS code sent to phone id {0}")]
    SmsCodeSent(String),

    /// The 2FA session has expired.
    #[error("2FA session expired")]
    SessionExpired,

    /// The provided 2FA code is invalid.
    #[error("invalid 2FA code")]
    InvalidCode,
}

/// Errors related to credential storage operations.
#[derive(Debug, Clone, Error)]
pub enum CredentialError {
    /// No stored credentials were found.
    #[error("no stored credentials found")]
    NotFound,

    /// Failed to save credentials.
    #[error("failed to save credentials: {0}")]
    SaveFailed(String),

    /// Failed to load credentials.
    #[error("failed to load credentials: {0}")]
    LoadFailed(String),

    /// Failed to delete credentials.
    #[error("failed to delete credentials: {0}")]
    DeleteFailed(String),

    /// Credentials are invalid or corrupted.
    #[error("credentials are invalid: {0}")]
    InvalidCredentials(String),
}
