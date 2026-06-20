//! Account entity representing an authenticated Apple ID.

/// An authenticated Apple account with session credentials.
///
/// This is the core domain entity for authentication. It holds
/// the tokens and metadata returned by Apple's authentication endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Account {
    /// The Apple ID email address.
    pub email: String,
    /// Display name from Apple account info.
    pub name: String,
    /// Session token for authenticated requests.
    pub password_token: String,
    /// Directory Services ID used in `X-Dsid` and `iCloud-DSID` headers.
    pub directory_services_id: String,
    /// Storefront identifier (e.g., "143441-2,26" for US).
    pub store_front: String,
    /// CDN routing prefix for pod-specific URLs.
    pub pod: String,

    /// IDMS token from `GrandSlam` authentication (optional, for 2FA flows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idms_token: Option<String>,

    /// Directory Services ID from `GrandSlam` (optional, for 2FA flows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dsid: Option<String>,

    /// Alternate Directory Services ID used by Apple identity token APIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adsid: Option<String>,

    /// Base64-encoded `GrandSlam` session key used to request app tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grandslam_session_key: Option<String>,

    /// Base64-encoded `GrandSlam` continuation data used for app tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grandslam_continuation: Option<String>,

    /// Raw `Set-Cookie` values returned by Apple authentication endpoints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<String>,
}
