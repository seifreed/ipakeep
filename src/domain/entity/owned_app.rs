//! Owned-app entity representing an app the authenticated account has purchased.

/// An app the authenticated App Store account already owns.
///
/// Returned by the owned-apps (purchase history) operation. It carries the
/// identity fields of an [`crate::domain::entity::App`] plus the purchase-only
/// metadata the catalog does not expose: the platforms the license covers and
/// the date the app was acquired.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OwnedApp {
    /// The numeric App Store ID (adamId / trackId).
    pub id: i64,
    /// The reverse-domain bundle identifier (e.g., "com.example.app").
    pub bundle_id: String,
    /// Display name of the application.
    pub name: String,
    /// Version string of the owned build (e.g., "1.2.3").
    pub version: String,
    /// Platforms the license covers (e.g., "iphone", "ipad", "macos").
    pub platforms: Vec<String>,
    /// RFC 3339 purchase date, when Apple reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_date: Option<String>,
}
