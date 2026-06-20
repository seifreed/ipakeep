//! App entity representing an iOS application on the App Store.

/// An iOS application available on the App Store.
///
/// Returned by search and lookup operations against the iTunes Search API.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct App {
    /// The numeric App Store ID (adamId / trackId).
    pub id: i64,
    /// The reverse-domain bundle identifier (e.g., "com.example.app").
    pub bundle_id: String,
    /// Display name of the application.
    pub name: String,
    /// Version string (e.g., "1.2.3").
    pub version: String,
    /// Price in the local currency (0 for free apps).
    pub price: f64,
}

/// A specific version of an app available for download.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppVersion {
    /// External version identifier used in download requests.
    pub external_version_id: String,
    /// Human-readable version string.
    pub version_string: String,
}
