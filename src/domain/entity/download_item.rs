//! Download item entity representing a file to download from Apple.

use super::Sinf;

/// Typed metadata dictionary returned by Apple's download endpoint.
pub type DownloadMetadata = serde_json::Map<String, serde_json::Value>;

/// Extract a non-empty string value for `key` from download metadata.
///
/// Returns `None` when the key is absent, not a string, or an empty string.
pub fn metadata_string(metadata: &DownloadMetadata, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// A single downloadable item from the App Store.
///
/// The download endpoint returns a list of these, each containing
/// the download URL, integrity hash, and DRM metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DownloadItem {
    /// URL to download the IPA file from.
    pub url: String,
    /// MD5 hash for download verification.
    pub md5: String,
    /// DRM encryption metadata to be replicated into the IPA.
    pub sinfs: Vec<Sinf>,
    /// Additional metadata from Apple (version info, bundle ID, etc.).
    pub metadata: DownloadMetadata,
}
