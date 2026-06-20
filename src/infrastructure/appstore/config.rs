//! Apple API endpoint configuration.

/// Configurable URLs for Apple's App Store APIs.
#[derive(Debug, Clone)]
pub struct AppleApiConfig {
    /// URL for the bag.xml discovery endpoint.
    pub bag_url: String,
    /// Base URL for the iTunes Search API.
    pub itunes_search_url: String,
    /// Base URL for the iTunes Lookup API.
    pub itunes_lookup_url: String,
    /// Base URL for the Apple Store purchase/download endpoints.
    pub store_base_url: String,
}

impl Default for AppleApiConfig {
    fn default() -> Self {
        Self {
            bag_url: "https://init.itunes.apple.com/bag.xml".into(),
            itunes_search_url: "https://itunes.apple.com/search".into(),
            itunes_lookup_url: "https://itunes.apple.com/lookup".into(),
            store_base_url: "https://buy.itunes.apple.com".into(),
        }
    }
}
