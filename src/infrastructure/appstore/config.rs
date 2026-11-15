//! Apple API endpoint configuration.

use super::store_api::native_commerce::bag::BAG_URL;
use super::store_api::native_commerce::owned_apps::PURCHASE_DAAP_BASE_URL;
use std::path::PathBuf;

/// Configurable URLs for Apple's App Store APIs.
#[derive(Debug, Clone)]
pub struct AppleApiConfig {
    /// URL for the Store bag.xml discovery endpoint.
    pub bag_url: String,
    /// Base URL for the iTunes Search API.
    pub itunes_search_url: String,
    /// Base URL for the iTunes Lookup API.
    pub itunes_lookup_url: String,
    /// `MZPurchaseDaap` base URL for the purchase history.
    pub purchase_history_url: String,
    /// When set, every Store commerce request goes to this origin instead of
    /// Apple's hosts (path and query kept); for proxies and tests.
    pub store_origin: Option<String>,
    /// Directory of the Store session files (`store-cookies.json`,
    /// `kbsync-v1.json`); `None` means `<user config dir>/ipakeep`.
    pub state_directory: Option<PathBuf>,
}

impl Default for AppleApiConfig {
    fn default() -> Self {
        Self {
            bag_url: BAG_URL.into(),
            itunes_search_url: "https://itunes.apple.com/search".into(),
            itunes_lookup_url: "https://itunes.apple.com/lookup".into(),
            purchase_history_url: PURCHASE_DAAP_BASE_URL.into(),
            store_origin: None,
            state_directory: None,
        }
    }
}
