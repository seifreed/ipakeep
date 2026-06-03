//! CLI command handlers — adapter layer between CLI input and use cases.

pub mod auth;
pub mod download;
pub mod list_versions;
pub mod purchase;
pub mod search;

/// Get the device GUID (MAC address) for Apple API requests.
pub fn get_guid() -> String {
    mac_address::get_mac_address().ok().flatten().map_or_else(
        || "000000000000".to_string(),
        |addr| addr.to_string().replace(':', "").to_uppercase(),
    )
}
