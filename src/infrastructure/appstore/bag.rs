//! Bag.xml discovery — resolves the Apple authentication endpoint URL.

use crate::domain::error::AppStoreError;
use crate::infrastructure::http::AppleHttpClient;

/// Modern native authentication endpoint used when bag.xml omits authenticateAccount.
const NATIVE_AUTH_ENDPOINT: &str = "https://auth.itunes.apple.com/auth/v1/native/fast";

/// Resolve the Apple authentication endpoint from the bag.xml configuration.
///
/// Apple's auth endpoint changes periodically, so it must be discovered
/// dynamically by fetching bag.xml with the device GUID.
///
/// # Errors
///
/// Returns `AppStoreError::NetworkError` if the HTTP request fails.
/// Returns `AppStoreError::Unexpected` if the response is malformed.
pub async fn resolve_auth_endpoint(
    client: &AppleHttpClient,
    bag_url: &str,
    guid: &str,
) -> Result<String, AppStoreError> {
    let url = format!("{bag_url}?guid={guid}");
    let response = client
        .get_json::<serde_json::Value>(&url)
        .await
        .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;

    if let Some(auth_url) = response
        .body
        .get("urlBag")
        .and_then(|v| v.get("authenticateAccount"))
        .or_else(|| response.body.get("authenticateAccount"))
        .and_then(|v| v.as_str())
    {
        return Ok(auth_url.to_string());
    }

    if response.body.get("accountSummary").is_some() {
        return Ok(NATIVE_AUTH_ENDPOINT.to_string());
    }

    Err(AppStoreError::Unexpected(
        "missing authentication endpoint in bag.xml".into(),
    ))
}
