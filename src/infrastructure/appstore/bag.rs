//! Bag.xml discovery — resolves the Apple authentication endpoint URL.

use crate::domain::error::AppStoreError;
use crate::infrastructure::http::AppleHttpClient;

/// Configurator authentication endpoint used when bag.xml omits
/// `authenticateAccount`.
const CONFIGURATOR_AUTH_ENDPOINT: &str = "https://auth.itunes.apple.com/auth/v1/native/fast/";

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
        return Ok(CONFIGURATOR_AUTH_ENDPOINT.to_string());
    }

    Err(AppStoreError::Unexpected(
        "missing authentication endpoint in bag.xml".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{CONFIGURATOR_AUTH_ENDPOINT, resolve_auth_endpoint};
    use crate::infrastructure::http::AppleHttpClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn falls_back_to_configurator_endpoint_when_only_account_summary_present() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bag.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accountSummary": "https://example.com/account/settings"
            })))
            .mount(&server)
            .await;

        let client = AppleHttpClient::new().expect("client");
        let endpoint = resolve_auth_endpoint(&client, &format!("{}/bag.xml", server.uri()), "GUID")
            .await
            .expect("endpoint");

        assert_eq!(endpoint, CONFIGURATOR_AUTH_ENDPOINT);
        assert_eq!(
            endpoint,
            "https://auth.itunes.apple.com/auth/v1/native/fast/"
        );
    }

    #[tokio::test]
    async fn prefers_explicit_authenticate_account_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bag.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authenticateAccount": "https://auth.example.com/custom"
            })))
            .mount(&server)
            .await;

        let client = AppleHttpClient::new().expect("client");
        let endpoint = resolve_auth_endpoint(&client, &format!("{}/bag.xml", server.uri()), "GUID")
            .await
            .expect("endpoint");
        assert_eq!(endpoint, "https://auth.example.com/custom");
    }
}
