//! HTTP client wrapper with Apple Configurator User-Agent spoofing.

mod response;

use super::response_snippet;
use reqwest::cookie::Jar;
use reqwest::{Client, ClientBuilder, Url};
pub use response::HttpResponse;
use response::{decode_json_or_plist, ensure_success_status, http_status_error};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;

/// Apple `akd` User-Agent string used for `GrandSlam` authentication.
const USER_AGENT: &str = "akd/1.0 CFNetwork/1560.4.3 Darwin/24.2.0";

/// Apple Root CA (PEM). `gsa.apple.com` (`GrandSlam`) chains to Apple's own
/// root, which macOS trusts natively but the default Linux and Windows trust
/// stores do not. Adding it lets authentication work off-macOS without
/// disabling certificate verification.
const APPLE_ROOT_CA: &[u8] = include_bytes!("apple_root_ca.pem");

/// An Apple HTTP client that spoofs the Configurator User-Agent.
#[derive(Clone)]
pub struct AppleHttpClient {
    client: Client,
    cookie_jar: Arc<Jar>,
}

impl AppleHttpClient {
    /// Create a new Apple HTTP client with Configurator User-Agent.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the HTTP client cannot be built.
    pub fn new() -> Result<Self, crate::domain::error::AppStoreError> {
        let apple_root = reqwest::Certificate::from_pem(APPLE_ROOT_CA)
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let cookie_jar = Arc::new(Jar::default());
        let client = ClientBuilder::new()
            .user_agent(USER_AGENT)
            .cookie_provider(cookie_jar.clone())
            .add_root_certificate(apple_root)
            .build()
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        Ok(Self { client, cookie_jar })
    }

    /// Seed the in-memory cookie jar with raw `Set-Cookie` values.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the cookie origin URL is invalid.
    pub fn seed_cookies(
        &self,
        cookies: &[String],
        origin: &str,
    ) -> Result<(), crate::domain::error::AppStoreError> {
        let url = Url::parse(origin)
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;
        for cookie in cookies {
            self.cookie_jar.add_cookie_str(cookie, &url);
        }
        Ok(())
    }

    /// Send a GET request and deserialize the JSON response.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request or deserialization fails.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<HttpResponse<T>, crate::domain::error::AppStoreError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let status = response.status();
        let headers = response.headers().clone();
        let text = response
            .text()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        ensure_success_status("GET", status, text.as_bytes())?;

        let value = decode_json_or_plist(&text).map_err(|e| {
            crate::domain::error::AppStoreError::NetworkError(format!(
                "response decode failed for HTTP {status}: {e}; body: {}",
                response_snippet(text.as_bytes())
            ))
        })?;
        let body = serde_json::from_value(value).map_err(|e| {
            crate::domain::error::AppStoreError::NetworkError(format!(
                "response conversion failed for HTTP {status}: {e}"
            ))
        })?;

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Send a POST request with URL-encoded form data.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request or deserialization fails.
    pub async fn post_form(
        &self,
        url: &str,
        form_data: &HashMap<String, String>,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        self.post_form_with_headers(url, form_data, None).await
    }

    /// Send a POST request with URL-encoded form data and additional headers.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request or deserialization fails.
    pub async fn post_form_with_headers(
        &self,
        url: &str,
        form_data: &HashMap<String, String>,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        let mut request = self.client.post(url).form(form_data);
        if let Some(extra_headers) = headers {
            for (key, value) in extra_headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let status = response.status();
        let headers = response.headers().clone();
        let text = response
            .text()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        ensure_success_status("POST form", status, text.as_bytes())?;

        let body = decode_json_or_plist(&text).map_err(|e| {
            crate::domain::error::AppStoreError::NetworkError(format!(
                "response decode failed for HTTP {status}: {e}; body: {}",
                response_snippet(text.as_bytes())
            ))
        })?;

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Send a POST request with plist XML body and return plist response.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request, encoding, or decoding fails.
    pub async fn post_plist(
        &self,
        url: &str,
        plist_data: &serde_json::Value,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        let plist_xml = super::plist_codec::encode_plist(plist_data)
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let content_type = headers
            .and_then(|extra| {
                extra
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
                    .map(|(_, value)| value.as_str())
            })
            .unwrap_or("application/x-apple-plist");

        let mut request = self.client.post(url);
        request = request
            .header("Content-Type", content_type)
            .header("Accept", "*/*")
            .body(plist_xml);

        if let Some(extra_headers) = headers {
            for (key, value) in extra_headers {
                if key.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let status = response.status();
        let resp_headers = response.headers().clone();
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        ensure_success_status("POST plist", status, &body_bytes)?;

        let content_type = resp_headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let body = super::plist_codec::decode_plist(&body_bytes)
            .or_else(|plist_error| {
                let text = String::from_utf8_lossy(&body_bytes);
                decode_json_or_plist(&text).map_err(|e| format!("{plist_error}; {e}"))
            })
            .map_err(|e| {
                crate::domain::error::AppStoreError::NetworkError(format!(
                    "plist decode failed for HTTP {status} ({content_type}): {e}; body: {}",
                    response_snippet(&body_bytes)
                ))
            })?;

        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body,
        })
    }

    /// Download a file from a URL, returning the raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn download_file(
        &self,
        url: &str,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<Vec<u8>, crate::domain::error::AppStoreError> {
        let mut request = self.client.get(url);

        if let Some(extra_headers) = headers {
            for (key, value) in extra_headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;
        let status = response.status();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(http_status_error("download", status, &bytes));
        }

        Ok(bytes.to_vec())
    }

    /// Get the underlying reqwest client reference.
    pub fn client(&self) -> &Client {
        &self.client
    }
}
