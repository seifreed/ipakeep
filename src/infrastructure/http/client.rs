//! HTTP client wrapper with Apple Configurator User-Agent spoofing.

mod response;

use super::telemetry::{read_response_bytes, read_response_text, send_with_observability};
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
        self.get_json_with_headers(url, None).await
    }

    /// Send a GET request with optional headers and deserialize its response.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request or deserialization fails.
    pub async fn get_json_with_headers<T: DeserializeOwned>(
        &self,
        url: &str,
        headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse<T>, crate::domain::error::AppStoreError> {
        let mut request = self.client.get(url);
        if let Some(headers) = headers {
            for (key, value) in headers {
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let status = response.status();
        let headers = response.headers().clone();
        let text = read_response_text(response)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        ensure_success_status("GET", status, text.as_bytes())?;

        let body = decode_get_body(status, &text)?;

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

        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        let status = response.status();
        let headers = response.headers().clone();
        let text = read_response_text(response)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        ensure_success_status("POST form", status, text.as_bytes())?;

        let body = decode_json_or_plist(&text).map_err(|e| {
            crate::domain::error::AppStoreError::NetworkError(format!(
                "response decode failed for HTTP {status}: {e}"
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

        self.post_plist_bytes(url, &plist_xml, headers).await
    }

    /// Send an already encoded plist body without changing its bytes.
    ///
    /// This is used when a request signature covers the exact serialized body.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request, status, or body decode fails.
    pub async fn post_plist_bytes(
        &self,
        url: &str,
        plist_xml: &[u8],
        headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        self.post_plist_bytes_with_server_errors(url, plist_xml, headers, false)
            .await
    }

    /// Send an authentication plist while preserving server errors for retry handling.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails or the response is malformed.
    pub async fn post_auth_plist_bytes(
        &self,
        url: &str,
        plist_xml: &[u8],
        headers: Option<&HashMap<String, String>>,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        self.post_plist_bytes_with_server_errors(url, plist_xml, headers, true)
            .await
    }

    async fn post_plist_bytes_with_server_errors(
        &self,
        url: &str,
        plist_xml: &[u8],
        headers: Option<&HashMap<String, String>>,
        preserve_server_errors: bool,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        let response = self.send_plist_request(url, plist_xml, headers).await?;
        Self::parse_plist_response(response, preserve_server_errors).await
    }

    async fn send_plist_request(
        &self,
        url: &str,
        plist_xml: &[u8],
        headers: Option<&HashMap<String, String>>,
    ) -> Result<reqwest::Response, crate::domain::error::AppStoreError> {
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
            .body(plist_xml.to_vec());

        if let Some(extra_headers) = headers {
            for (key, value) in extra_headers {
                if key.eq_ignore_ascii_case("content-type") {
                    continue;
                }
                request = request.header(key.as_str(), value.as_str());
            }
        }

        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;
        Ok(response)
    }

    async fn parse_plist_response(
        response: reqwest::Response,
        preserve_server_errors: bool,
    ) -> Result<HttpResponse<serde_json::Value>, crate::domain::error::AppStoreError> {
        let status = response.status();
        let resp_headers = response.headers().clone();
        let body_bytes = read_response_bytes(response)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        // Apple's login edge sometimes rejects an under-attested request before it
        // reaches account processing: a 5xx, an un-followable 3xx (a 301/302 with
        // no usable `Location`, which reqwest leaves for us), or a generic 404
        // HTML page. These carry no account data; surface them with a null body so
        // the caller can retry instead of failing on the undecodable HTML.
        if should_preserve_server_error(preserve_server_errors, status) {
            return Ok(null_plist_response(status, resp_headers));
        }

        ensure_success_status("POST plist", status, &body_bytes)?;

        if status == reqwest::StatusCode::NO_CONTENT && body_bytes.is_empty() {
            return Ok(null_plist_response(status, resp_headers));
        }

        let body = decode_plist_body(status, &resp_headers, &body_bytes)?;

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

        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;
        let status = response.status();

        let bytes = read_response_bytes(response)
            .await
            .map_err(|e| crate::domain::error::AppStoreError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(http_status_error("download", status, &bytes));
        }

        Ok(bytes)
    }

    /// Get the underlying reqwest client reference.
    pub fn client(&self) -> &Client {
        &self.client
    }
}

fn should_preserve_server_error(preserve: bool, status: reqwest::StatusCode) -> bool {
    preserve
        && (status.is_server_error()
            || status.is_redirection()
            || status == reqwest::StatusCode::NOT_FOUND)
}

fn null_plist_response(
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
) -> HttpResponse<serde_json::Value> {
    HttpResponse {
        status,
        headers,
        body: serde_json::Value::Null,
    }
}

fn decode_get_body<T: DeserializeOwned>(
    status: reqwest::StatusCode,
    text: &str,
) -> Result<T, crate::domain::error::AppStoreError> {
    let value = decode_json_or_plist(text).map_err(|e| {
        crate::domain::error::AppStoreError::NetworkError(format!(
            "response decode failed for HTTP {status}: {e}"
        ))
    })?;
    serde_json::from_value(value).map_err(|e| {
        crate::domain::error::AppStoreError::NetworkError(format!(
            "response conversion failed for HTTP {status}: {e}"
        ))
    })
}

fn decode_plist_body(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body_bytes: &[u8],
) -> Result<serde_json::Value, crate::domain::error::AppStoreError> {
    let content_type = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    super::plist_codec::decode_plist(body_bytes)
        .or_else(|plist_error| {
            let text = String::from_utf8_lossy(body_bytes);
            decode_json_or_plist(&text).map_err(|error| format!("{plist_error}; {error}"))
        })
        .map_err(|error| {
            crate::domain::error::AppStoreError::NetworkError(format!(
                "plist decode failed for HTTP {status} ({content_type}): {error}"
            ))
        })
}
