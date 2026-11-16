//! Store front to country code mapping.
//!
//! Ported from ipatool `pkg/appstore/storefront.go`: the table comes from
//! `availableStoreFronts`; identifiers it omits are resolved one at a time
//! through the `genre/id36` page, which reports its own store front.
//!
//! Uncertainty (no wire capture yet): upstream sends these GETs through the
//! emulated `AppleMediaServices` session, which may add headers of its own.
//! Only the headers upstream sets explicitly are reproduced here.

use crate::domain::error::AppStoreError;
use crate::infrastructure::http::telemetry::{read_response_bytes, send_with_observability};
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Apple's table of store front identifiers and country codes.
pub const AVAILABLE_STOREFRONTS_URL: &str =
    "https://itunes.apple.com/WebObjects/MZStore.woa/wa/availableStoreFronts";
/// Page whose embedded metadata names the store front of the request.
pub const STOREFRONT_GENRE_URL: &str = "https://apps.apple.com/genre/id36";
/// User agent upstream's Store backend sets on requests that name none.
pub const DEFAULT_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

const STORE_FRONT_HEADER: &str = "X-Apple-Store-Front";
const GENRE_STORE_FRONT_SUFFIX: &str = "-2,29";
const MAX_STOREFRONT_ID_RANGE: i64 = 1000;
const COUNTRY_CODE_LENGTH: usize = 2;

/// Resolves store front identifiers (`143441-1,29`) to ISO country codes,
/// caching Apple's table for the life of the resolver.
pub struct StorefrontResolver {
    client: reqwest::Client,
    available_url: String,
    genre_url: String,
    country_codes: Mutex<Option<HashMap<String, String>>>,
}

impl StorefrontResolver {
    /// Resolver against Apple's endpoints. `client` must not follow redirects.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            available_url: AVAILABLE_STOREFRONTS_URL.to_string(),
            genre_url: STOREFRONT_GENRE_URL.to_string(),
            country_codes: Mutex::new(None),
        }
    }

    /// Resolver against custom `availableStoreFronts` and genre page URLs
    /// (tests/proxies). `client` must not follow redirects.
    #[must_use]
    pub fn with_urls(client: reqwest::Client, available_url: &str, genre_url: &str) -> Self {
        Self {
            client,
            available_url: available_url.to_string(),
            genre_url: genre_url.to_string(),
            country_codes: Mutex::new(None),
        }
    }

    /// Uppercase country code of `store_front`.
    ///
    /// # Errors
    ///
    /// Returns [`AppStoreError::NetworkError`] when Apple's table cannot be
    /// fetched, or [`AppStoreError::Unexpected`] when no mapping exists.
    pub async fn country_code(&self, store_front: &str) -> Result<String, AppStoreError> {
        let mut guard = self.country_codes.lock().await;
        let codes = self.available(&mut guard).await?;
        let identifier = storefront_identifier(store_front);
        if let Some(code) = codes.get(identifier) {
            return Ok(code.clone());
        }
        match self.discover_country_code(codes, identifier).await? {
            Some(code) => Ok(code),
            None => Err(mapping_error(store_front)),
        }
    }

    /// Store front identifier of an ISO `country_code`.
    ///
    /// # Errors
    ///
    /// Returns an error when Apple's table cannot be fetched or no store
    /// front reports `country_code`.
    pub async fn storefront_id(&self, country_code: &str) -> Result<String, AppStoreError> {
        let country_code = country_code.trim().to_ascii_uppercase();
        let mut guard = self.country_codes.lock().await;
        let codes = self.available(&mut guard).await?;
        if let Some(identifier) = identifier_for(codes, &country_code) {
            return Ok(identifier);
        }
        for identifier in missing_identifiers(codes)? {
            let found = self.discover_country_code(codes, &identifier).await?;
            if found.as_deref() == Some(country_code.as_str()) {
                return Ok(identifier);
            }
        }
        Err(AppStoreError::Unexpected(format!(
            "store front mapping for country code ({country_code}) was not found"
        )))
    }

    async fn available<'a>(
        &self,
        cache: &'a mut Option<HashMap<String, String>>,
    ) -> Result<&'a mut HashMap<String, String>, AppStoreError> {
        if cache.is_none() {
            *cache = Some(self.fetch_available().await?);
        }
        cache
            .as_mut()
            .ok_or_else(|| AppStoreError::Unexpected("storefront table is unavailable".into()))
    }

    async fn fetch_available(&self) -> Result<HashMap<String, String>, AppStoreError> {
        let request = self.client.get(&self.available_url);
        let request = request.header(reqwest::header::USER_AGENT, DEFAULT_USER_AGENT);
        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|error| network("available storefronts request failed", &error))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AppStoreError::NetworkError(format!(
                "available storefronts request failed (HTTP {})",
                response.status().as_u16()
            )));
        }
        let body = read_response_bytes(response)
            .await
            .map_err(|error| network("read available storefronts", &error))?;
        parse_available_storefronts(&body)
    }

    async fn discover_country_code(
        &self,
        codes: &mut HashMap<String, String>,
        identifier: &str,
    ) -> Result<Option<String>, AppStoreError> {
        if identifier.parse::<i64>().is_err() {
            return Ok(None);
        }
        let Some(body) = self.fetch_genre_page(identifier).await? else {
            return Ok(None);
        };
        let Some(code) = genre_country_code(&body, identifier)? else {
            return Ok(None);
        };
        if codes
            .iter()
            .any(|(known, known_code)| *known_code == code && known != identifier)
        {
            return Ok(None);
        }
        codes.insert(identifier.to_string(), code.clone());
        Ok(Some(code))
    }

    async fn fetch_genre_page(&self, identifier: &str) -> Result<Option<Vec<u8>>, AppStoreError> {
        let request = self
            .client
            .get(&self.genre_url)
            .header(reqwest::header::USER_AGENT, DEFAULT_USER_AGENT)
            .header(
                STORE_FRONT_HEADER,
                format!("{identifier}{GENRE_STORE_FRONT_SUFFIX}"),
            );
        let response = send_with_observability(&self.client, request)
            .await
            .map_err(|error| network("storefront country code request failed", &error))?;
        let status = response.status();
        if status.is_redirection() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status != reqwest::StatusCode::OK {
            return Err(AppStoreError::NetworkError(format!(
                "storefront country code request failed (HTTP {})",
                status.as_u16()
            )));
        }
        let body = read_response_bytes(response)
            .await
            .map_err(|error| network("read storefront country code", &error))?;
        Ok(Some(body))
    }
}

/// Numeric identifier of a store front header value (`143441-1,29` → `143441`).
#[must_use]
pub fn storefront_identifier(store_front: &str) -> &str {
    let trimmed = store_front.trim();
    let identifier = trimmed.split(',').next().unwrap_or(trimmed);
    identifier.split('-').next().unwrap_or(identifier)
}

fn parse_available_storefronts(body: &[u8]) -> Result<HashMap<String, String>, AppStoreError> {
    let value = plist::Value::from_reader(std::io::Cursor::new(body)).map_err(|error| {
        AppStoreError::Unexpected(format!("failed to decode available storefronts: {error}"))
    })?;
    let codes: HashMap<String, String> = value
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("storefronts"))
        .and_then(plist::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(available_storefront)
        .collect();
    if codes.is_empty() {
        return Err(AppStoreError::Unexpected(
            "available storefronts response contains no storefronts".into(),
        ));
    }
    Ok(codes)
}

fn available_storefront(value: &plist::Value) -> Option<(String, String)> {
    let entry = value.as_dictionary()?;
    let id = entry.get("id")?.as_signed_integer()?;
    let code = entry
        .get("country-code")?
        .as_string()?
        .trim()
        .to_ascii_uppercase();
    (id > 0 && !code.is_empty()).then(|| (id.to_string(), code))
}

fn genre_country_code(body: &[u8], identifier: &str) -> Result<Option<String>, AppStoreError> {
    let page: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        AppStoreError::Unexpected(format!("failed to decode storefront country code: {error}"))
    })?;
    let storefront = page
        .get("storePlatformData")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(serde_json::Map::values)
        .filter_map(|data| data.pointer("/meta/storefront"))
        .find(|storefront| {
            storefront.get("id").and_then(serde_json::Value::as_str) == Some(identifier)
        });
    let Some(storefront) = storefront else {
        return Ok(None);
    };
    let code = storefront
        .get("cc")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_uppercase();
    validate_country_code(&code)?;
    Ok(Some(code))
}

fn validate_country_code(code: &str) -> Result<(), AppStoreError> {
    if code.len() != COUNTRY_CODE_LENGTH {
        return Err(AppStoreError::Unexpected(
            "storefront country code response contains no country code".into(),
        ));
    }
    if !code.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(AppStoreError::Unexpected(
            "storefront country code response contains an invalid country code".into(),
        ));
    }
    Ok(())
}

fn identifier_for(codes: &HashMap<String, String>, country_code: &str) -> Option<String> {
    codes
        .iter()
        .find(|(_, code)| code.as_str() == country_code)
        .map(|(identifier, _)| identifier.clone())
}

fn missing_identifiers(codes: &HashMap<String, String>) -> Result<Vec<String>, AppStoreError> {
    let known: Vec<i64> = codes
        .keys()
        .filter_map(|identifier| identifier.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .collect();
    let (Some(&minimum), Some(&maximum)) = (known.iter().min(), known.iter().max()) else {
        return Err(invalid_range());
    };
    if maximum - minimum > MAX_STOREFRONT_ID_RANGE {
        return Err(invalid_range());
    }
    Ok((minimum..=maximum)
        .filter(|identifier| !known.contains(identifier))
        .map(|identifier| identifier.to_string())
        .collect())
}

fn invalid_range() -> AppStoreError {
    AppStoreError::Unexpected("available storefront identifier range is invalid".into())
}

fn mapping_error(store_front: &str) -> AppStoreError {
    AppStoreError::Unexpected(format!(
        "country code mapping for store front ({store_front}) was not found"
    ))
}

fn network(context: &str, error: &reqwest::Error) -> AppStoreError {
    AppStoreError::NetworkError(format!("{context}: {error}"))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(in super::super) const AVAILABLE_PATH: &str =
        "/WebObjects/MZStore.woa/wa/availableStoreFronts";
    const GENRE_PATH: &str = "/genre/id36";

    pub(in super::super) fn available_plist(entries: &[(i64, &str)]) -> String {
        let rows = entries
            .iter()
            .map(|(id, code)| {
                [
                    "<dict><key>country-code</key><string>",
                    code,
                    "</string><key>id</key><integer>",
                    &id.to_string(),
                    "</integer></dict>",
                ]
                .concat()
            })
            .collect::<String>();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>storefronts</key><array>{rows}</array></dict></plist>"#
        )
    }

    pub(in super::super) async fn mount_available(server: &MockServer, entries: &[(i64, &str)]) {
        Mock::given(method("GET"))
            .and(path(AVAILABLE_PATH))
            .and(header("user-agent", DEFAULT_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string(available_plist(entries)))
            .mount(server)
            .await;
    }

    pub(in super::super) fn resolver(server: &MockServer) -> StorefrontResolver {
        StorefrontResolver::with_urls(
            crate::infrastructure::http::client_builder()
                .build()
                .expect("HTTP client"),
            &format!("{}{AVAILABLE_PATH}", server.uri()),
            &format!("{}{GENRE_PATH}", server.uri()),
        )
    }

    /// Exact header match; wiremock's `header` splits values at commas.
    pub(in super::super) fn raw_header(
        name: &'static str,
        expected: &'static str,
    ) -> impl Fn(&wiremock::Request) -> bool {
        move |request| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                == Some(expected)
        }
    }

    fn genre_page(identifier: &str, code: &str) -> String {
        format!(
            r#"{{"storePlatformData":{{"lockup":{{"meta":{{"storefront":{{"cc":"{code}","id":"{identifier}"}}}}}}}}}}"#
        )
    }

    #[test]
    fn extracts_the_identifier_from_a_store_front_header() {
        assert_eq!(storefront_identifier("143441-1,29"), "143441");
        assert_eq!(storefront_identifier(" 143454 "), "143454");
        assert_eq!(storefront_identifier("143444,32"), "143444");
    }

    #[tokio::test]
    async fn maps_store_fronts_from_the_available_table_once() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(AVAILABLE_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(available_plist(&[
                    (143_441, "us"),
                    (143_454, "ES"),
                    (0, "XX"),
                ])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let resolver = resolver(&server);

        assert_eq!(
            resolver.country_code("143441-1,29").await.expect("us"),
            "US"
        );
        assert_eq!(
            resolver.country_code("143454-8,29").await.expect("es"),
            "ES"
        );
        assert_eq!(resolver.storefront_id("es").await.expect("id"), "143454");
    }

    #[tokio::test]
    async fn discovers_missing_store_fronts_through_the_genre_page() {
        let server = MockServer::start().await;
        mount_available(&server, &[(143_441, "US")]).await;
        Mock::given(method("GET"))
            .and(path(GENRE_PATH))
            .and(raw_header(STORE_FRONT_HEADER, "143999-2,29"))
            .and(header("user-agent", DEFAULT_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string(genre_page("143999", "zz")))
            .expect(1)
            .mount(&server)
            .await;
        let resolver = resolver(&server);

        assert_eq!(
            resolver.country_code("143999-1,29").await.expect("zz"),
            "ZZ"
        );
        assert_eq!(resolver.country_code("143999").await.expect("cached"), "ZZ");
    }

    #[tokio::test]
    async fn rejects_unknown_redirected_and_duplicate_store_fronts() {
        let server = MockServer::start().await;
        mount_available(&server, &[(143_441, "US")]).await;
        Mock::given(path(GENRE_PATH))
            .and(raw_header(STORE_FRONT_HEADER, "143442-2,29"))
            .respond_with(ResponseTemplate::new(302))
            .mount(&server)
            .await;
        Mock::given(path(GENRE_PATH))
            .and(raw_header(STORE_FRONT_HEADER, "143443-2,29"))
            .respond_with(ResponseTemplate::new(200).set_body_string(genre_page("143443", "US")))
            .mount(&server)
            .await;
        let resolver = resolver(&server);

        assert!(resolver.country_code("143442-1").await.is_err());
        assert!(resolver.country_code("143443-1").await.is_err());
        assert!(resolver.country_code("abc").await.is_err());
    }

    #[tokio::test]
    async fn scans_the_identifier_range_for_a_country() {
        let server = MockServer::start().await;
        mount_available(&server, &[(143_441, "US"), (143_444, "GB")]).await;
        Mock::given(path(GENRE_PATH))
            .and(raw_header(STORE_FRONT_HEADER, "143442-2,29"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(path(GENRE_PATH))
            .and(raw_header(STORE_FRONT_HEADER, "143443-2,29"))
            .respond_with(ResponseTemplate::new(200).set_body_string(genre_page("143443", "DE")))
            .mount(&server)
            .await;
        let resolver = resolver(&server);

        assert_eq!(resolver.storefront_id("de").await.expect("de"), "143443");
        assert!(resolver.storefront_id("FR").await.is_err());
    }

    #[test]
    fn validates_genre_country_codes_and_ranges() {
        assert!(genre_country_code(genre_page("1", "U1").as_bytes(), "1").is_err());
        assert!(genre_country_code(genre_page("1", "").as_bytes(), "1").is_err());
        assert_eq!(
            genre_country_code(genre_page("1", "us").as_bytes(), "2").expect("absent"),
            None
        );
        assert!(genre_country_code(b"<html>", "1").is_err());
        let wide = HashMap::from([
            ("1".to_string(), "A".to_string()),
            ("5000".to_string(), "B".to_string()),
        ]);
        assert!(missing_identifiers(&wide).is_err());
        assert!(parse_available_storefronts(&available_plist(&[]).into_bytes()).is_err());
    }

    #[test]
    fn default_resolver_targets_apple() {
        let resolver = StorefrontResolver::new(reqwest::Client::new());
        assert_eq!(resolver.available_url, AVAILABLE_STOREFRONTS_URL);
        assert_eq!(resolver.genre_url, STOREFRONT_GENRE_URL);
    }

    #[test]
    fn rejects_undecodable_tables_and_empty_ranges() {
        assert!(matches!(
            parse_available_storefronts(b"not a plist"),
            Err(AppStoreError::Unexpected(m)) if m.starts_with("failed to decode available storefronts")
        ));
        assert!(missing_identifiers(&HashMap::new()).is_err());
    }

    #[tokio::test]
    async fn ignores_genre_pages_for_another_store_front() {
        let server = MockServer::start().await;
        mount_available(&server, &[(143_441, "US")]).await;
        Mock::given(path(GENRE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(genre_page("1", "DE")))
            .mount(&server)
            .await;
        assert!(matches!(
            resolver(&server).country_code("143442").await,
            Err(AppStoreError::Unexpected(m)) if m.contains("143442")
        ));
    }

    #[tokio::test]
    async fn reports_genre_page_failures() {
        let server = MockServer::start().await;
        mount_available(&server, &[(143_441, "US")]).await;
        Mock::given(path(GENRE_PATH))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        assert!(matches!(
            resolver(&server).country_code("143442").await,
            Err(AppStoreError::NetworkError(m)) if m.contains("HTTP 500")
        ));
    }

    #[tokio::test]
    async fn reports_unreachable_storefront_endpoints() {
        let resolver = StorefrontResolver::with_urls(
            reqwest::Client::new(),
            "http://127.0.0.1:1/available",
            "http://127.0.0.1:1/genre",
        );
        assert!(matches!(
            resolver.country_code("143441").await,
            Err(AppStoreError::NetworkError(m)) if m.starts_with("available storefronts request failed:")
        ));
    }

    #[tokio::test]
    async fn reports_available_table_failures() {
        let server = MockServer::start().await;
        Mock::given(path(AVAILABLE_PATH))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        assert!(matches!(
            resolver(&server).country_code("143441").await,
            Err(AppStoreError::NetworkError(_))
        ));
    }
}
