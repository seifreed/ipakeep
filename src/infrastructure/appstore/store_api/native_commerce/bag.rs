//! Store URL bag, shared Store HTTP client and plist response decoding.
//!
//! Ported from ipatool `pkg/appstore/appstore_bag.go` and the XML response
//! normalisation in `pkg/http/client.go`.

use crate::domain::error::AppStoreError;
use reqwest::Url;
use std::sync::Arc;

/// Production URL bag endpoint (`https://init.itunes.apple.com/bag.xml`).
pub const BAG_URL: &str = "https://init.itunes.apple.com/bag.xml";

/// User agent upstream sends on every native Store request.
pub const STORE_USER_AGENT: &str =
    "Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6";

/// `MZFinance` authentication path.
pub const AUTHENTICATE_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate";

const BUY_DOMAIN: &str = "buy.itunes.apple.com";
const POD_BUY_SUFFIX: &str = "-buy.itunes.apple.com";
const NATIVE_AUTH_DOMAIN: &str = "auth.itunes.apple.com";
const NATIVE_AUTH_PATHS: [&str; 4] = [
    "/auth/v1/native",
    "/auth/v1/native/",
    "/auth/v1/native/fast",
    "/auth/v1/native/fast/",
];
const BAG_INDEX: &str = "6";
const SUPPORTED_SAP_VERSION: u32 = 200;
const URL_BAG_KEY: &str = "urlBag";
const KEY_AUTHENTICATE: &str = "authenticateAccount";
const KEY_SAP_SETUP: &str = "sign-sap-setup";
const KEY_SAP_SETUP_CERT: &str = "sign-sap-setup-cert";
const KEY_SAP_VERSION: &str = "sign-sap-version";
const KEY_VOLUME_DOWNLOAD: &str = "volumeStoreDownloadProduct";
const KEY_REDOWNLOAD: &str = "redownloadProduct";
const KEY_UPDATE: &str = "updateProduct";
const BAG_KEYS: [&str; 7] = [
    KEY_AUTHENTICATE,
    KEY_VOLUME_DOWNLOAD,
    KEY_REDOWNLOAD,
    KEY_UPDATE,
    KEY_SAP_SETUP,
    KEY_SAP_SETUP_CERT,
    KEY_SAP_VERSION,
];

/// Endpoints parsed from Apple's URL bag.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreBag {
    /// `authenticateAccount`, validated and normalised to the `.../authenticate/` path.
    pub authenticate_account: String,
    /// `sign-sap-setup` endpoint.
    pub sap_setup: String,
    /// `sign-sap-setup-cert` endpoint.
    pub sap_setup_cert: String,
    /// `sign-sap-version` (only 200 is accepted).
    pub sap_version: u32,
    /// `volumeStoreDownloadProduct`, when present.
    pub volume_store_download_product: Option<String>,
    /// `redownloadProduct`, when present.
    pub redownload_product: Option<String>,
    /// `updateProduct`, when present.
    pub update_product: Option<String>,
    /// Every bag value, with `urlBag` entries merged over the top level.
    pub values: plist::Dictionary,
}

/// Uppercase hex machine GUID upstream derives from the MAC address.
#[must_use]
pub fn machine_guid(hardware_id: &[u8]) -> String {
    hex::encode_upper(hardware_id)
}

/// Build the shared Store client: cookies from `cookies` (any cookie store), redirects never followed
/// (login replays the signed POST itself), like upstream's Store transport.
///
/// # Errors
///
/// Returns [`AppStoreError::NetworkError`] when the client cannot be built.
pub fn store_client<C: reqwest::cookie::CookieStore + 'static>(
    cookies: Arc<C>,
) -> Result<reqwest::Client, AppStoreError> {
    reqwest::Client::builder()
        .cookie_provider(cookies)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| AppStoreError::NetworkError(format!("build Store client: {error}")))
}

/// `GET {bag_url}?ix=6&guid=GUID` and parse the bag.
///
/// # Errors
///
/// Network failures, non-200 statuses, malformed plists and invalid or
/// missing authentication/SAP endpoints.
pub async fn fetch_bag(
    client: &reqwest::Client,
    bag_url: &str,
    guid: &str,
) -> Result<StoreBag, AppStoreError> {
    let response = client
        .get(format!("{bag_url}?ix={BAG_INDEX}&guid={guid}"))
        .header("Accept", "application/xml")
        .header("User-Agent", STORE_USER_AGENT)
        .send()
        .await
        .map_err(|error| AppStoreError::NetworkError(format!("bag request failed: {error}")))?;
    let status = response.status();
    if status != reqwest::StatusCode::OK {
        return Err(AppStoreError::NetworkError(format!(
            "bag: received unexpected status code: {}",
            status.as_u16()
        )));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| AppStoreError::NetworkError(format!("read bag: {error}")))?;
    StoreBag::from_dictionary(&decode_store_plist(&body)?)
}

impl StoreBag {
    /// Parse and validate a decoded bag document.
    ///
    /// # Errors
    ///
    /// Invalid authentication endpoint, SAP endpoints or SAP version.
    pub fn from_dictionary(document: &plist::Dictionary) -> Result<Self, AppStoreError> {
        let source = bag_source(document);
        let text = |key: &str| string_value(source.get(key));
        let sap_version = parse_sap_version(&text(KEY_SAP_VERSION))?;
        let authenticate_account = normalize_authenticate_endpoint(&text(KEY_AUTHENTICATE))?;
        let sap_setup = validate_https(&text(KEY_SAP_SETUP), "SAP setup")?;
        let sap_setup_cert = validate_https(&text(KEY_SAP_SETUP_CERT), "SAP setup certificate")?;
        let optional = |key: &str| Some(text(key)).filter(|value| !value.is_empty());
        Ok(Self {
            authenticate_account,
            sap_setup,
            sap_setup_cert,
            sap_version,
            volume_store_download_product: optional(KEY_VOLUME_DOWNLOAD),
            redownload_product: optional(KEY_REDOWNLOAD),
            update_product: optional(KEY_UPDATE),
            values: merged_values(document),
        })
    }
}

/// Upstream reads the nested `urlBag` only when it carries a known key.
fn bag_source(document: &plist::Dictionary) -> &plist::Dictionary {
    match document
        .get(URL_BAG_KEY)
        .and_then(plist::Value::as_dictionary)
    {
        Some(nested)
            if BAG_KEYS
                .iter()
                .any(|key| !string_value(nested.get(key)).is_empty()) =>
        {
            nested
        }
        _ => document,
    }
}

fn merged_values(document: &plist::Dictionary) -> plist::Dictionary {
    let mut values = document.clone();
    if let Some(nested) = document
        .get(URL_BAG_KEY)
        .and_then(plist::Value::as_dictionary)
    {
        for (key, value) in nested {
            values.insert(key.clone(), value.clone());
        }
    }
    values
}

fn string_value(value: Option<&plist::Value>) -> String {
    match value {
        Some(plist::Value::String(text)) => text.clone(),
        Some(plist::Value::Integer(number)) => number.to_string(),
        _ => String::new(),
    }
}

fn parse_sap_version(value: &str) -> Result<u32, AppStoreError> {
    let version: u32 = value
        .parse()
        .map_err(|_| bag_error(format!("invalid SAP version {value:?} in bag")))?;
    if version != SUPPORTED_SAP_VERSION {
        return Err(bag_error(format!(
            "unsupported SAP version {version} in bag"
        )));
    }
    Ok(version)
}

fn validate_https(value: &str, name: &str) -> Result<String, AppStoreError> {
    match Url::parse(value) {
        Ok(url) if url.scheme() == "https" && url.host_str().is_some_and(|h| !h.is_empty()) => {
            Ok(value.to_string())
        }
        _ => Err(bag_error(format!(
            "invalid {name} endpoint {value:?} in bag"
        ))),
    }
}

/// Validate the bag's authentication URL and, on a `buy` host, force the
/// `/wa/authenticate/` path: the bare path can answer a 301 without Location.
fn normalize_authenticate_endpoint(value: &str) -> Result<String, AppStoreError> {
    let mut url = validate_authentication_endpoint(value)?;
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host.ends_with(BUY_DOMAIN) {
        url.set_path(&format!("{AUTHENTICATE_PATH}/"));
    }
    Ok(url.to_string())
}

/// Accept only Apple's authentication endpoints: `https`, no credentials,
/// fragment or non-443 port; `buy`/`pN-buy` on `/wa/authenticate[/]` or the
/// native `auth.itunes.apple.com/auth/v1/native[/fast][/]` paths.
///
/// # Errors
///
/// Returns [`AppStoreError::AuthenticationFailed`] for any other URL.
pub fn validate_authentication_endpoint(value: &str) -> Result<Url, AppStoreError> {
    let invalid = || AppStoreError::AuthenticationFailed("invalid authentication endpoint".into());
    let url = Url::parse(value).map_err(|_| invalid())?;
    let well_formed = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.port().is_none_or(|port| port == HTTPS_PORT)
        && url.host_str().is_some_and(|host| !host.is_empty());
    if !well_formed {
        return Err(invalid());
    }
    if allowed_authentication_path(&url) {
        Ok(url)
    } else {
        Err(AppStoreError::AuthenticationFailed(
            "unsupported authentication endpoint".into(),
        ))
    }
}

const HTTPS_PORT: u16 = 443;

fn allowed_authentication_path(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = url.path();
    if host == NATIVE_AUTH_DOMAIN {
        return NATIVE_AUTH_PATHS.contains(&path);
    }
    let buy_host = host == BUY_DOMAIN || host.ends_with(POD_BUY_SUFFIX);
    buy_host && (path == AUTHENTICATE_PATH || path == format!("{AUTHENTICATE_PATH}/"))
}

fn bag_error(message: String) -> AppStoreError {
    AppStoreError::Unexpected(message)
}

/// Decode a Store plist response: binary plists as-is; XML is unwrapped from
/// an optional `<Document>` envelope and surrounding markup like upstream's
/// `normalizeXMLPlistBody`.
///
/// # Errors
///
/// Returns [`AppStoreError::Unexpected`] for empty, non-plist or non-dictionary bodies.
pub fn decode_store_plist(body: &[u8]) -> Result<plist::Dictionary, AppStoreError> {
    let trimmed = body.trim_ascii();
    let document = if trimmed.starts_with(b"bplist") {
        trimmed.to_vec()
    } else {
        normalize_xml_plist(trimmed).ok_or_else(|| non_plist_error(trimmed))?
    };
    plist::from_bytes::<plist::Value>(&document)
        .map_err(|error| AppStoreError::Unexpected(format!("malformed Store plist: {error}")))?
        .into_dictionary()
        .ok_or_else(|| AppStoreError::Unexpected("Store plist is not a dictionary".into()))
}

fn non_plist_error(body: &[u8]) -> AppStoreError {
    AppStoreError::Unexpected(format!(
        "unexpected response from Apple: empty or non-plist body ({} bytes)",
        body.len()
    ))
}

fn normalize_xml_plist(body: &[u8]) -> Option<Vec<u8>> {
    let body = document_inner(body).unwrap_or(body);
    let body = between(body, b"<plist", b"</plist>", false).unwrap_or(body);
    if let Some(dict) = between(body, b"<dict", b"</dict>", true) {
        return Some(wrap_plist(dict));
    }
    if find_ci(body, b"<key>", false).is_some() {
        let mut dict = b"<dict>".to_vec();
        dict.extend_from_slice(body);
        dict.extend_from_slice(b"</dict>");
        return Some(wrap_plist(&dict));
    }
    None
}

fn wrap_plist(dict: &[u8]) -> Vec<u8> {
    let mut document =
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\">".to_vec();
    document.extend_from_slice(dict);
    document.extend_from_slice(b"</plist>");
    document
}

fn document_inner(body: &[u8]) -> Option<&[u8]> {
    let open = find_ci(body, b"<document", false)?;
    let content = open + body[open..].iter().position(|&byte| byte == b'>')? + 1;
    let close = find_ci(body, b"</document>", true)?;
    let inner = body.get(content..close)?.trim_ascii();
    (!inner.is_empty()).then_some(inner)
}

/// `open ... close` inclusive; `last_close` picks the last closing tag (greedy).
fn between<'a>(body: &'a [u8], open: &[u8], close: &[u8], last_close: bool) -> Option<&'a [u8]> {
    let start = find_ci(body, open, false)?;
    let end = if last_close {
        find_ci(body, close, true)?
    } else {
        start + find_ci(&body[start..], close, false)?
    };
    (end >= start).then(|| body[start..end + close.len()].trim_ascii())
}

fn find_ci(haystack: &[u8], needle: &[u8], last: bool) -> Option<usize> {
    let lower = haystack.to_ascii_lowercase();
    let mut matches = lower
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(index, _)| index);
    if last {
        matches.next_back()
    } else {
        matches.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::cookie::Jar;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const AUTH: &str = "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate";
    const SETUP: &str = "https://fpinit.example.com/v1/signSapSetup/legacy";
    const CERT: &str = "https://static.example.com/sap/setupCert.plist";

    fn bag_xml(auth: &str, version: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
             <key>urlBag</key><dict>\
             <key>authenticateAccount</key><string>{}</string>\
             <key>sign-sap-setup</key><string>{SETUP}</string>\
             <key>sign-sap-setup-cert</key><string>{CERT}</string>\
             <key>sign-sap-version</key><string>{version}</string>\
             <key>volumeStoreDownloadProduct</key><string>https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct</string>\
             </dict><key>other</key><string>x</string></dict></plist>",
            auth.replace('&', "&amp;")
        )
    }

    fn parse(xml: &str) -> Result<StoreBag, AppStoreError> {
        StoreBag::from_dictionary(&decode_store_plist(xml.as_bytes())?)
    }

    #[tokio::test]
    async fn fetches_bag_with_upstream_request_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bag.xml"))
            .and(query_param("ix", "6"))
            .and(query_param("guid", "AABBCCDDEEFF"))
            .and(header("Accept", "application/xml"))
            .and(header("User-Agent", STORE_USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string(bag_xml(AUTH, "200")))
            .expect(1)
            .mount(&server)
            .await;
        let client = store_client(Arc::new(Jar::default())).expect("client");
        let guid = machine_guid(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let bag = fetch_bag(&client, &format!("{}/bag.xml", server.uri()), &guid)
            .await
            .expect("bag");
        assert_eq!(bag.authenticate_account, format!("{AUTH}/"));
        assert_eq!(bag.sap_setup, SETUP);
        assert_eq!(bag.sap_setup_cert, CERT);
        assert_eq!(bag.sap_version, 200);
        assert!(bag.volume_store_download_product.is_some());
        assert_eq!(bag.redownload_product, None);
        assert!(bag.values.contains_key("other"));
        assert!(bag.values.contains_key(KEY_AUTHENTICATE));
    }

    #[tokio::test]
    async fn non_200_bag_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = store_client(Arc::new(Jar::default())).expect("client");
        let error = fetch_bag(&client, &server.uri(), "00")
            .await
            .expect_err("403");
        assert!(error.to_string().contains("unexpected status code: 403"));
    }

    #[test]
    fn normalizes_authentication_path_keeping_host_and_query() {
        let pod = "https://p7-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate";
        for (input, expected) in [
            (AUTH.to_string(), format!("{AUTH}/")),
            (format!("{AUTH}/"), format!("{AUTH}/")),
            (
                format!("{AUTH}?Pod=7&routing=a%2Fb+c"),
                format!("{AUTH}/?Pod=7&routing=a%2Fb+c"),
            ),
            (format!("{pod}?Pod=7&PRH=7"), format!("{pod}/?Pod=7&PRH=7")),
            (
                format!("{pod}/?routing=opaque"),
                format!("{pod}/?routing=opaque"),
            ),
        ] {
            assert_eq!(
                parse(&bag_xml(&input, "200"))
                    .expect(&input)
                    .authenticate_account,
                expected
            );
        }
    }

    #[test]
    fn rejects_invalid_authentication_urls() {
        for input in [
            format!("{AUTH}//"),
            format!("{AUTH}/extra"),
            format!("{AUTH}%2f"),
            "https://buy.itunes.apple.com/other".into(),
            "https://example.com/WebObjects/MZFinance.woa/wa/authenticate".into(),
            "http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate".into(),
            "https://user@buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate".into(),
            "https://buy.itunes.apple.com:8443/WebObjects/MZFinance.woa/wa/authenticate".into(),
            format!("{AUTH}#fragment"),
            format!("{AUTH}%zz"),
            String::new(),
        ] {
            assert!(parse(&bag_xml(&input, "200")).is_err(), "{input}");
        }
    }

    #[test]
    fn rejects_invalid_or_unsupported_sap_version() {
        assert!(parse(&bag_xml(AUTH, "invalid")).is_err());
        assert!(parse(&bag_xml(AUTH, "201")).is_err());
    }

    #[test]
    fn reads_top_level_keys_when_url_bag_is_absent() {
        let xml = format!(
            "<plist><dict><key>authenticateAccount</key><string>{AUTH}</string>\
             <key>sign-sap-setup</key><string>{SETUP}</string>\
             <key>sign-sap-setup-cert</key><string>{CERT}</string>\
             <key>sign-sap-version</key><integer>200</integer></dict></plist>"
        );
        assert_eq!(parse(&xml).expect("bag").sap_version, 200);
    }

    #[test]
    fn decodes_document_envelopes_bare_keys_and_rejects_html() {
        let wrapped = "<Document xmlns=\"x\"><plist><dict><key>a</key><string>1</string></dict></plist></Document>";
        assert!(
            decode_store_plist(wrapped.as_bytes())
                .expect("doc")
                .contains_key("a")
        );
        let bare = "<key>b</key><string>2</string>";
        assert!(
            decode_store_plist(bare.as_bytes())
                .expect("bare")
                .contains_key("b")
        );
        assert!(decode_store_plist(b"<html><h1>Forbidden</h1></html>").is_err());
        assert!(decode_store_plist(b"").is_err());
    }
}
