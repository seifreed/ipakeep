//! The Store "SP" (`otp/1.5/finish`) provisioning exchange.
//!
//! Port of the HTTP half of upstream ipatool's
//! `internal/storeauth/store_provisioning.go`; the ADI half runs on the
//! service worker.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::anisette::{
    ANISETTE_LIMIT, MD_HEADER, MD_M_HEADER, RINFO_HEADER, decode_base64, header_value, http,
    protocol, read_limited,
};
use super::error::StoreAuthResult;
use super::xml::{XmlValue, document};

/// Upstream `privateAppStoreProvisioningURL`.
pub const STORE_PROVISIONING_URL: &str = "https://auth.itunes.apple.com/auth/v1/otp/1.5/finish";
/// Upstream `storeAuthenticationUserAgent`.
pub const STORE_AUTHENTICATION_USER_AGENT: &str =
    "Configurator/2.21 (Macintosh; OS X 27.0.1; 26A434) AppleWebKit/0625.2.5.11.6";
const HTTP_OK: u16 = 200;
/// Headers the request sets itself, overriding any identity copy.
const OWN_HEADERS: [&str; 3] = ["Accept", "Content-Type", "User-Agent"];

/// Inputs of the Store "SP" provisioning action.
pub struct StoreProvisioningRequest<'a> {
    /// The authentication client (carries the Store session cookies).
    pub client: &'a reqwest::Client,
    /// The action's base64 `spim` challenge.
    pub challenge: &'a str,
    /// Usually [`STORE_PROVISIONING_URL`].
    pub endpoint: &'a str,
    /// Usually [`STORE_AUTHENTICATION_USER_AGENT`].
    pub user_agent: &'a str,
    /// Base64 kbsync for DSID `-2`; empty to omit.
    pub kbsync: &'a str,
    /// Store hardware identifier (MAC address bytes).
    pub hardware_id: &'a [u8],
    /// Request identity headers, typically the anisette headers; the machine
    /// proof (`X-Apple-I-MD`, `-M`, `-RINFO`) is dropped.
    pub identity: &'a [(String, String)],
}

/// What `otp/1.5/finish` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFinish {
    /// Decoded `settingInfo`.
    pub setting_info: Vec<u8>,
    /// Decoded `transportKey`.
    pub transport_key: Vec<u8>,
    /// `FairPlay` keybag; empty when Apple sent none.
    pub key_bag: Vec<u8>,
}

/// Decodes the base64 challenge into `spim`.
///
/// # Errors
/// Fails on invalid, empty or oversized data.
pub fn decode_challenge(challenge: &str) -> StoreAuthResult<Vec<u8>> {
    decode_base64(challenge.trim()).ok_or_else(|| protocol("decode Apple Store provisioning data"))
}

/// The request plist: `clientData` (base64 `cpim`) and, when present,
/// `kbsync`.
#[must_use]
pub fn finish_body(cpim: &[u8], kbsync: &str) -> Vec<u8> {
    let client_data = STANDARD.encode(cpim);
    let mut entries = vec![("clientData", XmlValue::String(&client_data))];
    if !kbsync.is_empty() {
        entries.push(("kbsync", XmlValue::String(kbsync)));
    }
    document(&XmlValue::Dict(entries))
}

/// Posts `cpim` to the Store and returns the provisioning material.
///
/// # Errors
/// Fails on transport errors, a non-200 status or a malformed response.
pub async fn finish_store(
    request: &StoreProvisioningRequest<'_>,
    cpim: &[u8],
) -> StoreAuthResult<StoreFinish> {
    let mut builder = request.client.post(request.endpoint);
    for (name, value) in identity_headers(request.identity) {
        builder = builder.header(name, value);
    }
    let response = builder
        .header("Accept", "*/*")
        .header("Content-Type", "application/x-apple-plist")
        .header("User-Agent", request.user_agent)
        .body(finish_body(cpim, request.kbsync))
        .send()
        .await
        .map_err(http("send Apple Store provisioning request"))?;
    let status = response.status().as_u16();
    let body = read_limited(response, "read Apple Store provisioning response").await?;
    parse_finish(status, &body)
}

fn identity_headers(identity: &[(String, String)]) -> impl Iterator<Item = &(String, String)> {
    let excluded = [MD_HEADER, MD_M_HEADER, RINFO_HEADER];
    identity.iter().filter(move |(name, _)| {
        !excluded
            .iter()
            .chain(OWN_HEADERS.iter())
            .any(|skip| skip.eq_ignore_ascii_case(name))
    })
}

/// Validates and decodes the `otp/1.5/finish` response.
///
/// # Errors
/// Fails on an oversized body, a non-200 status or missing fields.
pub fn parse_finish(status: u16, body: &[u8]) -> StoreAuthResult<StoreFinish> {
    if body.len() > ANISETTE_LIMIT {
        return Err(protocol("read Apple Store provisioning response"));
    }
    if status != HTTP_OK {
        return Err(protocol(format!(
            "apple Store provisioning returned HTTP {status}"
        )));
    }
    let result = plist::from_bytes::<plist::Dictionary>(body)
        .map_err(|_| protocol("decode Apple Store provisioning response"))?;
    Ok(StoreFinish {
        setting_info: decoded_value(&result, "settingInfo")?,
        transport_key: decoded_value(&result, "transportKey")?,
        key_bag: key_bag(&result),
    })
}

fn decoded_value(result: &plist::Dictionary, key: &str) -> StoreAuthResult<Vec<u8>> {
    let value = result
        .get(key)
        .and_then(plist::Value::as_string)
        .filter(|value| header_value(value, ANISETTE_LIMIT))
        .ok_or_else(|| {
            protocol(format!(
                "apple Store provisioning response is missing {key}"
            ))
        })?;
    decode_base64(value).ok_or_else(|| protocol(format!("decode Apple Store provisioning {key}")))
}

/// `keybag` as data, or as base64 text; invalid encodings yield no keybag
/// (Go ignores the decode error).
fn key_bag(result: &plist::Dictionary) -> Vec<u8> {
    match result.get("keybag") {
        Some(plist::Value::Data(data)) if data.len() <= ANISETTE_LIMIT => data.clone(),
        Some(plist::Value::String(text)) => decode_base64(text).unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_bytes, header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn response(keybag: Option<plist::Value>) -> Vec<u8> {
        let mut result = plist::Dictionary::new();
        result.insert("settingInfo".into(), plist::Value::String("AQID".into()));
        result.insert("transportKey".into(), plist::Value::String("BAU=".into()));
        if let Some(keybag) = keybag {
            result.insert("keybag".into(), keybag);
        }
        let mut body = Vec::new();
        plist::to_writer_xml(&mut body, &plist::Value::Dictionary(result)).unwrap();
        body
    }

    #[test]
    fn body_matches_go_plist_output() {
        let body = String::from_utf8(finish_body(&[1, 2, 3], "a2I=")).unwrap();
        assert!(body.ends_with(
            "<plist version=\"1.0\"><dict><key>clientData</key><string>AQID</string>\
             <key>kbsync</key><string>a2I=</string></dict></plist>"
        ));
        let without = String::from_utf8(finish_body(&[1], "")).unwrap();
        assert!(!without.contains("kbsync"));
    }

    #[test]
    fn parses_keybag_as_data_or_base64() {
        let data = parse_finish(200, &response(Some(plist::Value::Data(vec![9, 8])))).unwrap();
        assert_eq!(data.setting_info, vec![1, 2, 3]);
        assert_eq!(data.transport_key, vec![4, 5]);
        assert_eq!(data.key_bag, vec![9, 8]);
        let text = parse_finish(200, &response(Some(plist::Value::String("CQg=".into())))).unwrap();
        assert_eq!(text.key_bag, vec![9, 8]);
        assert_eq!(
            parse_finish(200, &response(None)).unwrap().key_bag,
            [] as [u8; 0]
        );
    }

    #[test]
    fn rejects_failures_and_missing_fields() {
        assert!(parse_finish(403, &response(None)).is_err());
        assert!(parse_finish(200, b"<plist").is_err());
        let mut body = Vec::new();
        plist::to_writer_xml(
            &mut body,
            &plist::Value::Dictionary(plist::Dictionary::new()),
        )
        .unwrap();
        assert!(parse_finish(200, &body).is_err());
        assert!(decode_challenge(" AQID \n").is_ok());
        assert!(decode_challenge("!").is_err());
    }

    #[tokio::test]
    async fn sends_identity_without_machine_proof() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("X-Apple-I-MD-LU", "lu"))
            .and(header("User-Agent", "ua"))
            .and(header("Content-Type", "application/x-apple-plist"))
            .and(body_bytes(finish_body(&[7], "kb")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(response(None)))
            .expect(1)
            .mount(&server)
            .await;
        let identity = [
            ("X-Apple-I-MD".to_owned(), "otp".to_owned()),
            ("x-apple-i-md-m".to_owned(), "mid".to_owned()),
            ("X-Apple-I-MD-LU".to_owned(), "lu".to_owned()),
            ("User-Agent".to_owned(), "other".to_owned()),
        ];
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let request = StoreProvisioningRequest {
            client: &client,
            challenge: "",
            endpoint: &server.uri(),
            user_agent: "ua",
            kbsync: "kb",
            hardware_id: &[2, 0, 0, 0, 0, 1],
            identity: &identity,
        };
        finish_store(&request, &[7]).await.unwrap();
        let received = &server.received_requests().await.unwrap()[0];
        assert!(received.headers.get("X-Apple-I-MD").is_none());
        assert!(received.headers.get("X-Apple-I-MD-M").is_none());
        assert_eq!(received.headers.get_all("User-Agent").iter().count(), 1);
    }
}
