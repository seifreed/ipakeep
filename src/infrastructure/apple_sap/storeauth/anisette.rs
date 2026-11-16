//! GSA `MidService` machine provisioning and the anisette header set.
//!
//! Port of upstream ipatool's `internal/storeauth/anisette.go`: the wire
//! format of `startMachineProvisioning` / `finishMachineProvisioning` and the
//! headers `AnisetteHeaders` returns.

use std::collections::HashMap;
use std::time::SystemTime;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::error::{StoreAuthError, StoreAuthResult};
use super::state::AnisetteState;
use super::xml::{XmlValue, document};
use crate::infrastructure::apple_sap::machine::modern_adi::AdiOtp;
use crate::infrastructure::http::telemetry::send_with_observability;

/// Largest accepted response body and decoded field (Go `anisetteLimit`).
pub const ANISETTE_LIMIT: usize = 1 << 20;
/// GSA endpoint that issues the server provisioning message (`spim`).
pub const MACHINE_START_URL: &str =
    "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning";
/// GSA endpoint that accepts the client message (`cpim`).
pub const MACHINE_FINISH_URL: &str =
    "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning";
/// `X-MMe-Client-Info` of the emulated `akd`.
pub const ANISETTE_CLIENT_INFO: &str =
    "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
/// `User-Agent` of the emulated `akd`.
pub const ANISETTE_USER_AGENT: &str = "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0";
/// What upstream sends as `X-Apple-I-TimeZone`: Go's `time.Local.String()`.
pub const LOCAL_TIME_ZONE: &str = "Local";
/// Header carrying the one-time password.
pub const MD_HEADER: &str = "X-Apple-I-MD";
/// Header carrying the machine identifier.
pub const MD_M_HEADER: &str = "X-Apple-I-MD-M";
/// Header carrying the GSA routing information.
pub const RINFO_HEADER: &str = "X-Apple-I-MD-RINFO";
const LU_HEADER: &str = "X-Apple-I-MD-LU";
const DEVICE_ID_HEADER: &str = "X-Mme-Device-Id";
const CLIENT_INFO_HEADER: &str = "X-MMe-Client-Info";
const LOCALE: &str = "en_US";
const SERIAL_NUMBER: &str = "0";
const MAX_PROVISIONING_STRING: usize = 32_768;
const RESPONSE_KEY: &str = "Response";
const HTTP_OK: u16 = 200;
/// Byte offsets splitting the 32 hex digits of the identifier into a UUID.
const UUID_GROUPS: [usize; 4] = [8, 12, 16, 20];

/// Anisette headers in upstream's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnisetteHeaders {
    entries: Vec<(&'static str, String)>,
}

impl AnisetteHeaders {
    /// All `(name, value)` pairs.
    #[must_use]
    pub fn entries(&self) -> &[(&'static str, String)] {
        &self.entries
    }

    /// The value of header `name` (ASCII case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The headers as an owned map (the shape `grandslam` consumes).
    #[must_use]
    pub fn to_map(&self) -> HashMap<String, String> {
        self.entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    /// The device identity without the machine proof (`X-Apple-I-MD`,
    /// `-M`, `-RINFO`): what the Store "RP" retry and "SP" request send.
    #[must_use]
    pub fn identity(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|(key, _)| ![MD_HEADER, MD_M_HEADER, RINFO_HEADER].contains(key))
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }
}

/// `X-Apple-I-MD-LU` (hex SHA-256 of the identifier) and `X-Mme-Device-Id`
/// (the identifier formatted as a lowercase UUID).
#[must_use]
pub fn identity_headers(identifier: &[u8]) -> (String, String) {
    let local_user = hex::encode(Sha256::digest(identifier));
    let encoded = hex::encode(identifier);
    let mut device = String::with_capacity(encoded.len() + UUID_GROUPS.len());
    for (index, character) in encoded.chars().enumerate() {
        if UUID_GROUPS.contains(&index) {
            device.push('-');
        }
        device.push(character);
    }
    (local_user, device)
}

/// Builds upstream's header set (`anisette.go` `anisetteHeaders`).
#[must_use]
pub fn build_headers(
    state: &AnisetteState,
    otp: &AdiOtp,
    now: SystemTime,
    time_zone: &str,
) -> AnisetteHeaders {
    let (local_user, device) = identity_headers(&state.identifier);
    let entries = vec![
        ("X-Apple-I-Client-Time", client_time(now)),
        (MD_HEADER, STANDARD.encode(&otp.otp)),
        (MD_M_HEADER, STANDARD.encode(&otp.mid)),
        (RINFO_HEADER, state.routing_info.to_string()),
        (LU_HEADER, local_user),
        ("X-Apple-I-SRL-NO", SERIAL_NUMBER.to_owned()),
        ("X-Apple-I-TimeZone", time_zone.to_owned()),
        ("X-Apple-Locale", LOCALE.to_owned()),
        (DEVICE_ID_HEADER, device),
        (CLIENT_INFO_HEADER, ANISETTE_CLIENT_INFO.to_owned()),
    ];
    AnisetteHeaders { entries }
}

/// Go layout `2006-01-02T15:04:05Z` in UTC.
fn client_time(now: SystemTime) -> String {
    let time = time::OffsetDateTime::from(now);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

/// The two `MidService` endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GsaEndpoints {
    /// `startMachineProvisioning`.
    pub start: String,
    /// `finishMachineProvisioning`.
    pub finish: String,
}

impl Default for GsaEndpoints {
    fn default() -> Self {
        Self {
            start: MACHINE_START_URL.to_owned(),
            finish: MACHINE_FINISH_URL.to_owned(),
        }
    }
}

/// What `finishMachineProvisioning` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineFinish {
    /// `ptm`: provisioning setting info.
    pub setting_info: Vec<u8>,
    /// `tk`: transport key.
    pub transport_key: Vec<u8>,
    /// `X-Apple-I-MD-RINFO`.
    pub routing_info: u64,
}

/// The `startMachineProvisioning` body (empty request dictionary).
#[must_use]
pub fn start_body() -> Vec<u8> {
    envelope(Vec::new())
}

/// The `finishMachineProvisioning` body carrying base64 `cpim`.
#[must_use]
pub fn finish_body(cpim: &[u8]) -> Vec<u8> {
    let cpim = STANDARD.encode(cpim);
    envelope(vec![("cpim", XmlValue::String(&cpim))])
}

fn envelope(request: Vec<(&str, XmlValue<'_>)>) -> Vec<u8> {
    document(&XmlValue::Dict(vec![
        ("Header", XmlValue::Dict(Vec::new())),
        ("Request", XmlValue::Dict(request)),
    ]))
}

/// Requests the server provisioning message for `identifier`.
///
/// # Errors
/// Fails on transport errors, a non-200 status or a malformed response.
pub async fn start_machine(
    client: &reqwest::Client,
    endpoints: &GsaEndpoints,
    identifier: &[u8],
) -> StoreAuthResult<Vec<u8>> {
    let response = send(client, &endpoints.start, identifier, start_body()).await?;
    decode_field(&response, "spim")
}

/// Sends `cpim` and returns the provisioning material.
///
/// # Errors
/// Fails on transport errors, a non-200 status or a malformed response.
pub async fn finish_machine(
    client: &reqwest::Client,
    endpoints: &GsaEndpoints,
    identifier: &[u8],
    cpim: &[u8],
) -> StoreAuthResult<MachineFinish> {
    let response = send(client, &endpoints.finish, identifier, finish_body(cpim)).await?;
    parse_finish(&response)
}

/// Extracts `ptm`, `tk` and a nonzero routing information.
///
/// # Errors
/// Fails when a field is missing or malformed.
pub fn parse_finish(response: &plist::Dictionary) -> StoreAuthResult<MachineFinish> {
    let setting_info = decode_field(response, "ptm")?;
    let transport_key = decode_field(response, "tk")?;
    let routing_info = provisioning_string(response, RINFO_HEADER)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| protocol("decode anisette routing information"))?;
    Ok(MachineFinish {
        setting_info,
        transport_key,
        routing_info,
    })
}

async fn send(
    client: &reqwest::Client,
    url: &str,
    identifier: &[u8],
    body: Vec<u8>,
) -> StoreAuthResult<plist::Dictionary> {
    let (local_user, device) = identity_headers(identifier);
    let request = client
        .post(url)
        .header("Accept", "*/*")
        .header("Connection", "close")
        .header("Content-Type", "text/x-xml-plist")
        .header("User-Agent", ANISETTE_USER_AGENT)
        .header(LU_HEADER, local_user)
        .header(CLIENT_INFO_HEADER, ANISETTE_CLIENT_INFO)
        .header(DEVICE_ID_HEADER, device)
        .body(body);
    let sent = send_with_observability(client, request).await;
    let response = sent.map_err(http("send anisette provisioning request"))?;
    let status = response.status().as_u16();
    let body = read_limited(response, "read anisette provisioning response").await?;
    parse_response(status, &body)
}

/// Reads at most [`ANISETTE_LIMIT`] + 1 bytes of `response`.
pub(super) async fn read_limited(
    mut response: reqwest::Response,
    context: &'static str,
) -> StoreAuthResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http(context))? {
        body.extend_from_slice(&chunk);
        if body.len() > ANISETTE_LIMIT {
            break;
        }
    }
    Ok(body)
}

/// Validates the status and size and unwraps `Response`.
///
/// # Errors
/// Fails on a non-200 status, an oversized body or a malformed plist.
pub fn parse_response(status: u16, body: &[u8]) -> StoreAuthResult<plist::Dictionary> {
    if status != HTTP_OK || body.len() > ANISETTE_LIMIT {
        return Err(protocol(format!(
            "anisette provisioning returned HTTP {status}"
        )));
    }
    plist::from_bytes::<plist::Dictionary>(body)
        .ok()
        .and_then(|mut envelope| envelope.remove(RESPONSE_KEY))
        .and_then(plist::Value::into_dictionary)
        .ok_or_else(|| protocol("decode anisette provisioning response"))
}

fn provisioning_string<'a>(values: &'a plist::Dictionary, key: &str) -> StoreAuthResult<&'a str> {
    values
        .get(key)
        .and_then(plist::Value::as_string)
        .filter(|value| header_value(value, MAX_PROVISIONING_STRING))
        .ok_or_else(|| protocol(format!("missing anisette {key}")))
}

fn decode_field(values: &plist::Dictionary, key: &str) -> StoreAuthResult<Vec<u8>> {
    decode_base64(provisioning_string(values, key)?)
        .ok_or_else(|| protocol(format!("decode anisette {key}")))
}

/// Non-empty base64 decoding to at most [`ANISETTE_LIMIT`] bytes.
pub(super) fn decode_base64(value: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(value)
        .ok()
        .filter(|decoded| !decoded.is_empty() && decoded.len() <= ANISETTE_LIMIT)
}

/// Go `headerValue`: non-empty printable ASCII of at most `limit` bytes.
pub(super) fn header_value(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

pub(super) fn protocol(message: impl Into<String>) -> StoreAuthError {
    StoreAuthError::Protocol(message.into())
}

pub(super) fn http(context: &'static str) -> impl FnOnce(reqwest::Error) -> StoreAuthError {
    move |source| StoreAuthError::Http { context, source }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{golden, hex_at, local_endpoints, recorded_gsa};
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use std::time::{Duration, UNIX_EPOCH};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const FIXED_UNIX_TIME: u64 = 1_794_744_000;

    fn golden_state(golden: &serde_json::Value) -> AnisetteState {
        AnisetteState::decode(&serde_json::to_vec(&golden["anisette_state_json"]).unwrap()).unwrap()
    }

    #[test]
    fn builds_the_golden_header_set_byte_for_byte() {
        let golden = golden();
        let otp = AdiOtp {
            mid: hex_at(&golden, "/request_otp/mid_hex"),
            otp: hex_at(&golden, "/request_otp/otp_hex"),
        };
        let now = UNIX_EPOCH + Duration::from_secs(FIXED_UNIX_TIME);
        let headers = build_headers(&golden_state(&golden), &otp, now, "UTC");
        let expected: HashMap<String, String> =
            serde_json::from_value(golden["anisette_headers"].clone()).unwrap();
        assert_eq!(headers.to_map(), expected);
        assert_eq!(
            headers.get("x-apple-i-md-m"),
            expected.get(MD_M_HEADER).map(String::as_str)
        );
    }

    #[test]
    fn identity_drops_only_the_machine_proof() {
        let golden = golden();
        let otp = AdiOtp {
            mid: vec![1],
            otp: vec![2],
        };
        let headers = build_headers(&golden_state(&golden), &otp, UNIX_EPOCH, LOCAL_TIME_ZONE);
        let identity = headers.identity();
        assert_eq!(identity.len(), headers.entries().len() - 3);
        assert!(
            identity
                .iter()
                .all(|(key, _)| !key.starts_with("X-Apple-I-MD") || key == LU_HEADER)
        );
        assert!(identity.contains(&("X-Apple-I-TimeZone".to_owned(), "Local".to_owned())));
    }

    #[test]
    fn identity_is_the_store_provisioning_header_set() {
        let otp = AdiOtp {
            mid: vec![1],
            otp: vec![2],
        };
        let headers = build_headers(
            &AnisetteState::new([0; 16]),
            &otp,
            UNIX_EPOCH,
            LOCAL_TIME_ZONE,
        );
        let mut names: Vec<String> = headers
            .identity()
            .into_iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "x-apple-i-client-time",
                "x-apple-i-md-lu",
                "x-apple-i-srl-no",
                "x-apple-i-timezone",
                "x-apple-locale",
                "x-mme-client-info",
                "x-mme-device-id",
            ]
        );
    }

    #[test]
    fn identity_headers_match_upstream_test() {
        let identifier: Vec<u8> = (0..16).collect();
        let (_, device) = identity_headers(&identifier);
        assert_eq!(device, "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn request_bodies_match_the_recorded_exchanges() {
        let golden = golden();
        assert_eq!(
            start_body(),
            hex_at(&golden, "/gsa_start_http/request_body_hex")
        );
        let cpim = hex_at(&golden, "/start_provisioning/cpim_hex");
        assert_eq!(
            finish_body(&cpim),
            hex_at(&golden, "/gsa_finish_http/request_body_hex")
        );
    }

    #[test]
    fn parses_the_recorded_responses() {
        let golden = golden();
        let start =
            parse_response(200, &hex_at(&golden, "/gsa_start_http/response_body_hex")).unwrap();
        assert_eq!(
            decode_field(&start, "spim").unwrap(),
            hex_at(&golden, "/start_provisioning/spim_hex")
        );
        let finish =
            parse_response(200, &hex_at(&golden, "/gsa_finish_http/response_body_hex")).unwrap();
        let finish = parse_finish(&finish).unwrap();
        assert_eq!(
            finish.setting_info,
            hex_at(&golden, "/end_provisioning/ptm_hex")
        );
        assert_eq!(
            finish.transport_key,
            hex_at(&golden, "/end_provisioning/tk_hex")
        );
        assert_eq!(finish.routing_info, 84_215_040);
    }

    #[test]
    fn rejects_bad_responses() {
        assert!(parse_response(500, b"").is_err());
        assert!(parse_response(200, b"garbage").is_err());
        let mut response = plist::Dictionary::new();
        response.insert(RINFO_HEADER.into(), plist::Value::String("0".into()));
        response.insert("ptm".into(), plist::Value::String("AQ==".into()));
        response.insert("tk".into(), plist::Value::String("AQ==".into()));
        assert!(parse_finish(&response).is_err());
        response.insert("tk".into(), plist::Value::String("\u{7f}".into()));
        assert!(parse_finish(&response).is_err());
        assert!(!header_value("", 4));
        assert!(!header_value("abcde", 4));
    }

    #[tokio::test]
    async fn replays_the_recorded_gsa_exchanges_over_http() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let golden = golden();
        let server = recorded_gsa().await;
        let endpoints = local_endpoints(&server);
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let identifier = hex_at(&golden, "/identifier_hex");
        let spim = start_machine(&client, &endpoints, &identifier)
            .await
            .unwrap();
        assert_eq!(spim, hex_at(&golden, "/start_provisioning/spim_hex"));
        let cpim = hex_at(&golden, "/start_provisioning/cpim_hex");
        let finish = finish_machine(&client, &endpoints, &identifier, &cpim)
            .await
            .unwrap();
        assert_eq!(finish.routing_info, 84_215_040);

        let logs = capture.contents();
        assert!(logs.contains("http.response.headers_received"), "{logs}");
        assert!(logs.contains("method=\"POST\""));
        assert!(logs.contains("status=200"));
        let (local_user, device) = identity_headers(&identifier);
        for secret in [
            hex::encode(&identifier),
            local_user,
            device,
            STANDARD.encode(&spim),
            STANDARD.encode(&cpim),
            STANDARD.encode(&finish.setting_info),
            STANDARD.encode(&finish.transport_key),
            "MidService".to_owned(),
        ] {
            assert!(!logs.contains(&secret), "{secret} leaked");
        }
    }

    #[tokio::test]
    async fn read_limited_stops_after_the_limit() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; ANISETTE_LIMIT * 2]))
            .mount(&server)
            .await;
        let response = reqwest::get(server.uri()).await.unwrap();

        let body = read_limited(response, "read test body").await.unwrap();

        assert!(body.len() > ANISETTE_LIMIT);
    }

    #[tokio::test]
    async fn surfaces_http_failures() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let error = start_machine(
            &crate::infrastructure::http::client_builder()
                .build()
                .expect("HTTP client"),
            &local_endpoints(&server),
            &[0; 16],
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 503"), "{error}");
    }
}
