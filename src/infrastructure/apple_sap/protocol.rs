//! HTTP side of the `FairPlay` SAP handshake with Apple's `sign-sap-setup`
//! endpoints.
//!
//! Port of upstream ipatool's `internal/sap/protocol.go`. Requests and
//! responses are plain values so the handshake can run over any
//! [`SetupTransport`], including a recorded replay.

use std::future::Future;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use thiserror::Error;

use crate::infrastructure::http::telemetry::{read_response_bytes, send_with_observability};

/// Plist key of the setup certificate in the bag's certificate document.
pub const SETUP_CERTIFICATE_KEY: &str = "sign-sap-setup-cert";
/// Plist key of the setup message in both directions.
pub const SETUP_BUFFER_KEY: &str = "sign-sap-setup-buffer";
/// Largest response body accepted from Apple.
pub const MAX_SETUP_BODY: usize = 1 << 20;
/// User agent Apple Configurator sends to the SAP endpoints.
pub const SETUP_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
const PLIST_CONTENT_TYPE: &str = "application/x-plist";
const HTTP_OK: u16 = 200;
const XML_PLIST_HEADER: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
);

/// Failure of the SAP setup protocol.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The request could not be sent or its response not read.
    #[error("send SAP request: {0}")]
    Transport(String),
    /// Apple answered with a non-200 status.
    #[error("apple returned HTTP {0}")]
    Status(u16),
    /// The response body exceeds [`MAX_SETUP_BODY`].
    #[error("apple response exceeds {MAX_SETUP_BODY} bytes")]
    TooLarge,
    /// The response is not a property list.
    #[error("decode Apple plist: {0}")]
    Plist(#[from] plist::Error),
    /// The property list lacks a non-empty data value for the key.
    #[error("Apple plist is missing {0}")]
    MissingKey(&'static str),
}

/// HTTP method of a setup request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One HTTP request of the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupRequest {
    /// Request method.
    pub method: SetupMethod,
    /// Absolute HTTPS URL.
    pub url: String,
    /// Header names and values, in send order.
    pub headers: Vec<(&'static str, String)>,
    /// Request body (empty for `GET`).
    pub body: Vec<u8>,
}

/// Apple's answer to a [`SetupRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
}

/// Sends setup requests; implemented over `reqwest` and by test replays.
pub trait SetupTransport {
    /// Sends `request` and returns the full response.
    fn send(
        &self,
        request: SetupRequest,
    ) -> impl Future<Output = Result<SetupResponse, ProtocolError>>;
}

/// [`SetupTransport`] over a `reqwest` client.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Wraps `client`.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

impl SetupTransport for ReqwestTransport {
    async fn send(&self, request: SetupRequest) -> Result<SetupResponse, ProtocolError> {
        let transport = |error: reqwest::Error| ProtocolError::Transport(error.to_string());
        let mut builder = match request.method {
            SetupMethod::Get => self.client.get(&request.url),
            SetupMethod::Post => self.client.post(&request.url).body(request.body),
        };
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        let sent = send_with_observability(&self.client, builder).await;
        let response = sent.map_err(transport)?;
        let status = response.status().as_u16();
        let body = read_response_bytes(response).await.map_err(transport)?;
        Ok(SetupResponse { status, body })
    }
}

/// Builds the `GET` for the setup certificate document.
pub fn certificate_request(url: &str) -> SetupRequest {
    SetupRequest {
        method: SetupMethod::Get,
        url: url.to_owned(),
        headers: vec![("User-Agent", SETUP_USER_AGENT.to_owned())],
        body: Vec::new(),
    }
}

/// Builds the `POST` carrying a setup message.
pub fn exchange_request(url: &str, message: &[u8]) -> SetupRequest {
    SetupRequest {
        method: SetupMethod::Post,
        url: url.to_owned(),
        headers: vec![
            ("Content-Type", PLIST_CONTENT_TYPE.to_owned()),
            ("User-Agent", SETUP_USER_AGENT.to_owned()),
        ],
        body: setup_envelope(message),
    }
}

/// Encodes `{sign-sap-setup-buffer: message}` as the compact XML plist
/// upstream sends.
pub fn setup_envelope(message: &[u8]) -> Vec<u8> {
    format!(
        "{XML_PLIST_HEADER}<plist version=\"1.0\"><dict><key>{SETUP_BUFFER_KEY}</key>\
         <data>{}</data></dict></plist>",
        STANDARD.encode(message)
    )
    .into_bytes()
}

/// Extracts the data value at `key` from a successful response.
///
/// # Errors
/// Fails on a non-200 status, an oversized body, an invalid plist or a
/// missing/empty value.
pub fn response_data(
    response: &SetupResponse,
    key: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    if response.status != HTTP_OK {
        return Err(ProtocolError::Status(response.status));
    }
    if response.body.len() > MAX_SETUP_BODY {
        return Err(ProtocolError::TooLarge);
    }
    let document: plist::Dictionary = plist::from_bytes(&response.body)?;
    match document.get(key).and_then(plist::Value::as_data) {
        Some(data) if !data.is_empty() => Ok(data.to_vec()),
        _ => Err(ProtocolError::MissingKey(key)),
    }
}

/// Downloads the setup certificate.
///
/// # Errors
/// See [`response_data`]; transport failures are propagated.
pub async fn fetch_certificate(
    transport: &impl SetupTransport,
    url: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let response = transport.send(certificate_request(url)).await?;
    response_data(&response, SETUP_CERTIFICATE_KEY)
}

/// Posts a setup message and returns Apple's reply message.
///
/// # Errors
/// See [`response_data`]; transport failures are propagated.
pub async fn exchange_setup(
    transport: &impl SetupTransport,
    url: &str,
    message: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let response = transport.send(exchange_request(url, message)).await?;
    response_data(&response, SETUP_BUFFER_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;

    fn golden() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apple_sap/golden/sap.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn hex_at(value: &serde_json::Value, pointer: &str) -> Vec<u8> {
        hex::decode(value.pointer(pointer).unwrap().as_str().unwrap()).unwrap()
    }

    fn ok(body: Vec<u8>) -> SetupResponse {
        SetupResponse {
            status: HTTP_OK,
            body,
        }
    }

    #[test]
    fn envelope_matches_upstream_bytes() {
        let golden = golden();
        let request = exchange_request(
            golden["setup_url"].as_str().unwrap(),
            &hex_at(&golden, "/exchange1_output_hex"),
        );
        assert_eq!(
            request.body,
            hex_at(&golden, "/setup_http/request_body_hex")
        );
        assert_eq!(request.method, SetupMethod::Post);
        assert_eq!(
            request.headers,
            vec![
                ("Content-Type", "application/x-plist".to_owned()),
                ("User-Agent", SETUP_USER_AGENT.to_owned()),
            ]
        );
    }

    #[test]
    fn recorded_responses_decode_to_recorded_messages() {
        let golden = golden();
        let certificate = ok(hex_at(&golden, "/certificate_http/response_body_hex"));
        assert_eq!(
            response_data(&certificate, SETUP_CERTIFICATE_KEY).unwrap(),
            hex_at(&golden, "/certificate_hex")
        );
        let reply = ok(hex_at(&golden, "/setup_http/response_body_hex"));
        assert_eq!(
            response_data(&reply, SETUP_BUFFER_KEY).unwrap(),
            hex_at(&golden, "/exchange2_input_hex")
        );
        let request = certificate_request(golden["certificate_url"].as_str().unwrap());
        assert_eq!(
            request.headers,
            vec![("User-Agent", SETUP_USER_AGENT.to_owned())]
        );
    }

    #[test]
    fn rejects_bad_status_size_and_missing_key() {
        let failed = SetupResponse {
            status: 500,
            body: Vec::new(),
        };
        assert!(matches!(
            response_data(&failed, SETUP_BUFFER_KEY),
            Err(ProtocolError::Status(500))
        ));
        let huge = ok(vec![b' '; MAX_SETUP_BODY + 1]);
        assert!(matches!(
            response_data(&huge, SETUP_BUFFER_KEY),
            Err(ProtocolError::TooLarge)
        ));
        let empty = ok(setup_envelope(b"x"));
        assert!(matches!(
            response_data(&empty, SETUP_CERTIFICATE_KEY),
            Err(ProtocolError::MissingKey(SETUP_CERTIFICATE_KEY))
        ));
        assert!(response_data(&ok(b"nope".to_vec()), SETUP_BUFFER_KEY).is_err());
    }

    fn data_plist(key: &str, data: &[u8]) -> Vec<u8> {
        format!(
            "{XML_PLIST_HEADER}<plist version=\"1.0\"><dict><key>{key}</key>\
             <data>{}</data></dict></plist>",
            STANDARD.encode(data)
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn reqwest_transport_fetches_certificate_and_exchanges_setup() {
        use wiremock::matchers::{body_bytes, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cert"))
            .and(header("User-Agent", SETUP_USER_AGENT))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(data_plist(SETUP_CERTIFICATE_KEY, b"cert")),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/setup"))
            .and(header("Content-Type", PLIST_CONTENT_TYPE))
            .and(body_bytes(setup_envelope(b"hello")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(data_plist(SETUP_BUFFER_KEY, b"reply")),
            )
            .mount(&server)
            .await;
        let transport = ReqwestTransport::new(reqwest::Client::new());
        let capture = LogCapture::default();
        let guard = capture.install();

        let certificate = fetch_certificate(&transport, &format!("{}/cert", server.uri()))
            .await
            .unwrap();
        let reply = exchange_setup(&transport, &format!("{}/setup", server.uri()), b"hello")
            .await
            .unwrap();

        drop(guard);
        assert_eq!(certificate, b"cert");
        assert_eq!(reply, b"reply");
        let logs = capture.contents();
        assert!(logs.contains("http.response.headers_received"), "{logs}");
        assert!(logs.contains("http.response.body_read"));
        for secret in [
            "/cert",
            "/setup",
            "Y2VydA==",
            "cmVwbHk=",
            "aGVsbG8=",
            SETUP_BUFFER_KEY,
        ] {
            assert!(!logs.contains(secret), "{secret} leaked: {logs}");
        }
    }

    #[tokio::test]
    async fn reqwest_transport_reports_connection_failures() {
        let transport = ReqwestTransport::new(reqwest::Client::new());

        let error = fetch_certificate(&transport, "http://127.0.0.1:1/cert")
            .await
            .unwrap_err();

        assert!(matches!(error, ProtocolError::Transport(_)));
    }
}
