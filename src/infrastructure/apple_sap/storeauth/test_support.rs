//! Recorded GSA exchanges shared by the Store authentication tests.

use std::path::PathBuf;

use wiremock::matchers::{body_bytes, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::anisette::GsaEndpoints;

/// `tests/fixtures/apple_sap/golden/adi.json`.
pub(super) fn golden() -> serde_json::Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/apple_sap/golden/adi.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Decodes the hex string at JSON `pointer`.
pub(super) fn hex_at(value: &serde_json::Value, pointer: &str) -> Vec<u8> {
    hex::decode(value.pointer(pointer).unwrap().as_str().unwrap()).unwrap()
}

async fn mount_recorded(server: &MockServer, golden: &serde_json::Value, key: &str) {
    let exchange = &golden[key];
    let url = reqwest::Url::parse(exchange["url"].as_str().unwrap()).unwrap();
    let mut mock = Mock::given(method("POST")).and(path(url.path()));
    for (name, value) in exchange["request_headers"].as_object().unwrap() {
        mock = mock.and(exact_header(
            name.clone(),
            value.as_str().unwrap().to_owned(),
        ));
    }
    mock.and(body_bytes(hex_at(
        golden,
        &format!("/{key}/request_body_hex"),
    )))
    .respond_with(
        ResponseTemplate::new(200)
            .set_body_bytes(hex_at(golden, &format!("/{key}/response_body_hex"))),
    )
    .expect(1)
    .mount(server)
    .await;
}

/// Matches one header value verbatim (wiremock's `header` splits on commas,
/// which `X-MMe-Client-Info` contains).
fn exact_header(name: String, value: String) -> impl Fn(&wiremock::Request) -> bool {
    move |request| {
        let values: Vec<_> = request.headers.get_all(name.as_str()).iter().collect();
        values.len() == 1 && values[0].as_bytes() == value.as_bytes()
    }
}

/// `/grandslam/MidService/...` endpoints served by `server`.
pub(super) fn local_endpoints(server: &MockServer) -> GsaEndpoints {
    GsaEndpoints {
        start: format!(
            "{}/grandslam/MidService/startMachineProvisioning",
            server.uri()
        ),
        finish: format!(
            "{}/grandslam/MidService/finishMachineProvisioning",
            server.uri()
        ),
    }
}

/// Serves the recorded GSA exchanges once each, matching headers and bodies
/// exactly.
pub(super) async fn recorded_gsa() -> MockServer {
    let golden = golden();
    let server = MockServer::start().await;
    mount_recorded(&server, &golden, "gsa_start_http").await;
    mount_recorded(&server, &golden, "gsa_finish_http").await;
    server
}
