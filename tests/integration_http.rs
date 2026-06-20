//! Integration tests for the shared Apple HTTP client.

use ipakeep::domain::error::AppStoreError;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::http::plist_codec::encode_plist;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_json_rejects_non_success_status_before_decoding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/json-error"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let result = client
        .get_json::<serde_json::Value>(&format!("{}/json-error", server.uri()))
        .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 500"));
    assert!(message.contains("results"));
}

#[tokio::test]
async fn post_form_rejects_non_success_status_before_decoding() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/form-error"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "passwordToken": "should-not-be-used"
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let result = client
        .post_form(&format!("{}/form-error", server.uri()), &HashMap::new())
        .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 401"));
    assert!(message.contains("passwordToken"));
}

#[tokio::test]
async fn post_plist_rejects_non_success_status_before_decoding() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/plist-error"))
        .respond_with(ResponseTemplate::new(503).set_body_raw(
            encode_plist(&serde_json::json!({ "songList": [] })).expect("plist"),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let result = client
        .post_plist(
            &format!("{}/plist-error", server.uri()),
            &serde_json::json!({}),
            None,
        )
        .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 503"));
    assert!(message.contains("songList"));
}
