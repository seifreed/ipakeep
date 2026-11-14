//! Integration tests for the shared Apple HTTP client.

use ipakeep::domain::error::AppStoreError;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::http::plist_codec::encode_plist;
use std::collections::HashMap;
use wiremock::matchers::{header, method, path};
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
    assert!(!message.contains("results"));
}

#[tokio::test]
async fn requests_report_invalid_url_errors() {
    let client = AppleHttpClient::new().unwrap();

    assert!(matches!(
        client.get_json::<serde_json::Value>("not a URL").await,
        Err(AppStoreError::NetworkError(_))
    ));
    assert!(matches!(
        client.post_form("not a URL", &HashMap::new()).await,
        Err(AppStoreError::NetworkError(_))
    ));
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
    assert!(!message.contains("should-not-be-used"));
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
    assert!(!message.contains("songList"));
}

#[tokio::test]
async fn get_json_with_headers_decodes_the_response_and_checks_conversion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/json"))
        .and(header("x-test", "present"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": 7})))
        .mount(&server)
        .await;
    let client = AppleHttpClient::new().unwrap();
    let headers = HashMap::from([("x-test".into(), "present".into())]);
    let response = client
        .get_json_with_headers::<serde_json::Value>(
            &format!("{}/json", server.uri()),
            Some(&headers),
        )
        .await
        .unwrap();
    assert_eq!(response.body["value"], 7);

    let error = client
        .get_json_with_headers::<u32>(&format!("{}/json", server.uri()), Some(&headers))
        .await
        .err()
        .expect("JSON value cannot convert to u32");
    assert!(error.to_string().contains("response conversion failed"));
}

#[tokio::test]
async fn get_json_and_plist_report_success_body_decode_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/invalid-json"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invalid-plist"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not a plist or JSON"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/invalid-form"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not a plist or JSON"))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    assert!(
        client
            .get_json::<serde_json::Value>(&format!("{}/invalid-json", server.uri()))
            .await
            .err()
            .expect("invalid JSON response")
            .to_string()
            .contains("response decode failed")
    );
    assert!(
        client
            .post_plist_bytes(&format!("{}/invalid-plist", server.uri()), b"request", None)
            .await
            .err()
            .expect("invalid plist response")
            .to_string()
            .contains("plist decode failed")
    );
    assert!(
        client
            .post_form(&format!("{}/invalid-form", server.uri()), &HashMap::new())
            .await
            .err()
            .expect("invalid form response")
            .to_string()
            .contains("response decode failed")
    );
}

#[tokio::test]
async fn form_and_download_requests_forward_custom_headers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/form"))
        .and(header("x-form", "present"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/file"))
        .and(header("x-download", "present"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ipa".to_vec()))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let form_headers = HashMap::from([("x-form".into(), "present".into())]);
    let response = client
        .post_form_with_headers(
            &format!("{}/form", server.uri()),
            &HashMap::from([("term".into(), "app".into())]),
            Some(&form_headers),
        )
        .await
        .unwrap();
    assert_eq!(response.body["ok"], true);

    let download_headers = HashMap::from([("x-download".into(), "present".into())]);
    assert_eq!(
        client
            .download_file(&format!("{}/file", server.uri()), Some(&download_headers))
            .await
            .unwrap(),
        b"ipa"
    );
}

#[tokio::test]
async fn seeded_cookies_are_sent_to_their_origin() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/cookie"))
        .and(header("cookie", "session=value"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    client
        .seed_cookies(&["session=value; Path=/".into()], &server.uri())
        .unwrap();
    assert!(
        client
            .get_json::<serde_json::Value>(&format!("{}/cookie", server.uri()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn auth_plist_preserves_retryable_server_errors_and_empty_204() {
    let server = MockServer::start().await;
    for (route, status) in [("/auth-error", 500), ("/empty", 204)] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_string("not a plist"))
            .mount(&server)
            .await;
    }
    let client = AppleHttpClient::new().unwrap();
    for route in ["/auth-error", "/empty"] {
        let response = client
            .post_auth_plist_bytes(&format!("{}{route}", server.uri()), b"request", None)
            .await
            .unwrap();
        assert!(response.body.is_null());
    }
    assert!(
        client
            .post_plist_bytes(&format!("{}/auth-error", server.uri()), b"request", None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn download_file_returns_raw_bytes_and_status_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/file"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ipa".to_vec()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/file-error"))
        .respond_with(ResponseTemplate::new(404).set_body_string("missing"))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    assert_eq!(
        client
            .download_file(&format!("{}/file", server.uri()), None)
            .await
            .unwrap(),
        b"ipa"
    );
    assert!(
        client
            .download_file(&format!("{}/file-error", server.uri()), None)
            .await
            .unwrap_err()
            .to_string()
            .contains("HTTP 404")
    );
}

#[test]
fn cookie_seeding_rejects_an_invalid_origin_url() {
    let client = AppleHttpClient::new().unwrap();
    assert!(
        client
            .seed_cookies(&["session=value".into()], "not a URL")
            .is_err()
    );
}
