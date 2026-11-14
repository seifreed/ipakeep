use super::parsing::{external_version_ids, parse_download_item};
use super::*;
use crate::domain::entity::test_support::test_account;
use crate::domain::repository::{DownloadRepository, PurchaseRepository, VersionRepository};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn commerce_download_sends_version_and_list_versions_skips_missing_ids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "songList": [{
                "URL": "https://example.test/app.ipa",
                "metadata": {"bundleShortVersionString": "1.2"}
            }]
        })))
        .expect(2)
        .mount(&server)
        .await;

    let config = AppleApiConfig {
        store_base_url: server.uri(),
        signed_store_login: false,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);
    let mut account = test_account();
    account.pod.clear();

    let items = repository
        .download(&account, 42, "guid", Some("9001".into()))
        .await
        .expect("download items");
    assert_eq!(items.len(), 1);
    assert!(
        repository
            .list_versions(&account, 42, "guid")
            .await
            .expect("versions")
            .is_empty()
    );

    let requests = server.received_requests().await.expect("requests");
    let first_body = String::from_utf8_lossy(&requests[0].body);
    let second_body = String::from_utf8_lossy(&requests[1].body);
    assert!(first_body.contains("externalVersionId"));
    assert!(first_body.contains("9001"));
    assert!(!second_body.contains("externalVersionId"));
}

#[tokio::test]
async fn commerce_list_versions_expands_external_version_ids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "songList": [{
                "URL": "https://example.test/app.ipa",
                "metadata": {
                    "bundleShortVersionString": "1.2",
                    "softwareVersionExternalIdentifiers": "9001, 9002"
                }
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = AppleApiConfig {
        store_base_url: server.uri(),
        signed_store_login: false,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);
    let mut account = test_account();
    account.pod.clear();

    let versions = repository
        .list_versions(&account, 42, "guid")
        .await
        .expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].external_version_id, "9001");
    assert_eq!(versions[0].version_string, "1.2");
    assert_eq!(versions[1].external_version_id, "9002");
    assert_eq!(versions[1].version_string, "1.2");
}

#[tokio::test]
async fn commerce_download_propagates_store_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "failureType": "503",
            "customerMessage": "try later"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let config = AppleApiConfig {
        store_base_url: server.uri(),
        signed_store_login: false,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);
    let mut account = test_account();
    account.pod.clear();

    assert!(matches!(
        repository.download(&account, 42, "guid", None).await,
        Err(AppStoreError::DownloadFailed(message)) if message == "try later"
    ));
}

#[tokio::test]
async fn commerce_purchase_reports_storefront_mismatch_without_failure_type() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/WebObjects/MZFinance.woa/wa/buyProduct"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-set-apple-store-front", "143441-7,28")
                .set_body_json(serde_json::json!({"customerMessage": "not eligible"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = AppleApiConfig {
        store_base_url: server.uri(),
        signed_store_login: false,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);
    let mut account = test_account();
    account.pod.clear();

    let error = repository
        .purchase(&account, 42, "guid")
        .await
        .expect_err("purchase should be rejected");
    assert!(matches!(error, AppStoreError::PurchaseFailed(message)
        if message.contains("not eligible")
            && message.contains("store front sent: 143441-2,26")
            && message.contains("Apple expects: 143441-7,28")));
}

#[tokio::test]
async fn repository_search_uses_configured_http_endpoint() {
    let body = r#"{"results":[{"trackId":42,"bundleId":"com.example.app","trackName":"Example","version":"1.0","price":0}]}"#;
    let (url, server) = serve_json_once(body);
    let config = AppleApiConfig {
        itunes_search_url: url,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);

    let apps = repository.search("ipakeep", "us", 3).await.expect("search");
    assert_eq!(apps[0].bundle_id, "com.example.app");
    assert_eq!(apps[0].name, "Example");
    let request = server.join().expect("server thread");
    assert!(request.starts_with("GET /?"));
    assert!(request.contains("term=ipakeep"));
    assert!(request.contains("country=us"));
}

fn serve_json_once(body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local server");
    let address = listener.local_addr().expect("local address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("HTTP client connection");
        let request = read_request_headers(&mut stream);
        write_json_response(&mut stream, body);
        request
    });
    (format!("http://{address}"), server)
}

#[test]
fn read_request_headers_stops_when_the_peer_closes_early() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request_headers(&mut stream)
    });
    let client = TcpStream::connect(address).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    assert!(server.join().unwrap().is_empty());
}

fn read_request_headers(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).expect("HTTP request");
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(request).expect("HTTP request headers")
}

fn write_json_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("HTTP response");
}

#[test]
fn parse_app_keeps_result_missing_optional_fields() {
    // Regression: a result with only the identity fields must not be
    // dropped just because price/version/name are absent.
    let item = serde_json::json!({
        "trackId": 42,
        "bundleId": "com.example.app",
    });

    let app = parse_app(&item).expect("app with identity fields should parse");
    assert_eq!(app.id, 42);
    assert_eq!(app.bundle_id, "com.example.app");
    assert_eq!(app.name, "");
    assert_eq!(app.version, "");
    assert!((app.price - 0.0).abs() < f64::EPSILON);
}

#[test]
fn parse_app_rejects_result_missing_identity() {
    assert!(parse_app(&serde_json::json!({ "bundleId": "com.example.app" })).is_none());
    assert!(parse_app(&serde_json::json!({ "trackId": 42 })).is_none());
}

#[test]
fn external_version_ids_parses_csv_array_and_number() {
    assert_eq!(
        external_version_ids(&serde_json::json!("1, 2 ,,3")),
        vec!["1", "2", "3"]
    );
    assert_eq!(
        external_version_ids(&serde_json::json!([10, "20", "", null, {}])),
        vec!["10", "20"]
    );
    assert_eq!(external_version_ids(&serde_json::json!(99)), vec!["99"]);
}

#[test]
fn parse_download_item_defaults_missing_optional_data_and_requires_url() {
    assert!(
        parse_download_item(&serde_json::json!({}))
            .unwrap()
            .is_none()
    );

    let item = parse_download_item(&serde_json::json!({ "URL": "https://example.test/app" }))
        .unwrap()
        .unwrap();
    assert_eq!(item.url, "https://example.test/app");
    assert!(item.md5.is_empty());
    assert!(item.sinfs.is_empty());
    assert!(item.metadata.is_empty());
}

#[test]
fn parse_download_item_filters_invalid_sinfs_and_reports_bad_base64() {
    let item = parse_download_item(&serde_json::json!({
        "URL": "https://example.test/app",
        "sinfs": [
            { "id": "invalid", "sinf": "AQ==" },
            { "id": 7, "sinf": "AQ==" },
            { "id": 8, "sinf": "" },
            { "id": 9, "sinf": 42 }
        ],
        "metadata": { "bundleId": "com.example.app" }
    }))
    .unwrap()
    .unwrap();
    assert_eq!(item.sinfs.len(), 3);
    assert_eq!(item.sinfs[0].data, [1]);
    assert!(item.sinfs[1].data.is_empty());
    assert!(item.sinfs[2].data.is_empty());
    assert_eq!(item.metadata["bundleId"], "com.example.app");

    let error = parse_download_item(&serde_json::json!({
        "URL": "https://example.test/app",
        "sinfs": [{ "id": 7, "sinf": "%%%" }]
    }))
    .unwrap_err();
    assert!(matches!(
        error,
        crate::domain::error::AppStoreError::Unexpected(_)
    ));
}

#[test]
fn pod_from_cookies_extracts_itspod() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::SET_COOKIE,
        "wosid-lite=abc; path=/".parse().unwrap(),
    );
    headers.append(
        reqwest::header::SET_COOKIE,
        "itspod=48; version=\"1\"; path=/; domain=.apple.com"
            .parse()
            .unwrap(),
    );
    assert_eq!(pod_from_cookies(&headers).as_deref(), Some("48"));
}

#[test]
fn pod_from_cookies_none_without_itspod() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::SET_COOKIE,
        "wosid-lite=abc; path=/".parse().unwrap(),
    );
    assert_eq!(pod_from_cookies(&headers), None);
}

#[test]
fn response_is_store_error_detects_failure_and_message() {
    assert!(response_is_store_error(
        &serde_json::json!({ "failureType": "5002" })
    ));
    assert!(response_is_store_error(
        &serde_json::json!({ "customerMessage": "could not be found" })
    ));
    assert!(!response_is_store_error(
        &serde_json::json!({ "jingleDocType": "purchaseSuccess" })
    ));
    assert!(!response_is_store_error(
        &serde_json::json!({ "failureType": "" })
    ));
}

#[test]
fn appstore_query_url_rejects_invalid_base_urls() {
    assert!(matches!(
        appstore_query_url("not a URL", &[]),
        Err(AppStoreError::NetworkError(_))
    ));
}
