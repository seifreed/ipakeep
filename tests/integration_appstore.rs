//! Integration tests for `AppleAppStoreRepository` using a local `WireMock` server.

use ipakeep::domain::entity::Account;
use ipakeep::domain::error::AppStoreError;
use ipakeep::domain::repository::AppStoreRepository;
use ipakeep::infrastructure::appstore::{AppleApiConfig, AppleAppStoreRepository};
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::http::plist_codec::encode_plist;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_account() -> Account {
    Account {
        email: "test@example.com".into(),
        name: "Test User".into(),
        password_token: "token123".into(),
        directory_services_id: "dsid123".into(),
        store_front: "143441-2,26".into(),
        pod: String::new(),
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: Vec::new(),
    }
}

fn test_config(server: &MockServer) -> AppleApiConfig {
    AppleApiConfig {
        bag_url: format!("{}/bag.xml", server.uri()),
        itunes_search_url: format!("{}/search", server.uri()),
        itunes_lookup_url: format!("{}/lookup", server.uri()),
        store_base_url: server.uri(),
    }
}

fn repo(client: AppleHttpClient, config: AppleApiConfig) -> AppleAppStoreRepository {
    AppleAppStoreRepository::with_config(client, config)
}

fn plist_body(value: &serde_json::Value) -> Vec<u8> {
    encode_plist(value).expect("encoding plist")
}

#[tokio::test]
async fn search_parses_apps() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [
                {
                    "trackId": 123,
                    "bundleId": "com.example.app",
                    "trackName": "Example App",
                    "version": "1.0",
                    "price": 0.0,
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let apps = app_store.search("example", "us", 5).await.unwrap();

    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].id, 123);
    assert_eq!(apps[0].bundle_id, "com.example.app");
}

#[tokio::test]
async fn search_url_encodes_term_query_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("term", "foo&country=jp=a+b"))
        .and(query_param("country", "us"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let apps = app_store
        .search("foo&country=jp=a+b", "us", 5)
        .await
        .unwrap();

    assert!(apps.is_empty());
}

#[tokio::test]
async fn lookup_returns_some_app() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": [
                {
                    "trackId": 456,
                    "bundleId": "com.test.app",
                    "trackName": "Test App",
                    "version": "2.0",
                    "price": 1.99,
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let app = app_store.lookup("com.test.app", "us").await.unwrap();

    assert!(app.is_some());
    let app = app.unwrap();
    assert_eq!(app.id, 456);
    assert!((app.price - 1.99).abs() < f64::EPSILON);
}

#[tokio::test]
async fn lookup_url_encodes_bundle_id_query_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lookup"))
        .and(query_param("bundleId", "com.example.app&country=jp"))
        .and(query_param("country", "us"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let app = app_store
        .lookup("com.example.app&country=jp", "us")
        .await
        .unwrap();

    assert!(app.is_none());
}

#[tokio::test]
async fn lookup_returns_none() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let app = app_store.lookup("com.missing.app", "us").await.unwrap();

    assert!(app.is_none());
}

#[tokio::test]
async fn purchase_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/WebObjects/MZFinance.woa/wa/buyProduct"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({ "jingleDocType": "purchaseSuccess" })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store.purchase(&test_account(), 123, "guid").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn purchase_already_owned_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/WebObjects/MZFinance.woa/wa/buyProduct"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({ "failureType": "5002" })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store.purchase(&test_account(), 123, "guid").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn purchase_failure_returns_purchase_failed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/WebObjects/MZFinance.woa/wa/buyProduct"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({
                "failureType": "5000",
                "customerMessage": "insufficient funds"
            })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store.purchase(&test_account(), 123, "guid").await;

    assert!(matches!(result, Err(AppStoreError::PurchaseFailed(_))));
}

#[tokio::test]
async fn purchase_without_password_token_fails_before_store_request() {
    let server = MockServer::start().await;
    let mut account = test_account();
    account.password_token.clear();
    account.idms_token = Some("idms".into());
    account.dsid = Some("1234567890".into());
    account.adsid = Some("adsid".into());
    account.grandslam_session_key = Some("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into());
    account.grandslam_continuation = Some("AgICAgICAgICAgICAgICAg==".into());

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store.purchase(&account, 123, "guid").await;

    let Err(AppStoreError::AuthenticationFailed(message)) = result else {
        panic!("expected AuthenticationFailed");
    };
    assert!(message.contains("missing MZFinance passwordToken"));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn download_returns_items() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .and(header("X-Token", "token123"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({
                "songList": [
                    {
                        "URL": "https://example.com/app.ipa",
                        "md5": "abc123",
                        "sinfs": [
                            {
                                "id": 1,
                                "sinf": "dGVzdA=="
                            }
                        ],
                        "metadata": {
                            "bundleId": "com.example.app",
                            "bundleShortVersionString": "1.0",
                            "softwareVersionExternalIdentifiers": [100, 200, 300]
                        }
                    }
                ]
            })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let items = app_store
        .download(&test_account(), 123, "guid", None)
        .await
        .unwrap();

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].url, "https://example.com/app.ipa");
    assert_eq!(items[0].md5, "abc123");
    assert_eq!(items[0].sinfs.len(), 1);
    assert_eq!(items[0].sinfs[0].data, b"test");
    assert_eq!(
        items[0].metadata["softwareVersionExternalIdentifiers"][2],
        300
    );
}

#[tokio::test]
async fn download_bytes_returns_http_status_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/forbidden.ipa"))
        .respond_with(ResponseTemplate::new(403).set_body_string("download denied"))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store
        .download_bytes(&format!("{}/forbidden.ipa", server.uri()))
        .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 403"));
    assert!(message.contains("download denied"));
}

#[tokio::test]
async fn download_failure_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({
                "failureType": "5000",
                "customerMessage": "download not allowed"
            })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store.download(&test_account(), 123, "guid", None).await;

    assert!(matches!(result, Err(AppStoreError::DownloadFailed(_))));
}

#[tokio::test]
async fn authenticate_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urlBag": {
                "authenticateAccount": format!("{}/authenticate", server.uri())
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .and(header("content-type", "application/x-apple-plist"))
        .and(body_string_contains("<key>appleId</key>"))
        .and(body_string_contains("<string>test@example.com</string>"))
        .and(body_string_contains("<key>attempt</key>"))
        .and(body_string_contains("<string>4</string>"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passwordToken": "ptok",
            "dsPersonId": "dsid",
            "accountInfo": {
                "appleId": "test@example.com",
                "address": {
                    "firstName": "Test",
                    "lastName": "User"
                }
            }
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let account = app_store
        .authenticate("test@example.com", "password", "guid")
        .await
        .unwrap();

    assert_eq!(account.email, "test@example.com");
    assert_eq!(account.name, "Test User");
    assert_eq!(account.password_token, "ptok");
}

#[tokio::test]
async fn authenticate_rejects_empty_password_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urlBag": {
                "authenticateAccount": format!("{}/authenticate", server.uri())
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "passwordToken": "",
            "dsPersonId": "dsid",
            "accountInfo": {
                "appleId": "test@example.com"
            }
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store
        .authenticate("test@example.com", "password", "guid")
        .await;

    let Err(AppStoreError::AuthenticationFailed(message)) = result else {
        panic!("expected AuthenticationFailed");
    };
    assert!(message.contains("missing passwordToken"));
}

#[tokio::test]
async fn authenticate_2fa_required() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urlBag": {
                "authenticateAccount": format!("{}/authenticate", server.uri())
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "customerMessage": "MZFinance.BadLogin.Configurator_message"
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store
        .authenticate("test@example.com", "password", "guid")
        .await;

    assert!(matches!(
        result,
        Err(AppStoreError::AuthCodeRequired { .. })
    ));
}

#[tokio::test]
async fn authenticate_invalid_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urlBag": {
                "authenticateAccount": format!("{}/authenticate", server.uri())
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "failureType": "-20101",
            "customerMessage": "wrong password"
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store
        .authenticate("test@example.com", "wrong", "guid")
        .await;

    assert!(matches!(
        result,
        Err(AppStoreError::AuthenticationFailed(_))
    ));
}

#[tokio::test]
async fn authenticate_persistent_5000_reports_retry_exhaustion() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urlBag": {
                "authenticateAccount": format!("{}/authenticate", server.uri())
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "failureType": "-5000"
        })))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let result = app_store
        .authenticate("test@example.com", "password", "guid")
        .await;

    match result {
        Err(AppStoreError::AuthenticationFailed(message)) => {
            assert_eq!(message, "authentication failed after retries");
        }
        other => panic!("expected retry-exhaustion auth failure, got {other:?}"),
    }
}

#[tokio::test]
async fn list_versions_parses_version_ids() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            plist_body(&serde_json::json!({
                "songList": [
                    {
                        "URL": "https://example.com/app.ipa",
                        "md5": "abc123",
                        "sinfs": [],
                        "metadata": {
                            "softwareVersionExternalIdentifiers": [100, "200", 300],
                            "bundleShortVersionString": "1.2.3"
                        }
                    }
                ]
            })),
            "application/x-apple-plist",
        ))
        .mount(&server)
        .await;

    let client = AppleHttpClient::new().unwrap();
    let app_store = repo(client, test_config(&server));
    let versions = app_store
        .list_versions(&test_account(), 123, "guid")
        .await
        .unwrap();

    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0].version_string, "1.2.3");
    assert_eq!(versions[1].version_string, "1.2.3");
    assert_eq!(versions[2].external_version_id, "300");
    assert_eq!(versions[2].version_string, "1.2.3");
}
