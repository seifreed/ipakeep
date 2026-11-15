//! Integration tests for `AppleAppStoreRepository` using a local `WireMock` server.

use async_trait::async_trait;
use ipakeep::domain::entity::Account;
use ipakeep::domain::error::AppStoreError;
use ipakeep::domain::repository::{
    AuthenticationRepository, CatalogRepository, DownloadRepository, PurchaseRepository,
    VersionRepository,
};
use ipakeep::infrastructure::apple_sap::signer::SignerConfig;
use ipakeep::infrastructure::apple_sap::storeauth::StoreProvisioningRequest;
use ipakeep::infrastructure::appstore::{AppleApiConfig, AppleAppStoreRepository, StoreMachine};
use ipakeep::infrastructure::developer::DeveloperClient;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::http::plist_codec::encode_plist;
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const GUID: &str = "AABBCCDDEEFF";
const AUTHENTICATE_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate/";
const BUY_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
const VOLUME_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";

fn test_account() -> Account {
    Account {
        email: "test@example.com".into(),
        name: "Test User".into(),
        password_token: "token123".into(),
        directory_services_id: "123456".into(),
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

/// A Store machine with a completed Store provisioning.
struct ProvisionedMachine;

#[async_trait]
impl StoreMachine for ProvisionedMachine {
    async fn anisette_headers(&self) -> Result<HashMap<String, String>, AppStoreError> {
        Ok(HashMap::from([("X-Apple-I-MD".into(), "otp".into())]))
    }

    async fn store_amd(&self) -> Result<(String, String), AppStoreError> {
        self.store_amd_blocking()
    }

    fn store_amd_blocking(&self) -> Result<(String, String), AppStoreError> {
        Ok(("amd".into(), "amd-m".into()))
    }

    async fn kbsync(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        self.kbsync_blocking(hardware_id, dsid)
    }

    fn kbsync_blocking(&self, _hardware_id: &[u8], _dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        Ok(b"kbsync".to_vec())
    }

    async fn connect_sap(&self, _config: SignerConfig) -> Result<(), AppStoreError> {
        Ok(())
    }

    fn sign_blocking(&self, _body: &[u8]) -> Result<Vec<u8>, AppStoreError> {
        Ok(b"signature".to_vec())
    }

    async fn provision_store(
        &self,
        _request: &StoreProvisioningRequest<'_>,
    ) -> Result<(), AppStoreError> {
        Ok(())
    }
}

#[tokio::test]
async fn developer_client_rejects_missing_grandslam_state_before_network() {
    assert!(DeveloperClient::for_account(&test_account()).await.is_err());
}

fn test_config(server: &MockServer, state: &tempfile::TempDir) -> AppleApiConfig {
    AppleApiConfig {
        bag_url: format!("{}/bag.xml", server.uri()),
        itunes_search_url: format!("{}/search", server.uri()),
        itunes_lookup_url: format!("{}/lookup", server.uri()),
        purchase_history_url: server.uri(),
        store_origin: Some(server.uri()),
        state_directory: Some(state.path().to_path_buf()),
    }
}

/// A repository over `server` with a provisioned fake machine; the returned
/// directory holds its session files and must outlive it.
fn store(server: &MockServer) -> (AppleAppStoreRepository, tempfile::TempDir) {
    let state = tempfile::tempdir().expect("state directory");
    let repository = AppleAppStoreRepository::with_store_machine(
        AppleHttpClient::new().unwrap(),
        test_config(server, &state),
        Arc::new(ProvisionedMachine),
    );
    (repository, state)
}

fn plist_body(value: &serde_json::Value) -> Vec<u8> {
    encode_plist(value).expect("encoding plist")
}

fn plist_response(value: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(plist_body(value), "application/x-apple-plist")
}

async fn mount_bag(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/bag.xml"))
        .and(query_param("guid", GUID))
        .respond_with(plist_response(&serde_json::json!({
            "urlBag": {
                "authenticateAccount": "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate",
                "sign-sap-setup": "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup",
                "sign-sap-setup-cert": "https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetupCert",
                "sign-sap-version": "200"
            }
        })))
        .mount(server)
        .await;
}

async fn mount_post(server: &MockServer, route: &str, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(response)
        .mount(server)
        .await;
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
    let (app_store, _state) = store_with_client(&server, client);
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
    let (app_store, _state) = store_with_client(&server, client);
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
    let (app_store, _state) = store_with_client(&server, client);
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
    let (app_store, _state) = store_with_client(&server, client);
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
    let (app_store, _state) = store_with_client(&server, client);
    let app = app_store.lookup("com.missing.app", "us").await.unwrap();

    assert!(app.is_none());
}

fn store_with_client(
    server: &MockServer,
    client: AppleHttpClient,
) -> (AppleAppStoreRepository, tempfile::TempDir) {
    let state = tempfile::tempdir().expect("state directory");
    let repository = AppleAppStoreRepository::with_store_machine(
        client,
        test_config(server, &state),
        Arc::new(ProvisionedMachine),
    );
    (repository, state)
}

#[tokio::test]
async fn purchase_success() {
    let server = MockServer::start().await;
    mount_post(
        &server,
        BUY_PATH,
        plist_response(&serde_json::json!({ "jingleDocType": "purchaseSuccess", "status": 0 })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store.purchase(&test_account(), 123, GUID).await;

    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn purchase_already_owned_returns_ok() {
    let server = MockServer::start().await;
    mount_post(
        &server,
        BUY_PATH,
        plist_response(&serde_json::json!({ "failureType": "5002" })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store.purchase(&test_account(), 123, GUID).await;

    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn purchase_failure_returns_purchase_failed() {
    let server = MockServer::start().await;
    mount_post(
        &server,
        BUY_PATH,
        plist_response(&serde_json::json!({
            "failureType": "5000",
            "customerMessage": "insufficient funds"
        })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store.purchase(&test_account(), 123, GUID).await;

    assert!(matches!(result, Err(AppStoreError::PurchaseFailed(_))));
}

#[tokio::test]
async fn purchase_without_password_token_fails_before_store_request() {
    let server = MockServer::start().await;
    let mut account = test_account();
    account.password_token.clear();
    account.idms_token = Some("idms".into());

    let (app_store, _state) = store(&server);
    let result = app_store.purchase(&account, 123, GUID).await;

    let Err(AppStoreError::AuthenticationFailed(message)) = result else {
        panic!("expected AuthenticationFailed");
    };
    assert!(message.contains("missing the MZFinance passwordToken"));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

fn song_list() -> serde_json::Value {
    serde_json::json!({
        "songList": [
            {
                "URL": "https://example.com/app.ipa",
                "md5": "abc123",
                "sinfs": [{ "id": 1, "sinf": "dGVzdA==" }],
                "metadata": {
                    "bundleId": "com.example.app",
                    "bundleShortVersionString": "1.0",
                    "softwareVersionExternalIdentifier": 300,
                    "softwareVersionExternalIdentifiers": [100, 200, 300]
                }
            }
        ]
    })
}

#[tokio::test]
async fn download_returns_items() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    Mock::given(method("POST"))
        .and(path(VOLUME_PATH))
        .and(header("X-Token", "token123"))
        .and(header("X-Apple-AMD", "amd"))
        .respond_with(plist_response(&song_list()))
        .mount(&server)
        .await;

    let (app_store, _state) = store(&server);
    let items = app_store
        .download(&test_account(), 123, GUID, Some("300".into()))
        .await
        .unwrap();

    assert_eq!(items.len(), 1);
    assert_eq!(items[0].url, "https://example.com/app.ipa");
    assert_eq!(items[0].md5, "abc123");
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
    let (app_store, _state) = store_with_client(&server, client);
    let result = app_store
        .download_bytes(&format!("{}/forbidden.ipa", server.uri()))
        .await;

    let Err(AppStoreError::NetworkError(message)) = result else {
        panic!("expected network error");
    };
    assert!(message.contains("HTTP 403"));
    assert!(!message.contains("download denied"));
}

#[tokio::test]
async fn download_failure_returns_error() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    mount_post(
        &server,
        VOLUME_PATH,
        plist_response(&serde_json::json!({
            "failureType": "5000",
            "customerMessage": "download not allowed"
        })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store
        .download(&test_account(), 123, GUID, Some("300".into()))
        .await;

    assert!(result.is_err(), "{result:?}");
}

#[tokio::test]
async fn list_versions_parses_version_ids() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    mount_post(&server, VOLUME_PATH, plist_response(&song_list())).await;

    let (app_store, _state) = store(&server);
    let versions = app_store
        .list_versions(&test_account(), 123, GUID)
        .await
        .unwrap();

    let identifiers: Vec<&str> = versions
        .iter()
        .map(|version| version.external_version_id.as_str())
        .collect();
    assert_eq!(identifiers, ["100", "200", "300"]);
}

fn signed_in() -> ResponseTemplate {
    plist_response(&serde_json::json!({
        "passwordToken": "ptok",
        "dsPersonId": "8765",
        "accountInfo": {
            "appleId": "test@example.com",
            "address": { "firstName": "Test", "lastName": "User" }
        }
    }))
    .insert_header("X-Set-Apple-Store-Front", "143441-1,29")
}

#[tokio::test]
async fn authenticate_success() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("content-type", "application/x-apple-plist"))
        .and(header("X-Apple-AMD", "amd"))
        .and(body_string_contains(
            "<key>appleId</key><string>test@example.com</string>",
        ))
        .respond_with(signed_in())
        .mount(&server)
        .await;

    let (app_store, _state) = store(&server);
    let account = app_store
        .authenticate("test@example.com", "password", GUID)
        .await
        .unwrap();

    assert_eq!(account.email, "test@example.com");
    assert_eq!(account.name, "Test User");
    assert_eq!(account.password_token, "ptok");
    assert_eq!(account.store_front, "143441-1,29");
}

#[tokio::test]
async fn authenticate_2fa_required_then_completed_with_the_code() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(body_string_contains("<string>password123456</string>"))
        .and(header("cookie", "pending=1"))
        .respond_with(signed_in())
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .respond_with(
            plist_response(&serde_json::json!({
                "customerMessage": "MZFinance.BadLogin.Configurator_message"
            }))
            .insert_header("Set-Cookie", "pending=1; Path=/"),
        )
        .mount(&server)
        .await;

    let (app_store, _state) = store(&server);
    let result = app_store
        .authenticate("test@example.com", "password", GUID)
        .await;
    assert!(matches!(
        result,
        Err(AppStoreError::AuthCodeRequired { .. })
    ));

    let account = app_store
        .authenticate_with_2fa("test@example.com", "password", "123456", GUID)
        .await
        .unwrap();
    assert_eq!(account.password_token, "ptok");
}

#[tokio::test]
async fn authenticate_invalid_credentials() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    mount_post(
        &server,
        AUTHENTICATE_PATH,
        plist_response(&serde_json::json!({
            "failureType": "-5000",
            "customerMessage": "wrong password"
        })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store
        .authenticate("test@example.com", "wrong", GUID)
        .await;

    assert!(matches!(result, Err(AppStoreError::InvalidCredentials)));
}

#[tokio::test]
async fn authenticate_reports_other_failures() {
    let server = MockServer::start().await;
    mount_bag(&server).await;
    mount_post(
        &server,
        AUTHENTICATE_PATH,
        plist_response(&serde_json::json!({
            "failureType": "-20101",
            "customerMessage": "account locked"
        })),
    )
    .await;

    let (app_store, _state) = store(&server);
    let result = app_store
        .authenticate("test@example.com", "password", GUID)
        .await;

    assert!(matches!(
        result,
        Err(AppStoreError::AuthenticationFailed(message)) if message == "account locked"
    ));
}
