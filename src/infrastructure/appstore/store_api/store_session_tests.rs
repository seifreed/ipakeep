use super::*;
use crate::infrastructure::observability::log_capture::LogCapture;
use async_trait::async_trait;
use std::sync::Mutex;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const GUID: &str = "AABBCCDDEEFF";
const AUTHENTICATE_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate/";
const BUY_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
const VOLUME_PATH: &str = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct";
const BAD_LOGIN: &str = "MZFinance.BadLogin.Configurator_message";
// Distinctive fake secrets: they cannot appear in logs by coincidence.
const PASSWORD: &str = "fake-password-QZ7XH2N5";
const TOKEN: &str = "fake-token-QZ7XK4M9";
const DSID: &str = "9073814265031";

#[derive(Default)]
struct FakeMachine {
    store_provisioned: Mutex<bool>,
    provisioned_challenges: Mutex<Vec<String>>,
    kbsync_dsids: Mutex<Vec<u64>>,
    sap_connections: Mutex<Vec<SignerConfig>>,
}

#[async_trait]
impl StoreMachine for FakeMachine {
    async fn anisette_headers(&self) -> Result<HashMap<String, String>, AppStoreError> {
        Ok(HashMap::from([
            ("X-Apple-I-MD".into(), "anisette-otp".into()),
            ("X-Apple-I-MD-M".into(), "anisette-mid".into()),
        ]))
    }

    async fn store_amd(&self) -> Result<(String, String), AppStoreError> {
        self.store_amd_blocking()
    }

    fn store_amd_blocking(&self) -> Result<(String, String), AppStoreError> {
        if *self.store_provisioned.lock().expect("lock") {
            Ok(("store-otp".into(), "store-mid".into()))
        } else {
            Err(AppStoreError::AuthenticationFailed(
                "not provisioned".into(),
            ))
        }
    }

    async fn kbsync(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        self.kbsync_blocking(hardware_id, dsid)
    }

    fn kbsync_blocking(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        assert_eq!(hardware_id, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        self.kbsync_dsids.lock().expect("lock").push(dsid);
        Ok(b"kbsync".to_vec())
    }

    async fn connect_sap(&self, config: SignerConfig) -> Result<(), AppStoreError> {
        self.sap_connections.lock().expect("lock").push(config);
        Ok(())
    }

    fn sign_blocking(&self, _body: &[u8]) -> Result<Vec<u8>, AppStoreError> {
        Ok(b"signature".to_vec())
    }

    async fn provision_store(
        &self,
        request: &StoreProvisioningRequest<'_>,
    ) -> Result<(), AppStoreError> {
        assert_eq!(request.kbsync, "a2JzeW5j");
        self.provisioned_challenges
            .lock()
            .expect("lock")
            .push(request.challenge.to_string());
        *self.store_provisioned.lock().expect("lock") = true;
        Ok(())
    }
}

struct Harness {
    server: MockServer,
    machine: Arc<FakeMachine>,
    directory: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bag.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string(bag_xml()))
            .mount(&server)
            .await;
        Self {
            server,
            machine: Arc::new(FakeMachine::default()),
            directory: tempfile::tempdir().expect("temporary directory"),
        }
    }

    /// A fresh session over the same files, as a new ipakeep run sees them.
    fn session(&self) -> StoreSession {
        let config = StoreSessionConfig {
            bag_url: format!("{}/bag.xml", self.server.uri()),
            purchase_history_url: self.server.uri(),
            origin: Some(self.server.uri()),
            state_directory: self.directory.path().to_path_buf(),
        };
        let machine: Arc<dyn StoreMachine> = self.machine.clone();
        StoreSession::open(machine, config).expect("session")
    }

    async fn requests(&self, route: &str) -> Vec<Request> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|request| request.url.path() == route)
            .collect()
    }
}

fn bag_xml() -> String {
    plist(
        "<key>urlBag</key><dict>\
         <key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string>\
         <key>sign-sap-setup</key><string>https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetup</string>\
         <key>sign-sap-setup-cert</key><string>https://play.itunes.apple.com/WebObjects/MZPlay.woa/wa/signSapSetupCert</string>\
         <key>sign-sap-version</key><string>200</string>\
         </dict>",
    )
}

fn plist(entries: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>{entries}</dict></plist>"
    )
}

fn plist_response(entries: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_string(plist(entries))
}

fn signed_in() -> ResponseTemplate {
    plist_response(&format!(
        "<key>passwordToken</key><string>{TOKEN}</string>\
         <key>dsPersonId</key><string>{DSID}</string>\
         <key>accountInfo</key><dict><key>appleId</key><string>user@example.com</string></dict>",
    ))
    .insert_header("X-Set-Apple-Store-Front", "143441-1,29")
    .insert_header("pod", "48")
}

fn credentials(auth_code: Option<&str>) -> Credentials<'_> {
    Credentials {
        email: "user@example.com",
        password: PASSWORD,
        auth_code,
    }
}

fn header_value(request: &Request, name: &str) -> String {
    let value = request.headers.get(name).map(|value| value.to_str());
    value.and_then(Result::ok).unwrap_or_default().to_string()
}

fn account() -> Account {
    Account {
        email: "user@example.com".into(),
        name: "User".into(),
        password_token: TOKEN.into(),
        directory_services_id: DSID.into(),
        store_front: "143441-1,29".into(),
        pod: String::new(),
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: Vec::new(),
    }
}

#[tokio::test]
async fn two_factor_sign_in_reuses_the_persisted_cookie_session() {
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("Cookie", "session=pending-2fa"))
        .respond_with(signed_in())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .respond_with(
            plist_response(&format!(
                "<key>customerMessage</key><string>{BAD_LOGIN}</string>"
            ))
            .insert_header("Set-Cookie", "session=pending-2fa; Path=/"),
        )
        .mount(&harness.server)
        .await;

    let first = harness.session().login(credentials(None), GUID).await;
    assert!(matches!(first, Err(AppStoreError::AuthCodeRequired { .. })));

    let account = harness
        .session()
        .login(credentials(Some("123456")), GUID)
        .await
        .expect("coded sign-in");

    assert_eq!(account.password_token, TOKEN);
    assert_eq!(account.directory_services_id, DSID);
    assert_eq!(account.store_front, "143441-1,29");
    assert!(harness.directory.path().join(STORE_COOKIES_FILE).exists());
    let sap = harness
        .machine
        .sap_connections
        .lock()
        .expect("lock")
        .clone();
    assert_eq!(sap[0].hardware_id, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    assert_eq!(sap[0].version, 200);
}

#[tokio::test]
async fn sign_in_runs_store_provisioning_and_retries_with_the_store_amd_proof() {
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("X-Apple-AMD", "store-otp"))
        .respond_with(signed_in())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .respond_with(
            plist_response("")
                .insert_header("X-Apple-AMD-Action", "SP")
                .insert_header("X-Apple-AMD-Data", "Y2hhbGxlbmdl"),
        )
        .mount(&harness.server)
        .await;

    let account = harness
        .session()
        .login(credentials(Some("123456")), GUID)
        .await
        .expect("sign-in after Store provisioning");

    assert_eq!(account.password_token, TOKEN);
    assert_eq!(
        *harness.machine.provisioned_challenges.lock().expect("lock"),
        ["Y2hhbGxlbmdl"]
    );
    assert_eq!(
        *harness.machine.kbsync_dsids.lock().expect("lock"),
        [PROVISIONING_DSID]
    );
    let attempts = harness.requests(AUTHENTICATE_PATH).await;
    assert_eq!(header_value(&attempts[0], "X-Apple-AMD"), "anisette-otp");
    assert_eq!(header_value(&attempts[1], "X-Apple-AMD-M"), "store-mid");
}

#[tokio::test]
async fn sign_in_starts_from_the_stored_store_amd_proof() {
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("X-Apple-AMD", "store-otp"))
        .respond_with(signed_in())
        .expect(1)
        .mount(&harness.server)
        .await;

    harness
        .session()
        .login(credentials(Some("123456")), GUID)
        .await
        .expect("sign-in with the Store AMD proof");
}

fn sign_in_again() -> ResponseTemplate {
    plist_response(
        "<key>failureType</key><string>2034</string>\
         <key>customerMessage</key><string>Sign In</string>",
    )
}

fn version_listing() -> ResponseTemplate {
    plist_response(
        "<key>songList</key><array><dict>\
         <key>URL</key><string>https://iosapps.itunes.apple.com/app.ipa</string>\
         <key>sinfs</key><array><dict><key>id</key><integer>0</integer><key>sinf</key><data>AQID</data></dict></array>\
         <key>metadata</key><dict>\
         <key>softwareVersionExternalIdentifier</key><integer>876660716</integer>\
         <key>softwareVersionExternalIdentifiers</key><array><integer>876660700</integer><integer>876660716</integer></array>\
         </dict></dict></array>",
    )
}

#[tokio::test]
async fn purchase_treats_sign_in_again_as_owned_when_versions_list() {
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    for (route, response) in [
        (BUY_PATH, sign_in_again()),
        (VOLUME_PATH, version_listing()),
    ] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(response)
            .mount(&harness.server)
            .await;
    }

    harness
        .session()
        .purchase(&account(), 42, GUID)
        .await
        .expect("owned app counts as purchased");

    let tickets = harness.requests(VOLUME_PATH).await;
    assert_eq!(header_value(&tickets[0], "X-Apple-AMD"), "store-otp");
}

#[tokio::test]
async fn purchase_reports_sign_in_again_without_a_license() {
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    Mock::given(method("POST"))
        .and(path(BUY_PATH))
        .respond_with(sign_in_again())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(VOLUME_PATH))
        .respond_with(plist_response(
            "<key>failureType</key><string>9610</string><key>customerMessage</key><string>License not found</string>",
        ))
        .mount(&harness.server)
        .await;

    let result = harness.session().purchase(&account(), 42, GUID).await;

    assert!(matches!(
        result,
        Err(AppStoreError::AuthenticationFailed(message)) if message.contains("recent sign-in")
    ));
}

#[tokio::test]
async fn download_returns_the_song_list_item_for_the_patch_pipeline() {
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    Mock::given(method("POST"))
        .and(path(VOLUME_PATH))
        .and(header_exists("X-Apple-AMD"))
        .respond_with(version_listing())
        .mount(&harness.server)
        .await;
    let session = harness.session();

    let items = session
        .download(&account(), 42, GUID, Some("876660716"))
        .await
        .expect("download ticket");
    let versions = session
        .list_versions(&account(), 42, GUID)
        .await
        .expect("versions");

    assert_eq!(items[0].url, "https://iosapps.itunes.apple.com/app.ipa");
    assert_eq!(items[0].sinfs[0].data, [1, 2, 3]);
    let identifiers: Vec<&str> = versions
        .iter()
        .map(|version| version.external_version_id.as_str())
        .collect();
    assert_eq!(identifiers, ["876660700", "876660716"]);
}

#[test]
fn reroutes_apple_urls_to_the_configured_origin() {
    assert_eq!(
        reroute(
            "https://p48-buy.itunes.apple.com/a/b?x=1",
            Some("http://127.0.0.1:9/")
        ),
        "http://127.0.0.1:9/a/b?x=1"
    );
    assert_eq!(reroute("https://apple.com/a", None), "https://apple.com/a");
}

#[test]
fn hardware_id_requires_a_hex_guid() {
    assert_eq!(hardware_id("00FF").expect("hex"), [0, 0xFF]);
    assert!(hardware_id("not-hex").is_err());
}

fn json_events(capture: &LogCapture) -> Vec<serde_json::Value> {
    capture
        .contents()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn find_event<'a>(
    events: &'a [serde_json::Value],
    name: &str,
    operation: &str,
) -> &'a serde_json::Value {
    events
        .iter()
        .find(|event| event["event_name"] == name && event["span"]["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {name} for {operation}"))
}

fn assert_no_secrets(logs: &str) {
    for secret in [
        "user@example.com",
        PASSWORD,
        TOKEN,
        "123456",
        GUID,
        DSID,
        "pending-2fa",
        "anisette-otp",
        "anisette-mid",
        "store-otp",
        "store-mid",
        "c2lnbmF0dXJl",
        "a2JzeW5j",
        "Y2hhbGxlbmdl",
        "iosapps.itunes.apple.com",
    ] {
        assert!(!logs.contains(secret), "{secret} leaked into the logs");
    }
}

#[tokio::test]
async fn sign_in_records_operation_outcomes_without_credentials() {
    let capture = LogCapture::default();
    let _guard = capture.install_json();
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("Cookie", "session=pending-2fa"))
        .respond_with(signed_in())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .respond_with(
            plist_response(&format!(
                "<key>customerMessage</key><string>{BAD_LOGIN}</string>"
            ))
            .insert_header("Set-Cookie", "session=pending-2fa; Path=/"),
        )
        .mount(&harness.server)
        .await;

    let first = harness.session().login(credentials(None), GUID).await;
    assert!(first.is_err());
    let events = json_events(&capture);
    let pending = find_event(&events, "appstore.operation.completed", "login");
    assert_eq!(pending["level"], "INFO");
    assert_eq!(pending["outcome"], "auth_code_required");
    assert!(pending["duration_ms"].is_number());
    let response = find_event(&events, "appstore.login.response", "login");
    assert_eq!(response["customer_message"], BAD_LOGIN);
    assert_eq!(response["status"], 200);
    let fallback = find_event(&events, "appstore.login.store_amd_unavailable", "login");
    assert_eq!(fallback["error_type"], "authentication_failed");

    harness
        .session()
        .login(credentials(Some("123456")), GUID)
        .await
        .expect("coded sign-in");

    let events = json_events(&capture);
    find_event(&events, "appstore.operation.started", "login");
    assert!(events.iter().any(|event| {
        event["event_name"] == "appstore.operation.completed" && event["outcome"] == "success"
    }));
    assert_no_secrets(&capture.contents());
}

#[tokio::test]
async fn store_provisioning_is_logged_without_its_challenge_or_proof() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let harness = Harness::new().await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .and(header("X-Apple-AMD", "store-otp"))
        .respond_with(signed_in())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(AUTHENTICATE_PATH))
        .respond_with(
            plist_response("")
                .insert_header("X-Apple-AMD-Action", "SP")
                .insert_header("X-Apple-AMD-Data", "Y2hhbGxlbmdl"),
        )
        .mount(&harness.server)
        .await;

    harness
        .session()
        .login(credentials(Some("123456")), GUID)
        .await
        .expect("sign-in after Store provisioning");

    let logs = capture.contents();
    for event in [
        "appstore.login.machine_action",
        "appstore.login.store_provisioning_started",
        "appstore.login.store_provisioned",
    ] {
        assert!(logs.contains(event), "missing {event}");
    }
    assert_no_secrets(&logs);
}

#[tokio::test]
async fn purchase_logs_apple_codes_and_the_nested_version_listing() {
    let capture = LogCapture::default();
    let _guard = capture.install_json();
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    for (route, response) in [
        (BUY_PATH, sign_in_again()),
        (VOLUME_PATH, version_listing()),
    ] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(response)
            .mount(&harness.server)
            .await;
    }

    harness
        .session()
        .purchase(&account(), 42, GUID)
        .await
        .expect("owned app counts as purchased");

    let events = json_events(&capture);
    let attempt = find_event(&events, "appstore.purchase.response", "purchase");
    assert_eq!(attempt["failure_type"], "2034");
    assert_eq!(attempt["outcome"], "token_expired");
    assert_eq!(attempt["span"]["app_id"], 42);
    let ticket = find_event(&events, "appstore.download.response", "list_versions");
    assert_eq!(
        ticket["endpoint"],
        "buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
    );
    let completed: Vec<&str> = events
        .iter()
        .filter(|event| event["event_name"] == "appstore.operation.completed")
        .filter_map(|event| event["operation"].as_str())
        .collect();
    assert_eq!(completed, ["list_versions", "purchase"]);
    assert_no_secrets(&capture.contents());
}

#[tokio::test]
async fn unconfirmed_license_is_a_logged_operation_failure() {
    let capture = LogCapture::default();
    let _guard = capture.install_json();
    let harness = Harness::new().await;
    *harness.machine.store_provisioned.lock().expect("lock") = true;
    Mock::given(method("POST"))
        .and(path(BUY_PATH))
        .respond_with(sign_in_again())
        .mount(&harness.server)
        .await;
    Mock::given(method("POST"))
        .and(path(VOLUME_PATH))
        .respond_with(plist_response(
            "<key>failureType</key><string>9610</string><key>customerMessage</key><string>License not found</string>",
        ))
        .mount(&harness.server)
        .await;

    assert!(
        harness
            .session()
            .purchase(&account(), 42, GUID)
            .await
            .is_err()
    );

    let events = json_events(&capture);
    let unconfirmed = find_event(&events, "appstore.purchase.license_unconfirmed", "purchase");
    assert_eq!(unconfirmed["error_type"], "no_license");
    let failed = find_event(&events, "appstore.operation.failed", "purchase");
    assert_eq!(failed["level"], "WARN");
    assert_eq!(failed["error_type"], "authentication_failed");
    assert!(!capture.contents().contains("License not found"));
    assert_no_secrets(&capture.contents());
}

#[tokio::test]
async fn signed_out_download_fails_observably() {
    let capture = LogCapture::default();
    let _guard = capture.install_json();
    let harness = Harness::new().await;
    let mut signed_out = account();
    signed_out.password_token.clear();

    let result = harness
        .session()
        .download(&signed_out, 42, GUID, None)
        .await;

    assert!(result.is_err());
    let events = json_events(&capture);
    let failed = find_event(&events, "appstore.operation.failed", "download");
    assert_eq!(failed["error_type"], "authentication_failed");
    assert_eq!(failed["span"]["app_id"], 42);
}
