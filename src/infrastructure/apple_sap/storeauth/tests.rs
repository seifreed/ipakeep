//! Service-level tests: worker plumbing offline, and (with the cached Apple
//! assets) GSA provisioning replayed from the recorded exchanges.

use std::collections::HashMap;
use std::path::PathBuf;

use wiremock::MockServer;

use super::anisette::{GsaEndpoints, LOCAL_TIME_ZONE};
use super::test_support::{golden, hex_at, local_endpoints, recorded_gsa};
use super::*;
use crate::domain::error::AppStoreError;
use crate::infrastructure::apple_sap::machine::sap::test_support::{
    PRIMARY_SEED, SeededHost, environment, fixture,
};
use crate::infrastructure::observability::log_capture::LogCapture;

const GOLDEN_IDENTIFIER: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn ipatool_assets() -> PathBuf {
    dirs::home_dir()
        .unwrap()
        .join("Library/Caches/ipatool/sap/apple-assets-macos-27-26A434-arm64-v5")
}

fn seeded_config(state: StateStore, bundle: BundleSource, gsa: GsaEndpoints) -> ServiceConfig {
    ServiceConfig {
        state,
        bundle,
        gsa,
        time_zone: "UTC".to_owned(),
        environment: Box::new(|| environment(&SeededHost::new(PRIMARY_SEED))),
        identifiers: IdentifierSource::Fixed(GOLDEN_IDENTIFIER),
    }
}

fn state_in(directory: &tempfile::TempDir) -> StateStore {
    StateStore::new(directory.path().join("ipakeep").join("anisette-v4.json"))
}

fn offline_service(directory: &tempfile::TempDir) -> SapService {
    let missing = BundleSource::Directory(directory.path().join("no-assets"));
    let gsa = GsaEndpoints {
        start: "http://127.0.0.1:9/start".to_owned(),
        finish: "http://127.0.0.1:9/finish".to_owned(),
    };
    SapService::spawn(seeded_config(state_in(directory), missing, gsa)).unwrap()
}

#[test]
fn standard_config_uses_the_go_helper_state_path() {
    let config = ServiceConfig::standard().unwrap();
    let expected = dirs::config_dir()
        .unwrap()
        .join("ipakeep")
        .join("anisette-v4.json");
    assert_eq!(config.state.path(), expected);
    assert_eq!(config.time_zone, LOCAL_TIME_ZONE);
    assert_eq!(config.gsa, GsaEndpoints::default());
}

#[test]
fn blocking_calls_report_worker_errors() {
    let directory = tempfile::tempdir().unwrap();
    let service = offline_service(&directory);
    assert!(matches!(
        service.store_amd_headers_blocking(),
        Err(StoreAuthError::StoreNotProvisioned)
    ));
    assert!(matches!(
        service.sign_blocking(b"body"),
        Err(StoreAuthError::NoSapSession)
    ));
    assert!(matches!(
        service.kbsync_blocking(&[2, 0, 0, 0, 0, 1], 1),
        Err(StoreAuthError::Bundle(_))
    ));
    let error: AppStoreError = StoreAuthError::StoreNotProvisioned.into();
    assert!(matches!(error, AppStoreError::AuthenticationFailed(_)));
}

#[test]
fn operation_outcomes_are_logged_without_inputs_or_paths() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let directory = tempfile::tempdir().unwrap();
    let service = offline_service(&directory);
    let hardware_id = b"HWID-SENTINEL";
    let dsid = 987_654_321_012;

    assert!(service.kbsync_blocking(hardware_id, dsid).is_err());
    assert!(service.store_amd_headers_blocking().is_err());
    assert!(service.sign_blocking(b"SIGN-INPUT-SENTINEL").is_err());

    let logs = capture.contents();
    assert!(logs.contains("apple_sap.worker.started"), "{logs}");
    assert!(logs.contains("WARN"), "{logs}");
    assert!(logs.contains("event_name=\"apple_sap.operation.failed\""));
    assert!(logs.contains("operation=\"kbsync\""));
    assert!(logs.contains("error_type=\"assets\""));
    assert!(logs.contains("operation=\"sign\""));
    assert!(logs.contains("error_type=\"no_sap_session\""));
    assert!(logs.contains("outcome=\"not_provisioned\""));
    assert!(logs.contains("duration_ms="));
    assert!(logs.contains("event_name=\"apple_sap.anisette.state_loaded\""));
    assert!(logs.contains("outcome=\"missing\""));
    assert!(!logs.contains("SENTINEL"));
    assert!(!logs.contains(&hex::encode(hardware_id)));
    assert!(!logs.contains(&dsid.to_string()));
    let root = directory.path().to_string_lossy().into_owned();
    assert!(!logs.contains(&root), "{logs}");
}

#[tokio::test]
async fn anisette_failure_is_logged_at_the_service_boundary() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let directory = tempfile::tempdir().unwrap();
    let service = offline_service(&directory);

    assert!(service.anisette_headers().await.is_err());

    let logs = capture.contents();
    assert!(logs.contains("operation=\"anisette_headers\""), "{logs}");
    assert!(logs.contains("event_name=\"apple_sap.operation.failed\""));
    assert!(logs.contains("error_type=\"assets\""));
    assert!(!logs.contains(&hex::encode(GOLDEN_IDENTIFIER)));
}

#[tokio::test(flavor = "multi_thread")]
async fn async_and_blocking_calls_share_one_worker() {
    let directory = tempfile::tempdir().unwrap();
    let service = offline_service(&directory);
    let error = service.anisette_headers().await.unwrap_err();
    assert!(matches!(error, StoreAuthError::Bundle(_)), "{error}");
    let clone = service.clone();
    let amd = tokio::spawn(async move { clone.store_amd_headers_blocking() });
    assert!(matches!(
        amd.await.unwrap(),
        Err(StoreAuthError::StoreNotProvisioned)
    ));
    assert!(matches!(
        service.sign(b"x").await,
        Err(StoreAuthError::NoSapSession)
    ));
}

#[tokio::test]
async fn store_provisioning_requires_a_valid_challenge() {
    let directory = tempfile::tempdir().unwrap();
    let service = offline_service(&directory);
    let client = crate::infrastructure::http::client_builder()
        .build()
        .expect("HTTP client");
    let request = StoreProvisioningRequest {
        client: &client,
        challenge: "%%%",
        endpoint: "http://127.0.0.1:9/finish",
        user_agent: "ua",
        kbsync: "",
        hardware_id: &[1],
        identity: &[],
    };
    let error = service.provision_store(&request).await.unwrap_err();
    assert!(matches!(error, StoreAuthError::Protocol(_)), "{error}");
}

fn golden_headers() -> HashMap<String, String> {
    serde_json::from_value(golden()["anisette_headers"].clone()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the cached Apple SAP assets"]
async fn provisions_from_scratch_reproducing_the_golden_headers() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let directory = tempfile::tempdir().unwrap();
    let server = recorded_gsa().await;
    let bundle = BundleSource::Directory(ipatool_assets());
    let config = seeded_config(state_in(&directory), bundle, local_endpoints(&server));
    let service = SapService::spawn(config).unwrap();
    let headers = service.anisette_headers().await.unwrap();
    assert_eq!(headers.to_map(), golden_headers());
    assert_eq!(service.anisette_headers().await.unwrap(), headers);

    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state_in(&directory).path()).unwrap()).unwrap();
    let expected = &golden()["anisette_state_json"];
    assert_eq!(saved["Identifier"], expected["Identifier"]);
    assert_eq!(saved["Provisioning"], expected["Provisioning"]);
    assert_eq!(saved["RoutingInfo"], serde_json::json!(84_215_040));
    server.verify().await;

    let logs = capture.contents();
    assert!(
        logs.contains("apple_sap.anisette.provisioning_started"),
        "{logs}"
    );
    assert!(logs.contains("apple_sap.anisette.provisioned"));
    assert!(logs.contains("apple_sap.anisette.state_persisted"));
    assert!(logs.contains("http.response.headers_received"));
    for (name, value) in headers.entries() {
        let identifying = name.starts_with("X-Apple-I-MD") || *name == "X-Mme-Device-Id";
        assert!(
            !identifying || !logs.contains(value.as_str()),
            "{name} leaked"
        );
    }
    assert!(!logs.contains(expected["Provisioning"].as_str().unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the cached Apple SAP assets"]
async fn reuses_persisted_provisioning_without_gsa() {
    let directory = tempfile::tempdir().unwrap();
    let store = state_in(&directory);
    let state =
        AnisetteState::decode(&serde_json::to_vec(&golden()["anisette_state_json"]).unwrap())
            .unwrap();
    store.write(&store.lock().unwrap(), &state).unwrap();
    let offline = MockServer::start().await;
    let bundle = BundleSource::Directory(ipatool_assets());
    let service =
        SapService::spawn(seeded_config(store, bundle, local_endpoints(&offline))).unwrap();
    let headers = service.anisette_headers().await.unwrap();
    let expected = golden_headers();
    for name in [
        "X-Apple-I-MD-M",
        "X-Apple-I-MD-RINFO",
        "X-Apple-I-MD-LU",
        "X-Mme-Device-Id",
    ] {
        assert_eq!(
            headers.get(name),
            expected.get(name).map(String::as_str),
            "{name}"
        );
    }
    assert!(offline.received_requests().await.unwrap().is_empty());
    assert!(matches!(
        service.store_amd_headers().await,
        Err(StoreAuthError::StoreNotProvisioned)
    ));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the cached Apple SAP assets"]
async fn kbsync_matches_the_golden_vector() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let directory = tempfile::tempdir().unwrap();
    let golden = fixture("kbsync.json");
    let bundle = BundleSource::Directory(ipatool_assets());
    let config = seeded_config(state_in(&directory), bundle, GsaEndpoints::default());
    let service = SapService::spawn(config).unwrap();
    let hardware = hex_at(&golden, "/hardware_id_hex");
    let dsid = golden["dsid"].as_u64().unwrap();
    let blob = service.kbsync(&hardware, dsid).await.unwrap();
    assert_eq!(hex::encode(&blob), golden["kbsync_hex"].as_str().unwrap());

    let logs = capture.contents();
    assert!(logs.contains("operation=\"kbsync\""), "{logs}");
    assert!(logs.contains("apple_sap.worker.assets_ready"));
    assert!(!logs.contains(&hex::encode(&blob)));
    assert!(!logs.contains(&base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &blob
    )));
    assert!(!logs.contains(&dsid.to_string()));
}
