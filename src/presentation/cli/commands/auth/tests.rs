use super::*;
use crate::domain::entity::Account;
use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

fn sensitive_account() -> Account {
    Account {
        email: "test@example.com".into(),
        name: "Test User".into(),
        password_token: "secret-password-token".into(),
        directory_services_id: "dsid123".into(),
        store_front: "143441-1".into(),
        pod: "11".into(),
        idms_token: Some("secret-idms-token".into()),
        dsid: Some("dsid123".into()),
        adsid: Some("adsid123".into()),
        grandslam_session_key: Some("secret-session-key".into()),
        grandslam_continuation: Some("secret-continuation".into()),
        cookies: vec!["secret-cookie=value".into()],
    }
}

#[test]
fn json_login_output_is_sanitized() {
    let output = format_login_account(&sensitive_account(), &OutputFormat::Json);

    assert!(!output.contains("secret-password-token"));
    assert!(!output.contains("secret-idms-token"));
    assert!(!output.contains("secret-session-key"));
    assert!(!output.contains("secret-continuation"));
    assert!(!output.contains("secret-cookie"));

    let value: serde_json::Value = serde_json::from_str(&output).expect("valid json");
    assert_eq!(value["email"], "test@example.com");
    assert_eq!(value["has_password_token"], true);
    assert_eq!(value["has_cookies"], true);
    assert_eq!(value["has_idms_token"], true);
    assert_eq!(value["has_grandslam_state"], true);
}

#[tokio::test]
async fn login_defaults_to_configurator_flow() {
    let app_store = FakeAppStoreRepository::new().with_authenticate_result(Ok(sensitive_account()));
    let credentials = InMemoryCredentialRepository::new();
    let options = LoginOptions {
        email: Some("test@example.com"),
        password: Some("password"),
        code: None,
        country: Some("es"),
        non_interactive: true,
        grandslam: false,
    };

    handle_login(
        &options,
        app_store.clone(),
        credentials,
        &OutputFormat::Json,
    )
    .await
    .expect("login should succeed");

    assert_eq!(app_store.authenticate_calls().len(), 1);
    assert!(app_store.authenticate_grandslam_calls().is_empty());
}

#[tokio::test]
async fn login_grandslam_flag_selects_srp_flow() {
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(sensitive_account()));
    let credentials = InMemoryCredentialRepository::new();
    let options = LoginOptions {
        email: Some("test@example.com"),
        password: Some("password"),
        code: None,
        country: Some("es"),
        non_interactive: true,
        grandslam: true,
    };

    handle_login(
        &options,
        app_store.clone(),
        credentials,
        &OutputFormat::Json,
    )
    .await
    .expect("login should succeed");

    assert_eq!(app_store.authenticate_grandslam_calls().len(), 1);
    assert!(app_store.authenticate_calls().is_empty());
}
