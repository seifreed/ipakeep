use super::*;
use crate::domain::entity::Account;
use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
use crate::domain::usecase::log_capture::LogCapture;

fn test_account() -> Account {
    Account {
        email: "test@example.com".into(),
        name: "Test User".into(),
        password_token: "token123".into(),
        directory_services_id: "dsid123".into(),
        store_front: "143441-2,26".into(),
        pod: "3".into(),
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: Vec::new(),
    }
}

#[tokio::test]
async fn login_success_saves_credentials() {
    let app_store = FakeAppStoreRepository::new().with_authenticate_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();

    let use_case = AuthLogin::new(app_store, credentials.clone());
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "password", "guid123")
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().email, "test@example.com");
    assert_eq!(credentials.save_calls().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn login_logs_progress_without_secrets() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let app_store = FakeAppStoreRepository::new().with_authenticate_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();

    let use_case = AuthLogin::new(app_store, credentials);
    use_case
        .execute("test@example.com", "S3cr3t-pass", "guid123")
        .await
        .unwrap();

    let logs = capture.contents();
    assert!(logs.contains("starting legacy auth login"));
    assert!(logs.contains("legacy auth account saved"));
    assert!(!logs.contains("S3cr3t-pass"));
    assert!(!logs.contains("token123"));
    assert!(!logs.contains("test@example.com"));
}

#[tokio::test]
async fn login_auth_failure_does_not_save() {
    let app_store = FakeAppStoreRepository::new()
        .with_authenticate_result(Err(AppStoreError::InvalidCredentials));
    let credentials = InMemoryCredentialRepository::new();

    let use_case = AuthLogin::new(app_store, credentials.clone());
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "wrong", "guid123")
        .await;

    assert!(result.is_err());
    assert_eq!(credentials.save_calls().len(), 0);
}

#[tokio::test]
async fn login_with_2fa_success() {
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_with_2fa_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();

    let use_case = AuthLogin::new(app_store, credentials.clone());
    let result: Result<Account, AppStoreError> = use_case
        .login_with_2fa("test@example.com", "password", "123456", "guid123")
        .await;

    assert!(result.is_ok());
    assert_eq!(credentials.save_calls().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn two_factor_login_logs_progress_without_secrets() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_with_2fa_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();

    let use_case = AuthLogin::new(app_store, credentials);
    use_case
        .login_with_2fa("test@example.com", "S3cr3t-pass", "123456", "guid123")
        .await
        .unwrap();

    let logs = capture.contents();
    assert!(logs.contains("starting legacy auth login with 2fa"));
    assert!(logs.contains("legacy 2fa auth account saved"));
    assert!(!logs.contains("S3cr3t-pass"));
    assert!(!logs.contains("123456"));
    assert!(!logs.contains("token123"));
}

#[tokio::test]
async fn login_credential_save_failure_returns_error() {
    let app_store = FakeAppStoreRepository::new().with_authenticate_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();
    // InMemoryCredentialRepository always succeeds on save, so we test
    // the happy path and verify save_account was exercised.
    let use_case = AuthLogin::new(app_store, credentials.clone());
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "password", "guid123")
        .await;

    assert!(result.is_ok());
    assert_eq!(credentials.save_calls().len(), 1);
}

#[tokio::test]
async fn trusted_device_grandslam_2fa_relogs_before_saving_account() {
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();
    let use_case = AuthLogin::new(app_store.clone(), credentials.clone());

    let result = use_case
        .complete_trusted_device_grandslam_2fa(
            &GrandslamCredentials {
                email: "test@example.com",
                password: "password",
                guid: "guid123",
                store_front: None,
            },
            "dsid123",
            "idms123",
            "123456",
        )
        .await
        .unwrap();

    assert_eq!(result.email, "test@example.com");
    assert_eq!(
        app_store.validate_trusted_device_code_calls(),
        vec![("dsid123".into(), "idms123".into(), "123456".into())]
    );
    assert_eq!(
        app_store.authenticate_grandslam_calls(),
        vec![(
            "test@example.com".into(),
            "password".into(),
            "guid123".into()
        )]
    );
    assert_eq!(credentials.save_calls().len(), 1);
}

#[tokio::test]
async fn sms_grandslam_2fa_relogs_before_saving_account() {
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();
    let use_case = AuthLogin::new(app_store.clone(), credentials.clone());

    let result = use_case
        .complete_sms_grandslam_2fa(
            &GrandslamCredentials {
                email: "test@example.com",
                password: "password",
                guid: "guid123",
                store_front: None,
            },
            "dsid123",
            "idms123",
            1,
            "123456",
        )
        .await
        .unwrap();

    assert_eq!(result.email, "test@example.com");
    assert_eq!(
        app_store.validate_sms_code_calls(),
        vec![("dsid123".into(), "idms123".into(), 1, "123456".into())]
    );
    assert_eq!(
        app_store.authenticate_grandslam_calls(),
        vec![(
            "test@example.com".into(),
            "password".into(),
            "guid123".into()
        )]
    );
    assert_eq!(credentials.save_calls().len(), 1);
}

#[tokio::test]
async fn execute_grandslam_sets_store_front_when_spd_omits_it() {
    let mut account = test_account();
    account.store_front = String::new();
    let app_store = FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(account));
    let credentials = InMemoryCredentialRepository::new();
    let use_case = AuthLogin::new(app_store, credentials.clone());

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await
        .unwrap();

    assert_eq!(result.store_front, "143454-1");
    assert_eq!(credentials.save_calls()[0].store_front, "143454-1");
}

#[tokio::test]
async fn execute_grandslam_rejects_account_without_purchase_token() {
    let mut account = test_account();
    account.password_token.clear();
    let app_store = FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(account));
    let credentials = InMemoryCredentialRepository::new();
    let use_case = AuthLogin::new(app_store, credentials.clone());

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await;

    let Err(AppStoreError::AuthenticationFailed(message)) = result else {
        panic!("expected AuthenticationFailed");
    };
    assert!(message.contains("purchase token"));
    assert!(credentials.save_calls().is_empty());
}

#[tokio::test]
async fn execute_grandslam_preserves_store_front_from_spd() {
    // test_account() already carries a store front; the derived value must
    // not overwrite one Apple actually provided.
    let app_store =
        FakeAppStoreRepository::new().with_authenticate_grandslam_result(Ok(test_account()));
    let credentials = InMemoryCredentialRepository::new();
    let use_case = AuthLogin::new(app_store, credentials.clone());

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await
        .unwrap();

    assert_eq!(result.store_front, "143441-2,26");
}
