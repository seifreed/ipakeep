use super::*;
use crate::domain::entity::test_support::test_account;
use crate::domain::error::CredentialError;
use crate::domain::repository::{AppStoreRepo, CredentialRepo};

#[tokio::test]
async fn login_success_saves_credentials() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate()
        .withf(|email, password, guid| {
            email == "test@example.com" && password == "password" && guid == "guid123"
        })
        .return_once(|_, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|_| Ok(()));

    let use_case = AuthLogin::new(app_store, credentials);
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "password", "guid123")
        .await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().email, "test@example.com");
}

#[tokio::test]
async fn login_auth_failure_does_not_save() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate()
        .return_once(|_, _, _| Err(AppStoreError::InvalidCredentials));
    let credentials = CredentialRepo::new();

    let use_case = AuthLogin::new(app_store, credentials);
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "wrong", "guid123")
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn login_with_2fa_success() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate_with_2fa()
        .return_once(|_, _, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|_| Ok(()));

    let use_case = AuthLogin::new(app_store, credentials);
    let result: Result<Account, AppStoreError> = use_case
        .login_with_2fa("test@example.com", "password", "123456", "guid123")
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn login_credential_save_failure_returns_error() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate()
        .return_once(|_, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials
        .expect_save_account()
        .return_once(|_| Err(CredentialError::SaveFailed("disk full".into())));
    let use_case = AuthLogin::new(app_store, credentials);
    let result: Result<Account, AppStoreError> = use_case
        .execute("test@example.com", "password", "guid123")
        .await;

    assert!(matches!(result, Err(AppStoreError::Unexpected(_))));
}

#[tokio::test]
async fn trusted_device_grandslam_2fa_relogs_before_saving_account() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_validate_trusted_device_code()
        .withf(|dsid, token, code| dsid == "dsid123" && token == "idms123" && code == "123456")
        .return_once(|_, _, _| Ok(()));
    app_store
        .expect_authenticate_grandslam()
        .withf(|email, password, guid| {
            email == "test@example.com" && password == "password" && guid == "guid123"
        })
        .return_once(|_, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|_| Ok(()));
    let use_case = AuthLogin::new(app_store, credentials);

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
}

#[tokio::test]
async fn sms_grandslam_2fa_relogs_before_saving_account() {
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_validate_sms_code()
        .withf(|dsid, token, phone_id, code| {
            dsid == "dsid123" && token == "idms123" && *phone_id == 1 && code == "123456"
        })
        .return_once(|_, _, _, _| Ok(()));
    app_store
        .expect_authenticate_grandslam()
        .return_once(|_, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|_| Ok(()));
    let use_case = AuthLogin::new(app_store, credentials);

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
}

#[tokio::test]
async fn execute_grandslam_sets_store_front_when_spd_omits_it() {
    let mut account = test_account();
    account.store_front = String::new();
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate_grandslam()
        .return_once(|_, _, _| Ok(account));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|account| {
        assert_eq!(account.store_front, "143454-1");
        Ok(())
    });
    let use_case = AuthLogin::new(app_store, credentials);

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await
        .unwrap();

    assert_eq!(result.store_front, "143454-1");
}

#[tokio::test]
async fn execute_grandslam_rejects_account_without_purchase_token() {
    let mut account = test_account();
    account.password_token.clear();
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate_grandslam()
        .return_once(|_, _, _| Ok(account));
    let credentials = CredentialRepo::new();
    let use_case = AuthLogin::new(app_store, credentials);

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await;

    let Err(AppStoreError::AuthenticationFailed(message)) = result else {
        panic!("expected AuthenticationFailed");
    };
    assert!(message.contains("purchase token"));
}

#[tokio::test]
async fn execute_grandslam_preserves_store_front_from_spd() {
    // test_account() already carries a store front; the derived value must
    // not overwrite one Apple actually provided.
    let mut app_store = AppStoreRepo::new();
    app_store
        .expect_authenticate_grandslam()
        .return_once(|_, _, _| Ok(test_account()));
    let mut credentials = CredentialRepo::new();
    credentials.expect_save_account().return_once(|_| Ok(()));
    let use_case = AuthLogin::new(app_store, credentials);

    let result = use_case
        .execute_grandslam("test@example.com", "password", "guid123", Some("143454-1"))
        .await
        .unwrap();

    assert_eq!(result.store_front, "143441-2,26");
}
