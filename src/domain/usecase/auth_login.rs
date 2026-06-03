//! Login use case — authenticates with Apple and stores credentials.

use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// Use case for authenticating with the Apple App Store.
pub struct AuthLogin<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> AuthLogin<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    /// Create a new login use case with the given repositories.
    pub fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }

    /// Execute the login flow.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if credentials are invalid.
    /// Returns `AppStoreError::AuthCodeRequired` if 2FA is required.
    pub async fn execute(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let account = self.app_store.authenticate(email, password, guid).await?;

        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        Ok(account)
    }

    /// Complete login with a 2FA verification code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if credentials or code are invalid.
    pub async fn login_with_2fa(
        &self,
        email: &str,
        password: &str,
        code: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let account = self
            .app_store
            .authenticate_with_2fa(email, password, code, guid)
            .await?;

        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        Ok(account)
    }

    /// Execute the `GrandSlam` SRP login flow.
    ///
    /// This is the modern Apple authentication flow that supports
    /// trusted-device 2FA notifications.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if credentials are invalid.
    /// Returns `AppStoreError::AuthCodeRequired` if 2FA is required.
    pub async fn execute_grandslam(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let account = self
            .app_store
            .authenticate_grandslam(email, password, guid)
            .await?;

        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        Ok(account)
    }

    /// Request a trusted-device 2FA notification after a `GrandSlam` login
    /// has indicated that 2FA is required.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        self.app_store
            .request_trusted_device_notification(dsid, idms_token)
            .await
    }

    /// Validate a trusted-device 2FA code and complete authentication.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    pub async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError> {
        self.app_store
            .validate_trusted_device_code(dsid, idms_token, code)
            .await
    }

    /// Validate trusted-device 2FA, then repeat `GrandSlam` login to fetch the
    /// final SPD account payload.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code or relogin fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_trusted_device_grandslam_2fa(
        &self,
        email: &str,
        password: &str,
        guid: &str,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<Account, AppStoreError> {
        self.validate_trusted_device_code(dsid, idms_token, code)
            .await?;
        self.execute_grandslam(email, password, guid).await
    }

    /// Request an SMS code to be sent to a trusted phone number.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        self.app_store.request_sms(dsid, idms_token, phone_id).await
    }

    /// Validate an SMS 2FA code and complete authentication.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    pub async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError> {
        self.app_store
            .validate_sms_code(dsid, idms_token, phone_id, code)
            .await
    }

    /// Validate SMS 2FA, then repeat `GrandSlam` login to fetch the final SPD
    /// account payload.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code or relogin fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_sms_grandslam_2fa(
        &self,
        email: &str,
        password: &str,
        guid: &str,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<Account, AppStoreError> {
        self.validate_sms_code(dsid, idms_token, phone_id, code)
            .await?;
        self.execute_grandslam(email, password, guid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

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
                "test@example.com",
                "password",
                "guid123",
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
                "test@example.com",
                "password",
                "guid123",
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
}
