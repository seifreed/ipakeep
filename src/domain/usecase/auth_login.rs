//! Login use case — authenticates with Apple and stores credentials.

use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// `GrandSlam` login credentials reused across the SRP login and 2FA flows.
pub struct GrandslamCredentials<'a> {
    /// Apple ID email.
    pub email: &'a str,
    /// Apple ID password.
    pub password: &'a str,
    /// Device GUID (MAC-derived).
    pub guid: &'a str,
    /// Store front to apply when the `GrandSlam` SPD omits it (e.g. `143454-1`).
    pub store_front: Option<&'a str>,
}

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
        store_front: Option<&str>,
    ) -> Result<Account, AppStoreError> {
        let mut account = self
            .app_store
            .authenticate_grandslam(email, password, guid)
            .await?;

        // The GrandSlam SPD payload omits the iTunes Store front, so apply the
        // caller-resolved value (from --country / locale) when it is missing;
        // never override one Apple did provide.
        if let Some(store_front) = store_front.filter(|s| !s.is_empty())
            && account.store_front.is_empty()
        {
            account.store_front = store_front.to_string();
        }
        if account.password_token.is_empty() {
            return Err(AppStoreError::AuthenticationFailed(
                "GrandSlam login did not return an App Store purchase token; retry without --grandslam".into(),
            ));
        }

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
    pub async fn complete_trusted_device_grandslam_2fa(
        &self,
        credentials: &GrandslamCredentials<'_>,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<Account, AppStoreError> {
        self.validate_trusted_device_code(dsid, idms_token, code)
            .await?;
        self.execute_grandslam(
            credentials.email,
            credentials.password,
            credentials.guid,
            credentials.store_front,
        )
        .await
    }

    /// List the account's trusted phone numbers for SMS 2FA.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<crate::domain::entity::TrustedPhoneNumber>, AppStoreError> {
        self.app_store
            .list_trusted_phone_numbers(dsid, idms_token)
            .await
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
    pub async fn complete_sms_grandslam_2fa(
        &self,
        credentials: &GrandslamCredentials<'_>,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<Account, AppStoreError> {
        self.validate_sms_code(dsid, idms_token, phone_id, code)
            .await?;
        self.execute_grandslam(
            credentials.email,
            credentials.password,
            credentials.guid,
            credentials.store_front,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
