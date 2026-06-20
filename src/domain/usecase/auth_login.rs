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
        tracing::debug!(
            email_present = !email.is_empty(),
            guid_len = guid.len(),
            "starting legacy auth login"
        );
        let account = self.app_store.authenticate(email, password, guid).await?;

        tracing::debug!(
            has_purchase_token = !account.password_token.is_empty(),
            has_cookies = !account.cookies.is_empty(),
            "legacy auth login succeeded; saving account"
        );
        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        tracing::debug!("legacy auth account saved");
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
        tracing::debug!(
            email_present = !email.is_empty(),
            code_len = code.len(),
            guid_len = guid.len(),
            "starting legacy auth login with 2fa"
        );
        let account = self
            .app_store
            .authenticate_with_2fa(email, password, code, guid)
            .await?;

        tracing::debug!(
            has_purchase_token = !account.password_token.is_empty(),
            has_cookies = !account.cookies.is_empty(),
            "legacy 2fa auth succeeded; saving account"
        );
        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        tracing::debug!("legacy 2fa auth account saved");
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
        tracing::debug!(
            email_present = !email.is_empty(),
            guid_len = guid.len(),
            store_front_present = store_front.is_some_and(|s| !s.is_empty()),
            "starting grandslam auth login"
        );
        let mut account = self
            .app_store
            .authenticate_grandslam(email, password, guid)
            .await?;

        let store_front_was_empty = account.store_front.is_empty();
        // The GrandSlam SPD payload omits the iTunes Store front, so apply the
        // caller-resolved value (from --country / locale) when it is missing;
        // never override one Apple did provide.
        if let Some(store_front) = store_front.filter(|s| !s.is_empty())
            && account.store_front.is_empty()
        {
            account.store_front = store_front.to_string();
        }
        tracing::debug!(
            has_purchase_token = !account.password_token.is_empty(),
            store_front_applied = store_front_was_empty && !account.store_front.is_empty(),
            "grandslam auth login succeeded; validating account"
        );
        if account.password_token.is_empty() {
            tracing::warn!("grandslam auth login missing purchase token");
            return Err(AppStoreError::AuthenticationFailed(
                "GrandSlam login did not return an App Store purchase token; retry without --grandslam".into(),
            ));
        }

        self.credentials
            .save_account(&account)
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?;

        tracing::debug!("grandslam auth account saved");
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
        tracing::debug!(
            dsid_len = dsid.len(),
            idms_token_present = !idms_token.is_empty(),
            "requesting trusted-device 2fa notification"
        );
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
        tracing::debug!(
            dsid_len = dsid.len(),
            idms_token_present = !idms_token.is_empty(),
            code_len = code.len(),
            "validating trusted-device 2fa code"
        );
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
        tracing::debug!("completing trusted-device grandslam 2fa");
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
        tracing::debug!(
            dsid_len = dsid.len(),
            idms_token_present = !idms_token.is_empty(),
            "listing trusted phone numbers"
        );
        let phones = self
            .app_store
            .list_trusted_phone_numbers(dsid, idms_token)
            .await?;
        tracing::debug!(
            trusted_phone_count = phones.len(),
            "trusted phone numbers listed"
        );
        Ok(phones)
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
        tracing::debug!(
            dsid_len = dsid.len(),
            idms_token_present = !idms_token.is_empty(),
            phone_id,
            "requesting sms 2fa code"
        );
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
        tracing::debug!(
            dsid_len = dsid.len(),
            idms_token_present = !idms_token.is_empty(),
            phone_id,
            code_len = code.len(),
            "validating sms 2fa code"
        );
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
        tracing::debug!(phone_id, "completing sms grandslam 2fa");
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
