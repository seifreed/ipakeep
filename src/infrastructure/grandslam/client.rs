//! `GrandSlam` HTTP client for Apple SRP authentication.
//!
//! Communicates with `gsa.apple.com` to perform SRP login and
//! two-factor authentication flows.

mod account;
mod app_token;
mod http;
mod response;
mod srp_flow;
mod srp_response;
mod two_factor;

use crate::domain::entity::{Account, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
pub use srp_flow::{SrpCompleteResult, SrpInitResponse};

const GRANDSLAM_URL: &str = "https://gsa.apple.com/grandslam/GsService2";

/// Client for Apple `GrandSlam` authentication endpoints.
#[derive(Debug, Clone)]
pub struct GrandSlamClient {
    client: reqwest::Client,
}

impl GrandSlamClient {
    /// Create a new `GrandSlam` client from an existing HTTP client.
    ///
    /// Sharing the `reqwest::Client` ensures cookies are persisted
    /// across legacy and `GrandSlam` requests.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Perform the first step of SRP authentication (init).
    ///
    /// Generates a client ephemeral, embeds it with Anisette CPD, and
    /// POSTs to Apple's `GrandSlam` endpoint.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    /// Returns `AppStoreError::AuthenticationFailed` if Apple rejects the init.
    pub async fn srp_init(&self, email: &str) -> Result<SrpInitResponse, AppStoreError> {
        srp_flow::init(&self.client, email).await
    }

    /// Perform the second step of SRP authentication (complete).
    ///
    /// Derives the SRP password, computes the client proof `M1`, and
    /// completes the exchange with Apple.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if credentials are invalid.
    /// Returns `AppStoreError::AuthCodeRequired` if 2FA is required.
    pub async fn srp_complete(
        &self,
        email: &str,
        password: &str,
        init: &SrpInitResponse,
    ) -> Result<SrpCompleteResult, AppStoreError> {
        srp_flow::complete(&self.client, email, password, init).await
    }

    /// Request a service-specific `GrandSlam` app token for an account.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the stored
    /// `GrandSlam` account state is incomplete or Apple rejects the request.
    pub async fn request_app_token(
        &self,
        account: &Account,
        app: &str,
    ) -> Result<String, AppStoreError> {
        app_token::request_app_token(&self.client, account, app).await
    }

    /// Send a trusted-device notification to trigger the Apple ID 2FA
    /// approval prompt on all trusted devices.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        two_factor::request_trusted_device_notification(&self.client, dsid, idms_token).await
    }

    /// List the account's trusted phone numbers for SMS 2FA.
    ///
    /// Reads Apple's HSA2 auth-options endpoint, whose `trustedPhoneNumbers`
    /// array carries the numeric `id` each number must be addressed by when
    /// requesting or validating an SMS code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails or the
    /// response is not valid JSON.
    pub async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
        two_factor::list_trusted_phone_numbers(&self.client, dsid, idms_token).await
    }

    /// Validate a trusted-device 2FA code.
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
        two_factor::validate_trusted_device_code(&self.client, dsid, idms_token, code).await
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
        two_factor::request_sms(&self.client, dsid, idms_token, phone_id).await
    }

    /// Validate an SMS 2FA code.
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
        two_factor::validate_sms_code(&self.client, dsid, idms_token, phone_id, code).await
    }
}

#[cfg(test)]
mod tests;
