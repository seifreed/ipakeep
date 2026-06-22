//! Async client for the Apple Developer Services plist protocol.
//!
//! Authenticated with the Xcode `GrandSlam` app token plus anisette headers.
//! Endpoints are reverse-engineered (`AltSign`/`SideStore`) and unverifiable
//! without a paid account — the pure request/response helpers are unit-tested;
//! these methods are the live integration.

use super::parsing::{self, Certificate, Device, Team};
use super::request;
use crate::domain::entity::Account;
use crate::infrastructure::grandslam::{AnisetteData, GrandSlamClient, resolve_anisette};
use crate::infrastructure::http::client::AppleHttpClient;
use std::collections::HashMap;

const BASE_URL: &str = "https://developerservices2.apple.com/services/QH65B2/";
const XCODE_TOKEN_APP: &str = "com.apple.gs.xcode.auth";

/// Live client bound to a logged-in account.
pub struct DeveloperClient {
    http: AppleHttpClient,
    identity_id: String,
    gs_token: String,
    anisette: AnisetteData,
}

impl DeveloperClient {
    /// Authenticate for `account` (fetches the Xcode token + anisette).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client, app token, or anisette fail.
    pub async fn for_account(account: &Account) -> Result<Self, String> {
        let http = AppleHttpClient::new().map_err(|e| e.to_string())?;
        let grandslam = GrandSlamClient::new(http.client().clone());
        let gs_token = grandslam
            .request_app_token(account, XCODE_TOKEN_APP)
            .await
            .map_err(|e| e.to_string())?;
        let anisette = resolve_anisette(http.client())
            .await
            .map_err(|e| e.to_string())?;
        let identity_id = account
            .adsid
            .as_deref()
            .or(account.dsid.as_deref())
            .filter(|s| !s.is_empty())
            .unwrap_or(account.directory_services_id.as_str())
            .to_string();

        Ok(Self {
            http,
            identity_id,
            gs_token,
            anisette,
        })
    }

    async fn post(
        &self,
        action: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{BASE_URL}{action}");
        let headers: HashMap<String, String> =
            request::headers(&self.identity_id, &self.gs_token, &self.anisette);
        let response = self
            .http
            .post_plist(&url, body, Some(&headers))
            .await
            .map_err(|e| e.to_string())?;
        Ok(response.body)
    }

    /// List the account's development teams.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or Apple reports an error.
    pub async fn list_teams(&self) -> Result<Vec<Team>, String> {
        let body = serde_json::Value::Object(request::base_body(None));
        parsing::parse_teams(&self.post("listTeams.action", &body).await?)
    }

    /// List devices registered to `team_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or Apple reports an error.
    pub async fn list_devices(&self, team_id: &str) -> Result<Vec<Device>, String> {
        let body = serde_json::Value::Object(request::base_body(Some(team_id)));
        parsing::parse_devices(&self.post("ios/listDevices.action", &body).await?)
    }

    /// Register `udid` under `team_id` (no-op if already registered).
    ///
    /// # Errors
    ///
    /// Returns an error only for unexpected failures; an "already registered"
    /// result is treated as success.
    pub async fn register_device(
        &self,
        team_id: &str,
        udid: &str,
        name: &str,
    ) -> Result<(), String> {
        if self
            .list_devices(team_id)
            .await?
            .iter()
            .any(|d| d.udid == udid)
        {
            return Ok(());
        }
        let body = request::add_device_body(team_id, udid, name);
        parsing::check_result(&self.post("ios/addDevice.action", &body).await?)
    }

    /// Submit a CSR and receive a development certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or no certificate is returned.
    pub async fn submit_csr(
        &self,
        team_id: &str,
        csr_pem: &str,
        machine_name: &str,
    ) -> Result<Certificate, String> {
        let body = request::submit_csr_body(team_id, csr_pem, machine_name);
        parsing::parse_certificate(&self.post("ios/submitDevelopmentCSR.action", &body).await?)
    }

    /// Download the team provisioning profile for `app_id_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or no profile is returned.
    pub async fn download_profile(
        &self,
        team_id: &str,
        app_id_id: &str,
    ) -> Result<Vec<u8>, String> {
        let body = request::download_profile_body(team_id, app_id_id);
        parsing::parse_profile(
            &self
                .post("ios/downloadTeamProvisioningProfile.action", &body)
                .await?,
        )
    }
}
