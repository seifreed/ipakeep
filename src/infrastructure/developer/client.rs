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
    base_url: String,
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
            base_url: BASE_URL.into(),
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
        let url = format!("{}{action}", self.base_url);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::http::plist_codec::encode_plist;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> DeveloperClient {
        DeveloperClient {
            http: AppleHttpClient::new().expect("HTTP client"),
            base_url: format!("{}/services/QH65B2/", server.uri()),
            identity_id: "12345".into(),
            gs_token: "token".into(),
            anisette: AnisetteData {
                headers: HashMap::new(),
                cpd: json!({}),
            },
        }
    }

    async fn mount_plist(server: &MockServer, action: &str, body: serde_json::Value) {
        let plist = encode_plist(&body).expect("plist response");
        Mock::given(method("POST"))
            .and(path(format!("/services/QH65B2/{action}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(plist, "application/x-apple-plist"),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn developer_operations_parse_local_plist_responses() {
        let server = MockServer::start().await;
        mount_plist(
            &server,
            "listTeams.action",
            json!({"teams": [{"teamId": "TEAM", "name": "Example"}]}),
        )
        .await;
        mount_plist(
            &server,
            "ios/listDevices.action",
            json!({"devices": [{"deviceId": "1", "deviceNumber": "UDID"}]}),
        )
        .await;
        mount_plist(
            &server,
            "ios/submitDevelopmentCSR.action",
            json!({"certRequest": {"serialNumber": "01", "certContent": "AQID"}}),
        )
        .await;
        mount_plist(
            &server,
            "ios/downloadTeamProvisioningProfile.action",
            json!({"provisioningProfile": {"encodedProfile": "UFJPRklMRQ=="}}),
        )
        .await;

        let client = client(&server);
        assert_eq!(client.list_teams().await.expect("teams")[0].id, "TEAM");
        assert_eq!(
            client.list_devices("TEAM").await.expect("devices")[0].udid,
            "UDID"
        );
        client
            .register_device("TEAM", "UDID", "device")
            .await
            .expect("existing device is a no-op");
        let certificate = client
            .submit_csr("TEAM", "csr", "machine")
            .await
            .expect("certificate");
        assert_eq!(certificate.der, [1, 2, 3]);
        assert_eq!(
            client
                .download_profile("TEAM", "APP")
                .await
                .expect("profile"),
            b"PROFILE"
        );
    }

    #[tokio::test]
    async fn register_device_adds_missing_device_and_surfaces_http_errors() {
        let server = MockServer::start().await;
        mount_plist(&server, "ios/listDevices.action", json!({"devices": []})).await;
        mount_plist(&server, "ios/addDevice.action", json!({"resultCode": 0})).await;
        client(&server)
            .register_device("TEAM", "NEW-UDID", "device")
            .await
            .expect("register device");

        let failed = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/services/QH65B2/listTeams.action"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&failed)
            .await;
        assert!(client(&failed).list_teams().await.is_err());
    }

    fn account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: String::new(),
            directory_services_id: "12345".into(),
            store_front: String::new(),
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
    async fn provision_rejects_missing_grandslam_state_before_network_access() {
        let account = account();
        let request = super::super::ProvisionRequest {
            account: &account,
            team_id: Some("TEAM"),
            device_udid: "UDID",
            device_name: "device",
            app_id_id: "APP",
        };

        let error = super::super::provision(&request)
            .await
            .err()
            .expect("incomplete account must fail before contacting Apple");

        assert!(error.contains("GrandSlam"));
    }

    #[tokio::test]
    async fn provision_with_client_runs_the_complete_local_flow() {
        let server = MockServer::start().await;
        mount_plist(
            &server,
            "ios/listDevices.action",
            json!({"devices": [{"deviceId": "1", "deviceNumber": "UDID"}]}),
        )
        .await;
        mount_plist(
            &server,
            "ios/submitDevelopmentCSR.action",
            json!({"certRequest": {"serialNumber": "01", "certContent": "AQID"}}),
        )
        .await;
        mount_plist(
            &server,
            "ios/downloadTeamProvisioningProfile.action",
            json!({"provisioningProfile": {"encodedProfile": "UFJPRklMRQ=="}}),
        )
        .await;
        let account = account();
        let request = super::super::ProvisionRequest {
            account: &account,
            team_id: Some("TEAM"),
            device_udid: "UDID",
            device_name: "device",
            app_id_id: "APP",
        };

        let result = super::super::provision_with_client(&request, &client(&server))
            .await
            .expect("local provisioning flow");

        assert_eq!(result.team_id, "TEAM");
        assert_eq!(result.certificate_der, [1, 2, 3]);
        assert_eq!(result.certificate_serial, "01");
        assert_eq!(result.mobileprovision, b"PROFILE");
        assert!(!result.key_pem.is_empty());
    }

    #[tokio::test]
    async fn provision_requires_a_team_when_account_has_none() {
        let server = MockServer::start().await;
        mount_plist(&server, "listTeams.action", json!({"teams": []})).await;
        let account = account();
        let request = super::super::ProvisionRequest {
            account: &account,
            team_id: None,
            device_udid: "UDID",
            device_name: "device",
            app_id_id: "APP",
        };

        let error = super::super::provision_with_client(&request, &client(&server))
            .await
            .err()
            .expect("empty team list must fail");

        assert!(error.contains("no development teams"));
    }
}
