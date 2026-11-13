//! Remote Anisette server adapter.

use super::AnisetteData;
use super::fields::{AnisetteFields, build_cpd, build_headers};
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::telemetry::{read_response_json, send_with_observability};
use serde_json::Value as JsonValue;

pub(super) async fn fetch_remote(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<AnisetteData, AppStoreError> {
    let url = base_url.trim_end_matches('/').to_string();
    let response = send_with_observability(client, client.get(&url))
        .await
        .map_err(|e| AppStoreError::NetworkError(format!("anisette server request failed: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        return Err(AppStoreError::NetworkError(format!(
            "anisette server returned HTTP {status}"
        )));
    }

    let body: JsonValue = read_response_json(response).await.map_err(|e| {
        AppStoreError::NetworkError(format!("anisette server response decode failed: {e}"))
    })?;
    let obj = body.as_object().ok_or_else(|| {
        AppStoreError::NetworkError("anisette server response is not a JSON object".into())
    })?;

    let fields = AnisetteFields::from_remote(obj)?;
    let mut headers = build_headers(&fields);
    if let Some(user_agent) = fetch_remote_user_agent(client, &url, &fields.client_info).await? {
        headers.insert("User-Agent".into(), user_agent);
    }
    Ok(AnisetteData {
        headers,
        cpd: build_cpd(&fields),
    })
}

async fn fetch_remote_user_agent(
    client: &reqwest::Client,
    base_url: &str,
    client_info: &str,
) -> Result<Option<String>, AppStoreError> {
    let url = format!("{base_url}/v3/client_info");
    let response = send_with_observability(client, client.get(&url))
        .await
        .map_err(|e| {
            AppStoreError::NetworkError(format!("anisette client info request failed: {e}"))
        })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status().map_err(|e| {
        AppStoreError::NetworkError(format!(
            "anisette client info request failed: {}",
            e.without_url()
        ))
    })?;
    let body: JsonValue = read_response_json(response).await.map_err(|e| {
        AppStoreError::NetworkError(format!("anisette client info decode failed: {e}"))
    })?;
    let info = body.get("client_info").and_then(JsonValue::as_str);
    let user_agent = body.get("user_agent").and_then(JsonValue::as_str);
    match (info, user_agent) {
        (Some(info), Some(user_agent)) if info == client_info && !user_agent.is_empty() => {
            Ok(Some(user_agent.to_string()))
        }
        _ => Err(AppStoreError::AuthenticationFailed(
            "anisette client info endpoint returned incomplete or inconsistent data".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn fetch_remote_maps_server_headers() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "X-Apple-I-MD": "remote-md",
                    "X-Apple-I-MD-M": "remote-md-m",
                    "X-Apple-I-MD-LU": "remote-lu",
                    "X-Apple-I-MD-RINFO": 50_660_608_u64,
                    "X-Mme-Device-Id": "REMOTE-DEVICE",
                    "X-Apple-I-SRL-NO": "REMOTE-SERIAL",
                    "X-Apple-I-Client-Time": "2026-01-01T00:00:00Z",
                    "X-Apple-I-TimeZone": "UTC",
                    "X-Apple-Locale": "es_ES",
                    "X-MMe-Client-Info": "REMOTE-CLIENT-INFO",
                })),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(method("GET"))
            .and(path("/v3/client_info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "client_info": "REMOTE-CLIENT-INFO",
                    "user_agent": "REMOTE-USER-AGENT",
                })),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let data = fetch_remote(&client, &server.uri())
            .await
            .expect("remote anisette");

        assert_eq!(data.headers.get("X-Apple-I-MD").unwrap(), "remote-md");
        assert_eq!(data.headers.get("X-Apple-I-MD-M").unwrap(), "remote-md-m");
        assert_eq!(
            data.headers.get("X-Mme-Device-Id").unwrap(),
            "REMOTE-DEVICE"
        );
        assert_eq!(
            data.headers.get("X-Apple-I-SRL-NO").unwrap(),
            "REMOTE-SERIAL"
        );
        assert_eq!(data.headers.get("X-Apple-I-Locale").unwrap(), "es_ES");
        assert_eq!(
            data.headers.get("X-MMe-Client-Info").unwrap(),
            "REMOTE-CLIENT-INFO"
        );
        assert_eq!(data.headers.get("User-Agent").unwrap(), "REMOTE-USER-AGENT");
        assert_eq!(data.cpd["X-MMe-Client-Info"], "REMOTE-CLIENT-INFO");
        assert_eq!(data.headers.get("X-Apple-I-MD-RINFO").unwrap(), "50660608");

        let cpd = data.cpd.as_object().unwrap();
        assert_eq!(
            cpd.get("X-Apple-I-MD").unwrap().as_str().unwrap(),
            "remote-md"
        );
        assert_eq!(cpd.get("cl").unwrap().as_str().unwrap(), "es_ES");
    }

    #[tokio::test]
    async fn fetch_remote_rejects_unprovisioned_server() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "X-Apple-I-TimeZone": "UTC" })),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let result = fetch_remote(&client, &server.uri()).await;
        assert!(matches!(
            result,
            Err(AppStoreError::AuthenticationFailed(_))
        ));
    }

    #[tokio::test]
    async fn fetch_remote_user_agent_allows_legacy_server() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/v3/client_info"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let result = fetch_remote_user_agent(&reqwest::Client::new(), &server.uri(), "info").await;
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn fetch_remote_user_agent_rejects_mismatched_client_info() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/v3/client_info"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "client_info": "OTHER-CLIENT-INFO",
                    "user_agent": "REMOTE-USER-AGENT",
                })),
            )
            .mount(&server)
            .await;

        let result = fetch_remote_user_agent(&reqwest::Client::new(), &server.uri(), "info").await;
        assert!(matches!(
            result,
            Err(AppStoreError::AuthenticationFailed(_))
        ));
    }
}
