//! Remote Anisette server adapter.

use super::AnisetteData;
use super::fields::{AnisetteFields, build_cpd, build_headers};
use crate::domain::error::AppStoreError;
use serde_json::Value as JsonValue;

pub(super) async fn fetch_remote(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<AnisetteData, AppStoreError> {
    let url = base_url.trim_end_matches('/').to_string();
    let response = client.get(&url).send().await.map_err(|e| {
        AppStoreError::NetworkError(format!("anisette server request to {url} failed: {e}"))
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(AppStoreError::NetworkError(format!(
            "anisette server returned HTTP {status}"
        )));
    }

    let body: JsonValue = response.json().await.map_err(|e| {
        AppStoreError::NetworkError(format!("anisette server response decode failed: {e}"))
    })?;
    let obj = body.as_object().ok_or_else(|| {
        AppStoreError::NetworkError("anisette server response is not a JSON object".into())
    })?;

    let fields = AnisetteFields::from_remote(obj)?;
    Ok(AnisetteData {
        headers: build_headers(&fields),
        cpd: build_cpd(&fields),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_remote_maps_server_headers() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
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
}
