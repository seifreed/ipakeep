//! Apple authentication implementation.

use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::AppleHttpClient;
use reqwest::header::SET_COOKIE;
use std::collections::HashMap;
use std::time::Duration;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
const CONFIGURATOR_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

/// Authenticate with Apple using email and password.
///
/// Handles 302 redirects and spurious -5000 errors that Apple
/// sometimes returns on the first attempt. Retries up to 3 times.
///
/// # Errors
///
/// Returns `AppStoreError::NetworkError` if the HTTP request fails.
/// Returns `AppStoreError::AuthCodeRequired` if 2FA is needed.
/// Returns `AppStoreError::AuthenticationFailed` if credentials are invalid.
pub async fn authenticate(
    client: &AppleHttpClient,
    auth_url: &str,
    email: &str,
    password: &str,
    guid: &str,
) -> Result<Account, AppStoreError> {
    authenticate_with_attempt(client, auth_url, email, password, guid, "4").await
}

async fn authenticate_with_attempt(
    client: &AppleHttpClient,
    auth_url: &str,
    email: &str,
    password: &str,
    guid: &str,
    login_attempt: &str,
) -> Result<Account, AppStoreError> {
    let auth_url = auth_url_with_guid(auth_url, guid);
    let plist_body = crate::infrastructure::http::plist_codec::build_plist_dict(&[
        ("appleId", email),
        ("password", password),
        ("attempt", login_attempt),
        ("guid", guid),
        ("why", "signIn"),
        ("rmp", "0"),
    ]);
    let headers = HashMap::from([("User-Agent".into(), CONFIGURATOR_USER_AGENT.into())]);

    for attempt in 0..MAX_RETRIES {
        let response = client
            .post_plist(&auth_url, &plist_body, Some(&headers))
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;

        let failure_type = response
            .body
            .get("failureType")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if failure_type == "-5000" && attempt < MAX_RETRIES - 1 {
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            continue;
        }

        return parse_auth_response(&response.body, &response.headers);
    }

    Err(AppStoreError::AuthenticationFailed(
        "authentication failed after retries".into(),
    ))
}

fn auth_url_with_guid(auth_url: &str, guid: &str) -> String {
    if let Ok(mut url) = reqwest::Url::parse(auth_url) {
        let mut pairs = Vec::new();
        let mut replaced = false;

        for (key, value) in url.query_pairs() {
            if key == "guid" {
                if !replaced {
                    pairs.push((key.to_string(), guid.to_string()));
                    replaced = true;
                }
            } else {
                pairs.push((key.to_string(), value.to_string()));
            }
        }

        if !replaced {
            pairs.push(("guid".into(), guid.into()));
        }

        url.set_query(None);
        url.query_pairs_mut().extend_pairs(pairs);
        return url.to_string();
    }

    let separator = if auth_url.contains('?') { '&' } else { '?' };
    format!("{auth_url}{separator}guid={guid}")
}

/// Authenticate with Apple using email, password, and a 2FA code.
///
/// The 2FA code is appended to the password.
///
/// # Errors
///
/// Returns the same errors as [`authenticate`].
pub async fn authenticate_with_2fa(
    client: &AppleHttpClient,
    auth_url: &str,
    email: &str,
    password: &str,
    code: &str,
    guid: &str,
) -> Result<Account, AppStoreError> {
    let combined_password = format!("{password}{code}");
    authenticate_with_attempt(client, auth_url, email, &combined_password, guid, "2").await
}

/// Parse the authentication response from Apple.
fn parse_auth_response(
    body: &serde_json::Value,
    headers: &reqwest::header::HeaderMap,
) -> Result<Account, AppStoreError> {
    // Check for 2FA requirement
    let failure_type = body
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let customer_message = body
        .get("customerMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check if 2FA code is required
    if failure_type.is_empty()
        && customer_message.contains("MZFinance.BadLogin.Configurator_message")
    {
        return Err(AppStoreError::AuthCodeRequired {
            dsid: String::new(),
            idms_token: String::new(),
        });
    }

    // Check for account disabled
    if customer_message.contains("disabled") {
        return Err(AppStoreError::AccountDisabled);
    }

    // Check for invalid credentials
    if !failure_type.is_empty() && failure_type != "-5000" {
        return Err(AppStoreError::AuthenticationFailed(
            customer_message.to_string(),
        ));
    }

    // Extract account data from successful response
    let password_token = body
        .get("passwordToken")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppStoreError::AuthenticationFailed("missing passwordToken".into()))?
        .to_string();

    let ds_person_id = body
        .get("dsPersonId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppStoreError::AuthenticationFailed("missing dsPersonId".into()))?
        .to_string();

    let account_info = body
        .get("accountInfo")
        .ok_or_else(|| AppStoreError::AuthenticationFailed("missing accountInfo".into()))?;

    let email = account_info
        .get("appleId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let first_name = account_info
        .get("address")
        .and_then(|a| a.get("firstName"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let last_name = account_info
        .get("address")
        .and_then(|a| a.get("lastName"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let name = format!("{first_name} {last_name}");

    let store_front = headers
        .get("x-set-apple-store-front")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let pod = headers
        .get("pod")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let cookies = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(std::string::ToString::to_string)
        .collect();

    Ok(Account {
        email,
        name,
        password_token,
        directory_services_id: ds_person_id,
        store_front,
        pod,
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_url_with_guid_replaces_existing_guid() {
        let url = auth_url_with_guid(
            "https://auth.itunes.apple.com/auth/v1/native/fast?guid=old&foo=bar",
            "new",
        );

        assert_eq!(
            url,
            "https://auth.itunes.apple.com/auth/v1/native/fast?guid=new&foo=bar"
        );
    }
}
