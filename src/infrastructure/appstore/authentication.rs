//! Apple authentication implementation.

mod account;

use self::account::build_account_from_response;
use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::AppleHttpClient;
use std::collections::HashMap;
use std::time::Duration;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
/// Spurious `failureType` Apple sometimes returns on the first attempt; retried.
const SPURIOUS_FAILURE_TYPE: &str = "-5000";
#[cfg(target_os = "macos")]
pub(super) const CONFIGURATOR_USER_AGENT: &str =
    "Configurator/2.21 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";
#[cfg(not(target_os = "macos"))]
pub(super) const CONFIGURATOR_USER_AGENT: &str =
    "Configurator/2.15 (Macintosh; OperatingSystem X 11.0.0; 16G29) AppleWebKit/2603.3.8";

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
    authenticate_with_attempt(client, auth_url, email, password, guid, false).await
}

async fn authenticate_with_attempt(
    client: &AppleHttpClient,
    auth_url: &str,
    email: &str,
    password: &str,
    guid: &str,
    has_auth_code: bool,
) -> Result<Account, AppStoreError> {
    let is_mzfinance_auth = auth_url.contains("MZFinance.woa/wa/authenticate");
    let auth_url = auth_url_with_guid(auth_url, guid, has_auth_code);
    let login_attempt = if has_auth_code { "2" } else { "4" };
    let mut plist_pairs = vec![
        ("appleId", email),
        ("attempt", login_attempt),
        ("guid", guid),
        ("password", password),
        ("rmp", "0"),
        ("why", "signIn"),
    ];
    if is_mzfinance_auth {
        plist_pairs.push(("createSession", "true"));
    }
    let plist_body = crate::infrastructure::http::plist_codec::build_plist_dict(&plist_pairs);
    let plist_xml = crate::infrastructure::http::plist_codec::encode_plist(&plist_body)
        .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;
    let mut headers = HashMap::from([("User-Agent".into(), CONFIGURATOR_USER_AGENT.into())]);
    if is_mzfinance_auth {
        headers.insert(
            "Content-Type".into(),
            "application/x-www-form-urlencoded".into(),
        );
    }

    for attempt in 0..MAX_RETRIES {
        let request_headers = request_headers(&auth_url, &plist_xml, &headers).await?;

        let response = client
            .post_auth_plist_bytes(&auth_url, &plist_xml, Some(&request_headers))
            .await
            .map_err(|e| AppStoreError::NetworkError(e.to_string()))?;

        if response.status.is_server_error() {
            if attempt < MAX_RETRIES - 1 {
                tracing::warn!(
                    service = "ipakeep",
                    component = "authentication",
                    operation = "apple_login",
                    event_name = "auth.retry.scheduled",
                    attempt = attempt + 1,
                    max_attempts = MAX_RETRIES,
                    reason = "server_error",
                    retry_after_ms = RETRY_DELAY_MS,
                    "retrying Apple authentication"
                );
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            return Err(AppStoreError::NetworkError(format!(
                "Apple authentication endpoint returned HTTP {} after retries",
                response.status
            )));
        }

        if response.status == reqwest::StatusCode::NO_CONTENT && response.body.is_null() {
            if attempt < MAX_RETRIES - 1 {
                tracing::warn!(
                    service = "ipakeep",
                    component = "authentication",
                    operation = "apple_login",
                    event_name = "auth.retry.scheduled",
                    attempt = attempt + 1,
                    max_attempts = MAX_RETRIES,
                    reason = "no_auth_data",
                    retry_after_ms = RETRY_DELAY_MS,
                    "retrying Apple authentication"
                );
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            return Err(AppStoreError::NetworkError(
                "Apple returned HTTP 204 without authentication data; this does not confirm whether the password is correct".into(),
            ));
        }

        let failure_type = response
            .body
            .get("failureType")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if failure_type == SPURIOUS_FAILURE_TYPE {
            if attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            break;
        }

        return parse_auth_response(&response.body, &response.headers);
    }

    Err(AppStoreError::AuthenticationFailed(
        "authentication failed after retries".into(),
    ))
}

async fn request_headers(
    auth_url: &str,
    plist_xml: &[u8],
    headers: &HashMap<String, String>,
) -> Result<HashMap<String, String>, AppStoreError> {
    #[cfg(target_os = "macos")]
    if is_native_auth_url(auth_url) {
        let mut headers = headers.clone();
        headers.extend(super::native_auth::request_headers(auth_url, plist_xml).await?);
        return Ok(headers);
    }

    #[cfg(not(target_os = "macos"))]
    if is_native_auth_url(auth_url) {
        return Err(AppStoreError::AuthenticationFailed(
            "Apple's native App Store login requires macOS Store signing and device proof".into(),
        ));
    }

    let _ = plist_xml;
    Ok(headers.clone())
}

fn is_native_auth_url(auth_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(auth_url) else {
        return false;
    };

    url.scheme() == "https"
        && url.host_str() == Some("auth.itunes.apple.com")
        && url.path() == "/auth/v1/native"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port_or_known_default() == Some(443)
        && url.fragment().is_none()
}

fn auth_url_with_guid(auth_url: &str, guid: &str, has_auth_code: bool) -> String {
    let auth_url = if has_auth_code {
        auth_url.replace("://p25-buy.itunes.apple.com", "://p71-buy.itunes.apple.com")
    } else {
        auth_url.to_string()
    };

    if let Ok(mut url) = reqwest::Url::parse(&auth_url) {
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
    authenticate_with_attempt(client, auth_url, email, &combined_password, guid, true).await
}

/// Parse the authentication response from Apple.
fn parse_auth_response(
    body: &serde_json::Value,
    headers: &reqwest::header::HeaderMap,
) -> Result<Account, AppStoreError> {
    check_auth_failures(body)?;
    build_account_from_response(body, headers)
}

/// Map Apple's failure signals to the corresponding error, if any.
fn check_auth_failures(body: &serde_json::Value) -> Result<(), AppStoreError> {
    let failure_type = body
        .get("failureType")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let customer_message = body
        .get("customerMessage")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if failure_type.is_empty()
        && customer_message.contains("MZFinance.BadLogin.Configurator_message")
    {
        return Err(AppStoreError::AuthCodeRequired {
            dsid: String::new(),
            idms_token: String::new(),
        });
    }

    if customer_message.contains("disabled") {
        return Err(AppStoreError::AccountDisabled);
    }

    if !failure_type.is_empty() && failure_type != SPURIOUS_FAILURE_TYPE {
        return Err(AppStoreError::AuthenticationFailed(
            customer_message.to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_url_with_guid_replaces_existing_guid() {
        let url = auth_url_with_guid(
            "https://auth.itunes.apple.com/auth/v1/native/fast?guid=old&foo=bar",
            "new",
            false,
        );

        assert_eq!(
            url,
            "https://auth.itunes.apple.com/auth/v1/native/fast?guid=new&foo=bar"
        );
    }

    #[test]
    fn native_auth_url_requires_the_exact_apple_origin_and_path() {
        assert!(is_native_auth_url(
            "https://auth.itunes.apple.com/auth/v1/native?guid=GUID"
        ));
        assert!(!is_native_auth_url(
            "https://auth.itunes.apple.com.example.invalid/auth/v1/native"
        ));
        assert!(!is_native_auth_url(
            "https://auth.itunes.apple.com/auth/v1/native/fast"
        ));
        assert!(!is_native_auth_url(
            "http://auth.itunes.apple.com/auth/v1/native"
        ));
    }

    #[tokio::test]
    async fn non_native_auth_headers_are_preserved() {
        let headers = HashMap::from([("User-Agent".into(), "safe-agent".into())]);

        let result = request_headers("https://example.invalid/auth", b"", &headers)
            .await
            .expect("non-native headers");

        assert_eq!(result, headers);
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn native_auth_headers_fail_closed_off_macos() {
        let result = request_headers(
            "https://auth.itunes.apple.com/auth/v1/native",
            b"",
            &HashMap::new(),
        )
        .await;

        assert!(matches!(
            result,
            Err(AppStoreError::AuthenticationFailed(_))
        ));
    }
}
