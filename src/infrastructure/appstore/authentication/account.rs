use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use reqwest::header::SET_COOKIE;

/// Build an [`Account`] from a successful authentication response.
pub(super) fn build_account_from_response(
    body: &serde_json::Value,
    headers: &reqwest::header::HeaderMap,
) -> Result<Account, AppStoreError> {
    let password_token = required_str(body, "passwordToken")?;
    let ds_person_id = required_str(body, "dsPersonId")?;

    let account_info = body
        .get("accountInfo")
        .ok_or_else(|| AppStoreError::AuthenticationFailed("missing accountInfo".into()))?;

    let email = account_info
        .get("appleId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Account {
        email,
        name: account_full_name(account_info),
        password_token,
        directory_services_id: ds_person_id,
        store_front: header_str(headers, "x-set-apple-store-front"),
        pod: header_str(headers, "pod"),
        idms_token: None,
        dsid: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: response_cookies(headers),
    })
}

fn required_str(body: &serde_json::Value, key: &str) -> Result<String, AppStoreError> {
    body.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| AppStoreError::AuthenticationFailed(format!("missing {key}")))
}

fn account_full_name(account_info: &serde_json::Value) -> String {
    let address_field = |field: &str| {
        account_info
            .get("address")
            .and_then(|a| a.get(field))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    format!(
        "{} {}",
        address_field("firstName"),
        address_field("lastName")
    )
}

fn header_str(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn response_cookies(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(std::string::ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_account_from_response;
    use crate::domain::error::AppStoreError;
    use reqwest::header::{HeaderMap, HeaderValue, SET_COOKIE};
    use serde_json::json;

    #[test]
    fn rejects_missing_required_account_fields() {
        let headers = HeaderMap::new();
        assert!(matches!(
            build_account_from_response(&json!({"passwordToken": "token"}), &headers),
            Err(AppStoreError::AuthenticationFailed(message)) if message == "missing dsPersonId"
        ));
        assert!(matches!(
            build_account_from_response(
                &json!({"passwordToken": "token", "dsPersonId": "123"}),
                &headers
            ),
            Err(AppStoreError::AuthenticationFailed(message)) if message == "missing accountInfo"
        ));
    }

    #[test]
    fn ignores_header_values_that_are_not_valid_text() {
        let mut headers = HeaderMap::new();
        let invalid = HeaderValue::from_bytes(b"\xff").expect("header value");
        headers.insert("pod", invalid.clone());
        headers.append(SET_COOKIE, invalid);

        let account = build_account_from_response(
            &json!({"passwordToken": "token", "dsPersonId": "123", "accountInfo": {}}),
            &headers,
        )
        .expect("account fields are valid");

        assert!(account.pod.is_empty());
        assert!(account.cookies.is_empty());
    }
}
