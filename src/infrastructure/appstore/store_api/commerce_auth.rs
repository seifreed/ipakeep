//! Authentication headers for App Store commerce endpoints.

use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::AppleHttpClient;
use std::collections::HashMap;

/// US App Store storefront used when `GrandSlam` does not provide legacy store metadata.
const DEFAULT_US_STORE_FRONT: &str = "143441-1";

/// Apple Configurator user agent expected by `MZFinance` commerce endpoints.
const CONFIGURATOR_USER_AGENT: &str =
    "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6";

/// Origin used to replay cookies captured from native Apple authentication.
const AUTH_COOKIE_ORIGIN: &str = "https://auth.itunes.apple.com/";

/// Build authentication headers for `MZFinance` commerce endpoints.
pub(super) fn auth_headers(
    client: &AppleHttpClient,
    account: &Account,
) -> Result<HashMap<String, String>, AppStoreError> {
    seed_account_cookies(client, account)?;
    if !account.password_token.is_empty() {
        return Ok(legacy_purchase_headers(account));
    }

    Err(AppStoreError::AuthenticationFailed(
        "missing MZFinance passwordToken; GrandSlam IDMS/PET tokens cannot be used for App Store purchases; retry auth login without --grandslam".into(),
    ))
}

fn seed_account_cookies(client: &AppleHttpClient, account: &Account) -> Result<(), AppStoreError> {
    if account.cookies.is_empty() {
        return Ok(());
    }
    client.seed_cookies(&account.cookies, AUTH_COOKIE_ORIGIN)
}

fn identity_headers(account: &Account) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("User-Agent".into(), CONFIGURATOR_USER_AGENT.into());
    headers.insert("X-Dsid".into(), account.directory_services_id.clone());
    headers.insert("iCloud-DSID".into(), account.directory_services_id.clone());
    headers
}

/// Build legacy purchase authentication headers from an account.
fn legacy_purchase_headers(account: &Account) -> HashMap<String, String> {
    let mut headers = identity_headers(account);
    headers.insert("X-Token".into(), account.password_token.clone());
    let store_front = if account.store_front.is_empty() {
        DEFAULT_US_STORE_FRONT
    } else {
        &account.store_front
    };
    headers.insert("X-Apple-Store-Front".into(), store_front.to_string());
    headers
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_US_STORE_FRONT, auth_headers};
    use crate::domain::entity::test_support::test_account;
    use crate::domain::error::AppStoreError;
    use crate::infrastructure::http::AppleHttpClient;

    #[test]
    fn builds_legacy_headers_and_seeds_optional_cookies() {
        let client = AppleHttpClient::new().expect("HTTP client");
        let mut account = test_account();
        account.store_front.clear();

        let headers = auth_headers(&client, &account).expect("legacy headers");
        assert_eq!(headers["X-Token"], account.password_token);
        assert_eq!(headers["X-Apple-Store-Front"], DEFAULT_US_STORE_FRONT);
        assert_eq!(headers["X-Dsid"], account.directory_services_id);

        account.cookies = vec!["session=example; Path=/; Secure".into()];
        assert!(auth_headers(&client, &account).is_ok());
    }

    #[test]
    fn rejects_accounts_without_a_purchase_password_token() {
        let client = AppleHttpClient::new().expect("HTTP client");
        let mut account = test_account();
        account.password_token.clear();

        assert!(matches!(
            auth_headers(&client, &account),
            Err(AppStoreError::AuthenticationFailed(message))
                if message.contains("missing MZFinance passwordToken")
        ));
    }
}
