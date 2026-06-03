//! macOS Keychain credential storage implementation.
//!
//! Uses the native macOS Security framework via `security_framework`
//! to store credentials as a generic password item.

use crate::domain::entity::Account;
use crate::domain::error::CredentialError;
use crate::domain::repository::CredentialRepository;
use async_trait::async_trait;

const DEFAULT_SERVICE: &str = "com.github.seifreed.ipakeep";
const DEFAULT_ACCOUNT: &str = "default";

/// macOS Keychain credential repository.
///
/// Stores credentials as a generic password in the user's default
/// macOS Keychain. The password payload is JSON-serialized `Account`.
pub struct MacOSKeychain {
    service_name: String,
    account_name: String,
}

impl MacOSKeychain {
    /// Create a new macOS keychain repository with default service/account names.
    ///
    /// # Errors
    ///
    /// Never returns an error in this constructor, but returns `Result` for
    /// consistency with `FileKeychain::new`.
    pub fn new() -> Result<Self, CredentialError> {
        Ok(Self {
            service_name: DEFAULT_SERVICE.into(),
            account_name: DEFAULT_ACCOUNT.into(),
        })
    }

    /// Create a macOS keychain repository with a custom service name (useful for testing).
    pub fn with_service(service_name: &str) -> Self {
        Self {
            service_name: service_name.into(),
            account_name: DEFAULT_ACCOUNT.into(),
        }
    }

    /// Create a macOS keychain repository with custom service and account names.
    ///
    /// Using unique account names per test avoids race conditions when tests
    /// run in parallel against the same keychain.
    pub fn with_service_and_account(service_name: &str, account_name: &str) -> Self {
        Self {
            service_name: service_name.into(),
            account_name: account_name.into(),
        }
    }
}

#[async_trait]
impl CredentialRepository for MacOSKeychain {
    async fn save_account(&self, account: &Account) -> Result<(), CredentialError> {
        let json = serde_json::to_string_pretty(account).map_err(|e: serde_json::Error| {
            CredentialError::SaveFailed(format!("serialization failed: {e}"))
        })?;

        tokio::task::spawn_blocking({
            let service = self.service_name.clone();
            let account = self.account_name.clone();
            move || {
                security_framework::passwords::set_generic_password(
                    &service,
                    &account,
                    json.as_bytes(),
                )
                .map_err(|e| CredentialError::SaveFailed(e.to_string()))
            }
        })
        .await
        .map_err(|e| CredentialError::SaveFailed(format!("task failed: {e}")))?
    }

    async fn load_account(&self) -> Result<Option<Account>, CredentialError> {
        let result = tokio::task::spawn_blocking({
            let service = self.service_name.clone();
            let account = self.account_name.clone();
            move || {
                security_framework::passwords::get_generic_password(&service, &account).map_err(
                    |e| {
                        let code = e.code();
                        if code == -25300 {
                            // errSecItemNotFound
                            CredentialError::NotFound
                        } else {
                            CredentialError::LoadFailed(e.to_string())
                        }
                    },
                )
            }
        })
        .await
        .map_err(|e| CredentialError::LoadFailed(format!("task failed: {e}")))?;

        match result {
            Ok(bytes) => {
                let account: Account =
                    serde_json::from_slice(&bytes).map_err(|e: serde_json::Error| {
                        CredentialError::InvalidCredentials(format!(
                            "failed to parse credentials: {e}"
                        ))
                    })?;
                Ok(Some(account))
            }
            Err(CredentialError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn delete_account(&self) -> Result<(), CredentialError> {
        tokio::task::spawn_blocking({
            let service = self.service_name.clone();
            let account = self.account_name.clone();
            move || {
                security_framework::passwords::delete_generic_password(&service, &account).map_err(
                    |e| {
                        let code = e.code();
                        if code == -25300 {
                            // errSecItemNotFound
                            CredentialError::NotFound
                        } else {
                            CredentialError::DeleteFailed(e.to_string())
                        }
                    },
                )
            }
        })
        .await
        .map_err(|e| CredentialError::DeleteFailed(format!("task failed: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "token123".into(),
            directory_services_id: "dsid123".into(),
            store_front: "143441-2,26".into(),
            pod: "3".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    /// Build a unique keychain instance for a given test name and attempt
    /// to delete any pre-existing item so the test starts from a clean slate.
    fn test_keychain(test_name: &str) -> MacOSKeychain {
        let keychain =
            MacOSKeychain::with_service_and_account("com.github.seifreed.ipakeep.test", test_name);
        let _ = std::thread::spawn({
            let service = keychain.service_name.clone();
            let account = keychain.account_name.clone();
            move || {
                let _ = security_framework::passwords::delete_generic_password(&service, &account);
            }
        })
        .join();
        keychain
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn save_and_load_account() {
        let keychain = test_keychain("save_and_load_account");
        let account = test_account();

        keychain.save_account(&account).await.unwrap();
        let loaded = keychain.load_account().await.unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.email, "test@example.com");
        assert_eq!(loaded.password_token, "token123");

        // cleanup
        keychain.delete_account().await.unwrap();
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn load_returns_none_when_not_found() {
        let keychain = test_keychain("load_returns_none_when_not_found");

        let result = keychain.load_account().await;
        assert!(
            matches!(result, Ok(None)),
            "Expected Ok(None), got {result:?}"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn delete_account_removes_item() {
        let keychain = test_keychain("delete_account_removes_item");
        let account = test_account();

        keychain.save_account(&account).await.unwrap();
        keychain.delete_account().await.unwrap();

        let result = keychain.load_account().await;
        assert!(
            matches!(result, Ok(None)),
            "Expected Ok(None) after delete, got {result:?}"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn delete_without_item_returns_not_found() {
        let keychain = test_keychain("delete_without_item_returns_not_found");

        let result = keychain.delete_account().await;
        assert!(
            matches!(result, Err(CredentialError::NotFound)),
            "Expected NotFound, got {result:?}"
        );
    }
}
