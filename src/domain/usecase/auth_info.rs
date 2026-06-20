//! Auth info use case — retrieves stored account information.

use crate::domain::entity::Account;
use crate::domain::error::CredentialError;
use crate::domain::repository::CredentialRepository;

/// Use case for retrieving stored Apple account information.
pub struct AuthInfo<C>
where
    C: CredentialRepository,
{
    credentials: C,
}

impl<C> AuthInfo<C>
where
    C: CredentialRepository,
{
    /// Create a new auth info use case.
    pub fn new(credentials: C) -> Self {
        Self { credentials }
    }

    /// Execute the auth info use case.
    ///
    /// # Errors
    ///
    /// Returns `CredentialError::LoadFailed` if credentials cannot be read.
    pub async fn execute(&self) -> Result<Option<Account>, CredentialError> {
        tracing::debug!("loading stored auth account");
        let account = self.credentials.load_account().await?;
        tracing::debug!(
            account_present = account.is_some(),
            "stored auth account loaded"
        );
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
    use crate::domain::error::CredentialError;
    use crate::domain::repository::InMemoryCredentialRepository;

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

    #[tokio::test]
    async fn info_returns_stored_account() {
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = AuthInfo::new(credentials);
        let result: Result<Option<Account>, CredentialError> = use_case.execute().await;

        assert!(result.is_ok());
        let account = result.unwrap();
        assert!(account.is_some());
        assert_eq!(account.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn info_returns_none_when_no_credentials() {
        let credentials = InMemoryCredentialRepository::new();

        let use_case = AuthInfo::new(credentials);
        let result: Result<Option<Account>, CredentialError> = use_case.execute().await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
