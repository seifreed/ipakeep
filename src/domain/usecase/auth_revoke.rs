//! Auth revoke use case — deletes stored credentials.

use crate::domain::error::CredentialError;
use crate::domain::repository::CredentialRepository;

/// Use case for revoking (deleting) stored Apple account credentials.
pub struct AuthRevoke<C>
where
    C: CredentialRepository,
{
    credentials: C,
}

impl<C> AuthRevoke<C>
where
    C: CredentialRepository,
{
    /// Create a new auth revoke use case.
    pub fn new(credentials: C) -> Self {
        Self { credentials }
    }

    /// Execute the revoke use case, deleting stored credentials.
    ///
    /// # Errors
    ///
    /// Returns `CredentialError::NotFound` if no credentials exist.
    pub async fn execute(&self) -> Result<(), CredentialError> {
        tracing::debug!("deleting stored auth account");
        self.credentials.delete_account().await?;
        tracing::debug!("stored auth account deleted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::CredentialError;
    use crate::domain::repository::InMemoryCredentialRepository;

    #[tokio::test]
    async fn revoke_deletes_credentials() {
        let credentials =
            InMemoryCredentialRepository::new().with_account(crate::domain::entity::Account {
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
            });

        let use_case = AuthRevoke::new(credentials.clone());
        let result: Result<(), CredentialError> = use_case.execute().await;

        assert!(result.is_ok());
        assert_eq!(credentials.delete_calls(), 1);
    }

    #[tokio::test]
    async fn revoke_fails_when_no_credentials() {
        let credentials = InMemoryCredentialRepository::new();

        let use_case = AuthRevoke::new(credentials);
        let result: Result<(), CredentialError> = use_case.execute().await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CredentialError::NotFound));
    }
}
