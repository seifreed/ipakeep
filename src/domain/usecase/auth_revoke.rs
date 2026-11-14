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
        self.credentials.delete_account().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::CredentialError;
    use crate::domain::repository::CredentialRepo;

    #[tokio::test]
    async fn revoke_deletes_credentials() {
        let mut credentials = CredentialRepo::new();
        credentials.expect_delete_account().return_once(|| Ok(()));

        let use_case = AuthRevoke::new(credentials);
        let result: Result<(), CredentialError> = use_case.execute().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn revoke_fails_when_no_credentials() {
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_delete_account()
            .return_once(|| Err(CredentialError::NotFound));

        let use_case = AuthRevoke::new(credentials);
        let result: Result<(), CredentialError> = use_case.execute().await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CredentialError::NotFound));
    }
}
