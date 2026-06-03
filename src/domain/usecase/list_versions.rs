//! List versions use case — lists available versions for an app.

use crate::domain::entity::AppVersion;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// Use case for listing available versions of an app on the App Store.
pub struct ListVersions<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> ListVersions<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    /// Create a new list versions use case.
    pub fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }

    /// List available versions for an app.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if not logged in.
    /// Returns `AppStoreError::Unexpected` if version metadata is missing.
    pub async fn execute(&self, app_id: i64, guid: &str) -> Result<Vec<AppVersion>, AppStoreError> {
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;

        self.app_store.list_versions(&account, app_id, guid).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

    #[tokio::test]
    async fn list_versions_fails_without_login() {
        let app_store = FakeAppStoreRepository::new();
        let credentials = InMemoryCredentialRepository::new();
        let use_case = ListVersions::new(app_store, credentials);
        let result: Result<Vec<AppVersion>, AppStoreError> =
            use_case.execute(12345, "guid123").await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AppStoreError::AuthenticationFailed(_)),
            "expected AuthenticationFailed error"
        );
    }
}
