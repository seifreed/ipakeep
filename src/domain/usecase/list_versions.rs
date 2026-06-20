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
        tracing::debug!(
            app_id,
            guid_len = guid.len(),
            "starting list versions use case"
        );
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        tracing::debug!(
            store_front_present = !account.store_front.is_empty(),
            "list versions account loaded"
        );

        let versions = self.app_store.list_versions(&account, app_id, guid).await?;
        tracing::debug!(
            app_id,
            version_count = versions.len(),
            "app versions returned"
        );
        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

    fn account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "token".into(),
            directory_services_id: "123".into(),
            store_front: "143441-2,26".into(),
            pod: "1".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

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

    #[tokio::test]
    async fn list_versions_returns_repository_versions() {
        let app_store =
            FakeAppStoreRepository::new().with_list_versions_result(Ok(vec![AppVersion {
                external_version_id: "100".into(),
                version_string: "1.0".into(),
            }]));
        let credentials = InMemoryCredentialRepository::new().with_account(account());
        let use_case = ListVersions::new(app_store, credentials);

        let versions = use_case.execute(12345, "guid123").await.unwrap();

        assert_eq!(versions[0].external_version_id, "100");
    }
}
