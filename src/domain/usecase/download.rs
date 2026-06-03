//! Download use case — downloads an IPA and patches it with sinf data.

use crate::domain::entity::DownloadItem;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// Use case for downloading an IPA file from the App Store.
pub struct Download<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Download<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    /// Create a new download use case.
    pub fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }

    /// Execute the download use case.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if not logged in.
    /// Returns `AppStoreError::DownloadFailed` if the download is rejected.
    pub async fn execute(
        &self,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
        auto_purchase: bool,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;

        if auto_purchase {
            match self.app_store.purchase(&account, app_id, guid).await {
                Ok(()) | Err(AppStoreError::NoLicense(_)) => {}
                Err(e) => return Err(e),
            }
        }

        self.app_store
            .download(&account, app_id, guid, version_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

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
    async fn download_without_auto_purchase() {
        let app_store = FakeAppStoreRepository::new().with_download_result(Ok(vec![]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = Download::new(app_store, credentials);
        let result: Result<Vec<DownloadItem>, AppStoreError> =
            use_case.execute(12345, "guid123", None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn download_fails_without_login() {
        let app_store = FakeAppStoreRepository::new();
        let credentials = InMemoryCredentialRepository::new();

        let use_case = Download::new(app_store, credentials);
        let result: Result<Vec<DownloadItem>, AppStoreError> =
            use_case.execute(12345, "guid123", None, false).await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AppStoreError::AuthenticationFailed(_)),
            "expected AuthenticationFailed error"
        );
    }
}
