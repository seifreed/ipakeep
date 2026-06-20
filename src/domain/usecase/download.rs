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
        tracing::debug!(
            app_id,
            guid_len = guid.len(),
            version_id_present = version_id.is_some(),
            auto_purchase,
            "starting download use case"
        );
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        tracing::debug!(
            has_purchase_token = !account.password_token.is_empty(),
            store_front_present = !account.store_front.is_empty(),
            "download account loaded"
        );

        if auto_purchase {
            tracing::debug!(app_id, "attempting auto-purchase before download");
            match self.app_store.purchase(&account, app_id, guid).await {
                Ok(()) => tracing::debug!(app_id, "auto-purchase completed"),
                Err(AppStoreError::NoLicense(_)) => {
                    tracing::debug!(app_id, "auto-purchase skipped for existing license");
                }
                Err(e) => return Err(e),
            }
        }

        let items = self
            .app_store
            .download(&account, app_id, guid, version_id)
            .await?;
        tracing::debug!(app_id, item_count = items.len(), "download items returned");
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use crate::domain::usecase::log_capture::LogCapture;

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

    #[tokio::test]
    async fn download_auto_purchase_ignores_existing_license() {
        let app_store = FakeAppStoreRepository::new()
            .with_purchase_result(Err(AppStoreError::NoLicense(12345)))
            .with_download_result(Ok(vec![]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = Download::new(app_store, credentials);

        assert!(
            use_case
                .execute(12345, "guid123", Some("100".into()), true)
                .await
                .is_ok()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn download_logs_context_and_result() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let app_store = FakeAppStoreRepository::new()
            .with_purchase_result(Ok(()))
            .with_download_result(Ok(vec![]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = Download::new(app_store, credentials);
        use_case
            .execute(12345, "guid123", Some("100".into()), true)
            .await
            .unwrap();

        let logs = capture.contents();
        assert!(logs.contains("starting download use case"));
        assert!(logs.contains("auto_purchase=true"));
        assert!(logs.contains("version_id_present=true"));
        assert!(logs.contains("auto-purchase completed"));
        assert!(logs.contains("download items returned"));
        assert!(!logs.contains("token123"));
    }

    #[tokio::test]
    async fn download_auto_purchase_returns_purchase_error() {
        let app_store = FakeAppStoreRepository::new()
            .with_purchase_result(Err(AppStoreError::PurchaseFailed("nope".into())))
            .with_download_result(Ok(vec![]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = Download::new(app_store, credentials);
        let error = use_case
            .execute(12345, "guid123", None, true)
            .await
            .unwrap_err();

        assert!(matches!(error, AppStoreError::PurchaseFailed(_)));
    }
}
