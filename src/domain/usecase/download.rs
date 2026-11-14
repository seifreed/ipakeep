//! Download use case — downloads an IPA and patches it with sinf data.

use crate::domain::entity::DownloadItem;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{CredentialRepository, DownloadRepository, PurchaseRepository};

/// Use case for downloading an IPA file from the App Store.
pub struct Download<R, C>
where
    R: DownloadRepository + PurchaseRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Download<R, C>
where
    R: DownloadRepository + PurchaseRepository,
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

        let items = self
            .app_store
            .download(&account, app_id, guid, version_id)
            .await?;
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{AppStoreRepo, CredentialRepo};
    use crate::domain::usecase::test_support::test_account;

    #[tokio::test]
    async fn download_without_auto_purchase() {
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_download()
            .return_once(|_, _, _, _| Ok(vec![]));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(test_account())));

        let use_case = Download::new(app_store, credentials);
        let result: Result<Vec<DownloadItem>, AppStoreError> =
            use_case.execute(12345, "guid123", None, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn download_fails_without_login() {
        let app_store = AppStoreRepo::new();
        let mut credentials = CredentialRepo::new();
        credentials.expect_load_account().return_once(|| Ok(None));

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
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_purchase()
            .return_once(|_, _, _| Err(AppStoreError::NoLicense(12345)));
        app_store
            .expect_download()
            .return_once(|_, _, _, _| Ok(vec![]));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(test_account())));

        let use_case = Download::new(app_store, credentials);

        assert!(
            use_case
                .execute(12345, "guid123", Some("100".into()), true)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn download_auto_purchase_returns_purchase_error() {
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_purchase()
            .return_once(|_, _, _| Err(AppStoreError::PurchaseFailed("nope".into())));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(test_account())));

        let use_case = Download::new(app_store, credentials);
        let error = use_case
            .execute(12345, "guid123", None, true)
            .await
            .unwrap_err();

        assert!(matches!(error, AppStoreError::PurchaseFailed(_)));
    }
}
