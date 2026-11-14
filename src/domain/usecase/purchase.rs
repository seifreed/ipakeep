//! Purchase use case — acquires a license for an app on the App Store.

use crate::domain::error::AppStoreError;
use crate::domain::repository::{CredentialRepository, PurchaseRepository};

/// Use case for acquiring an app license on the Apple App Store.
pub struct Purchase<R, C>
where
    R: PurchaseRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Purchase<R, C>
where
    R: PurchaseRepository,
    C: CredentialRepository,
{
    /// Create a new purchase use case.
    pub fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }

    /// Purchase an app by its App Store ID.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if not logged in.
    /// Returns `AppStoreError::PurchaseFailed` if the purchase is rejected.
    pub async fn execute(&self, app_id: i64, guid: &str) -> Result<(), AppStoreError> {
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        self.app_store.purchase(&account, app_id, guid).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::repository::{AppStoreRepo, CredentialRepo};
    use crate::domain::usecase::test_support::test_account;

    #[tokio::test]
    async fn purchase_success() {
        let mut app_store = AppStoreRepo::new();
        app_store.expect_purchase().return_once(|_, _, _| Ok(()));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(test_account())));

        let use_case = Purchase::new(app_store, credentials);
        let result: Result<(), AppStoreError> = use_case.execute(12345, "guid123").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn purchase_fails_without_login() {
        let app_store = AppStoreRepo::new();
        let mut credentials = CredentialRepo::new();
        credentials.expect_load_account().return_once(|| Ok(None));

        let use_case = Purchase::new(app_store, credentials);
        let result: Result<(), AppStoreError> = use_case.execute(12345, "guid123").await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AppStoreError::AuthenticationFailed(_)),
            "expected AuthenticationFailed error"
        );
    }
}
