//! Purchase use case — acquires a license for an app on the App Store.

use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// Use case for acquiring an app license on the Apple App Store.
pub struct Purchase<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Purchase<R, C>
where
    R: AppStoreRepository,
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
        tracing::debug!(app_id, guid_len = guid.len(), "starting purchase use case");
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        tracing::debug!(
            has_purchase_token = !account.password_token.is_empty(),
            store_front_present = !account.store_front.is_empty(),
            "purchase account loaded"
        );

        self.app_store.purchase(&account, app_id, guid).await?;
        tracing::debug!(app_id, "purchase use case completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;
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
    async fn purchase_success() {
        let app_store = FakeAppStoreRepository::new().with_purchase_result(Ok(()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let use_case = Purchase::new(app_store, credentials);
        let result: Result<(), AppStoreError> = use_case.execute(12345, "guid123").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn purchase_fails_without_login() {
        let app_store = FakeAppStoreRepository::new();
        let credentials = InMemoryCredentialRepository::new();

        let use_case = Purchase::new(app_store, credentials);
        let result: Result<(), AppStoreError> = use_case.execute(12345, "guid123").await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AppStoreError::AuthenticationFailed(_)),
            "expected AuthenticationFailed error"
        );
    }
}
