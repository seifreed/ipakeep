//! Purchases use case — lists the apps the authenticated account owns.

use crate::domain::entity::OwnedApp;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};

/// Use case for listing the authenticated account's owned (purchased) apps.
pub struct Purchases<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Purchases<R, C>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    /// Create a new purchases use case.
    pub fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }

    /// List the apps the authenticated account already owns.
    ///
    /// `limit` caps the number of apps returned, most recent purchase first.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if not logged in.
    /// Returns any `AppStoreError` surfaced by the repository.
    pub async fn execute(&self, limit: u32) -> Result<Vec<OwnedApp>, AppStoreError> {
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        let apps = self.app_store.list_purchases(&account, limit).await?;
        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{Account, OwnedApp};
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

    fn owned_app() -> OwnedApp {
        OwnedApp {
            id: 894_490_049,
            bundle_id: "com.example.ludostar".into(),
            name: "Ludo Star".into(),
            version: "1.376".into(),
            platforms: vec!["iphone".into(), "ipad".into()],
            purchase_date: Some("2021-01-01T00:00:00Z".into()),
        }
    }

    #[tokio::test]
    async fn purchases_fails_without_login() {
        let app_store = FakeAppStoreRepository::new();
        let credentials = InMemoryCredentialRepository::new();
        let use_case = Purchases::new(app_store, credentials);

        let result: Result<Vec<OwnedApp>, AppStoreError> = use_case.execute(10).await;

        assert!(
            matches!(result, Err(AppStoreError::AuthenticationFailed(_))),
            "expected AuthenticationFailed error"
        );
    }

    #[tokio::test]
    async fn purchases_returns_repository_apps() {
        let app_store =
            FakeAppStoreRepository::new().with_list_purchases_result(Ok(vec![owned_app()]));
        let credentials = InMemoryCredentialRepository::new().with_account(account());
        let use_case = Purchases::new(app_store.clone(), credentials);

        let apps = use_case.execute(25).await.unwrap();

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, 894_490_049);
        assert_eq!(apps[0].platforms, vec!["iphone", "ipad"]);
        let calls = app_store.list_purchases_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, 25);
    }

    #[tokio::test]
    async fn purchases_propagates_repository_error() {
        let app_store = FakeAppStoreRepository::new()
            .with_list_purchases_result(Err(AppStoreError::NetworkError("boom".into())));
        let credentials = InMemoryCredentialRepository::new().with_account(account());
        let use_case = Purchases::new(app_store, credentials);

        let error = use_case.execute(10).await.unwrap_err();

        assert!(matches!(error, AppStoreError::NetworkError(_)));
    }
}
