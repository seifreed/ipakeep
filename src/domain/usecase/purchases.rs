//! Purchases use case — lists the apps the authenticated account owns.

use crate::domain::entity::OwnedApp;
use crate::domain::error::AppStoreError;
use crate::domain::repository::{CredentialRepository, PurchaseRepository};

const MAX_FILTERED_PURCHASE_CANDIDATES: u32 = 100;

/// Use case for listing the authenticated account's owned (purchased) apps.
pub struct Purchases<R, C>
where
    R: PurchaseRepository,
    C: CredentialRepository,
{
    app_store: R,
    credentials: C,
}

impl<R, C> Purchases<R, C>
where
    R: PurchaseRepository,
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
    /// `limit` caps returned apps, most recent purchase first. `platform`
    /// optionally retains apps licensed for that platform (case-insensitive).
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if not logged in.
    /// Returns any `AppStoreError` surfaced by the repository.
    pub async fn execute(
        &self,
        limit: u32,
        platform: Option<&str>,
    ) -> Result<Vec<OwnedApp>, AppStoreError> {
        let account = self
            .credentials
            .load_account()
            .await
            .map_err(|e| AppStoreError::Unexpected(e.to_string()))?
            .ok_or(AppStoreError::AuthenticationFailed("not logged in".into()))?;
        let fetch_limit = if platform.is_some() {
            limit.max(MAX_FILTERED_PURCHASE_CANDIDATES)
        } else {
            limit
        };
        let mut apps = self.app_store.list_purchases(&account, fetch_limit).await?;
        if let Some(platform) = platform {
            apps.retain(|app| {
                app.platforms
                    .iter()
                    .any(|owned_platform| owned_platform.eq_ignore_ascii_case(platform))
            });
        }
        apps.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{Account, OwnedApp};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{AppStoreRepo, CredentialRepo};

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
        let app_store = AppStoreRepo::new();
        let mut credentials = CredentialRepo::new();
        credentials.expect_load_account().return_once(|| Ok(None));
        let use_case = Purchases::new(app_store, credentials);

        let result: Result<Vec<OwnedApp>, AppStoreError> = use_case.execute(10, None).await;

        assert!(
            matches!(result, Err(AppStoreError::AuthenticationFailed(_))),
            "expected AuthenticationFailed error"
        );
    }

    #[tokio::test]
    async fn purchases_returns_repository_apps() {
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_list_purchases()
            .withf(|_, limit| *limit == 25)
            .return_once(|_, _| Ok(vec![owned_app()]));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(account())));
        let use_case = Purchases::new(app_store, credentials);

        let apps = use_case.execute(25, None).await.unwrap();

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, 894_490_049);
        assert_eq!(apps[0].platforms, vec!["iphone", "ipad"]);
    }

    #[tokio::test]
    async fn purchases_propagates_repository_error() {
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_list_purchases()
            .return_once(|_, _| Err(AppStoreError::NetworkError("boom".into())));
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(account())));
        let use_case = Purchases::new(app_store, credentials);

        let error = use_case.execute(10, None).await.unwrap_err();

        assert!(matches!(error, AppStoreError::NetworkError(_)));
    }

    #[tokio::test]
    async fn purchases_filters_platform_case_insensitively() {
        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_list_purchases()
            .withf(|_, limit| *limit == 100)
            .return_once(|_, _| {
                Ok(vec![
                    owned_app(),
                    owned_app(),
                    OwnedApp {
                        id: 8,
                        bundle_id: "com.example.macapp".into(),
                        name: "Mac app".into(),
                        version: "1.0".into(),
                        platforms: vec!["macos".into()],
                        purchase_date: None,
                    },
                ])
            });
        let mut credentials = CredentialRepo::new();
        credentials
            .expect_load_account()
            .return_once(|| Ok(Some(account())));
        let use_case = Purchases::new(app_store, credentials);

        let apps = use_case.execute(1, Some("IPad")).await.unwrap();

        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].id, 894_490_049);
    }
}
