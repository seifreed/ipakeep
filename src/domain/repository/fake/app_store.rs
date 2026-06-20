//! Fake App Store repository for domain unit tests.

#![allow(clippy::missing_panics_doc, clippy::return_self_not_must_use)]

mod repository;

use crate::domain::entity::{Account, App, AppVersion, DownloadItem, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
use std::sync::{Arc, Mutex, MutexGuard};

/// In-memory fake of [`AppStoreRepository`] for domain unit tests.
#[derive(Debug, Clone, Default)]
pub struct FakeAppStoreRepository {
    inner: Arc<Mutex<FakeAppStoreRepositoryInner>>,
}

#[derive(Debug, Default)]
struct FakeAppStoreRepositoryInner {
    authenticate_result: Option<Result<Account, AppStoreError>>,
    authenticate_with_2fa_result: Option<Result<Account, AppStoreError>>,
    authenticate_grandslam_result: Option<Result<Account, AppStoreError>>,
    validate_trusted_device_code_result: Option<Result<(), AppStoreError>>,
    list_trusted_phone_numbers_result: Option<Result<Vec<TrustedPhoneNumber>, AppStoreError>>,
    validate_sms_code_result: Option<Result<(), AppStoreError>>,
    search_result: Option<Result<Vec<App>, AppStoreError>>,
    lookup_result: Option<Result<Option<App>, AppStoreError>>,
    purchase_result: Option<Result<(), AppStoreError>>,
    download_result: Option<Result<Vec<DownloadItem>, AppStoreError>>,
    download_bytes_result: Option<Result<Vec<u8>, AppStoreError>>,
    list_versions_result: Option<Result<Vec<AppVersion>, AppStoreError>>,

    authenticate_calls: Vec<(String, String, String)>,
    authenticate_with_2fa_calls: Vec<(String, String, String, String)>,
    authenticate_grandslam_calls: Vec<(String, String, String)>,
    request_trusted_device_notification_calls: Vec<(String, String)>,
    validate_trusted_device_code_calls: Vec<(String, String, String)>,
    list_trusted_phone_numbers_calls: Vec<(String, String)>,
    request_sms_calls: Vec<(String, String, i64)>,
    validate_sms_code_calls: Vec<(String, String, i64, String)>,
    search_calls: Vec<(String, String, u32)>,
    lookup_calls: Vec<(String, String)>,
    purchase_calls: Vec<(Account, i64, String)>,
    download_calls: Vec<(Account, i64, String, Option<String>)>,
    download_bytes_calls: Vec<String>,
    list_versions_calls: Vec<(Account, i64, String)>,
}

impl FakeAppStoreRepository {
    /// Create a new fake with no preconfigured results.
    pub fn new() -> Self {
        Self::default()
    }

    fn with_inner<F>(&self, f: F) -> Self
    where
        F: FnOnce(&mut FakeAppStoreRepositoryInner),
    {
        f(&mut self.lock_inner());
        self.clone()
    }

    fn lock_inner(&self) -> MutexGuard<'_, FakeAppStoreRepositoryInner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Preconfigure the result of `authenticate`.
    pub fn with_authenticate_result(&self, result: Result<Account, AppStoreError>) -> Self {
        self.with_inner(|inner| inner.authenticate_result = Some(result))
    }

    /// Preconfigure the result of `authenticate_with_2fa`.
    pub fn with_authenticate_with_2fa_result(
        &self,
        result: Result<Account, AppStoreError>,
    ) -> Self {
        self.with_inner(|inner| inner.authenticate_with_2fa_result = Some(result))
    }

    /// Preconfigure the result of `authenticate_grandslam`.
    pub fn with_authenticate_grandslam_result(
        &self,
        result: Result<Account, AppStoreError>,
    ) -> Self {
        self.with_inner(|inner| inner.authenticate_grandslam_result = Some(result))
    }

    /// Preconfigure the result of `validate_trusted_device_code`.
    pub fn with_validate_trusted_device_code_result(
        &self,
        result: Result<(), AppStoreError>,
    ) -> Self {
        self.with_inner(|inner| inner.validate_trusted_device_code_result = Some(result))
    }

    /// Preconfigure the result of `list_trusted_phone_numbers`.
    pub fn with_list_trusted_phone_numbers_result(
        &self,
        result: Result<Vec<TrustedPhoneNumber>, AppStoreError>,
    ) -> Self {
        self.with_inner(|inner| inner.list_trusted_phone_numbers_result = Some(result))
    }

    /// Preconfigure the result of `validate_sms_code`.
    pub fn with_validate_sms_code_result(&self, result: Result<(), AppStoreError>) -> Self {
        self.with_inner(|inner| inner.validate_sms_code_result = Some(result))
    }

    /// Preconfigure the result of `search`.
    pub fn with_search_result(&self, result: Result<Vec<App>, AppStoreError>) -> Self {
        self.with_inner(|inner| inner.search_result = Some(result))
    }

    /// Preconfigure the result of `lookup`.
    pub fn with_lookup_result(&self, result: Result<Option<App>, AppStoreError>) -> Self {
        self.with_inner(|inner| inner.lookup_result = Some(result))
    }

    /// Preconfigure the result of `purchase`.
    pub fn with_purchase_result(&self, result: Result<(), AppStoreError>) -> Self {
        self.with_inner(|inner| inner.purchase_result = Some(result))
    }

    /// Preconfigure the result of `download`.
    pub fn with_download_result(&self, result: Result<Vec<DownloadItem>, AppStoreError>) -> Self {
        self.with_inner(|inner| inner.download_result = Some(result))
    }

    /// Preconfigure the result of `download_bytes`.
    pub fn with_download_bytes_result(&self, result: Result<Vec<u8>, AppStoreError>) -> Self {
        self.with_inner(|inner| inner.download_bytes_result = Some(result))
    }

    /// Preconfigure the result of `list_versions`.
    pub fn with_list_versions_result(
        &self,
        result: Result<Vec<AppVersion>, AppStoreError>,
    ) -> Self {
        self.with_inner(|inner| inner.list_versions_result = Some(result))
    }

    /// Return the recorded calls to `authenticate`.
    pub fn authenticate_calls(&self) -> Vec<(String, String, String)> {
        self.lock_inner().authenticate_calls.clone()
    }

    /// Return the recorded calls to `authenticate_with_2fa`.
    pub fn authenticate_with_2fa_calls(&self) -> Vec<(String, String, String, String)> {
        self.lock_inner().authenticate_with_2fa_calls.clone()
    }

    /// Return the recorded calls to `authenticate_grandslam`.
    pub fn authenticate_grandslam_calls(&self) -> Vec<(String, String, String)> {
        self.lock_inner().authenticate_grandslam_calls.clone()
    }

    /// Return the recorded calls to `validate_trusted_device_code`.
    pub fn validate_trusted_device_code_calls(&self) -> Vec<(String, String, String)> {
        self.lock_inner().validate_trusted_device_code_calls.clone()
    }

    /// Return the recorded calls to `list_trusted_phone_numbers`.
    pub fn list_trusted_phone_numbers_calls(&self) -> Vec<(String, String)> {
        self.lock_inner().list_trusted_phone_numbers_calls.clone()
    }

    /// Return the recorded calls to `validate_sms_code`.
    pub fn validate_sms_code_calls(&self) -> Vec<(String, String, i64, String)> {
        self.lock_inner().validate_sms_code_calls.clone()
    }

    /// Return the recorded calls to `search`.
    pub fn search_calls(&self) -> Vec<(String, String, u32)> {
        self.lock_inner().search_calls.clone()
    }

    /// Return the recorded calls to `lookup`.
    pub fn lookup_calls(&self) -> Vec<(String, String)> {
        self.lock_inner().lookup_calls.clone()
    }

    /// Return the recorded calls to `purchase`.
    pub fn purchase_calls(&self) -> Vec<(Account, i64, String)> {
        self.lock_inner().purchase_calls.clone()
    }

    /// Return the recorded calls to `download`.
    pub fn download_calls(&self) -> Vec<(Account, i64, String, Option<String>)> {
        self.lock_inner().download_calls.clone()
    }

    /// Return the recorded calls to `download_bytes`.
    pub fn download_bytes_calls(&self) -> Vec<String> {
        self.lock_inner().download_bytes_calls.clone()
    }

    /// Return the recorded calls to `list_versions`.
    pub fn list_versions_calls(&self) -> Vec<(Account, i64, String)> {
        self.lock_inner().list_versions_calls.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::repository::AppStoreRepository;

    fn account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "token".into(),
            directory_services_id: "123".into(),
            store_front: "143441-2,26".into(),
            pod: "1".into(),
            idms_token: Some("idms".into()),
            dsid: Some("123".into()),
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    fn app() -> App {
        App {
            id: 42,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            price: 0.0,
        }
    }

    fn configured_repo() -> (
        FakeAppStoreRepository,
        Account,
        App,
        DownloadItem,
        AppVersion,
        TrustedPhoneNumber,
    ) {
        let account = account();
        let app = app();
        let item = DownloadItem {
            url: "https://example.invalid/app.ipa".into(),
            md5: "abc".into(),
            sinfs: Vec::new(),
            metadata: serde_json::Map::new(),
        };
        let version = AppVersion {
            external_version_id: "100".into(),
            version_string: "1.0".into(),
        };
        let phone = TrustedPhoneNumber {
            id: 7,
            number: "+34•••".into(),
        };
        let repo = FakeAppStoreRepository::new()
            .with_authenticate_result(Ok(account.clone()))
            .with_authenticate_with_2fa_result(Ok(account.clone()))
            .with_authenticate_grandslam_result(Ok(account.clone()))
            .with_validate_trusted_device_code_result(Ok(()))
            .with_list_trusted_phone_numbers_result(Ok(vec![phone.clone()]))
            .with_validate_sms_code_result(Ok(()))
            .with_search_result(Ok(vec![app.clone()]))
            .with_lookup_result(Ok(Some(app.clone())))
            .with_purchase_result(Ok(()))
            .with_download_result(Ok(vec![item.clone()]))
            .with_download_bytes_result(Ok(vec![1, 2, 3]))
            .with_list_versions_result(Ok(vec![version.clone()]));

        (repo, account, app, item, version, phone)
    }

    #[tokio::test]
    async fn configured_results_cover_repository_surface() {
        let (repo, account, app, item, version, phone) = configured_repo();

        assert_eq!(
            repo.authenticate("email", "pass", "guid")
                .await
                .unwrap()
                .email,
            account.email
        );
        assert!(
            repo.authenticate_with_2fa("email", "pass", "code", "guid")
                .await
                .is_ok()
        );
        assert!(
            repo.authenticate_grandslam("email", "pass", "guid")
                .await
                .is_ok()
        );
        repo.request_trusted_device_notification("123", "idms")
            .await
            .unwrap();
        repo.validate_trusted_device_code("123", "idms", "111111")
            .await
            .unwrap();
        assert_eq!(
            repo.list_trusted_phone_numbers("123", "idms")
                .await
                .unwrap()[0]
                .id,
            phone.id
        );
        repo.request_sms("123", "idms", 7).await.unwrap();
        repo.validate_sms_code("123", "idms", 7, "111111")
            .await
            .unwrap();
        assert_eq!(repo.search("term", "es", 5).await.unwrap()[0].id, app.id);
        assert_eq!(
            repo.lookup("com.example.app", "es")
                .await
                .unwrap()
                .map(|app| app.id),
            Some(app.id)
        );
        repo.purchase(&account, 42, "guid").await.unwrap();
        let downloaded = repo
            .download(&account, 42, "guid", Some("100".into()))
            .await
            .unwrap();
        assert_eq!(downloaded[0].url, item.url);
        assert_eq!(
            repo.download_bytes("https://example.invalid/app.ipa")
                .await
                .unwrap(),
            vec![1, 2, 3]
        );
        assert_eq!(
            repo.list_versions(&account, 42, "guid").await.unwrap()[0].external_version_id,
            version.external_version_id
        );
    }

    #[tokio::test]
    async fn configured_calls_cover_repository_surface() {
        let (repo, account, _app, _item, _version, _phone) = configured_repo();

        let _ = repo.authenticate("email", "pass", "guid").await;
        let _ = repo
            .authenticate_with_2fa("email", "pass", "code", "guid")
            .await;
        let _ = repo.authenticate_grandslam("email", "pass", "guid").await;
        let _ = repo
            .request_trusted_device_notification("123", "idms")
            .await;
        let _ = repo
            .validate_trusted_device_code("123", "idms", "111111")
            .await;
        let _ = repo.list_trusted_phone_numbers("123", "idms").await;
        let _ = repo.request_sms("123", "idms", 7).await;
        let _ = repo.validate_sms_code("123", "idms", 7, "111111").await;
        let _ = repo.search("term", "es", 5).await;
        let _ = repo.lookup("com.example.app", "es").await;
        let _ = repo.purchase(&account, 42, "guid").await;
        let _ = repo
            .download(&account, 42, "guid", Some("100".into()))
            .await;
        let _ = repo.download_bytes("https://example.invalid/app.ipa").await;
        let _ = repo.list_versions(&account, 42, "guid").await;

        assert_eq!(repo.authenticate_calls().len(), 1);
        assert_eq!(repo.authenticate_with_2fa_calls().len(), 1);
        assert_eq!(repo.authenticate_grandslam_calls().len(), 1);
        assert_eq!(repo.validate_trusted_device_code_calls().len(), 1);
        assert_eq!(repo.list_trusted_phone_numbers_calls().len(), 1);
        assert_eq!(repo.validate_sms_code_calls().len(), 1);
        assert_eq!(repo.search_calls().len(), 1);
        assert_eq!(repo.lookup_calls().len(), 1);
        assert_eq!(repo.purchase_calls().len(), 1);
        assert_eq!(repo.download_calls().len(), 1);
        assert_eq!(repo.download_bytes_calls().len(), 1);
        assert_eq!(repo.list_versions_calls().len(), 1);
        let inner = repo.lock_inner();
        assert_eq!(inner.request_trusted_device_notification_calls.len(), 1);
        assert_eq!(inner.request_sms_calls.len(), 1);
    }
}
