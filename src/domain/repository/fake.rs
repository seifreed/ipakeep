//! Manual fake implementations of repository traits for domain unit tests.
//!
//! These fakes replace `mockall` mocks with real, deterministic, in-memory
//! implementations that respect Clean Architecture (no I/O, no external deps).

use crate::domain::entity::{Account, App, AppVersion, DownloadItem};
use crate::domain::error::{AppStoreError, CredentialError};
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// FakeAppStoreRepository
// ---------------------------------------------------------------------------

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
        f(&mut self.inner.lock().unwrap());
        self.clone()
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
        self.inner.lock().unwrap().authenticate_calls.clone()
    }

    /// Return the recorded calls to `authenticate_with_2fa`.
    pub fn authenticate_with_2fa_calls(&self) -> Vec<(String, String, String, String)> {
        self.inner
            .lock()
            .unwrap()
            .authenticate_with_2fa_calls
            .clone()
    }

    /// Return the recorded calls to `authenticate_grandslam`.
    pub fn authenticate_grandslam_calls(&self) -> Vec<(String, String, String)> {
        self.inner
            .lock()
            .unwrap()
            .authenticate_grandslam_calls
            .clone()
    }

    /// Return the recorded calls to `validate_trusted_device_code`.
    pub fn validate_trusted_device_code_calls(&self) -> Vec<(String, String, String)> {
        self.inner
            .lock()
            .unwrap()
            .validate_trusted_device_code_calls
            .clone()
    }

    /// Return the recorded calls to `validate_sms_code`.
    pub fn validate_sms_code_calls(&self) -> Vec<(String, String, i64, String)> {
        self.inner.lock().unwrap().validate_sms_code_calls.clone()
    }

    /// Return the recorded calls to `search`.
    pub fn search_calls(&self) -> Vec<(String, String, u32)> {
        self.inner.lock().unwrap().search_calls.clone()
    }

    /// Return the recorded calls to `lookup`.
    pub fn lookup_calls(&self) -> Vec<(String, String)> {
        self.inner.lock().unwrap().lookup_calls.clone()
    }

    /// Return the recorded calls to `purchase`.
    pub fn purchase_calls(&self) -> Vec<(Account, i64, String)> {
        self.inner.lock().unwrap().purchase_calls.clone()
    }

    /// Return the recorded calls to `download`.
    pub fn download_calls(&self) -> Vec<(Account, i64, String, Option<String>)> {
        self.inner.lock().unwrap().download_calls.clone()
    }

    /// Return the recorded calls to `download_bytes`.
    pub fn download_bytes_calls(&self) -> Vec<String> {
        self.inner.lock().unwrap().download_bytes_calls.clone()
    }

    /// Return the recorded calls to `list_versions`.
    pub fn list_versions_calls(&self) -> Vec<(Account, i64, String)> {
        self.inner.lock().unwrap().list_versions_calls.clone()
    }
}

#[async_trait]
impl AppStoreRepository for FakeAppStoreRepository {
    async fn authenticate(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .authenticate_calls
            .push((email.to_string(), password.to_string(), guid.to_string()));
        inner.authenticate_result.clone().unwrap_or_else(|| {
            Err(AppStoreError::Unexpected(
                "authenticate not configured".into(),
            ))
        })
    }

    async fn authenticate_with_2fa(
        &self,
        email: &str,
        password: &str,
        code: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.authenticate_with_2fa_calls.push((
            email.to_string(),
            password.to_string(),
            code.to_string(),
            guid.to_string(),
        ));
        inner
            .authenticate_with_2fa_result
            .clone()
            .unwrap_or_else(|| {
                Err(AppStoreError::Unexpected(
                    "authenticate_with_2fa not configured".into(),
                ))
            })
    }

    async fn authenticate_grandslam(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.authenticate_grandslam_calls.push((
            email.to_string(),
            password.to_string(),
            guid.to_string(),
        ));
        inner
            .authenticate_grandslam_result
            .clone()
            .unwrap_or_else(|| {
                Err(AppStoreError::Unexpected(
                    "authenticate_grandslam not configured".into(),
                ))
            })
    }

    async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .request_trusted_device_notification_calls
            .push((dsid.to_string(), idms_token.to_string()));
        Ok(())
    }

    async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.validate_trusted_device_code_calls.push((
            dsid.to_string(),
            idms_token.to_string(),
            code.to_string(),
        ));
        inner
            .validate_trusted_device_code_result
            .clone()
            .unwrap_or(Ok(()))
    }

    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .request_sms_calls
            .push((dsid.to_string(), idms_token.to_string(), phone_id));
        Ok(())
    }

    async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.validate_sms_code_calls.push((
            dsid.to_string(),
            idms_token.to_string(),
            phone_id,
            code.to_string(),
        ));
        inner.validate_sms_code_result.clone().unwrap_or(Ok(()))
    }

    async fn search(
        &self,
        term: &str,
        country: &str,
        limit: u32,
    ) -> Result<Vec<App>, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .search_calls
            .push((term.to_string(), country.to_string(), limit));
        inner
            .search_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("search not configured".into())))
    }

    async fn lookup(&self, bundle_id: &str, country: &str) -> Result<Option<App>, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .lookup_calls
            .push((bundle_id.to_string(), country.to_string()));
        inner
            .lookup_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("lookup not configured".into())))
    }

    async fn purchase(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .purchase_calls
            .push((account.clone(), app_id, guid.to_string()));
        inner
            .purchase_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("purchase not configured".into())))
    }

    async fn download(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
        version_id: Option<String>,
    ) -> Result<Vec<DownloadItem>, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .download_calls
            .push((account.clone(), app_id, guid.to_string(), version_id));
        inner
            .download_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("download not configured".into())))
    }

    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner.download_bytes_calls.push(url.to_string());
        inner.download_bytes_result.clone().unwrap_or_else(|| {
            Err(AppStoreError::Unexpected(
                "download_bytes not configured".into(),
            ))
        })
    }

    async fn list_versions(
        &self,
        account: &Account,
        app_id: i64,
        guid: &str,
    ) -> Result<Vec<AppVersion>, AppStoreError> {
        let mut inner = self.inner.lock().unwrap();
        inner
            .list_versions_calls
            .push((account.clone(), app_id, guid.to_string()));
        inner.list_versions_result.clone().unwrap_or_else(|| {
            Err(AppStoreError::Unexpected(
                "list_versions not configured".into(),
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// InMemoryCredentialRepository
// ---------------------------------------------------------------------------

/// In-memory fake of [`CredentialRepository`] for domain unit tests.
#[derive(Debug, Clone)]
pub struct InMemoryCredentialRepository {
    inner: Arc<Mutex<InMemoryCredentialRepositoryInner>>,
}

#[derive(Debug, Default)]
struct InMemoryCredentialRepositoryInner {
    account: Option<Account>,
    save_calls: Vec<Account>,
    load_calls: usize,
    delete_calls: usize,
}

impl InMemoryCredentialRepository {
    /// Create a new empty in-memory credential repository.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryCredentialRepositoryInner::default())),
        }
    }

    /// Pre-populate with an account.
    pub fn with_account(&self, account: Account) -> Self {
        self.inner.lock().unwrap().account = Some(account);
        self.clone()
    }

    /// Return the accounts passed to `save_account`.
    pub fn save_calls(&self) -> Vec<Account> {
        self.inner.lock().unwrap().save_calls.clone()
    }

    /// Return the number of times `load_account` was called.
    pub fn load_calls(&self) -> usize {
        self.inner.lock().unwrap().load_calls
    }

    /// Return the number of times `delete_account` was called.
    pub fn delete_calls(&self) -> usize {
        self.inner.lock().unwrap().delete_calls
    }
}

impl Default for InMemoryCredentialRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CredentialRepository for InMemoryCredentialRepository {
    async fn save_account(&self, account: &Account) -> Result<(), CredentialError> {
        let mut inner = self.inner.lock().unwrap();
        inner.save_calls.push(account.clone());
        inner.account = Some(account.clone());
        Ok(())
    }

    async fn load_account(&self) -> Result<Option<Account>, CredentialError> {
        let mut inner = self.inner.lock().unwrap();
        inner.load_calls += 1;
        Ok(inner.account.clone())
    }

    async fn delete_account(&self) -> Result<(), CredentialError> {
        let mut inner = self.inner.lock().unwrap();
        inner.delete_calls += 1;
        if inner.account.is_none() {
            return Err(CredentialError::NotFound);
        }
        inner.account = None;
        Ok(())
    }
}
