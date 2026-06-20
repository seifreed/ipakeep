//! [`AppStoreRepository`] implementation for the in-memory fake.

use super::FakeAppStoreRepository;
use crate::domain::entity::{Account, App, AppVersion, DownloadItem, TrustedPhoneNumber};
use crate::domain::error::AppStoreError;
use crate::domain::repository::AppStoreRepository;
use async_trait::async_trait;

#[async_trait]
impl AppStoreRepository for FakeAppStoreRepository {
    async fn authenticate(
        &self,
        email: &str,
        password: &str,
        guid: &str,
    ) -> Result<Account, AppStoreError> {
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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

    async fn list_trusted_phone_numbers(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError> {
        let mut inner = self.lock_inner();
        inner
            .list_trusted_phone_numbers_calls
            .push((dsid.to_string(), idms_token.to_string()));
        inner
            .list_trusted_phone_numbers_result
            .clone()
            .unwrap_or_else(|| Ok(Vec::new()))
    }

    async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
        inner
            .search_calls
            .push((term.to_string(), country.to_string(), limit));
        inner
            .search_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("search not configured".into())))
    }

    async fn lookup(&self, bundle_id: &str, country: &str) -> Result<Option<App>, AppStoreError> {
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
        inner
            .download_calls
            .push((account.clone(), app_id, guid.to_string(), version_id));
        inner
            .download_result
            .clone()
            .unwrap_or_else(|| Err(AppStoreError::Unexpected("download not configured".into())))
    }

    async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError> {
        let mut inner = self.lock_inner();
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
        let mut inner = self.lock_inner();
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
