use crate::domain::entity::{Account, App, AppVersion, DownloadItem, OwnedApp, TrustedPhoneNumber};
use crate::domain::error::{AppStoreError, CredentialError};
use crate::domain::repository::{
    AuthenticationRepository, CatalogRepository, CredentialRepository, DownloadRepository,
    PurchaseRepository, VersionRepository,
};
use async_trait::async_trait;
use mockall::mock;

mock! {
    pub AppStoreRepo {}

    #[async_trait]
    impl AuthenticationRepository for AppStoreRepo {
        async fn authenticate(
            &self,
            email: &str,
            password: &str,
            guid: &str,
        ) -> Result<Account, AppStoreError>;
        async fn authenticate_with_2fa(
            &self,
            email: &str,
            password: &str,
            code: &str,
            guid: &str,
        ) -> Result<Account, AppStoreError>;
        async fn authenticate_grandslam(
            &self,
            email: &str,
            password: &str,
            guid: &str,
        ) -> Result<Account, AppStoreError>;
        async fn request_trusted_device_notification(
            &self,
            dsid: &str,
            idms_token: &str,
        ) -> Result<(), AppStoreError>;
        async fn validate_trusted_device_code(
            &self,
            dsid: &str,
            idms_token: &str,
            code: &str,
        ) -> Result<(), AppStoreError>;
        async fn list_trusted_phone_numbers(
            &self,
            dsid: &str,
            idms_token: &str,
        ) -> Result<Vec<TrustedPhoneNumber>, AppStoreError>;
        async fn request_sms(
            &self,
            dsid: &str,
            idms_token: &str,
            phone_id: i64,
        ) -> Result<(), AppStoreError>;
        async fn validate_sms_code(
            &self,
            dsid: &str,
            idms_token: &str,
            phone_id: i64,
            code: &str,
        ) -> Result<(), AppStoreError>;
    }

    #[async_trait]
    impl CatalogRepository for AppStoreRepo {
        async fn search(
            &self,
            term: &str,
            country: &str,
            limit: u32,
        ) -> Result<Vec<App>, AppStoreError>;
        async fn lookup(
            &self,
            bundle_id: &str,
            country: &str,
        ) -> Result<Option<App>, AppStoreError>;
    }

    #[async_trait]
    impl PurchaseRepository for AppStoreRepo {
        async fn purchase(
            &self,
            account: &Account,
            app_id: i64,
            guid: &str,
        ) -> Result<(), AppStoreError>;
        async fn list_purchases(
            &self,
            account: &Account,
            limit: u32,
        ) -> Result<Vec<OwnedApp>, AppStoreError>;
    }

    #[async_trait]
    impl DownloadRepository for AppStoreRepo {
        async fn download(
            &self,
            account: &Account,
            app_id: i64,
            guid: &str,
            version_id: Option<String>,
        ) -> Result<Vec<DownloadItem>, AppStoreError>;
        async fn download_bytes(&self, url: &str) -> Result<Vec<u8>, AppStoreError>;
    }

    #[async_trait]
    impl VersionRepository for AppStoreRepo {
        async fn list_versions(
            &self,
            account: &Account,
            app_id: i64,
            guid: &str,
        ) -> Result<Vec<AppVersion>, AppStoreError>;
    }
}

mock! {
    pub CredentialRepo {}

    #[async_trait]
    impl CredentialRepository for CredentialRepo {
        async fn save_account(&self, account: &Account) -> Result<(), CredentialError>;
        async fn load_account(&self) -> Result<Option<Account>, CredentialError>;
        async fn delete_account(&self) -> Result<(), CredentialError>;
    }
}

pub(crate) use MockAppStoreRepo as AppStoreRepo;
pub(crate) use MockCredentialRepo as CredentialRepo;
