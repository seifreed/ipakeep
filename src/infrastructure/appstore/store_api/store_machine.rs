//! The Apple machine services the native Store session depends on.
//!
//! Production uses the in-process [`SapService`]; tests substitute a fake so
//! the Store HTTP flows can run against a mock server.

use crate::domain::error::AppStoreError;
use crate::infrastructure::apple_sap::signer::SignerConfig;
use crate::infrastructure::apple_sap::storeauth::{SapService, StoreProvisioningRequest};
use async_trait::async_trait;
use std::collections::HashMap;

/// `X-Apple-AMD` header name (base64 Store ADI one-time password).
pub const AMD_HEADER: &str = "X-Apple-AMD";
/// `X-Apple-AMD-M` header name (base64 Store ADI machine identifier).
pub const AMD_M_HEADER: &str = "X-Apple-AMD-M";

/// Store AMD proof as `(X-Apple-AMD, X-Apple-AMD-M)`.
pub type StoreAmd = (String, String);

/// Anisette, Store AMD, kbsync and SAP signing for one machine identity.
///
/// The `*_blocking` methods serve the synchronous callbacks of the Store
/// commerce clients; they park the calling thread until the machine answers.
#[async_trait]
pub trait StoreMachine: Send + Sync {
    /// GSA anisette headers (`X-Apple-I-MD`, `-M`, `-RINFO`, ...).
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    async fn anisette_headers(&self) -> Result<HashMap<String, String>, AppStoreError>;

    /// Store AMD proof; fails until the Store "SP" provisioning ran.
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    async fn store_amd(&self) -> Result<StoreAmd, AppStoreError>;

    /// Blocking [`Self::store_amd`].
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    fn store_amd_blocking(&self) -> Result<StoreAmd, AppStoreError>;

    /// Raw kbsync for `dsid` on `hardware_id`.
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    async fn kbsync(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError>;

    /// Blocking [`Self::kbsync`].
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    fn kbsync_blocking(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError>;

    /// Opens (or keeps) the SAP session `sign_blocking` uses.
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    async fn connect_sap(&self, config: SignerConfig) -> Result<(), AppStoreError>;

    /// `X-Apple-ActionSignature` bytes for `body`.
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    fn sign_blocking(&self, body: &[u8]) -> Result<Vec<u8>, AppStoreError>;

    /// Runs the Store "SP" provisioning action Apple requested at sign-in.
    ///
    /// # Errors
    ///
    /// Asset, emulated machine, Apple HTTP or state-file failures.
    async fn provision_store(
        &self,
        request: &StoreProvisioningRequest<'_>,
    ) -> Result<(), AppStoreError>;
}

#[async_trait]
impl StoreMachine for SapService {
    async fn anisette_headers(&self) -> Result<HashMap<String, String>, AppStoreError> {
        Ok(SapService::anisette_headers(self).await?.to_map())
    }

    async fn store_amd(&self) -> Result<StoreAmd, AppStoreError> {
        let headers = self.store_amd_headers().await?;
        Ok((headers.amd, headers.amd_m))
    }

    fn store_amd_blocking(&self) -> Result<StoreAmd, AppStoreError> {
        let headers = self.store_amd_headers_blocking()?;
        Ok((headers.amd, headers.amd_m))
    }

    async fn kbsync(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        Ok(SapService::kbsync(self, hardware_id, dsid).await?)
    }

    fn kbsync_blocking(&self, hardware_id: &[u8], dsid: u64) -> Result<Vec<u8>, AppStoreError> {
        Ok(SapService::kbsync_blocking(self, hardware_id, dsid)?)
    }

    async fn connect_sap(&self, config: SignerConfig) -> Result<(), AppStoreError> {
        Ok(SapService::connect_sap(self, config).await?)
    }

    fn sign_blocking(&self, body: &[u8]) -> Result<Vec<u8>, AppStoreError> {
        Ok(SapService::sign_blocking(self, body)?)
    }

    async fn provision_store(
        &self,
        request: &StoreProvisioningRequest<'_>,
    ) -> Result<(), AppStoreError> {
        Ok(SapService::provision_store(self, request).await?)
    }
}

/// The Store AMD proof as request headers.
#[must_use]
pub fn amd_headers((amd, amd_m): StoreAmd) -> HashMap<String, String> {
    HashMap::from([
        (AMD_HEADER.to_string(), amd),
        (AMD_M_HEADER.to_string(), amd_m),
    ])
}
