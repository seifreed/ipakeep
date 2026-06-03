//! Credential repository trait — the port for credential persistence.

use crate::domain::entity::Account;
use crate::domain::error::CredentialError;

/// Repository trait for storing and retrieving Apple account credentials.
///
/// Implementations may store credentials in a file, OS keychain,
/// or any other persistent medium.
#[async_trait::async_trait]
pub trait CredentialRepository: Send + Sync {
    /// Save account credentials to persistent storage.
    async fn save_account(&self, account: &Account) -> Result<(), CredentialError>;

    /// Load stored account credentials. Returns `None` if no credentials exist.
    async fn load_account(&self) -> Result<Option<Account>, CredentialError>;

    /// Delete stored account credentials.
    async fn delete_account(&self) -> Result<(), CredentialError>;
}
