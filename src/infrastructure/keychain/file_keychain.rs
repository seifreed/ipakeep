//! File-based credential storage for Apple account data.
//!
//! Stores credentials as JSON in `~/.ipakeep/auth.json`.
//! This implementation prioritizes simplicity and cross-platform compatibility.

use crate::domain::entity::Account;
use crate::domain::error::CredentialError;
use crate::domain::repository::CredentialRepository;
use async_trait::async_trait;
use std::path::Path;
use std::path::PathBuf;

/// File-based credential repository.
///
/// Credentials are stored as JSON at `~/.ipakeep/auth.json`.
/// The directory is created on first save if it doesn't exist.
pub struct FileKeychain {
    config_dir: PathBuf,
}

impl FileKeychain {
    /// Create a new file keychain using the default config directory.
    ///
    /// # Errors
    ///
    /// Returns `CredentialError::SaveFailed` if the config directory cannot be determined.
    pub fn new() -> Result<Self, CredentialError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| CredentialError::SaveFailed("cannot determine config directory".into()))?
            .join("ipakeep");

        Ok(Self { config_dir })
    }

    /// Create a file keychain with a custom config directory (useful for testing).
    pub fn with_dir(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    fn auth_file(&self) -> PathBuf {
        self.config_dir.join("auth.json")
    }

    async fn ensure_dir(&self) -> Result<(), CredentialError> {
        tokio::fs::create_dir_all(&self.config_dir)
            .await
            .map_err(|e: std::io::Error| CredentialError::SaveFailed(e.to_string()))?;
        secure_config_dir(&self.config_dir)
    }
}

#[async_trait]
impl CredentialRepository for FileKeychain {
    async fn save_account(&self, account: &Account) -> Result<(), CredentialError> {
        self.ensure_dir().await?;

        let json = serde_json::to_string_pretty(account).map_err(|e: serde_json::Error| {
            CredentialError::SaveFailed(format!("serialization failed: {e}"))
        })?;

        write_private_file(&self.auth_file(), &json)
    }

    async fn load_account(&self) -> Result<Option<Account>, CredentialError> {
        let path = self.auth_file();

        if !path.exists() {
            return Ok(None);
        }

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e: std::io::Error| CredentialError::LoadFailed(e.to_string()))?;

        let account: Account = serde_json::from_str(&content).map_err(|e: serde_json::Error| {
            CredentialError::InvalidCredentials(format!("failed to parse credentials: {e}"))
        })?;

        Ok(Some(account))
    }

    async fn delete_account(&self) -> Result<(), CredentialError> {
        let path = self.auth_file();

        if !path.exists() {
            return Err(CredentialError::NotFound);
        }

        tokio::fs::remove_file(&path)
            .await
            .map_err(|e: std::io::Error| CredentialError::DeleteFailed(e.to_string()))
    }
}

#[cfg(unix)]
fn secure_config_dir(path: &Path) -> Result<(), CredentialError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| CredentialError::SaveFailed(e.to_string()))
}

#[cfg(not(unix))]
fn secure_config_dir(_path: &Path) -> Result<(), CredentialError> {
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: &str) -> Result<(), CredentialError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CredentialError::SaveFailed(e.to_string()))?;

    file.write_all(content.as_bytes())
        .map_err(|e| CredentialError::SaveFailed(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CredentialError::SaveFailed(e.to_string()))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, content: &str) -> Result<(), CredentialError> {
    std::fs::write(path, content).map_err(|e| CredentialError::SaveFailed(e.to_string()))
}

impl Default for FileKeychain {
    fn default() -> Self {
        Self::new().expect("failed to create default FileKeychain")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
    async fn save_and_load_account() {
        let dir = TempDir::new().unwrap();
        let keychain = FileKeychain::with_dir(dir.path().to_path_buf());
        let account = test_account();

        keychain.save_account(&account).await.unwrap();
        let loaded = keychain.load_account().await.unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.email, "test@example.com");
        assert_eq!(loaded.password_token, "token123");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn save_account_sets_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let keychain = FileKeychain::with_dir(dir.path().to_path_buf());
        let account = test_account();

        keychain.save_account(&account).await.unwrap();

        let file_mode = std::fs::metadata(keychain.auth_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;

        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[tokio::test]
    async fn load_returns_none_when_no_file() {
        let dir = TempDir::new().unwrap();
        let keychain = FileKeychain::with_dir(dir.path().to_path_buf());

        let result = keychain.load_account().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_account_removes_file() {
        let dir = TempDir::new().unwrap();
        let keychain = FileKeychain::with_dir(dir.path().to_path_buf());
        let account = test_account();

        keychain.save_account(&account).await.unwrap();
        keychain.delete_account().await.unwrap();

        let result = keychain.load_account().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_without_file_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let keychain = FileKeychain::with_dir(dir.path().to_path_buf());

        let result = keychain.delete_account().await;
        assert!(result.is_err());
    }
}
