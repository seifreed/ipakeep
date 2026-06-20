//! In-memory credential repository for domain unit tests.

#![allow(clippy::missing_panics_doc, clippy::return_self_not_must_use)]

use crate::domain::entity::Account;
use crate::domain::error::CredentialError;
use crate::domain::repository::CredentialRepository;
use async_trait::async_trait;
use std::sync::{Arc, Mutex, MutexGuard};

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
        self.lock_inner().account = Some(account);
        self.clone()
    }

    /// Return the accounts passed to `save_account`.
    pub fn save_calls(&self) -> Vec<Account> {
        self.lock_inner().save_calls.clone()
    }

    /// Return the number of times `load_account` was called.
    pub fn load_calls(&self) -> usize {
        self.lock_inner().load_calls
    }

    /// Return the number of times `delete_account` was called.
    pub fn delete_calls(&self) -> usize {
        self.lock_inner().delete_calls
    }

    fn lock_inner(&self) -> MutexGuard<'_, InMemoryCredentialRepositoryInner> {
        match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        }
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
        let mut inner = self.lock_inner();
        inner.save_calls.push(account.clone());
        inner.account = Some(account.clone());
        Ok(())
    }

    async fn load_account(&self) -> Result<Option<Account>, CredentialError> {
        let mut inner = self.lock_inner();
        inner.load_calls += 1;
        Ok(inner.account.clone())
    }

    async fn delete_account(&self) -> Result<(), CredentialError> {
        let mut inner = self.lock_inner();
        inner.delete_calls += 1;
        if inner.account.is_none() {
            return Err(CredentialError::NotFound);
        }
        inner.account = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn records_calls_and_stores_account() {
        let repo = InMemoryCredentialRepository::new();
        let account = account();

        repo.save_account(&account).await.unwrap();
        assert_eq!(
            repo.load_account()
                .await
                .unwrap()
                .as_ref()
                .map(|a| a.email.as_str()),
            Some("test@example.com")
        );
        repo.delete_account().await.unwrap();

        assert_eq!(repo.save_calls().len(), 1);
        assert_eq!(repo.save_calls()[0].email, account.email);
        assert_eq!(repo.load_calls(), 1);
        assert_eq!(repo.delete_calls(), 1);
        assert!(repo.load_account().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn with_account_prepopulates_repository() {
        let repo = InMemoryCredentialRepository::new().with_account(account());

        assert!(repo.load_account().await.unwrap().is_some());
    }
}
