//! Repository traits — ports defining data access contracts.

pub mod app_store_repository;
pub mod credential_repository;

#[cfg(test)]
pub mod fake;

pub use app_store_repository::AppStoreRepository;
pub use credential_repository::CredentialRepository;

#[cfg(test)]
pub use fake::{FakeAppStoreRepository, InMemoryCredentialRepository};
