//! Manual fake implementations of repository traits for domain unit tests.
//!
//! These fakes replace `mockall` mocks with real, deterministic, in-memory
//! implementations that respect Clean Architecture (no I/O, no external deps).

mod app_store;
mod credential;

pub use app_store::FakeAppStoreRepository;
pub use credential::InMemoryCredentialRepository;
