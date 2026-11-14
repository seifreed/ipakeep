//! Deterministic in-memory repository implementations for adapter tests.
//!
//! These fakes avoid I/O and external dependencies.

mod app_store;
mod credential;

pub use app_store::FakeAppStoreRepository;
pub use credential::InMemoryCredentialRepository;
