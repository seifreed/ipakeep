//! Infrastructure layer — frameworks, drivers, and external service implementations.
//!
//! This layer contains concrete implementations of the repository traits
//! defined in the domain layer. It depends on the domain layer but
//! nothing in the domain layer depends on it.

pub mod appstore;
pub mod decrypt;
pub(crate) mod exec;
pub mod grandslam;
pub mod http;
pub mod ipa;
pub mod keychain;
pub mod simulator;
