//! Domain layer — enterprise business rules with no external dependencies.
//!
//! This layer contains:
//! - **Entities**: Core business objects (Account, App, Sinf)
//! - **Repositories**: Trait contracts for data access (ports)
//! - **Use Cases**: Application business rules orchestrating entities
//! - **Errors**: Domain-specific error types
//!
//! The dependency rule: this layer depends on NOTHING outside itself.

pub mod entity;
pub mod error;
pub mod repository;
pub mod usecase;
