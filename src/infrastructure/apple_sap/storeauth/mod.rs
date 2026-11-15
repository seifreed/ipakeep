//! In-process Store authentication: GSA machine provisioning (anisette),
//! Store AMD headers, the Store "SP" provisioning action, kbsync and SAP
//! signing.
//!
//! Port of upstream ipatool's `internal/storeauth` and the anisette state
//! handling of `pkg/appstore/appstore_native_login.go`, replacing the Go
//! helper. All emulated machines live on one worker thread behind the
//! `Send + Sync` [`SapService`] handle; the provisioning is persisted in the
//! Go helper's `anisette-v4.json` (see [`state`]).

pub mod anisette;
pub mod error;
pub mod service;
pub mod state;
pub mod store_provisioning;
mod worker;
mod xml;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use anisette::AnisetteHeaders;
pub use error::{StoreAuthError, StoreAuthResult};
pub use service::{SapService, ServiceConfig, apple_auth_client};
pub use state::{AnisetteState, StateStore};
pub use store_provisioning::StoreProvisioningRequest;
pub use worker::{BundleSource, EnvironmentFactory, IdentifierSource};
