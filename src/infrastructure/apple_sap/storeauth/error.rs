//! Failures of the in-process Store authentication service.

use thiserror::Error;

use crate::domain::error::AppStoreError;
use crate::infrastructure::apple_sap::assets::bundle::BundleError;
use crate::infrastructure::apple_sap::machine::sap::MachineError;
use crate::infrastructure::apple_sap::signer::SignerError;

/// Failure of anisette provisioning, Store AMD, kbsync or SAP signing.
#[derive(Debug, Error)]
pub enum StoreAuthError {
    /// The persisted `anisette-v4.json` state is invalid.
    #[error("invalid persisted anisette state: {0}")]
    State(&'static str),
    /// Reading, locking or replacing the state file failed.
    #[error("{action}: {source}")]
    Io {
        /// What was being done.
        action: &'static str,
        /// The operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The pinned Apple framework bundle is unavailable.
    #[error("load Apple SAP assets: {0}")]
    Bundle(#[from] BundleError),
    /// An emulated machine failed.
    #[error("Apple SAP machine: {0}")]
    Machine(#[from] MachineError),
    /// The SAP signer failed.
    #[error("Apple SAP signer: {0}")]
    Signer(#[from] SignerError),
    /// An HTTP exchange with Apple failed at the transport level.
    #[error("{context}: {source}")]
    Http {
        /// Which exchange.
        context: &'static str,
        /// The client error.
        #[source]
        source: reqwest::Error,
    },
    /// Apple answered with an unexpected status or body.
    #[error("{0}")]
    Protocol(String),
    /// DSID `-1` has not been provisioned through the Store "SP" action.
    #[error("store AMD state is not provisioned; run 'auth login' to authenticate")]
    StoreNotProvisioned,
    /// No SAP session was opened with [`super::SapService::connect_sap`].
    #[error("no Apple SAP session is open")]
    NoSapSession,
    /// A multi-step operation was continued without being started.
    #[error("{0} was not started")]
    NotStarted(&'static str),
    /// The worker thread that owns the machines has stopped.
    #[error("Apple SAP worker thread stopped")]
    WorkerStopped,
}

/// Result alias of the Store authentication service.
pub type StoreAuthResult<T> = Result<T, StoreAuthError>;

impl From<StoreAuthError> for AppStoreError {
    fn from(error: StoreAuthError) -> Self {
        match error {
            StoreAuthError::StoreNotProvisioned => Self::AuthenticationFailed(error.to_string()),
            StoreAuthError::Http { .. } | StoreAuthError::Protocol(_) => {
                Self::NetworkError(error.to_string())
            }
            other => Self::Unexpected(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_store_failures_to_domain_errors() {
        assert!(matches!(
            AppStoreError::from(StoreAuthError::StoreNotProvisioned),
            AppStoreError::AuthenticationFailed(_)
        ));
        assert!(matches!(
            AppStoreError::from(StoreAuthError::Protocol("HTTP 503".into())),
            AppStoreError::NetworkError(message) if message == "HTTP 503"
        ));
        assert!(matches!(
            AppStoreError::from(StoreAuthError::NoSapSession),
            AppStoreError::Unexpected(message) if message == "no Apple SAP session is open"
        ));
    }
}
