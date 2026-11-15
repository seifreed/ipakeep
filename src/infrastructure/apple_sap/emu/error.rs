//! Errors raised by the ARM64 emulator layer.

use std::time::Duration;

use thiserror::Error;
use unicorn_engine::uc_error;

/// Failure of an emulator operation or of guest code running inside it.
#[derive(Debug, Clone, Error)]
pub enum EmuError {
    /// Unicorn rejected a host request or stopped guest execution with an error.
    #[error("unicorn {operation} failed: {source}")]
    Unicorn {
        /// The host operation that failed (for example `emu_start`).
        operation: &'static str,
        /// The native Unicorn status code.
        #[source]
        source: uc_error,
    },
    /// Guest execution did not reach its stop address before the deadline.
    #[error("unicorn emulation timed out after {timeout:?}")]
    Timeout {
        /// The wall-clock budget that elapsed.
        timeout: Duration,
    },
    /// A bounded run was requested with a zero timeout.
    #[error("unicorn timeout must be positive")]
    InvalidTimeout,
    /// A register index outside the architectural range was requested.
    #[error("invalid arm64 register index {index}")]
    InvalidRegister {
        /// The rejected register index.
        index: u32,
    },
    /// A memory validator is already installed on this engine.
    #[error("unicorn memory validator is already installed")]
    GuardAlreadyInstalled,
    /// The installed memory validator rejected an access.
    #[error("guest memory access rejected at {address:#x} ({size} bytes): {reason}")]
    MemoryRejected {
        /// First byte of the rejected access.
        address: u64,
        /// Length of the rejected access in bytes.
        size: u64,
        /// Why the validator rejected the access.
        reason: String,
    },
    /// A hook callback reported a guest-level failure and stopped emulation.
    #[error("{0}")]
    Guest(String),
}

impl EmuError {
    /// Builds a [`EmuError::Guest`] fault from any displayable message.
    pub fn guest(message: impl std::fmt::Display) -> Self {
        Self::Guest(message.to_string())
    }

    /// Returns the native Unicorn status code, if this error carries one.
    pub fn unicorn_code(&self) -> Option<uc_error> {
        match self {
            Self::Unicorn { source, .. } => Some(*source),
            _ => None,
        }
    }
}

/// Builds a `map_err` adapter that tags a Unicorn status with its operation.
pub(super) fn native(operation: &'static str) -> impl Fn(uc_error) -> EmuError {
    move |source| EmuError::Unicorn { operation, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicorn_errors_expose_their_native_code() {
        let error = native("mem_map")(uc_error::MAP);

        assert_eq!(error.unicorn_code(), Some(uc_error::MAP));
        assert!(error.to_string().contains("mem_map"));
        assert_eq!(EmuError::guest("boom").unicorn_code(), None);
    }

    #[test]
    fn guest_faults_keep_their_message() {
        assert_eq!(
            EmuError::guest("unsupported import _foo").to_string(),
            "unsupported import _foo"
        );
    }
}
