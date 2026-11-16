//! Errors raised by the ARM64 emulator layer.
//!
//! The error type is backend-neutral: it carries an [`EngineErrorCode`] rather
//! than a Unicorn `uc_error`, so the same surface serves either the Unicorn
//! backend or the native interpreter.

use std::time::Duration;

use thiserror::Error;

/// A backend-neutral classification of an engine-level failure.
///
/// The Unicorn backend maps its `uc_error` onto these; the native interpreter
/// raises them directly. [`EngineErrorCode::InvalidInstruction`] and
/// [`EngineErrorCode::Exception`] are the ones the run loop uses to decide
/// whether to attempt soft-emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineErrorCode {
    /// A memory-map request was rejected (misaligned, overlapping, unmapped).
    Map,
    /// A guest load hit unmapped memory.
    ReadUnmapped,
    /// A guest store hit unmapped memory.
    WriteUnmapped,
    /// An instruction fetch hit unmapped memory.
    FetchUnmapped,
    /// Guest execution raised an exception (e.g. an undefined instruction).
    Exception,
    /// The engine decoded an instruction it does not implement.
    InvalidInstruction,
    /// Any other engine-level failure.
    Other,
}

impl std::fmt::Display for EngineErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Map => "memory map rejected",
            Self::ReadUnmapped => "unmapped read",
            Self::WriteUnmapped => "unmapped write",
            Self::FetchUnmapped => "unmapped fetch",
            Self::Exception => "guest exception",
            Self::InvalidInstruction => "invalid instruction",
            Self::Other => "engine error",
        };
        f.write_str(text)
    }
}

/// Failure of an emulator operation or of guest code running inside it.
#[derive(Debug, Clone, Error)]
pub enum EmuError {
    /// The engine rejected a host request or stopped guest execution with an error.
    #[error("engine {operation} failed: {code}")]
    Engine {
        /// The host operation that failed (for example `emu_start`).
        operation: &'static str,
        /// The backend-neutral failure classification.
        code: EngineErrorCode,
    },
    /// Guest execution did not reach its stop address before the deadline.
    #[error("emulation timed out after {timeout:?}")]
    Timeout {
        /// The wall-clock budget that elapsed.
        timeout: Duration,
    },
    /// A bounded run was requested with a zero timeout.
    #[error("emulation timeout must be positive")]
    InvalidTimeout,
    /// A register index outside the architectural range was requested.
    #[error("invalid arm64 register index {index}")]
    InvalidRegister {
        /// The rejected register index.
        index: u32,
    },
    /// A memory validator is already installed on this engine.
    #[error("memory validator is already installed")]
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

    /// Builds an [`EmuError::Engine`] from an operation name and a code.
    pub(super) fn engine(operation: &'static str, code: EngineErrorCode) -> Self {
        Self::Engine { operation, code }
    }

    /// Returns the backend-neutral failure code, if this error carries one.
    pub fn engine_code(&self) -> Option<EngineErrorCode> {
        match self {
            Self::Engine { code, .. } => Some(*code),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_errors_expose_their_code() {
        let error = EmuError::engine("mem_map", EngineErrorCode::Map);

        assert_eq!(error.engine_code(), Some(EngineErrorCode::Map));
        assert!(error.to_string().contains("mem_map"));
        assert_eq!(EmuError::guest("boom").engine_code(), None);
    }

    #[test]
    fn guest_faults_keep_their_message() {
        assert_eq!(
            EmuError::guest("unsupported import _foo").to_string(),
            "unsupported import _foo"
        );
    }
}
