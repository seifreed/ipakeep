//! Errors raised by the ARM64 emulator layer.

use std::time::Duration;

use thiserror::Error;

/// A classification of an engine-level failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineErrorCode {
    /// A guest or host memory access hit unmapped memory.
    ReadUnmapped,
    /// The engine decoded an instruction it does not implement.
    InvalidInstruction,
}

impl std::fmt::Display for EngineErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::ReadUnmapped => "unmapped read",
            Self::InvalidInstruction => "invalid instruction",
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
        /// The failure classification.
        code: EngineErrorCode,
    },
    /// A memory access hit unmapped memory at a known address.
    #[error("engine {operation} failed: {code} at {address:#x}{}", pc_suffix(*.pc))]
    Unmapped {
        /// The host operation that failed (for example `mem_access`).
        operation: &'static str,
        /// The failure classification.
        code: EngineErrorCode,
        /// The first unmapped byte of the access.
        address: u64,
        /// The guest instruction that faulted, when the access came from
        /// executing guest code (`None` for a host-side memory access).
        pc: Option<u64>,
    },
    /// Guest execution did not reach its stop address before the deadline.
    #[error("emulation timed out after {timeout:?}")]
    Timeout {
        /// The wall-clock budget that elapsed.
        timeout: Duration,
    },
    /// A register index outside the architectural range was requested.
    #[error("invalid arm64 register index {index}")]
    InvalidRegister {
        /// The rejected register index.
        index: u32,
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

    /// Returns the failure code, if this error carries one.
    pub fn engine_code(&self) -> Option<EngineErrorCode> {
        match self {
            Self::Engine { code, .. } | Self::Unmapped { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// Formats the optional faulting PC of [`EmuError::Unmapped`].
fn pc_suffix(pc: Option<u64>) -> String {
    pc.map_or_default(|pc| format!(" (pc {pc:#x})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_errors_expose_their_code() {
        let error = EmuError::engine("execute", EngineErrorCode::InvalidInstruction);

        assert_eq!(
            error.engine_code(),
            Some(EngineErrorCode::InvalidInstruction)
        );
        assert!(error.to_string().contains("execute"));
        assert_eq!(EmuError::guest("boom").engine_code(), None);
    }

    #[test]
    fn unmapped_errors_name_the_address_and_pc() {
        let error = EmuError::Unmapped {
            operation: "mem_access",
            code: EngineErrorCode::ReadUnmapped,
            address: 0xdead_beef,
            pc: Some(0x1000),
        };
        assert_eq!(error.engine_code(), Some(EngineErrorCode::ReadUnmapped));
        assert_eq!(
            error.to_string(),
            "engine mem_access failed: unmapped read at 0xdeadbeef (pc 0x1000)"
        );
        let host = EmuError::Unmapped {
            operation: "mem_access",
            code: EngineErrorCode::ReadUnmapped,
            address: 0x10,
            pc: None,
        };
        assert_eq!(
            host.to_string(),
            "engine mem_access failed: unmapped read at 0x10"
        );
    }

    #[test]
    fn engine_error_codes_display_a_readable_text() {
        for (code, text) in [
            (EngineErrorCode::ReadUnmapped, "unmapped read"),
            (EngineErrorCode::InvalidInstruction, "invalid instruction"),
        ] {
            assert_eq!(code.to_string(), text);
        }
    }

    #[test]
    fn guest_faults_keep_their_message() {
        assert_eq!(
            EmuError::guest("unsupported import _foo").to_string(),
            "unsupported import _foo"
        );
    }
}
