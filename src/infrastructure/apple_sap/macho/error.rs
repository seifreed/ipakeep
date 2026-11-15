//! Errors raised while preparing Mach-O images for emulation.

use thiserror::Error;

/// Failure to parse, prepare, relocate or lay out a Mach-O image.
#[derive(Debug, Error)]
pub enum MachoError {
    /// The universal (fat) binary header is malformed.
    #[error("invalid universal binary: {0}")]
    InvalidFat(&'static str),
    /// A universal binary does not contain an arm64e slice.
    #[error("universal binary has no arm64e slice")]
    MissingArm64e,
    /// The thin image is not a 64-bit little-endian arm64 Mach-O.
    #[error("{image}: expected an arm64 Mach-O image")]
    NotArm64 {
        /// Image name.
        image: String,
    },
    /// A structure inside the Mach-O is truncated or out of bounds.
    #[error("{image}: malformed Mach-O: {reason}")]
    Malformed {
        /// Image name.
        image: String,
        /// Human-readable description of the inconsistency.
        reason: String,
    },
    /// The image uses a fixup encoding that the emulator does not support.
    #[error("{image}: unsupported fixup: {reason}")]
    Unsupported {
        /// Image name.
        image: String,
        /// Human-readable description of the unsupported construct.
        reason: String,
    },
    /// A symbol could not be found in the image.
    #[error("{image}: symbol {symbol} not found")]
    SymbolNotFound {
        /// Image name.
        image: String,
        /// Requested symbol.
        symbol: String,
    },
    /// The caller-supplied resolver failed for an import.
    #[error("{image}: resolve {symbol}: {reason}")]
    Resolve {
        /// Image name.
        image: String,
        /// Import being resolved.
        symbol: String,
        /// Resolver failure message.
        reason: String,
    },
    /// Address arithmetic overflowed or underflowed.
    #[error("{image}: address overflow: {context}")]
    Overflow {
        /// Image name.
        image: String,
        /// What was being computed.
        context: String,
    },
    /// The image was relocated twice, or loaded before relocation.
    #[error("{image}: {reason}")]
    State {
        /// Image name.
        image: String,
        /// Description of the state violation.
        reason: &'static str,
    },
    /// Reading the input stream failed.
    #[error("read image: {0}")]
    Io(#[from] std::io::Error),
}

impl MachoError {
    pub(crate) fn malformed(image: &str, reason: impl Into<String>) -> Self {
        Self::Malformed {
            image: image.to_owned(),
            reason: reason.into(),
        }
    }

    pub(crate) fn unsupported(image: &str, reason: impl Into<String>) -> Self {
        Self::Unsupported {
            image: image.to_owned(),
            reason: reason.into(),
        }
    }

    pub(crate) fn overflow(image: &str, context: impl Into<String>) -> Self {
        Self::Overflow {
            image: image.to_owned(),
            context: context.into(),
        }
    }
}

/// Result alias for this module.
pub type MachoResult<T> = Result<T, MachoError>;
