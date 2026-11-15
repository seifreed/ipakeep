//! Decoded, load-address-independent pointer fixups.

/// A pointer-sized fixup at a file offset of the thin image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relocation {
    /// Write `load_base + target` at `offset`.
    Rebase {
        /// File offset of the pointer.
        offset: u64,
        /// Target relative to the image's preferred base.
        target: u64,
    },
    /// Write `resolve(symbol) + addend` at `offset`.
    Bind {
        /// File offset of the pointer.
        offset: u64,
        /// Imported symbol name.
        symbol: String,
        /// Signed addend applied to the resolved address.
        addend: i64,
    },
}

impl Relocation {
    /// File offset the fixup writes to.
    pub fn offset(&self) -> u64 {
        match self {
            Self::Rebase { offset, .. } | Self::Bind { offset, .. } => *offset,
        }
    }
}
