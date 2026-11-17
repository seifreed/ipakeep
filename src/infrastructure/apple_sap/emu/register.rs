//! ARM64 register naming used by the engine API.

/// Index of the frame pointer in the general-purpose register file.
pub const FRAME_POINTER_INDEX: u8 = 29;
/// Index of the link register in the general-purpose register file.
pub const LINK_REGISTER_INDEX: u8 = 30;
/// Number of 128-bit SIMD/FP registers (`V0`..`V31`).
pub const VECTOR_REGISTER_COUNT: u8 = 32;
/// Number of general-purpose argument registers in the AAPCS64 (`X0`..`X7`).
pub const ARGUMENT_REGISTER_COUNT: u8 = 8;

/// A 64-bit ARM64 register accessible through the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    /// General-purpose register `X0`..`X30` (`X29` = FP, `X30` = LR).
    X(u8),
    /// Stack pointer.
    Sp,
    /// Program counter.
    Pc,
    /// Condition flags.
    Nzcv,
}

impl Register {
    /// The frame pointer, `X29`.
    pub const FP: Self = Self::X(FRAME_POINTER_INDEX);
    /// The link register, `X30`.
    pub const LR: Self = Self::X(LINK_REGISTER_INDEX);
}
