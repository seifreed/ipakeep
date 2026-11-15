//! ARM64 register naming independent of Unicorn's numeric identifiers.

use unicorn_engine::RegisterARM64;

use super::error::EmuError;

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

    /// Resolves this register to Unicorn's numeric identifier.
    pub(super) fn unicorn_id(self) -> Result<i32, EmuError> {
        match self {
            Self::X(index) if index < FRAME_POINTER_INDEX => {
                Ok(i32::from(RegisterARM64::X0) + i32::from(index))
            }
            Self::X(FRAME_POINTER_INDEX) => Ok(i32::from(RegisterARM64::X29)),
            Self::X(LINK_REGISTER_INDEX) => Ok(i32::from(RegisterARM64::X30)),
            Self::X(index) => Err(EmuError::InvalidRegister {
                index: u32::from(index),
            }),
            Self::Sp => Ok(i32::from(RegisterARM64::SP)),
            Self::Pc => Ok(i32::from(RegisterARM64::PC)),
            Self::Nzcv => Ok(i32::from(RegisterARM64::NZCV)),
        }
    }
}

/// Resolves vector register `V<index>` to Unicorn's numeric identifier.
pub(super) fn vector_id(index: u8) -> Result<i32, EmuError> {
    if index >= VECTOR_REGISTER_COUNT {
        return Err(EmuError::InvalidRegister {
            index: u32::from(index),
        });
    }

    Ok(i32::from(RegisterARM64::V0) + i32::from(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_registers_follow_unicorn_numbering() {
        assert_eq!(Register::X(0).unicorn_id().ok(), Some(199));
        assert_eq!(Register::X(28).unicorn_id().ok(), Some(227));
        assert_eq!(Register::FP.unicorn_id().ok(), Some(1));
        assert_eq!(Register::LR.unicorn_id().ok(), Some(2));
        assert_eq!(Register::Sp.unicorn_id().ok(), Some(4));
        assert_eq!(Register::Pc.unicorn_id().ok(), Some(260));
    }

    #[test]
    fn out_of_range_registers_are_rejected() {
        assert!(matches!(
            Register::X(31).unicorn_id(),
            Err(EmuError::InvalidRegister { index: 31 })
        ));
        assert!(vector_id(32).is_err());
        assert_eq!(vector_id(0).ok(), Some(228));
        assert_eq!(vector_id(31).ok(), Some(259));
    }
}
