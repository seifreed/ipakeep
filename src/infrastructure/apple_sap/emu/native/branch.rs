//! Branches, exception generating and system (ARM ARM C4.1.4)

use super::{NativeCpu, NativeError, Step};

/// Runs a branch instruction. (Stub — filled in per instruction group.)
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    Err(NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what: "branch/system (stub)",
    })
}
