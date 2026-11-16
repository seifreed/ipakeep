//! Loads and stores (ARM ARM C4.1.5)

use super::{NativeCpu, NativeError, Step};

/// Runs a ldst instruction. (Stub — filled in per instruction group.)
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    Err(NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what: "load/store (stub)",
    })
}
