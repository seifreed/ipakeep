//! Data-processing -- register (ARM ARM C4.1.3)

use super::{NativeCpu, NativeError, Step};

/// Runs a dpreg instruction. (Stub — filled in per instruction group.)
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    Err(NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what: "data-proc-reg (stub)",
    })
}
