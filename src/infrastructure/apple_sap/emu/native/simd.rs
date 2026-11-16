//! SIMD/FP + crypto-extension (NEON, scalar FP, `eor3`) — the small vector
//! surface the OTP whitebox uses (~0.01% of executed instructions).

use super::{NativeCpu, NativeError, Step};

/// Runs a data-processing SIMD/FP instruction. (Stub — filled in by the SIMD group.)
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    Err(NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what: "simd/fp (stub)",
    })
}

/// Runs a SIMD/FP load/store — the `V == 1` forms of the load/store class,
/// delegated here by `ldst::run`. (Stub — filled in by the SIMD group.)
pub(super) fn load_store(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    Err(NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what: "simd/fp ldst (stub)",
    })
}
