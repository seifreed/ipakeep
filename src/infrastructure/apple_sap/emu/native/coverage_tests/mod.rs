//! Coverage-closing tests for the native interpreter.
//!
//! * `unsupported` — encodings that are unallocated or deliberately out of
//!   scope must stop with the exact [`NativeError::Unsupported`] (native only).
//! * `engine` / `cpu` — the `NativeEngine` run loop and `NativeCpu`/`Memory`
//!   helpers (native only).
//! * `diff_*` — executable encodings checked differentially against Unicorn.

use super::{NativeCpu, NativeError, Step};

mod cpu;
mod engine;
mod unsupported;

#[cfg(feature = "unicorn")]
mod diff_bugs;
#[cfg(feature = "unicorn")]
mod diff_int;
#[cfg(feature = "unicorn")]
mod diff_ldst;
#[cfg(feature = "unicorn")]
mod diff_simd;

/// Code base used for single-instruction native runs (same as the diff harness).
const CODE: u64 = 0x1_0000;

/// Executes the single instruction `word` at [`CODE`] on a fresh CPU.
fn step_one(word: u32) -> Result<Step, NativeError> {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(CODE, 0x1000);
    cpu.mem.write(CODE, &word.to_le_bytes()).unwrap();
    cpu.set_pc(CODE);
    cpu.step()
}

/// Asserts that `word` is rejected with exactly `Unsupported { what }`.
#[track_caller]
fn assert_unsupported(word: u32, what: &'static str) {
    assert_eq!(
        step_one(word),
        Err(NativeError::Unsupported {
            pc: CODE,
            word,
            what
        }),
        "word {word:#010x}"
    );
}
