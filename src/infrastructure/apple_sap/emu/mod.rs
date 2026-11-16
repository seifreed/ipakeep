//! ARM64 emulator layer over the `unicorn-engine` crate.
//!
//! Port of ipatool's `internal/sap/unicorn` engine wrapper (CPU model, memory,
//! registers, bounded execution, code/memory hooks, memory guard) and of
//! `internal/sap/machine/arm64.go` (software emulation of `CASAL`, `SWPAL` and
//! `EOR3`). Unicorn is compiled from source by the crate, so nothing is
//! downloaded or loaded at runtime.
//!
//! # Host-implemented functions (shims)
//!
//! Write [`RET_INSTRUCTION`] at each shim address with
//! [`Engine::write_return_stub`], register one [`Engine::add_code_hook`] over the
//! shim area and dispatch on the hooked address. The hook runs before the `ret`
//! executes, so a handler only needs to read arguments from `X0..X7`, write its
//! result to `X0` and return `Ok(())`; the stub then returns to `LR`. Returning
//! `Err` stops the guest and surfaces the error from [`Engine::run`].

mod arm64;
/// Backend-neutral A64 instruction classifier (decode-only, no execution).
/// Foundation for the native interpreter and the opcode-histogram probe.
#[cfg(test)]
pub(crate) mod decode;
mod engine;
mod error;
mod guard;
mod hook;
/// Native Rust A64 interpreter (in development; validated differentially
/// against the Unicorn backend before replacing it).
#[cfg(test)]
mod native;
mod register;

pub use engine::{
    Engine, INSTRUCTION_SIZE, RET_INSTRUCTION, UNLIMITED_INSTRUCTIONS, VECTOR_REGISTER_SIZE,
};
pub use error::EmuError;
pub use hook::{ALL_ADDRESSES_BEGIN, ALL_ADDRESSES_END, HookId, MemoryAccess};
pub use register::{
    ARGUMENT_REGISTER_COUNT, FRAME_POINTER_INDEX, LINK_REGISTER_INDEX, Register,
    VECTOR_REGISTER_COUNT,
};

#[cfg(test)]
mod tests;
