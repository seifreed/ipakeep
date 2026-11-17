//! ARM64 emulator layer that runs the Apple SAP/ADI guest code.
//!
//! [`Engine`] is ipakeep's own native Rust A64 interpreter (`native`): no C
//! toolchain, no external engine, nothing downloaded or loaded at runtime. It
//! is checked differentially against Unicorn results frozen as test fixtures
//! (see `native/frozen.rs`) and end to end against golden Apple vectors.
//!
//! # Host-implemented functions (shims)
//!
//! Write [`RET_INSTRUCTION`] at each shim address with
//! [`Engine::write_return_stub`], register one [`Engine::add_code_hook`] over the
//! shim area and dispatch on the hooked address. The hook runs before the `ret`
//! executes, so a handler only needs to read arguments from `X0..X7`, write its
//! result to `X0` and return `Ok(())`; the stub then returns to `LR`. Returning
//! `Err` stops the guest and surfaces the error from [`Engine::run`].

mod consts;
mod error;
mod register;

/// A64 instruction classifier (decode-only, no execution). Foundation for the
/// native interpreter and the opcode-histogram probe.
pub(crate) mod decode;
/// Native Rust A64 interpreter.
mod native;

pub use consts::{INSTRUCTION_SIZE, RET_INSTRUCTION};
pub use error::EmuError;
pub use native::engine::{HookId, NativeEngine as Engine};
pub use register::{
    ARGUMENT_REGISTER_COUNT, FRAME_POINTER_INDEX, LINK_REGISTER_INDEX, Register,
    VECTOR_REGISTER_COUNT,
};
