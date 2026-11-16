//! ARM64 emulator layer that runs the Apple SAP/ADI guest code.
//!
//! Two backends implement the same [`Engine`] API:
//!
//! - `native-cpu` (default, MIT): the native Rust A64 interpreter in `native`.
//! - `unicorn` (deprecated, GPLv2): a port of ipatool's `internal/sap/unicorn`
//!   engine wrapper (CPU model, memory, registers, bounded execution,
//!   code/memory hooks, memory guard) and of `internal/sap/machine/arm64.go`
//!   (software emulation of `CASAL`, `SWPAL` and `EOR3`) over the
//!   `unicorn-engine` crate, compiled from source (needs cmake and libclang).
//!   Kept as a legacy backend and as the oracle of the differential tests.
//!
//! `native-cpu` wins when both features are on; the Unicorn engine then stays
//! reachable as `UnicornEngine`. Nothing is downloaded or loaded at runtime.
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

// Deprecated Unicorn backend (GPLv2): compiled whenever `unicorn` is on. It is
// the selected `Engine` only without `native-cpu`; with both features it stays
// reachable as [`UnicornEngine`], the oracle of the native differential tests.
#[cfg(feature = "unicorn")]
mod arm64;
#[cfg(feature = "unicorn")]
mod engine;
#[cfg(feature = "unicorn")]
mod guard;
#[cfg(feature = "unicorn")]
mod hook;

/// Backend-neutral A64 instruction classifier (decode-only, no execution).
/// Foundation for the native interpreter and the opcode-histogram probe.
#[cfg(any(test, feature = "native-cpu"))]
pub(crate) mod decode;
/// Native Rust A64 interpreter (permissively licensed replacement for Unicorn).
#[cfg(any(test, feature = "native-cpu"))]
mod native;

pub use consts::{INSTRUCTION_SIZE, RET_INSTRUCTION};
pub use error::EmuError;
pub use register::{
    ARGUMENT_REGISTER_COUNT, FRAME_POINTER_INDEX, LINK_REGISTER_INDEX, Register,
    VECTOR_REGISTER_COUNT,
};

// Backend selection — `native-cpu` takes priority when both features are on.
/// The deprecated Unicorn engine under an explicit name, whichever backend is
/// selected as [`Engine`].
#[cfg(feature = "unicorn")]
pub use engine::Engine as UnicornEngine;
#[cfg(all(feature = "unicorn", not(feature = "native-cpu")))]
pub use engine::{Engine, UNLIMITED_INSTRUCTIONS, VECTOR_REGISTER_SIZE};
#[cfg(all(feature = "unicorn", not(feature = "native-cpu")))]
pub use hook::{ALL_ADDRESSES_BEGIN, ALL_ADDRESSES_END, HookId, MemoryAccess};
#[cfg(feature = "native-cpu")]
pub use native::engine::{HookId, NativeEngine as Engine};

// Unicorn-backend tests: they exercise APIs only the Unicorn engine exposes.
#[cfg(all(test, feature = "unicorn"))]
mod tests;
