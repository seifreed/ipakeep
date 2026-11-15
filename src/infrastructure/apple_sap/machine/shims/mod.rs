//! Emulated platform functions for Apple SAP/ADI images.
//!
//! Port of upstream ipatool's `internal/sap/machine` shim layer (`shims.go`,
//! `shim_memory.go`, `shim_platform.go`, `ioaes.go`, `macos27.go`): about two
//! hundred libc, `CoreFoundation`, `IOKit`, XPC, Mach, pthread and dispatch
//! functions, a guest heap, in-memory files for `adi.pb` and `CoreFP.icxs`,
//! faked XPC objects for `com.apple.adid`, Mach message routing, the
//! `IOAESAccelerator` zero-key AES-CBC, pinned `sysctl`/`gethostuuid` values and
//! the macOS 27 shared-cache function tables.
//!
//! # Use
//!
//! 1. Map the guest heap (`[HEAP_BASE, HEAP_BASE + HEAP_SIZE)`), then call
//!    [`Shims::install`], which maps the service area at [`SHIM_BASE`], gives
//!    every emulated symbol a `ret` slot and hooks the slots.
//! 2. Resolve image imports through [`ShimState::resolve`] (e.g. as the
//!    Mach-O loader's resolver). Unknown imports get slots in first-call order
//!    that fault with [`ShimError::UnsupportedImport`] if executed.
//! 3. Before running guests, set [`ShimState::host_uuid`], seed
//!    [`GuestFiles::adi`] and install [`HostHandlers`]. Between guest calls,
//!    read and reset [`XpcState`] and [`MachState`].
//!
//! A shim error stops the guest and surfaces from `Engine::run` as
//! `EmuError::Guest("<symbol>: <reason>")`.

mod bytes;
mod call;
mod callback;
mod corefoundation;
mod error;
mod files;
mod heap;
mod ioaes;
mod iokit;
mod kernel;
mod layout;
mod mach;
mod macos27;
mod memory;
mod registry;
mod state;
mod system;
mod table;
mod xpc;

#[cfg(test)]
mod tests;

use std::cell::RefCell;
use std::rc::Rc;

use crate::infrastructure::apple_sap::emu::{EmuError, Engine, HookId, RET_INSTRUCTION};

pub use error::ShimError;
pub use layout::{
    FAKE_HANDLE, HEAP_BASE, HEAP_SIZE, MAX_GUEST_TRANSFER, PAGE_SIZE, SHIM_AREA_SIZE, SHIM_BASE,
    SHIM_CODE_SIZE, SHIM_SLOT_SIZE,
};
pub use macos27::{MACOS27_SHARED_CACHE_FUNCTIONS, MACOS27_SHARED_CACHE_SLOTS};
pub use state::{
    ADI_STATE_PATH, FairPlayHandler, FairPlayReply, FairPlayRequest, GuestFiles, HostEnvironment,
    HostHandlers, MachRpcHandler, MachState, ShimConfig, ShimState, SystemHost, XpcState,
};

use call::{SharedState, ShimCall};

/// The shim layer installed on one emulator.
pub struct Shims {
    state: SharedState,
    hook: HookId,
}

impl Shims {
    /// Maps the service area, registers every emulated function and data
    /// symbol, and installs the dispatch hook.
    ///
    /// # Errors
    /// Returns [`ShimError::Emu`] if the area cannot be mapped or hooked.
    pub fn install(engine: &mut Engine<'_>, config: ShimConfig) -> Result<Self, ShimError> {
        engine.mem_map(SHIM_BASE, SHIM_AREA_SIZE)?;
        engine.mem_write(SHIM_BASE, &return_stubs()?)?;
        let aliases = config.zero_return_aliases.clone();
        let mut state = ShimState::new(config);
        registry::register_all(&mut state, engine, &aliases)?;
        let state = Rc::new(RefCell::new(state));
        let dispatcher = Rc::clone(&state);
        let last_slot = SHIM_BASE + SHIM_CODE_SIZE - 1;
        let hook = engine.add_code_hook(SHIM_BASE, last_slot, move |engine, address, _| {
            dispatch(&dispatcher, engine, address)
        })?;

        Ok(Self { state, hook })
    }

    /// The shared platform state (heap, files, XPC, Mach, identity, handlers).
    /// Do not hold a borrow across guest execution.
    pub fn state(&self) -> Rc<RefCell<ShimState>> {
        Rc::clone(&self.state)
    }

    /// Removes the dispatch hook; the service area stays mapped.
    ///
    /// # Errors
    /// Returns [`ShimError::Emu`] if Unicorn does not know the hook.
    pub fn uninstall(self, engine: &mut Engine<'_>) -> Result<(), ShimError> {
        Ok(engine.remove_hook(self.hook)?)
    }
}

/// A `ret` at the start of every slot of the code area.
fn return_stubs() -> Result<Vec<u8>, ShimError> {
    let mut stubs = vec![0; call::checked_size(SHIM_CODE_SIZE)?];
    for slot in stubs.chunks_exact_mut(call::checked_size(SHIM_SLOT_SIZE)?) {
        slot[..RET_INSTRUCTION.len()].copy_from_slice(&RET_INSTRUCTION);
    }

    Ok(stubs)
}

fn dispatch(state: &SharedState, engine: &mut Engine<'_>, address: u64) -> Result<(), EmuError> {
    let entry = state
        .try_borrow()
        .map_err(|_| EmuError::guest(ShimError::StateBusy))?
        .table
        .entry(address)
        .ok_or_else(|| EmuError::guest(ShimError::UnknownAddress { address }))?;
    let mut call = ShimCall::new(engine, state, &entry.name);

    (entry.handler)(&mut call)
        .map_err(|error| EmuError::guest(format_args!("{}: {error}", entry.name)))
}
