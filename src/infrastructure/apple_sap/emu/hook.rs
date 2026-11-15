//! Hook registration: Rust closures invoked from inside guest execution.
//!
//! Every callback receives a temporary [`Engine`] handle to the running
//! emulator. Returning `Err` records the error as the run's fault (first one
//! wins) and stops emulation; the pending `start`/`run` call returns it.

use unicorn_engine::{HookType, MemType, UcHookId, Unicorn};

use super::engine::{Engine, EngineState};
use super::error::{EmuError, native};

/// Hook range start that, paired with [`ALL_ADDRESSES_END`], covers every address.
pub const ALL_ADDRESSES_BEGIN: u64 = 1;
/// Hook range end that, paired with [`ALL_ADDRESSES_BEGIN`], covers every address.
pub const ALL_ADDRESSES_END: u64 = 0;

/// The Unicorn handle every hook callback receives.
type Uc<'u> = Unicorn<'u, EngineState>;

/// Identifies a registered hook so it can be removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookId(UcHookId);

/// The kind of guest memory access that triggered a memory hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAccess {
    /// A data load.
    Read,
    /// A data store.
    Write,
    /// An instruction fetch.
    Fetch,
}

impl MemoryAccess {
    fn from_mem_type(kind: MemType) -> Self {
        match kind {
            MemType::WRITE | MemType::WRITE_UNMAPPED | MemType::WRITE_PROT => Self::Write,
            MemType::FETCH | MemType::FETCH_UNMAPPED | MemType::FETCH_PROT => Self::Fetch,
            MemType::READ | MemType::READ_UNMAPPED | MemType::READ_PROT | MemType::READ_AFTER => {
                Self::Read
            }
        }
    }
}

/// Runs `callback` with an [`Engine`] view of `uc`, routing errors to [`Engine::fail`].
fn with_engine<T>(
    uc: &Unicorn<'_, EngineState>,
    fallback: T,
    callback: impl FnOnce(&mut Engine<'_>) -> Result<T, EmuError>,
) -> T {
    let mut engine = Engine { uc: uc.clone() };
    match callback(&mut engine) {
        Ok(value) => value,
        Err(error) => {
            engine.fail(error);
            fallback
        }
    }
}

impl<'a> Engine<'a> {
    /// Calls `callback(engine, address, size)` before each instruction whose
    /// address lies in the inclusive range `[begin, end]` (`begin > end` covers
    /// all addresses).
    ///
    /// This is the shim dispatch primitive: fill a region with
    /// [`Engine::write_return_stub`] entries, hook the region, look up the
    /// handler by `address`, set `X0` and let the stub return to `LR`.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn rejects the hook.
    pub fn add_code_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        mut callback: F,
    ) -> Result<HookId, EmuError>
    where
        F: FnMut(&mut Engine<'_>, u64, u32) -> Result<(), EmuError> + 'a,
    {
        let hook = move |uc: &mut Unicorn<'_, EngineState>, address: u64, size: u32| {
            with_engine(uc, (), |engine| callback(engine, address, size));
        };

        let added = self.uc.add_code_hook(begin, end, hook);
        added.map(HookId).map_err(native("hook_add code"))
    }

    /// Calls `callback(engine, access, address, size, value)` for guest loads and
    /// stores in `[begin, end]`; `value` is the stored value for writes.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn rejects the hook.
    pub fn add_memory_access_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        mut callback: F,
    ) -> Result<HookId, EmuError>
    where
        F: FnMut(&mut Engine<'_>, MemoryAccess, u64, usize, i64) -> Result<(), EmuError> + 'a,
    {
        let hook = move |uc: &mut Uc<'_>, kind: MemType, address: u64, size: usize, value: i64| {
            let access = MemoryAccess::from_mem_type(kind);
            with_engine(uc, true, |engine| {
                callback(engine, access, address, size, value).map(|()| true)
            })
        };
        let accesses = HookType::MEM_READ | HookType::MEM_WRITE;

        let added = self.uc.add_mem_hook(accesses, begin, end, hook);
        added.map(HookId).map_err(native("hook_add memory"))
    }

    /// Calls `callback(engine, access, address, size)` when the guest touches
    /// unmapped memory. Returning `Ok(true)` after mapping the page retries the
    /// access; `Ok(false)` lets Unicorn fail with an unmapped-memory error.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn rejects the hook.
    pub fn add_memory_fault_hook<F>(&mut self, mut callback: F) -> Result<HookId, EmuError>
    where
        F: FnMut(&mut Engine<'_>, MemoryAccess, u64, usize) -> Result<bool, EmuError> + 'a,
    {
        let hook = move |uc: &mut Uc<'_>, kind: MemType, address: u64, size: usize, _: i64| {
            let access = MemoryAccess::from_mem_type(kind);
            with_engine(uc, false, |engine| callback(engine, access, address, size))
        };
        let unmapped = HookType::MEM_READ_UNMAPPED | HookType::MEM_WRITE_UNMAPPED;
        let unmapped = unmapped | HookType::MEM_FETCH_UNMAPPED;
        let (begin, end) = (ALL_ADDRESSES_BEGIN, ALL_ADDRESSES_END);

        let added = self.uc.add_mem_hook(unmapped, begin, end, hook);
        added.map(HookId).map_err(native("hook_add memory fault"))
    }

    /// Calls `callback(engine, exception_number)` on guest interrupts and
    /// exceptions such as `svc`, `brk` and undefined instructions (QEMU
    /// `EXCP_UDEF`, which Unicorn reports here instead of through its
    /// invalid-instruction hook on ARM64). Without this hook such exceptions stop
    /// the run with [`unicorn_engine::uc_error::EXCEPTION`], which is what lets
    /// [`Engine::run`] soft-emulate unsupported instructions.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn rejects the hook.
    pub fn add_interrupt_hook<F>(&mut self, mut callback: F) -> Result<HookId, EmuError>
    where
        F: FnMut(&mut Engine<'_>, u32) -> Result<(), EmuError> + 'a,
    {
        let hook = move |uc: &mut Unicorn<'_, EngineState>, number: u32| {
            with_engine(uc, (), |engine| callback(engine, number));
        };

        let added = self.uc.add_intr_hook(hook);
        added.map(HookId).map_err(native("hook_add interrupt"))
    }

    /// Removes a hook and drops its callback. Never call this from inside the
    /// callback being removed.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn does not know the hook.
    pub fn remove_hook(&mut self, id: HookId) -> Result<(), EmuError> {
        self.uc.remove_hook(id.0).map_err(native("hook_del"))
    }
}
