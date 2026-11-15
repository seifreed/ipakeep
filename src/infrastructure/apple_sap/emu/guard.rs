//! Memory guard: validates every guest and host access against a host policy.

use std::rc::Rc;

use super::engine::Engine;
use super::error::EmuError;
use super::hook::{ALL_ADDRESSES_BEGIN, ALL_ADDRESSES_END};

impl Engine<'_> {
    /// Installs `check(address, size)` as the validator for guest loads, stores
    /// and instruction fetches, and for host [`Engine::mem_read`],
    /// [`Engine::mem_read_into`] and [`Engine::mem_write`] calls.
    ///
    /// Install it once, before running guest code. The first rejected guest
    /// access stops emulation and permanently fails every later run; host
    /// accesses return the rejection directly.
    ///
    /// # Errors
    /// Returns [`EmuError::GuardAlreadyInstalled`] on a second call, or
    /// [`EmuError::Unicorn`] if the hooks cannot be registered.
    pub fn guard_memory<F>(&mut self, check: F) -> Result<(), EmuError>
    where
        F: Fn(u64, u64) -> Result<(), EmuError> + 'static,
    {
        if self.uc.get_data().guard.is_some() {
            return Err(EmuError::GuardAlreadyInstalled);
        }

        let data_hook = self.add_memory_access_hook(
            ALL_ADDRESSES_BEGIN,
            ALL_ADDRESSES_END,
            |engine, _access, address, size, _value| {
                engine.enforce_guard(address, size as u64);
                Ok(())
            },
        )?;
        // Instruction hooks also cover fetches served from Unicorn's translation
        // cache, which need not trigger a memory-fetch hook when re-executed.
        let code_hook = self.add_code_hook(
            ALL_ADDRESSES_BEGIN,
            ALL_ADDRESSES_END,
            |engine, address, size| {
                engine.enforce_guard(address, u64::from(size));
                Ok(())
            },
        );
        if let Err(error) = code_hook {
            self.remove_hook(data_hook)?;
            return Err(error);
        }

        self.uc.get_data_mut().guard = Some(Rc::new(check));
        Ok(())
    }

    fn enforce_guard(&mut self, address: u64, size: u64) {
        let Some(check) = self.uc.get_data().guard.clone() else {
            return;
        };
        if let Err(error) = check(address, size) {
            let state = self.uc.get_data_mut();
            if state.guard_violation.is_none() {
                state.guard_violation = Some(error);
            }
            // The sticky violation is reported by the run even if stopping fails.
            let _ = self.uc.emu_stop();
        }
    }
}
