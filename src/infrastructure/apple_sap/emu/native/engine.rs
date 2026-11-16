//! `NativeEngine` — the Engine-API surface over [`NativeCpu`], so the native
//! interpreter is a drop-in for the Unicorn backend.
//!
//! The load-bearing piece is the **code-hook model** the machine layer's shims
//! rely on: one hook is registered over the shim area; when the guest reaches a
//! hooked address the Rust closure runs *before* the instruction, reads
//! arguments from the registers, writes its result, and lets the `ret` stub
//! return to `LR` — or it redirects `PC` / stops the run. A hook is stored in
//! the engine yet is called with `&mut NativeEngine`; the borrow is resolved by
//! moving the hook list out with `mem::take` for the duration of the call.

use std::time::{Duration, Instant};

use super::super::error::{EmuError, EngineErrorCode};
use super::super::register::Register;
use super::{INSN_SIZE, NativeCpu, NativeError, Step};

/// The stop sentinel the machine layer uses as a return address (holds `brk #0`).
pub(crate) const RETURN_ADDRESS: u64 = 0x1_0000_0000;
/// Little-endian `RET X30`.
pub(crate) const RET_INSTRUCTION: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];

fn native_err(error: NativeError) -> EmuError {
    match error {
        NativeError::Unmapped { .. } => {
            EmuError::engine("mem_access", EngineErrorCode::ReadUnmapped)
        }
        NativeError::Unsupported { .. } => {
            EmuError::engine("execute", EngineErrorCode::InvalidInstruction)
        }
    }
}

/// Identifies a registered hook so it can be removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HookId(u64);

type CodeHook = Box<dyn FnMut(&mut NativeEngine, u64, u32) -> Result<(), EmuError>>;

struct CodeHookEntry {
    id: u64,
    begin: u64,
    end: u64,
    hook: CodeHook,
}

/// A native ARM64 engine exposing the same surface the machine layer calls on
/// the Unicorn `Engine`.
pub(crate) struct NativeEngine {
    cpu: NativeCpu,
    code_hooks: Vec<CodeHookEntry>,
    next_id: u64,
    fault: Option<EmuError>,
    stopped: bool,
}

impl NativeEngine {
    pub(crate) fn new() -> Result<Self, EmuError> {
        Ok(Self {
            cpu: NativeCpu::new(),
            code_hooks: Vec::new(),
            next_id: 1,
            fault: None,
            stopped: false,
        })
    }

    // --- memory ---

    pub(crate) fn mem_map(&mut self, address: u64, size: u64) -> Result<(), EmuError> {
        self.cpu.mem.map(address, size);
        Ok(())
    }

    pub(crate) fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>, EmuError> {
        let mut buf = vec![0u8; size];
        self.cpu.mem.read(address, &mut buf).map_err(native_err)?;
        Ok(buf)
    }

    pub(crate) fn mem_read_into(&self, address: u64, buffer: &mut [u8]) -> Result<(), EmuError> {
        self.cpu.mem.read(address, buffer).map_err(native_err)
    }

    pub(crate) fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), EmuError> {
        self.cpu.mem.write(address, data).map_err(native_err)
    }

    pub(crate) fn read_u32(&self, address: u64) -> Result<u32, EmuError> {
        let mut b = [0u8; 4];
        self.mem_read_into(address, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    pub(crate) fn read_u64(&self, address: u64) -> Result<u64, EmuError> {
        let mut b = [0u8; 8];
        self.mem_read_into(address, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    pub(crate) fn write_u32(&mut self, address: u64, value: u32) -> Result<(), EmuError> {
        self.mem_write(address, &value.to_le_bytes())
    }

    pub(crate) fn write_u64(&mut self, address: u64, value: u64) -> Result<(), EmuError> {
        self.mem_write(address, &value.to_le_bytes())
    }

    pub(crate) fn write_return_stub(&mut self, address: u64) -> Result<(), EmuError> {
        self.mem_write(address, &RET_INSTRUCTION)
    }

    // --- registers ---

    pub(crate) fn reg_read(&self, register: Register) -> Result<u64, EmuError> {
        Ok(match register {
            Register::X(n) => self.cpu.x(u32::from(n)),
            Register::Sp => self.cpu.sp(),
            Register::Pc => self.cpu.pc(),
            Register::Nzcv => u64::from(self.cpu.nzcv()),
        })
    }

    pub(crate) fn reg_write(&mut self, register: Register, value: u64) -> Result<(), EmuError> {
        match register {
            Register::X(n) => self.cpu.set_x(u32::from(n), value),
            Register::Sp => self.cpu.set_sp(value),
            Register::Pc => self.cpu.set_pc(value),
            Register::Nzcv => self.cpu.set_nzcv(value as u32),
        }
        Ok(())
    }

    pub(crate) fn vreg_read(&self, index: u8) -> Result<[u8; 16], EmuError> {
        Ok(self.cpu.v(u32::from(index)).to_le_bytes())
    }

    pub(crate) fn vreg_write(&mut self, index: u8, value: [u8; 16]) -> Result<(), EmuError> {
        self.cpu.set_v(u32::from(index), u128::from_le_bytes(value));
        Ok(())
    }

    // --- hooks ---

    pub(crate) fn add_code_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        hook: F,
    ) -> Result<HookId, EmuError>
    where
        F: FnMut(&mut NativeEngine, u64, u32) -> Result<(), EmuError> + 'static,
    {
        let id = self.next_id;
        self.next_id += 1;
        self.code_hooks.push(CodeHookEntry {
            id,
            begin,
            end,
            hook: Box::new(hook),
        });
        Ok(HookId(id))
    }

    pub(crate) fn remove_hook(&mut self, id: HookId) -> Result<(), EmuError> {
        self.code_hooks.retain(|entry| entry.id != id.0);
        Ok(())
    }

    pub(crate) fn stop(&mut self) -> Result<(), EmuError> {
        self.stopped = true;
        Ok(())
    }

    pub(crate) fn fail(&mut self, error: EmuError) {
        if self.fault.is_none() {
            self.fault = Some(error);
        }
        self.stopped = true;
    }

    /// Fires every code hook covering `pc`. Hooks are moved out for the call so
    /// each receives `&mut self`; hooks added during the call are preserved.
    fn fire_code_hooks(&mut self, pc: u64) -> Result<(), EmuError> {
        if self.code_hooks.is_empty() {
            return Ok(());
        }
        let mut hooks = std::mem::take(&mut self.code_hooks);
        let mut outcome = Ok(());
        for entry in &mut hooks {
            let covers = if entry.begin > entry.end {
                true // begin > end means "all addresses"
            } else {
                pc >= entry.begin && pc <= entry.end
            };
            if covers {
                if let Err(error) = (entry.hook)(self, pc, INSN_SIZE as u32) {
                    self.fail(error.clone());
                    outcome = Err(error);
                    break;
                }
                if self.stopped {
                    break;
                }
            }
        }
        let added = std::mem::take(&mut self.code_hooks);
        self.code_hooks = hooks;
        self.code_hooks.extend(added);
        outcome
    }

    /// Runs from `begin` until `pc == until`, a `brk`, the instruction limit, or
    /// the timeout. `instruction_limit == 0` means unlimited; `timeout`
    /// `Duration::ZERO` means no wall-clock bound.
    pub(crate) fn run(
        &mut self,
        begin: u64,
        until: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<(), EmuError> {
        self.cpu.set_pc(begin);
        self.stopped = false;
        let deadline = (!timeout.is_zero()).then(|| Instant::now() + timeout);
        let mut count = 0usize;
        loop {
            if let Some(error) = self.fault.take() {
                return Err(error);
            }
            let pc = self.cpu.pc();
            if pc == until {
                return Ok(());
            }
            if instruction_limit != 0 && count >= instruction_limit {
                return Ok(());
            }
            if let Some(deadline) = deadline
                && Instant::now() >= deadline
            {
                return Err(EmuError::Timeout { timeout });
            }

            self.fire_code_hooks(pc)?;
            if self.stopped {
                return match self.fault.take() {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
            // A hook may have redirected control flow; if so, resume at the new
            // PC without executing the hooked instruction.
            if self.cpu.pc() != pc {
                continue;
            }

            match self.cpu.step().map_err(native_err)? {
                Step::Next => self.cpu.set_pc(pc + INSN_SIZE),
                Step::Branch(target) => self.cpu.set_pc(target),
                Step::Break(_) => return Ok(()),
            }
            count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: u64 = 0x1_0000;
    const STACK: u64 = 0x5_0000;

    /// The shim dispatch pattern: a hooked `ret` stub whose hook sets X0, then
    /// the `ret` returns to LR == `RETURN_ADDRESS`, ending the run.
    #[test]
    fn code_hook_runs_before_ret_stub_and_returns_to_lr() {
        let mut e = NativeEngine::new().unwrap();
        e.mem_map(CODE, 0x1000).unwrap();
        e.mem_map(RETURN_ADDRESS, 0x1000).unwrap();
        e.mem_map(STACK & !0xfff, 0x1000).unwrap();
        e.write_return_stub(CODE).unwrap();
        e.reg_write(Register::X(30), RETURN_ADDRESS).unwrap();
        e.add_code_hook(CODE, CODE, |engine, _addr, _size| {
            engine.reg_write(Register::X(0), 42)
        })
        .unwrap();

        e.run(CODE, RETURN_ADDRESS, Duration::ZERO, 16).unwrap();

        assert_eq!(e.reg_read(Register::X(0)).unwrap(), 42);
        assert_eq!(e.reg_read(Register::Pc).unwrap(), RETURN_ADDRESS);
    }

    /// A hook that redirects PC is honored and the original instruction skipped.
    #[test]
    fn code_hook_can_redirect_control_flow() {
        let mut e = NativeEngine::new().unwrap();
        e.mem_map(CODE, 0x1000).unwrap();
        e.mem_map(RETURN_ADDRESS, 0x1000).unwrap();
        // CODE+0 would be a brk (stop) if executed; the hook jumps past it.
        e.mem_write(CODE, &[0x00, 0x00, 0x20, 0xd4]).unwrap(); // brk #0
        e.write_return_stub(CODE + 4).unwrap();
        e.reg_write(Register::X(30), RETURN_ADDRESS).unwrap();
        e.add_code_hook(CODE, CODE, |engine, _addr, _size| {
            engine.reg_write(Register::Pc, CODE + 4)
        })
        .unwrap();

        e.run(CODE, RETURN_ADDRESS, Duration::ZERO, 16).unwrap();
        assert_eq!(e.reg_read(Register::Pc).unwrap(), RETURN_ADDRESS);
    }

    /// A hook returning Err stops the run and surfaces the error.
    #[test]
    fn code_hook_error_stops_and_is_returned() {
        let mut e = NativeEngine::new().unwrap();
        e.mem_map(CODE, 0x1000).unwrap();
        e.write_return_stub(CODE).unwrap();
        e.add_code_hook(CODE, CODE, |_engine, _addr, _size| {
            Err(EmuError::guest("boom"))
        })
        .unwrap();
        let error = e.run(CODE, RETURN_ADDRESS, Duration::ZERO, 16).unwrap_err();
        assert!(matches!(error, EmuError::Guest(_)));
    }
}
