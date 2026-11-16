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

use std::marker::PhantomData;
use std::time::{Duration, Instant};

use super::super::error::{EmuError, EngineErrorCode};
use super::super::register::Register;
use super::{INSN_SIZE, NativeCpu, NativeError, Step};

/// The stop sentinel the machine layer uses as a return address (holds `brk #0`).
pub(crate) const RETURN_ADDRESS: u64 = 0x1_0000_0000;
/// How many instructions run between two wall-clock deadline checks.
const DEADLINE_CHECK_INTERVAL: usize = 4096;

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
pub struct HookId(u64);

type CodeHook<'a> = Box<dyn FnMut(&mut NativeEngine<'a>, u64, u32) -> Result<(), EmuError> + 'a>;

struct CodeHookEntry<'a> {
    id: u64,
    begin: u64,
    end: u64,
    hook: CodeHook<'a>,
}

impl CodeHookEntry<'_> {
    /// Whether this hook fires at `pc`; `begin > end` means "all addresses".
    #[inline]
    fn covers(&self, pc: u64) -> bool {
        self.begin > self.end || (pc >= self.begin && pc <= self.end)
    }
}

/// A native ARM64 engine exposing the same surface the machine layer calls on
/// the Unicorn `Engine`.
pub struct NativeEngine<'a> {
    cpu: NativeCpu,
    code_hooks: Vec<CodeHookEntry<'a>>,
    /// Inclusive `[lo, hi]` hull of every hook range (`lo > hi` when there are
    /// no hooks), so the per-instruction check is two compares.
    hook_span: (u64, u64),
    next_id: u64,
    fault: Option<EmuError>,
    stopped: bool,
    _marker: PhantomData<&'a ()>,
}

impl<'a> NativeEngine<'a> {
    pub(crate) fn new() -> Result<Self, EmuError> {
        Ok(Self {
            cpu: NativeCpu::new(),
            code_hooks: Vec::new(),
            hook_span: (u64::MAX, 0),
            next_id: 1,
            fault: None,
            stopped: false,
            _marker: PhantomData,
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
        F: FnMut(&mut NativeEngine<'a>, u64, u32) -> Result<(), EmuError> + 'a,
    {
        let id = self.next_id;
        self.next_id += 1;
        self.code_hooks.push(CodeHookEntry {
            id,
            begin,
            end,
            hook: Box::new(hook),
        });
        self.update_hook_span();
        Ok(HookId(id))
    }

    pub(crate) fn remove_hook(&mut self, id: HookId) -> Result<(), EmuError> {
        self.code_hooks.retain(|entry| entry.id != id.0);
        self.update_hook_span();
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
        // Fast path: almost every instruction is outside every hook range, so
        // skip moving the hook list out and back in when nothing covers `pc`.
        let (lo, hi) = self.hook_span;
        if pc < lo || pc > hi || !self.code_hooks.iter().any(|entry| entry.covers(pc)) {
            return Ok(());
        }
        let mut hooks = std::mem::take(&mut self.code_hooks);
        let mut outcome = Ok(());
        for entry in &mut hooks {
            if entry.covers(pc) {
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
        self.update_hook_span();
        outcome
    }

    /// Recomputes `hook_span` after the hook list changes.
    fn update_hook_span(&mut self) {
        self.hook_span = self
            .code_hooks
            .iter()
            .fold((u64::MAX, 0), |(lo, hi), entry| {
                if entry.begin > entry.end {
                    (0, u64::MAX) // an "all addresses" hook
                } else {
                    (lo.min(entry.begin), hi.max(entry.end))
                }
            });
    }

    /// Unmaps the pages covering `[address, address+size)`.
    pub(crate) fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), EmuError> {
        self.cpu.mem.unmap(address, size);
        Ok(())
    }

    /// Runs from `begin` until `pc == until` or a `brk`, with no instruction or
    /// time bound beyond `timeout`. This matches the machine layer's call shape.
    pub(crate) fn run(
        &mut self,
        begin: u64,
        until: u64,
        timeout: Duration,
    ) -> Result<(), EmuError> {
        self.start_bounded(begin, until, timeout, 0)
    }

    /// Runs with no instruction or time bound (`until` is the only stop).
    pub(crate) fn start(&mut self, begin: u64, until: u64) -> Result<(), EmuError> {
        self.start_bounded(begin, until, Duration::ZERO, 0)
    }

    /// Runs from `begin` until `pc == until`, a `brk`, the instruction limit, or
    /// the timeout. `instruction_limit == 0` means unlimited; `timeout`
    /// `Duration::ZERO` means no wall-clock bound.
    pub(crate) fn start_bounded(
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
        let mut iterations = 0usize;
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
            // Reading the clock costs more than most instructions, so the
            // wall-clock bound is only checked every `DEADLINE_CHECK_INTERVAL`
            // instructions (the timeout is a coarse safety net, not exact).
            if let Some(deadline) = deadline
                && iterations.is_multiple_of(DEADLINE_CHECK_INTERVAL)
                && Instant::now() >= deadline
            {
                return Err(EmuError::Timeout { timeout });
            }
            iterations = iterations.wrapping_add(1);

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

        e.start_bounded(CODE, RETURN_ADDRESS, Duration::ZERO, 16)
            .unwrap();

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

        e.start_bounded(CODE, RETURN_ADDRESS, Duration::ZERO, 16)
            .unwrap();
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
        let error = e
            .start_bounded(CODE, RETURN_ADDRESS, Duration::ZERO, 16)
            .unwrap_err();
        assert!(matches!(error, EmuError::Guest(_)));
    }
}
