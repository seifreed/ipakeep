//! Unicorn-backed ARM64 engine: memory, registers and execution control.

use std::rc::Rc;
use std::time::Duration;

use unicorn_engine::{Arch, Arm64CpuModel, Mode, Prot, Query, Unicorn, uc_error};

use super::error::{EmuError, EngineErrorCode};
use super::register::{Register, vector_id};

/// Maps a Unicorn status code onto the backend-neutral [`EngineErrorCode`].
fn code_of(source: uc_error) -> EngineErrorCode {
    match source {
        uc_error::MAP => EngineErrorCode::Map,
        uc_error::READ_UNMAPPED => EngineErrorCode::ReadUnmapped,
        uc_error::WRITE_UNMAPPED => EngineErrorCode::WriteUnmapped,
        uc_error::FETCH_UNMAPPED => EngineErrorCode::FetchUnmapped,
        uc_error::EXCEPTION => EngineErrorCode::Exception,
        uc_error::INSN_INVALID => EngineErrorCode::InvalidInstruction,
        _ => EngineErrorCode::Other,
    }
}

/// Builds a `map_err` adapter that tags a Unicorn status with its operation.
pub(super) fn native(operation: &'static str) -> impl Fn(uc_error) -> EmuError {
    move |source| EmuError::engine(operation, code_of(source))
}

/// Size in bytes of an ARM64 instruction and of a `ret` stub.
pub const INSTRUCTION_SIZE: u64 = 4;
/// Little-endian encoding of `ret` (`RET X30`), used for host-implemented stubs.
pub const RET_INSTRUCTION: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
/// Size in bytes of an ARM64 SIMD/FP vector register.
pub const VECTOR_REGISTER_SIZE: usize = 16;

const MICROSECONDS_MINIMUM: u64 = 1;
/// Instruction limit meaning "no limit" for [`Engine::start_bounded`].
pub const UNLIMITED_INSTRUCTIONS: usize = 0;
const UNBOUNDED_TIMEOUT: u64 = 0;
const TIMEOUT_NOT_REACHED: usize = 0;

/// Host policy that accepts or rejects a guest/host access of `size` bytes at
/// `address`.
pub(super) type MemoryCheck = dyn Fn(u64, u64) -> Result<(), EmuError>;

/// Engine-wide state shared between the owner and every hook invocation.
#[derive(Default)]
pub(super) struct EngineState {
    /// First fault reported by a hook during the current run; cleared when read.
    pub(super) fault: Option<EmuError>,
    /// Installed memory validator, if any.
    pub(super) guard: Option<Rc<MemoryCheck>>,
    /// First guard rejection; sticky, it fails every later run.
    pub(super) guard_violation: Option<EmuError>,
}

/// An ARM64 Unicorn emulator configured like ipatool's SAP runtime.
///
/// The engine is `!Send`: create and drive it on a single thread (for example
/// inside `tokio::task::spawn_blocking`). Hook callbacks receive a temporary
/// `Engine` handle to the same emulator, so they can use the full API.
pub struct Engine<'a> {
    pub(super) uc: Unicorn<'a, EngineState>,
}

impl Engine<'_> {
    /// Opens an ARM64 emulator using Unicorn's most capable CPU model.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn cannot create or configure the CPU.
    pub fn new() -> Result<Self, EmuError> {
        Self::with_cpu_model(Arm64CpuModel::MAX)
    }

    /// Opens an ARM64 emulator with an explicit CPU model.
    pub(super) fn with_cpu_model(model: Arm64CpuModel) -> Result<Self, EmuError> {
        let mut uc = Unicorn::new_with_data(Arch::ARM64, Mode::ARM, EngineState::default())
            .map_err(native("open arm64 emulator"))?;
        uc.ctl_set_cpu_model(i32::from(model))
            .map_err(native("configure arm64 CPU model"))?;

        Ok(Self { uc })
    }

    /// Maps `size` bytes of read/write/execute memory at `address`; both must be
    /// page aligned.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] on misalignment or overlap.
    pub fn mem_map(&mut self, address: u64, size: u64) -> Result<(), EmuError> {
        self.uc
            .mem_map(address, size, Prot::ALL)
            .map_err(native("mem_map"))
    }

    /// Unmaps `size` bytes at `address`.
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if the range is not mapped.
    pub fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), EmuError> {
        self.uc
            .mem_unmap(address, size)
            .map_err(native("mem_unmap"))
    }

    /// Reads `size` bytes of guest memory at `address`.
    ///
    /// # Errors
    /// Returns the guard rejection or [`EmuError::Unicorn`] for unmapped memory.
    pub fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>, EmuError> {
        let mut data = vec![0; size];
        self.mem_read_into(address, &mut data)?;

        Ok(data)
    }

    /// Fills `buffer` from guest memory at `address`.
    ///
    /// # Errors
    /// Returns the guard rejection or [`EmuError::Unicorn`] for unmapped memory.
    pub fn mem_read_into(&self, address: u64, buffer: &mut [u8]) -> Result<(), EmuError> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.check_host_access(address, buffer.len())?;

        self.uc
            .mem_read(address, buffer)
            .map_err(native("mem_read"))
    }

    /// Writes `data` to guest memory at `address`.
    ///
    /// # Errors
    /// Returns the guard rejection or [`EmuError::Unicorn`] for unmapped memory.
    pub fn mem_write(&mut self, address: u64, data: &[u8]) -> Result<(), EmuError> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_host_access(address, data.len())?;

        self.uc
            .mem_write(address, data)
            .map_err(native("mem_write"))
    }

    /// Reads a little-endian `u32` from guest memory.
    ///
    /// # Errors
    /// See [`Engine::mem_read_into`].
    pub fn read_u32(&self, address: u64) -> Result<u32, EmuError> {
        let mut bytes = [0; 4];
        self.mem_read_into(address, &mut bytes)?;

        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads a little-endian `u64` from guest memory.
    ///
    /// # Errors
    /// See [`Engine::mem_read_into`].
    pub fn read_u64(&self, address: u64) -> Result<u64, EmuError> {
        let mut bytes = [0; 8];
        self.mem_read_into(address, &mut bytes)?;

        Ok(u64::from_le_bytes(bytes))
    }

    /// Writes a little-endian `u32` to guest memory.
    ///
    /// # Errors
    /// See [`Engine::mem_write`].
    pub fn write_u32(&mut self, address: u64, value: u32) -> Result<(), EmuError> {
        self.mem_write(address, &value.to_le_bytes())
    }

    /// Writes a little-endian `u64` to guest memory.
    ///
    /// # Errors
    /// See [`Engine::mem_write`].
    pub fn write_u64(&mut self, address: u64, value: u64) -> Result<(), EmuError> {
        self.mem_write(address, &value.to_le_bytes())
    }

    /// Writes a `ret` instruction at `address`, turning it into a host-implemented
    /// function entry: a code hook on `address` runs first, then the guest returns
    /// to `LR` with whatever the hook left in `X0`.
    ///
    /// # Errors
    /// See [`Engine::mem_write`].
    pub fn write_return_stub(&mut self, address: u64) -> Result<(), EmuError> {
        self.mem_write(address, &RET_INSTRUCTION)
    }

    /// Reads a 64-bit register.
    ///
    /// # Errors
    /// Returns [`EmuError::InvalidRegister`] or [`EmuError::Unicorn`].
    pub fn reg_read(&self, register: Register) -> Result<u64, EmuError> {
        self.uc
            .reg_read(register.unicorn_id()?)
            .map_err(native("reg_read"))
    }

    /// Writes a 64-bit register.
    ///
    /// # Errors
    /// Returns [`EmuError::InvalidRegister`] or [`EmuError::Unicorn`].
    pub fn reg_write(&mut self, register: Register, value: u64) -> Result<(), EmuError> {
        self.uc
            .reg_write(register.unicorn_id()?, value)
            .map_err(native("reg_write"))
    }

    /// Reads vector register `V<index>` as 16 little-endian bytes.
    ///
    /// # Errors
    /// Returns [`EmuError::InvalidRegister`] or [`EmuError::Unicorn`].
    pub fn vreg_read(&self, index: u8) -> Result<[u8; VECTOR_REGISTER_SIZE], EmuError> {
        let value = self
            .uc
            .reg_read_long(vector_id(index)?)
            .map_err(native("reg_read"))?;
        let mut bytes = [0; VECTOR_REGISTER_SIZE];
        let length = value.len().min(VECTOR_REGISTER_SIZE);
        bytes[..length].copy_from_slice(&value[..length]);

        Ok(bytes)
    }

    /// Writes vector register `V<index>` from 16 little-endian bytes.
    ///
    /// # Errors
    /// Returns [`EmuError::InvalidRegister`] or [`EmuError::Unicorn`].
    pub fn vreg_write(
        &mut self,
        index: u8,
        value: [u8; VECTOR_REGISTER_SIZE],
    ) -> Result<(), EmuError> {
        self.uc
            .reg_write_long(vector_id(index)?, &value)
            .map_err(native("reg_write"))
    }

    /// Executes from `begin` until `until` without time or instruction bounds.
    ///
    /// # Errors
    /// Returns the first hook fault, a guard rejection, or [`EmuError::Unicorn`].
    pub fn start(&mut self, begin: u64, until: u64) -> Result<(), EmuError> {
        self.ensure_no_guard_violation()?;
        let result = self
            .uc
            .emu_start(begin, until, UNBOUNDED_TIMEOUT, UNLIMITED_INSTRUCTIONS);

        self.finish(result)
    }

    /// Executes from `begin` until `until`, stopping after `timeout` of wall time
    /// or `instruction_limit` instructions (`0` = unlimited).
    ///
    /// # Errors
    /// Returns [`EmuError::InvalidTimeout`] for a zero timeout,
    /// [`EmuError::Timeout`] when the deadline expires, the first hook fault, a
    /// guard rejection, or [`EmuError::Unicorn`].
    pub fn start_bounded(
        &mut self,
        begin: u64,
        until: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<(), EmuError> {
        if timeout.is_zero() {
            return Err(EmuError::InvalidTimeout);
        }
        self.ensure_no_guard_violation()?;
        let result = self.uc.emu_start(
            begin,
            until,
            timeout_microseconds(timeout),
            instruction_limit,
        );
        self.finish(result)?;

        let timed_out = self
            .uc
            .query(Query::TIMEOUT)
            .map_err(native("query timeout"))?;
        if timed_out == TIMEOUT_NOT_REACHED {
            Ok(())
        } else {
            Err(EmuError::Timeout { timeout })
        }
    }

    /// Requests that the running emulation stop (after the current block).
    ///
    /// # Errors
    /// Returns [`EmuError::Unicorn`] if Unicorn rejects the request.
    pub fn stop(&mut self) -> Result<(), EmuError> {
        self.uc.emu_stop().map_err(native("emu_stop"))
    }

    /// Records `error` as the run's fault (the first one wins) and stops
    /// emulation. The pending `start`/`start_bounded`/`run` returns it.
    ///
    /// Hook callbacks that return `Err` are routed here automatically.
    pub fn fail(&mut self, error: EmuError) {
        let state = self.uc.get_data_mut();
        if state.fault.is_none() {
            state.fault = Some(error);
        }
        // A failed stop leaves the recorded fault to be reported once Unicorn
        // returns on its own, so the stop status carries no extra information.
        let _ = self.uc.emu_stop();
    }

    fn ensure_no_guard_violation(&self) -> Result<(), EmuError> {
        match &self.uc.get_data().guard_violation {
            Some(violation) => Err(violation.clone()),
            None => Ok(()),
        }
    }

    fn finish(&mut self, result: Result<(), uc_error>) -> Result<(), EmuError> {
        let state = self.uc.get_data_mut();
        let fault = state.fault.take();
        if let Some(violation) = &state.guard_violation {
            return Err(violation.clone());
        }
        if let Some(fault) = fault {
            return Err(fault);
        }

        result.map_err(native("emu_start"))
    }

    fn check_host_access(&self, address: u64, size: usize) -> Result<(), EmuError> {
        match &self.uc.get_data().guard {
            Some(check) => check(address, size as u64),
            None => Ok(()),
        }
    }
}

fn timeout_microseconds(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_micros())
        .unwrap_or(u64::MAX)
        .max(MICROSECONDS_MINIMUM)
}
