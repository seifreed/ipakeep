//! The view a shim handler gets of one guest call: arguments, result, guest
//! memory and the shared platform state.

use std::cell::{RefCell, RefMut};
use std::rc::Rc;

use crate::infrastructure::apple_sap::emu::{ARGUMENT_REGISTER_COUNT, Engine, Register};

use super::error::ShimError;
use super::layout::{MAX_GUEST_TRANSFER, PAGE_SIZE};
use super::state::ShimState;

/// Platform state shared between the owner and the dispatch hook.
pub(super) type SharedState = Rc<RefCell<ShimState>>;

/// Longest C string a shim reads from the guest, terminator excluded.
const C_STRING_LIMIT: usize = 4096;
/// Size of one stacked argument.
const STACK_SLOT_SIZE: u64 = 8;

/// One in-flight guest call to a shim.
pub(super) struct ShimCall<'c, 'e> {
    engine: &'c mut Engine<'e>,
    state: &'c SharedState,
    name: &'c str,
}

impl<'c, 'e> ShimCall<'c, 'e> {
    pub(super) fn new(engine: &'c mut Engine<'e>, state: &'c SharedState, name: &'c str) -> Self {
        Self {
            engine,
            state,
            name,
        }
    }

    /// The symbol name the guest called.
    pub(super) fn name(&self) -> &str {
        self.name
    }

    /// The emulator running the guest.
    pub(super) fn engine(&mut self) -> &mut Engine<'e> {
        self.engine
    }

    /// Borrows the platform state. Drop the guard before running host
    /// callbacks that may re-enter the shims.
    pub(super) fn state(&self) -> Result<RefMut<'c, ShimState>, ShimError> {
        let state: &'c SharedState = self.state;

        state.try_borrow_mut().map_err(|_| ShimError::StateBusy)
    }

    /// Reads AAPCS64 integer argument `index` (`X0..X7`, then the stack).
    pub(super) fn arg(&self, index: usize) -> Result<u64, ShimError> {
        if let Ok(register) = u8::try_from(index)
            && register < ARGUMENT_REGISTER_COUNT
        {
            return Ok(self.engine.reg_read(Register::X(register))?);
        }
        let stacked = index - usize::from(ARGUMENT_REGISTER_COUNT);
        let stack = self.engine.reg_read(Register::Sp)?;
        let offset = stacked as u64 * STACK_SLOT_SIZE;

        self.read_u64(stack + offset)
    }

    /// Reads the first `N` integer arguments.
    pub(super) fn args<const N: usize>(&self) -> Result<[u64; N], ShimError> {
        let mut values = [0; N];
        for (index, value) in values.iter_mut().enumerate() {
            *value = self.arg(index)?;
        }

        Ok(values)
    }

    /// Sets the guest's return value (`X0`).
    pub(super) fn set_result(&mut self, value: u64) -> Result<(), ShimError> {
        Ok(self.engine.reg_write(Register::X(0), value)?)
    }

    /// Reads `length` bytes of guest memory, bounded by the transfer limit.
    pub(super) fn read_bytes(&self, address: u64, length: u64) -> Result<Vec<u8>, ShimError> {
        let size = checked_size(length)?;

        Ok(self.engine.mem_read(address, size)?)
    }

    /// Writes `data` to guest memory.
    pub(super) fn write_bytes(&mut self, address: u64, data: &[u8]) -> Result<(), ShimError> {
        Ok(self.engine.mem_write(address, data)?)
    }

    /// Fills `length` guest bytes at `address` with `value`.
    pub(super) fn fill(&mut self, address: u64, value: u8, length: u64) -> Result<(), ShimError> {
        let size = checked_size(length)?;

        self.write_bytes(address, &vec![value; size])
    }

    /// Reads a little-endian `u32`.
    pub(super) fn read_u32(&self, address: u64) -> Result<u32, ShimError> {
        Ok(self.engine.read_u32(address)?)
    }

    /// Reads a little-endian `u64`.
    pub(super) fn read_u64(&self, address: u64) -> Result<u64, ShimError> {
        Ok(self.engine.read_u64(address)?)
    }

    /// Writes a little-endian `u32`.
    pub(super) fn write_u32(&mut self, address: u64, value: u32) -> Result<(), ShimError> {
        Ok(self.engine.write_u32(address, value)?)
    }

    /// Writes a little-endian `u64`.
    pub(super) fn write_u64(&mut self, address: u64, value: u64) -> Result<(), ShimError> {
        Ok(self.engine.write_u64(address, value)?)
    }

    /// Reads a NUL-terminated guest string (without the terminator).
    pub(super) fn read_c_string(&self, address: u64) -> Result<Vec<u8>, ShimError> {
        let mut value = Vec::new();
        while value.len() < C_STRING_LIMIT {
            let cursor = address + value.len() as u64;
            let in_page = PAGE_SIZE - cursor % PAGE_SIZE;
            let wanted = (C_STRING_LIMIT - value.len()) as u64;
            let chunk = self.read_bytes(cursor, in_page.min(wanted))?;
            if let Some(end) = chunk.iter().position(|&byte| byte == 0) {
                value.extend_from_slice(&chunk[..end]);
                return Ok(value);
            }
            value.extend_from_slice(&chunk);
        }

        Err(ShimError::StringTooLong {
            limit: C_STRING_LIMIT,
        })
    }

    /// Reserves guest heap memory (contents are not cleared).
    pub(super) fn allocate(&self, size: u64) -> Result<u64, ShimError> {
        self.state()?.heap.allocate(size)
    }

    /// Reserves `size` bytes at an `alignment` boundary of the guest heap.
    pub(super) fn allocate_aligned(&self, size: u64, alignment: u64) -> Result<u64, ShimError> {
        self.state()?.heap.allocate_aligned(size, alignment)
    }

    /// Clears and frees a heap allocation.
    pub(super) fn release(&mut self, address: u64) -> Result<(), ShimError> {
        let allocation = self.state()?.heap.allocation(address);
        let allocation = allocation.ok_or(ShimError::UnknownPointer {
            operation: "free",
            address,
        })?;
        self.fill(address, 0, allocation.reserved)?;
        self.state()?.heap.release(address)?;

        Ok(())
    }

    /// Clears the first `size` bytes of a fresh allocation, freeing it again
    /// if guest memory cannot be written.
    pub(super) fn clear_new(&mut self, address: u64, size: u64) -> Result<(), ShimError> {
        let cleared = self.fill(address, 0, size);
        if cleared.is_err() {
            // The write failure is what the guest needs to hear about; the
            // allocation is unusable whether or not freeing it succeeds.
            let _ = self.release(address);
        }

        cleared
    }
}

/// Validates a guest-supplied transfer length.
pub(super) fn checked_size(length: u64) -> Result<usize, ShimError> {
    if length > MAX_GUEST_TRANSFER {
        return Err(ShimError::TransferTooLarge { size: length });
    }

    usize::try_from(length).map_err(|_| ShimError::TransferTooLarge { size: length })
}

/// The low 32 bits of a register value (a `W` register view).
pub(super) fn low_word(value: u64) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();

    u32::from_le_bytes([a, b, c, d])
}
