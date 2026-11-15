//! Software emulation of ARMv8.1+/v8.2 instructions this Unicorn build rejects
//! (`CASAL`, `SWPAL`, `EOR3`), and the run loop that resumes after them.

use std::time::{Duration, Instant};

use super::engine::{Engine, INSTRUCTION_SIZE};
use super::error::EmuError;
use super::register::Register;

const ATOMIC_MASK: u32 = 0xffe0_fc00;
const CASAL_32: u32 = 0x88e0_fc00;
const CASAL_64: u32 = 0xc8e0_fc00;
const SWPAL_32: u32 = 0xb8e0_8000;
const SWPAL_64: u32 = 0xf8e0_8000;
const EOR3_MASK: u32 = 0xffe0_8000;
const EOR3: u32 = 0xce00_0000;

const REGISTER_FIELD_MASK: u32 = 0x1f;
const RT_SHIFT: u32 = 0;
const RN_SHIFT: u32 = 5;
const RA_SHIFT: u32 = 10;
const RS_SHIFT: u32 = 16;
/// Register number 31 encodes `SP` as a base and `XZR`/`WZR` as a value.
const ZERO_OR_SP: u8 = 31;
const WORD_BYTES: usize = 4;
const DOUBLEWORD_BYTES: usize = 8;

/// The atomic read-modify-write operations emulated in software.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AtomicOperation {
    CompareAndSwap,
    Swap,
}

/// A decoded `CASAL`/`SWPAL` instruction.
#[derive(Debug, Clone, Copy)]
struct Atomic {
    operation: AtomicOperation,
    width: usize,
    rs: u8,
    rn: u8,
    rt: u8,
}

fn field(instruction: u32, shift: u32) -> u8 {
    // The mask keeps the value below 32, so its low byte is the whole value.
    ((instruction >> shift) & REGISTER_FIELD_MASK).to_le_bytes()[0]
}

fn decode_atomic(instruction: u32) -> Option<Atomic> {
    let (operation, width) = match instruction & ATOMIC_MASK {
        CASAL_32 => (AtomicOperation::CompareAndSwap, WORD_BYTES),
        CASAL_64 => (AtomicOperation::CompareAndSwap, DOUBLEWORD_BYTES),
        SWPAL_32 => (AtomicOperation::Swap, WORD_BYTES),
        SWPAL_64 => (AtomicOperation::Swap, DOUBLEWORD_BYTES),
        _ => return None,
    };

    Some(Atomic {
        operation,
        width,
        rs: field(instruction, RS_SHIFT),
        rn: field(instruction, RN_SHIFT),
        rt: field(instruction, RT_SHIFT),
    })
}

fn truncate(value: u64, width: usize) -> u64 {
    if width == WORD_BYTES {
        value & u64::from(u32::MAX)
    } else {
        value
    }
}

impl Engine<'_> {
    /// Executes from `begin` until `until` within `timeout`, soft-emulating
    /// `CASAL`, `SWPAL` (32/64-bit) and `EOR3` whenever Unicorn stops on them,
    /// then resuming. This is ipatool's SAP guest call loop.
    ///
    /// Unlike ipatool, which restarts each resumed segment with a fresh budget,
    /// `timeout` bounds the whole call.
    ///
    /// # Errors
    /// Returns the first hook fault, a guard rejection, [`EmuError::Timeout`],
    /// or the native error for any instruction that cannot be emulated.
    pub fn run(&mut self, begin: u64, until: u64, timeout: Duration) -> Result<(), EmuError> {
        let deadline = Instant::now() + timeout;
        let mut next = begin;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(EmuError::Timeout { timeout });
            }
            let error = match self.start_bounded(next, until, remaining, 0) {
                Ok(()) => return Ok(()),
                Err(error @ EmuError::Unicorn { .. }) => error,
                Err(error) => return Err(error.with_timeout(timeout)),
            };
            if !self.emulate_invalid_instruction()? {
                return Err(error);
            }
            next = self.reg_read(Register::Pc)?;
        }
    }

    /// Emulates the instruction at `PC` if it is `CASAL`, `SWPAL` or `EOR3`,
    /// advancing `PC` past it.
    ///
    /// Returns `Ok(false)` when the instruction is unreadable or not one of those.
    ///
    /// # Errors
    /// Returns an error if a register or the atomic memory operand cannot be
    /// accessed.
    pub fn emulate_invalid_instruction(&mut self) -> Result<bool, EmuError> {
        let pc = self.reg_read(Register::Pc)?;
        let Ok(instruction) = self.read_u32(pc) else {
            return Ok(false);
        };

        if instruction & EOR3_MASK == EOR3 {
            self.emulate_eor3(instruction)?;
        } else if let Some(atomic) = decode_atomic(instruction) {
            self.emulate_atomic(atomic)?;
        } else {
            return Ok(false);
        }

        self.reg_write(Register::Pc, pc + INSTRUCTION_SIZE)?;
        Ok(true)
    }

    fn emulate_eor3(&mut self, instruction: u32) -> Result<(), EmuError> {
        let first = self.vreg_read(field(instruction, RN_SHIFT))?;
        let second = self.vreg_read(field(instruction, RS_SHIFT))?;
        let third = self.vreg_read(field(instruction, RA_SHIFT))?;
        let mut result = first;
        for (index, byte) in result.iter_mut().enumerate() {
            *byte ^= second[index] ^ third[index];
        }

        self.vreg_write(field(instruction, RT_SHIFT), result)
    }

    fn emulate_atomic(&mut self, atomic: Atomic) -> Result<(), EmuError> {
        let address = self.read_base_register(atomic.rn)?;
        let mut bytes = [0; DOUBLEWORD_BYTES];
        self.mem_read_into(address, &mut bytes[..atomic.width])?;
        let old_value = u64::from_le_bytes(bytes);
        let source = truncate(self.read_value_register(atomic.rs)?, atomic.width);

        match atomic.operation {
            AtomicOperation::CompareAndSwap => {
                let new_value = truncate(self.read_value_register(atomic.rt)?, atomic.width);
                if old_value == source {
                    self.mem_write(address, &new_value.to_le_bytes()[..atomic.width])?;
                }
                self.write_value_register(atomic.rs, old_value)
            }
            AtomicOperation::Swap => {
                self.mem_write(address, &source.to_le_bytes()[..atomic.width])?;
                self.write_value_register(atomic.rt, old_value)
            }
        }
    }

    fn read_base_register(&self, index: u8) -> Result<u64, EmuError> {
        if index == ZERO_OR_SP {
            return self.reg_read(Register::Sp);
        }

        self.reg_read(Register::X(index))
    }

    fn read_value_register(&self, index: u8) -> Result<u64, EmuError> {
        if index == ZERO_OR_SP {
            return Ok(0);
        }

        self.reg_read(Register::X(index))
    }

    fn write_value_register(&mut self, index: u8, value: u64) -> Result<(), EmuError> {
        if index == ZERO_OR_SP {
            return Ok(());
        }

        self.reg_write(Register::X(index), value)
    }
}

impl EmuError {
    /// Reports a segment timeout against the caller's whole-call budget.
    fn with_timeout(self, budget: Duration) -> Self {
        match self {
            Self::Timeout { .. } => Self::Timeout { timeout: budget },
            other => other,
        }
    }
}
