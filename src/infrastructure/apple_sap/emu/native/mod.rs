//! Native Rust ARM64 (A64) interpreter — a permissively-licensed replacement
//! for the `unicorn-engine` backend.
//!
//! This module executes the already-PAC-stripped A64 code of the Apple SAP/ADI
//! guest binaries. It is developed standalone and validated **differentially
//! against the Unicorn backend** (see [`diff`]) and against the golden vectors;
//! only once it reproduces them is it wired in as the selected engine.
//!
//! Scope (from the OTP opcode histogram): the hot path is ~99.98% integer, so
//! the integer core is built first; the small NEON/FP + `eor3`/`swpal` surface
//! follows. No system registers are touched by the guest, so there is no
//! system-register file.
//!
//! The whole module compiles only under `cfg(test)` for now; it is un-gated and
//! wired behind the `native-cpu` feature once it passes the golden suite.
#![allow(dead_code)]
// Interpreter code inherently truncates and reinterprets integer widths (W vs X
// registers, sign/zero extension, flag packing) and uses dense bit-encoded
// literals; these pedantic lints are noise here.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::unreadable_literal,
    clippy::similar_names,
    clippy::match_same_arms,
    clippy::unnested_or_patterns,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value
)]

mod branch;
mod dpimm;
mod dpreg;
mod ldst;

use std::collections::HashMap;

use super::decode::{A64Class, classify};

/// Size of a mapped page.
pub(crate) const PAGE_SIZE: u64 = 0x1000;
/// Bytes in one A64 instruction.
pub(crate) const INSN_SIZE: u64 = 4;

/// A failure raised while decoding or running guest code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NativeError {
    /// The decoder reached an instruction class/encoding it does not implement.
    Unsupported {
        /// Program counter of the instruction.
        pc: u64,
        /// The raw 32-bit instruction word.
        word: u32,
        /// A short description (class or mnemonic).
        what: &'static str,
    },
    /// A guest memory access hit an unmapped address.
    Unmapped {
        /// The faulting address.
        address: u64,
    },
}

/// The result of running one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Continue at `pc + 4`.
    Next,
    /// Continue at the given address (a taken branch).
    Branch(u64),
    /// A `brk #imm` trap was hit; stop.
    Break(u16),
}

/// Sparse page-granular guest memory.
#[derive(Default)]
pub(crate) struct Memory {
    pages: HashMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
}

impl Memory {
    fn page_mut(&mut self, page: u64) -> &mut [u8; PAGE_SIZE as usize] {
        self.pages
            .entry(page)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE as usize]))
    }

    /// Maps `[address, address+size)` as zeroed pages (idempotent).
    pub(crate) fn map(&mut self, address: u64, size: u64) {
        let start = address & !(PAGE_SIZE - 1);
        let end = (address + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut page = start;
        while page < end {
            self.page_mut(page);
            page += PAGE_SIZE;
        }
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.pages.contains_key(&(address & !(PAGE_SIZE - 1)))
    }

    /// Reads `buf.len()` bytes starting at `address`.
    pub(crate) fn read(&self, address: u64, buf: &mut [u8]) -> Result<(), NativeError> {
        for (i, byte) in buf.iter_mut().enumerate() {
            let addr = address + i as u64;
            let page = self
                .pages
                .get(&(addr & !(PAGE_SIZE - 1)))
                .ok_or(NativeError::Unmapped { address: addr })?;
            *byte = page[(addr & (PAGE_SIZE - 1)) as usize];
        }
        Ok(())
    }

    /// Writes `data` starting at `address`.
    pub(crate) fn write(&mut self, address: u64, data: &[u8]) -> Result<(), NativeError> {
        for (i, byte) in data.iter().enumerate() {
            let addr = address + i as u64;
            if !self.is_mapped(addr) {
                return Err(NativeError::Unmapped { address: addr });
            }
            let page = self.page_mut(addr & !(PAGE_SIZE - 1));
            page[(addr & (PAGE_SIZE - 1)) as usize] = *byte;
        }
        Ok(())
    }

    fn read_u32(&self, address: u64) -> Result<u32, NativeError> {
        let mut b = [0u8; 4];
        self.read(address, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }
}

/// Evaluates a condition code (`cond` field) against packed flags (ARM ARM C1.2.4).
pub(crate) fn cond_holds(nzcv: u32, cond: u8) -> bool {
    let n = (nzcv >> 31) & 1 == 1;
    let z = (nzcv >> 30) & 1 == 1;
    let c = (nzcv >> 29) & 1 == 1;
    let v = (nzcv >> 28) & 1 == 1;
    let base = match cond >> 1 {
        0b000 => z,            // EQ/NE
        0b001 => c,            // CS/CC
        0b010 => n,            // MI/PL
        0b011 => v,            // VS/VC
        0b100 => c && !z,      // HI/LS
        0b101 => n == v,       // GE/LT
        0b110 => n == v && !z, // GT/LE
        _ => true,             // AL/NV
    };
    // The low bit inverts the condition, except for AL/NV (cond 0b111x).
    if cond & 1 == 1 && cond >> 1 != 0b111 {
        !base
    } else {
        base
    }
}

/// Packs NZCV into bits [31:28] for a 64-bit `result` with the given carry/overflow.
pub(crate) fn nzcv_bits(result: u64, carry: bool, overflow: bool) -> u32 {
    let n = ((result >> 63) & 1) as u32;
    let z = u32::from(result == 0);
    (n << 31) | (z << 30) | (u32::from(carry) << 29) | (u32::from(overflow) << 28)
}

/// The native A64 CPU: register file + flags + vectors + memory.
pub(crate) struct NativeCpu {
    /// X0..X30.
    x: [u64; 31],
    /// Stack pointer (register 31 in SP-form).
    sp: u64,
    /// Program counter.
    pc: u64,
    /// Condition flags in bits [31:28] (N,Z,C,V).
    nzcv: u32,
    /// V0..V31, 128-bit little-endian.
    v: [u128; 32],
    /// Guest memory.
    pub(crate) mem: Memory,
}

impl NativeCpu {
    pub(crate) fn new() -> Self {
        Self {
            x: [0; 31],
            sp: 0,
            pc: 0,
            nzcv: 0,
            v: [0; 32],
            mem: Memory::default(),
        }
    }

    // --- register access with reg-31 semantics ---

    /// Reads register `n` as a 64-bit value; register 31 reads as zero (XZR).
    pub(crate) fn x(&self, n: u32) -> u64 {
        if n == 31 { 0 } else { self.x[n as usize] }
    }

    /// Writes register `n`; register 31 is discarded (XZR).
    pub(crate) fn set_x(&mut self, n: u32, value: u64) {
        if n != 31 {
            self.x[n as usize] = value;
        }
    }

    /// Reads register `n` where 31 denotes the stack pointer (SP-form).
    pub(crate) fn x_sp(&self, n: u32) -> u64 {
        if n == 31 { self.sp } else { self.x[n as usize] }
    }

    /// Writes register `n` where 31 denotes the stack pointer (SP-form).
    pub(crate) fn set_x_sp(&mut self, n: u32, value: u64) {
        if n == 31 {
            self.sp = value;
        } else {
            self.x[n as usize] = value;
        }
    }

    /// Reads a 32-bit view of register `n` (31 = WZR).
    pub(crate) fn w(&self, n: u32) -> u32 {
        self.x(n) as u32
    }

    /// Writes a 32-bit result to register `n`, zero-extending to 64 bits.
    pub(crate) fn set_w(&mut self, n: u32, value: u32) {
        self.set_x(n, u64::from(value));
    }

    pub(crate) fn pc(&self) -> u64 {
        self.pc
    }
    pub(crate) fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }
    pub(crate) fn nzcv(&self) -> u32 {
        self.nzcv
    }
    pub(crate) fn set_nzcv(&mut self, nzcv: u32) {
        self.nzcv = nzcv & 0xf000_0000;
    }
    pub(crate) fn sp(&self) -> u64 {
        self.sp
    }
    pub(crate) fn set_sp(&mut self, sp: u64) {
        self.sp = sp;
    }

    /// Runs the instruction at `pc` and returns the control-flow outcome.
    pub(crate) fn step(&mut self) -> Result<Step, NativeError> {
        let pc = self.pc;
        let word = self.mem.read_u32(pc)?;
        match classify(word) {
            A64Class::DataProcImm => dpimm::run(self, word),
            A64Class::DataProcReg => dpreg::run(self, word),
            A64Class::BranchSystem => branch::run(self, word),
            A64Class::LoadStore => ldst::run(self, word),
            other => Err(NativeError::Unsupported {
                pc,
                word,
                what: class_name(other),
            }),
        }
    }

    /// Runs up to `max_steps` instructions from `pc`, stopping early on a
    /// branch to `until`, a `brk`, or an error.
    pub(crate) fn run(&mut self, until: u64, max_steps: usize) -> Result<Step, NativeError> {
        for _ in 0..max_steps {
            if self.pc == until {
                return Ok(Step::Next);
            }
            match self.step()? {
                Step::Next => self.pc += INSN_SIZE,
                Step::Branch(target) => self.pc = target,
                Step::Break(imm) => return Ok(Step::Break(imm)),
            }
        }
        Ok(Step::Next)
    }
}

fn class_name(class: A64Class) -> &'static str {
    match class {
        A64Class::Reserved => "reserved",
        A64Class::Unallocated => "unallocated",
        A64Class::DataProcImm => "data-proc-imm",
        A64Class::BranchSystem => "branch/system",
        A64Class::LoadStore => "load/store",
        A64Class::DataProcReg => "data-proc-reg",
        A64Class::DataProcSimdFp => "simd/fp",
    }
}

#[cfg(test)]
mod diff;
