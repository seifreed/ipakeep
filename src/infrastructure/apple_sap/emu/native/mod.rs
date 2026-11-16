//! Native Rust ARM64 (A64) interpreter — ipakeep's default emulation engine
//! (`native-cpu` feature), a permissively-licensed replacement for the
//! deprecated `unicorn-engine` backend.
//!
//! It executes the already-PAC-stripped A64 code of the Apple SAP/ADI/kbsync
//! guest binaries. It is validated **differentially against Unicorn** (see
//! [`diff`] and `coverage_tests::decode_oracle`, built with the `unicorn`
//! feature) and end to end against the golden vectors of the real Apple guests.
//!
//! Scope (from the OTP opcode histogram): the hot path is ~99.98% integer; the
//! small NEON/FP + `eor3`/`swpal` surface follows. Anything outside the modelled
//! set stops with [`NativeError::Unsupported`] instead of being guessed. No
//! system registers are touched by the guest, so there is no system-register
//! file.
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
pub(crate) mod engine;
#[cfg(feature = "jit")]
pub(crate) mod jit;
mod ldst;
mod simd;

use std::cell::Cell;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

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

/// Hasher for page-aligned addresses. Keys are already well-distributed
/// integers, so a single multiply (Fibonacci hashing) replaces `SipHash`, which
/// dominated the interpreter's profile (two hashes per guest byte accessed).
#[derive(Default)]
struct PageHasher(u64);

impl Hasher for PageHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(byte)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        // Page addresses have their low 12 bits clear; fold the high product
        // bits down so hashbrown's top-7-bit tag and bucket index both vary.
        let h = (value >> 12).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = h ^ (h >> 32);
    }
}

type PageIndex = HashMap<u64, usize, BuildHasherDefault<PageHasher>>;
type Frame = Box<[u8; PAGE_SIZE as usize]>;

/// A page-number cache entry that never matches (page keys are page-aligned).
const NO_PAGE: (u64, usize) = (u64::MAX, 0);

/// Sparse page-granular guest memory.
///
/// Page contents live in `frames`; `index` maps a page-aligned address to its
/// frame. Two one-entry caches (instruction fetch and data access) remember
/// the last page each touched, so straight-line code and loops over one
/// buffer skip the hash lookup. Frame indices only change on `unmap`, which
/// resets both caches; writes go through the frames, so they never stale a
/// cache.
pub(crate) struct Memory {
    index: PageIndex,
    frames: Vec<Frame>,
    fetch_cache: Cell<(u64, usize)>,
    data_cache: Cell<(u64, usize)>,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            index: PageIndex::default(),
            frames: Vec::new(),
            fetch_cache: Cell::new(NO_PAGE),
            data_cache: Cell::new(NO_PAGE),
        }
    }
}

impl Memory {
    /// Frame index of the page containing `address`, via `cache`.
    #[inline]
    fn frame_of(&self, address: u64, cache: &Cell<(u64, usize)>) -> Option<usize> {
        let page = address & !(PAGE_SIZE - 1);
        let (cached_page, cached_frame) = cache.get();
        if cached_page == page {
            return Some(cached_frame);
        }
        let frame = *self.index.get(&page)?;
        cache.set((page, frame));
        Some(frame)
    }

    fn page_mut(&mut self, page: u64) -> &mut [u8; PAGE_SIZE as usize] {
        let frames = &mut self.frames;
        let frame = *self.index.entry(page).or_insert_with(|| {
            frames.push(Box::new([0u8; PAGE_SIZE as usize]));
            frames.len() - 1
        });
        &mut self.frames[frame]
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

    /// Unmaps the pages covering `[address, address+size)`.
    pub(crate) fn unmap(&mut self, address: u64, size: u64) {
        self.fetch_cache.set(NO_PAGE);
        self.data_cache.set(NO_PAGE);
        let start = address & !(PAGE_SIZE - 1);
        let end = (address + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut page = start;
        while page < end {
            if let Some(frame) = self.index.remove(&page) {
                // `swap_remove` moves the last frame into the hole; repoint
                // the page that owned it (unmap is rare, so a scan is fine).
                self.frames.swap_remove(frame);
                if frame < self.frames.len() {
                    for slot in self.index.values_mut() {
                        if *slot == self.frames.len() {
                            *slot = frame;
                            break;
                        }
                    }
                }
            }
            page += PAGE_SIZE;
        }
    }

    fn is_mapped(&self, address: u64) -> bool {
        self.index.contains_key(&(address & !(PAGE_SIZE - 1)))
    }

    /// Reads `buf.len()` bytes starting at `address`.
    ///
    /// Copies page-sized chunks; on an unmapped page the bytes before it are
    /// already filled and the error names the first unmapped byte, exactly as
    /// a byte-by-byte copy would.
    pub(crate) fn read(&self, address: u64, buf: &mut [u8]) -> Result<(), NativeError> {
        let mut done = 0usize;
        while done < buf.len() {
            let addr = address + done as u64;
            let offset = (addr & (PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - offset).min(buf.len() - done);
            let frame = self
                .frame_of(addr, &self.data_cache)
                .ok_or(NativeError::Unmapped { address: addr })?;
            buf[done..done + chunk].copy_from_slice(&self.frames[frame][offset..offset + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Writes `data` starting at `address`.
    ///
    /// Same chunking and partial-write-on-fault behavior as [`Memory::read`].
    pub(crate) fn write(&mut self, address: u64, data: &[u8]) -> Result<(), NativeError> {
        let mut done = 0usize;
        while done < data.len() {
            let addr = address + done as u64;
            let offset = (addr & (PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - offset).min(data.len() - done);
            let frame = self
                .frame_of(addr, &self.data_cache)
                .ok_or(NativeError::Unmapped { address: addr })?;
            self.frames[frame][offset..offset + chunk].copy_from_slice(&data[done..done + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Fetches the instruction word at `address` (through the fetch cache).
    #[inline]
    fn read_u32(&self, address: u64) -> Result<u32, NativeError> {
        // Fast path: an aligned word never straddles a page, so one (usually
        // cached) page lookup and a direct 4-byte load suffice.
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if offset <= PAGE_SIZE as usize - 4
            && let Some(frame) = self.frame_of(address, &self.fetch_cache)
        {
            let page = &self.frames[frame];
            return Ok(u32::from_le_bytes([
                page[offset],
                page[offset + 1],
                page[offset + 2],
                page[offset + 3],
            ]));
        }
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

    /// Reads SIMD/FP register `n` (V0..V31) as a 128-bit little-endian value.
    pub(crate) fn v(&self, n: u32) -> u128 {
        self.v[n as usize]
    }
    /// Writes SIMD/FP register `n` (V0..V31) as a 128-bit little-endian value.
    pub(crate) fn set_v(&mut self, n: u32, value: u128) {
        self.v[n as usize] = value;
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
            A64Class::DataProcSimdFp => simd::run(self, word),
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

#[cfg(all(test, feature = "unicorn"))]
mod diff;

/// Coverage-closing tests (differential where an encoding executes, exact
/// `Unsupported` where it is out of scope), kept apart from the per-group
/// test modules.
#[cfg(test)]
mod coverage_tests;

#[cfg(test)]
mod memory_tests {
    use super::{Memory, NativeError, PAGE_SIZE};

    /// Unmapping a page moves another frame; every surviving page (and both
    /// page caches) must still resolve to its own contents.
    #[test]
    fn unmap_keeps_other_pages_and_caches_coherent() {
        let mut mem = Memory::default();
        mem.map(0x1000, 3 * PAGE_SIZE);
        for (i, page) in [0x1000u64, 0x2000, 0x3000].iter().enumerate() {
            mem.write(*page, &[i as u8 + 1; 4]).unwrap();
        }
        assert_eq!(mem.read_u32(0x3000).unwrap(), 0x0303_0303);
        mem.unmap(0x1000, PAGE_SIZE);
        assert_eq!(
            mem.read_u32(0x1000),
            Err(NativeError::Unmapped { address: 0x1000 })
        );
        assert_eq!(mem.read_u32(0x2000).unwrap(), 0x0202_0202);
        assert_eq!(mem.read_u32(0x3000).unwrap(), 0x0303_0303);
        let mut buf = [0u8; 8];
        assert_eq!(
            mem.read(0x2ffc, &mut buf),
            Ok(()),
            "a read straddling two mapped pages succeeds"
        );
        assert_eq!(buf, [0, 0, 0, 0, 3, 3, 3, 3]);
        mem.write(0x3000, &[9; 4]).unwrap();
        assert_eq!(mem.read_u32(0x3000).unwrap(), 0x0909_0909);
    }
}
