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

mod block;
mod branch;
mod dpimm;
mod dpreg;
pub(crate) mod engine;
mod ldst;
mod predecode;
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

/// A page-number cache entry that never matches: TLB tags are page numbers
/// (`address >> 12`, at most 2^52 - 1) and the fetch cache keys page-aligned
/// addresses, so `u64::MAX` is never a valid key in either.
const NO_PAGE: (u64, usize) = (u64::MAX, 0);

/// log2 of [`PAGE_SIZE`].
const PAGE_SHIFT: u32 = 12;

/// Entries in the data software TLB (a power of two; 16 KiB of slots).
/// Boxed so `Memory` (and the futures that own an engine) stay small.
/// Measured on the kbsync access stream (271M data accesses, ~420 distinct
/// data pages): a one-entry cache misses 85%, 64 entries 0.9%, 256 entries
/// 0.26%, 1024 entries 0.01%. kbsync never unmaps, so the bigger flush is free.
const TLB_ENTRIES: usize = 1024;

/// Sparse page-granular guest memory.
///
/// Page contents live in `frames`; `index` maps a page-aligned address to its
/// frame. Lookups avoid the hash map through two caches:
///
/// * `tlb` — a direct-mapped software TLB for data accesses. Slot
///   `page_number % TLB_ENTRIES` holds `(page_number, frame)`. A hit costs one
///   compare; a miss consults `index` and refills the slot (evicting whatever
///   page shared it). Only mapped pages are ever cached (no negative entries).
/// * `fetch_cache` — a one-entry cache for instruction fetch, which walks one
///   page at a time and would otherwise compete with data for TLB slots.
///
/// Coherence: `map` only adds pages and never moves an existing frame, and no
/// cache remembers an unmapped page, so `map` needs no invalidation. `unmap`
/// is the only operation that removes a page or renumbers frames
/// (`swap_remove`), so it flushes every cache. Writes go through the frames
/// and never stale a cache.
///
/// Code-page tracking (for the block cache): `code[frame]` is set while the
/// page holds instructions the block cache translated. The first write to (or
/// unmap of) such a page clears the flag and records the page in
/// `code_writes`; the engine drains that list and drops the stale blocks.
/// Every write path checks the flag — the in-page fast path falls back to
/// [`Memory::write_slow`] (which records the page) when it is set — so a
/// TLB hit can never skip the invalidation.
pub(crate) struct Memory {
    index: PageIndex,
    frames: Vec<Frame>,
    fetch_cache: Cell<(u64, usize)>,
    tlb: Box<[Cell<(u64, usize)>; TLB_ENTRIES]>,
    code: Vec<bool>,
    code_writes: Vec<u64>,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            index: PageIndex::default(),
            frames: Vec::new(),
            fetch_cache: Cell::new(NO_PAGE),
            tlb: Box::new(std::array::from_fn(|_| Cell::new(NO_PAGE))),
            code: Vec::new(),
            code_writes: Vec::new(),
        }
    }
}

/// Copies `src` into `dst` (equal lengths). The power-of-two sizes of A64
/// scalar and vector accesses get fixed-size copies, which compile to plain
/// loads/stores instead of a `memcpy` call.
// Forced inline: the whole point is a call-free load/store fast path.
#[allow(clippy::inline_always)]
#[inline(always)]
fn copy_small(dst: &mut [u8], src: &[u8]) {
    match dst.len() {
        1 => dst[0] = src[0],
        2 => dst[..2].copy_from_slice(&src[..2]),
        4 => dst[..4].copy_from_slice(&src[..4]),
        8 => dst[..8].copy_from_slice(&src[..8]),
        16 => dst[..16].copy_from_slice(&src[..16]),
        _ => dst.copy_from_slice(src),
    }
}

impl Memory {
    /// Frame index of the page containing `address`, via the one-entry
    /// instruction-fetch cache.
    #[inline]
    fn fetch_frame(&self, address: u64) -> Option<usize> {
        let page = address & !(PAGE_SIZE - 1);
        let (cached_page, cached_frame) = self.fetch_cache.get();
        if cached_page == page {
            return Some(cached_frame);
        }
        let frame = *self.index.get(&page)?;
        self.fetch_cache.set((page, frame));
        Some(frame)
    }

    /// Frame index of the page containing `address`, via the data TLB.
    // Forced inline: a TLB hit must not cost a call.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn data_frame(&self, address: u64) -> Option<usize> {
        let vpn = address >> PAGE_SHIFT;
        let slot = &self.tlb[vpn as usize & (TLB_ENTRIES - 1)];
        let (tag, frame) = slot.get();
        if tag == vpn {
            return Some(frame);
        }
        self.tlb_fill(vpn, slot)
    }

    /// TLB miss: looks the page up in `index` and, if mapped, caches it in
    /// `slot` (evicting the previous occupant).
    #[inline(never)]
    fn tlb_fill(&self, vpn: u64, slot: &Cell<(u64, usize)>) -> Option<usize> {
        let frame = *self.index.get(&(vpn << PAGE_SHIFT))?;
        slot.set((vpn, frame));
        Some(frame)
    }

    /// Drops every cached translation (after frames were removed/renumbered).
    fn flush_caches(&self) {
        self.fetch_cache.set(NO_PAGE);
        for slot in &self.tlb {
            slot.set(NO_PAGE);
        }
    }

    fn page_mut(&mut self, page: u64) -> &mut [u8; PAGE_SIZE as usize] {
        let (frames, code) = (&mut self.frames, &mut self.code);
        let frame = *self.index.entry(page).or_insert_with(|| {
            frames.push(Box::new([0u8; PAGE_SIZE as usize]));
            code.push(false);
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
        self.flush_caches();
        let start = address & !(PAGE_SIZE - 1);
        let end = (address + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut page = start;
        while page < end {
            if let Some(frame) = self.index.remove(&page) {
                if self.code.swap_remove(frame) {
                    self.code_writes.push(page);
                }
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
    /// An access inside one mapped page (every aligned A64 load) takes the
    /// fast path: one TLB lookup and a fixed-size copy. Anything else —
    /// page-straddling, unmapped or empty — takes [`Memory::read_slow`].
    pub(crate) fn read(&self, address: u64, buf: &mut [u8]) -> Result<(), NativeError> {
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if offset + buf.len() <= PAGE_SIZE as usize
            && let Some(frame) = self.data_frame(address)
        {
            copy_small(buf, &self.frames[frame][offset..offset + buf.len()]);
            return Ok(());
        }
        self.read_slow(address, buf)
    }

    /// General read: copies page-sized chunks; on an unmapped page the bytes
    /// before it are already filled and the error names the first unmapped
    /// byte, exactly as a byte-by-byte copy would.
    #[inline(never)]
    fn read_slow(&self, address: u64, buf: &mut [u8]) -> Result<(), NativeError> {
        let mut done = 0usize;
        while done < buf.len() {
            let addr = address + done as u64;
            let offset = (addr & (PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - offset).min(buf.len() - done);
            let frame = self
                .data_frame(addr)
                .ok_or(NativeError::Unmapped { address: addr })?;
            buf[done..done + chunk].copy_from_slice(&self.frames[frame][offset..offset + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Writes `data` starting at `address`.
    ///
    /// Same fast path and partial-write-on-fault behavior as [`Memory::read`].
    /// A store into a page flagged as cached code leaves the fast path so
    /// [`Memory::write_slow`] can record it for block invalidation.
    pub(crate) fn write(&mut self, address: u64, data: &[u8]) -> Result<(), NativeError> {
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if offset + data.len() <= PAGE_SIZE as usize
            && let Some(frame) = self.data_frame(address)
            && !self.code[frame]
        {
            copy_small(&mut self.frames[frame][offset..offset + data.len()], data);
            return Ok(());
        }
        self.write_slow(address, data)
    }

    /// General write; see [`Memory::read_slow`].
    #[inline(never)]
    fn write_slow(&mut self, address: u64, data: &[u8]) -> Result<(), NativeError> {
        let mut done = 0usize;
        while done < data.len() {
            let addr = address + done as u64;
            let offset = (addr & (PAGE_SIZE - 1)) as usize;
            let chunk = (PAGE_SIZE as usize - offset).min(data.len() - done);
            let frame = self
                .data_frame(addr)
                .ok_or(NativeError::Unmapped { address: addr })?;
            if self.code[frame] {
                self.code[frame] = false;
                self.code_writes.push(addr & !(PAGE_SIZE - 1));
            }
            self.frames[frame][offset..offset + chunk].copy_from_slice(&data[done..done + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Flags the (mapped) page containing `address` as holding cached code, so
    /// the next write to it is reported by [`Memory::take_code_writes`].
    pub(crate) fn mark_code(&mut self, address: u64) {
        if let Some(&frame) = self.index.get(&(address & !(PAGE_SIZE - 1))) {
            self.code[frame] = true;
        }
    }

    /// Whether a page holding cached code was written or unmapped since the
    /// last [`Memory::take_code_writes`].
    #[inline]
    pub(crate) fn code_written(&self) -> bool {
        !self.code_writes.is_empty()
    }

    /// Drains the pages whose cached code went stale.
    pub(crate) fn take_code_writes(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.code_writes)
    }

    /// Fetches the instruction word at `address` (through the fetch cache).
    ///
    /// Forced inline: it runs once per guest instruction, and LLVM otherwise
    /// leaves it out of line in `NativeCpu::step` (measured: ~12% more host
    /// instructions on kbsync).
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn read_u32(&self, address: u64) -> Result<u32, NativeError> {
        // Fast path: an aligned word never straddles a page, so one (usually
        // cached) page lookup and a direct 4-byte load suffice.
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if offset <= PAGE_SIZE as usize - 4
            && let Some(frame) = self.fetch_frame(address)
        {
            let page = &self.frames[frame];
            return Ok(u32::from_le_bytes([
                page[offset],
                page[offset + 1],
                page[offset + 2],
                page[offset + 3],
            ]));
        }
        // Straddling or unmapped: the general path (kept out of line so this
        // function stays small enough to inline into the step loop).
        let mut b = [0u8; 4];
        self.read_slow(address, &mut b)?;
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

/// Register-file slot that always reads as zero (register 31 as XZR).
pub(crate) const SLOT_ZR: usize = 31;
/// Register-file slot that swallows writes to XZR (never read).
pub(crate) const SLOT_SINK: usize = 32;
/// Register-file slot holding the stack pointer (register 31 in SP-form).
pub(crate) const SLOT_SP: usize = 33;

/// The native A64 CPU: register file + flags + vectors + memory.
pub(crate) struct NativeCpu {
    /// Integer register file: X0..X30 in slots 0..=30, then [`SLOT_ZR`],
    /// [`SLOT_SINK`] and [`SLOT_SP`]. Register-31 reads and writes map onto
    /// those slots without a branch; the array is 64 long so a 6-bit masked
    /// index needs no bounds check.
    r: [u64; 64],
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
            r: [0; 64],
            pc: 0,
            nzcv: 0,
            v: [0; 32],
            mem: Memory::default(),
        }
    }

    // --- register access with reg-31 semantics ---

    /// Reads register-file slot `slot` (see [`NativeCpu::r`]).
    #[inline]
    pub(crate) fn slot(&self, slot: u8) -> u64 {
        self.r[usize::from(slot) & 63]
    }

    /// Writes register-file slot `slot`; never pass [`SLOT_ZR`].
    #[inline]
    pub(crate) fn set_slot(&mut self, slot: u8, value: u64) {
        self.r[usize::from(slot) & 63] = value;
    }

    /// Reads register `n` as a 64-bit value; register 31 reads as zero (XZR).
    #[inline]
    pub(crate) fn x(&self, n: u32) -> u64 {
        self.r[(n & 31) as usize]
    }

    /// Writes register `n`; register 31 is discarded (XZR).
    #[inline]
    pub(crate) fn set_x(&mut self, n: u32, value: u64) {
        self.r[(n & 31) as usize + usize::from(n & 31 == 31)] = value;
    }

    /// Reads register `n` where 31 denotes the stack pointer (SP-form).
    #[inline]
    pub(crate) fn x_sp(&self, n: u32) -> u64 {
        self.r[(n & 31) as usize + 2 * usize::from(n & 31 == 31)]
    }

    /// Writes register `n` where 31 denotes the stack pointer (SP-form).
    #[inline]
    pub(crate) fn set_x_sp(&mut self, n: u32, value: u64) {
        self.r[(n & 31) as usize + 2 * usize::from(n & 31 == 31)] = value;
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
        self.r[SLOT_SP]
    }
    pub(crate) fn set_sp(&mut self, sp: u64) {
        self.r[SLOT_SP] = sp;
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
        let word = self.mem.read_u32(self.pc)?;
        self.execute(word)
    }

    /// Runs the already-fetched instruction `word` as if it sat at `pc`.
    pub(crate) fn execute(&mut self, word: u32) -> Result<Step, NativeError> {
        let pc = self.pc;
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

/// Guest-memory access micro-benchmark (a fast unit test unless
/// `IPAKEEP_MEM_BENCH_ITERS` asks for a real measurement).
#[cfg(test)]
mod memory_bench;

/// Software-TLB and access-path tests for [`Memory`].
#[cfg(test)]
mod memory_tlb_tests;

#[cfg(test)]
mod block_tests;

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
