//! Optional Cranelift JIT tier for the native interpreter (`jit` feature).
//!
//! # Tiering
//! [`Jit::try_run`] is consulted by the engine loop before each interpreted
//! instruction. It counts entries per guest PC in a direct-mapped profile and,
//! once a PC has been entered [`DEFAULT_THRESHOLD`] times, decodes the block
//! starting there (straight-line translatable instructions up to and including
//! the first branch, never past a hooked address) and compiles it with
//! Cranelift. A block whose final branch targets its own start is compiled as
//! a loop.
//!
//! # Execution
//! A *session* copies the guest registers into a [`JitCtx`], then chains
//! compiled blocks through the same direct-mapped table (indirect `BR`/`RET`
//! targets included) until the next PC has no compiled block, equals `until`,
//! the session quota or instruction budget would be exceeded, or a block exits
//! on a memory miss. Registers are then copied back and the engine resumes
//! with the interpreter, so hooks, `brk`, faults and every untranslated
//! instruction keep their exact interpreter semantics.
//!
//! # Memory
//! Guest memory is reached through a 256-entry direct-mapped TLB of host page
//! pointers inside [`JitCtx`]. A miss leaves the block before the access; the
//! dispatcher fills the TLB and the interpreter executes that instruction, so
//! unmapped accesses fault exactly as without the JIT. Pages holding compiled
//! code never get a write entry, so a JIT store to them exits and invalidates
//! the blocks on that page first.
//!
//! # Invalidation
//! Every session starts a new epoch; a block's guest words are re-compared with
//! memory the first time it runs in an epoch, which catches writes by the
//! interpreter, by hooks and by the host (and unmapped code). Adding a hook
//! flushes every block. Mapping or unmapping memory flushes the TLB.
//!
//! The only `unsafe` code is in [`exec`].

// Decoders/translators are long flat matches over encoding fields, and the
// IR emitters use the architectural single-letter names (n, z, c, v, a, b).
#![allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::enum_variant_names
)]

mod decode;
mod exec;
mod translate;


use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use cranelift_codegen::Context;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::FunctionBuilderContext;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Module, default_libcall_names};

use super::{INSN_SIZE, Memory, NativeCpu, PAGE_SIZE};
use translate::MAX_BLOCK_INSNS;

/// Entries of a block PC before it is compiled.
pub(crate) const DEFAULT_THRESHOLD: u32 = 1024;
/// Most guest instructions one session runs before returning to the engine
/// (keeps the engine's wall-clock deadline checks frequent).
const SESSION_QUOTA: usize = 4096;
/// Direct-mapped profile/lookup table size (power of two).
const SLOTS: usize = 1 << 14;
/// Guest TLB entries (power of two).
pub(super) const TLB_ENTRIES: usize = 256;
/// A tag that never matches a page-aligned address.
const NO_PAGE: u64 = 1;

/// Exit statuses returned by compiled blocks.
pub(super) const EXIT_OK: u32 = 0;
pub(super) const EXIT_READ_MISS: u32 = 1;
pub(super) const EXIT_WRITE_MISS: u32 = 2;

/// One TLB entry: the page it maps for reads / for writes, and its host frame.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct TlbEntry {
    read_tag: u64,
    write_tag: u64,
    host: u64,
    _pad: u64,
}

const EMPTY_ENTRY: TlbEntry = TlbEntry {
    read_tag: NO_PAGE,
    write_tag: NO_PAGE,
    host: 0,
    _pad: 0,
};

/// State shared with generated code (`#[repr(C)]`; offsets via `offset_of!`).
#[repr(C)]
pub(super) struct JitCtx {
    x: [u64; 31],
    sp: u64,
    nzcv: u32,
    _pad: u32,
    /// Next guest PC (written by every exit).
    pc: u64,
    /// Guest instructions completed by the call.
    count: u64,
    /// Instructions a looping block may run in this call.
    budget: u64,
    /// Faulting guest address of a miss exit.
    miss_addr: u64,
    tlb: [TlbEntry; TLB_ENTRIES],
}

impl JitCtx {
    fn new() -> Box<Self> {
        Box::new(Self {
            x: [0; 31],
            sp: 0,
            nzcv: 0,
            _pad: 0,
            pc: 0,
            count: 0,
            budget: 0,
            miss_addr: 0,
            tlb: [EMPTY_ENTRY; TLB_ENTRIES],
        })
    }

    fn load(&mut self, cpu: &NativeCpu) {
        self.x = cpu.x;
        self.sp = cpu.sp;
        self.nzcv = cpu.nzcv;
        self.pc = cpu.pc;
    }

    fn store(&self, cpu: &mut NativeCpu) {
        cpu.x = self.x;
        cpu.sp = self.sp;
        cpu.nzcv = self.nzcv;
        cpu.pc = self.pc;
    }
}

fn tlb_index(page: u64) -> usize {
    ((page >> 12) as usize) & (TLB_ENTRIES - 1)
}

fn slot_index(pc: u64) -> usize {
    ((pc >> 2) as usize) & (SLOTS - 1)
}

impl Memory {
    /// Host address of the frame backing the page that contains `address`.
    ///
    /// The pointer stays valid until that page is unmapped (frames are boxed,
    /// so mapping other pages never moves them); the JIT flushes its TLB on
    /// every map/unmap.
    fn host_page(&mut self, address: u64) -> Option<u64> {
        let frame = *self.index.get(&(address & !(PAGE_SIZE - 1)))?;
        Some(self.frames[frame].as_mut_ptr() as u64)
    }
}

/// A compiled block.
struct Block {
    start: u64,
    end: u64,
    /// Guest instructions of one pass through the block.
    len: usize,
    words: Vec<u32>,
    code: *const u8,
    /// Epoch of the last successful re-verification of `words`.
    verified: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Count(u32),
    Block(u32),
    Never,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    pc: u64,
    state: SlotState,
}

/// Counters describing the JIT's work.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JitStats {
    /// Blocks compiled.
    pub(crate) compiled: u64,
    /// Guest instructions in compiled blocks.
    pub(crate) compiled_insns: u64,
    /// Total time spent decoding and compiling.
    pub(crate) compile_time: Duration,
    /// Guest instructions executed by compiled code.
    pub(crate) executed: u64,
    /// Sessions entered.
    pub(crate) sessions: u64,
    /// Blocks discarded because their code changed or a hook was added.
    pub(crate) invalidated: u64,
    /// Memory-miss exits.
    pub(crate) misses: u64,
}

/// The JIT tier of one engine.
pub(crate) struct Jit {
    module: Option<JITModule>,
    context: Context,
    builder_context: FunctionBuilderContext,
    ctx: Box<JitCtx>,
    blocks: Vec<Block>,
    by_pc: HashMap<u64, u32>,
    never: HashSet<u64>,
    slots: Vec<Slot>,
    code_pages: HashMap<u64, Vec<u32>>,
    epoch: u64,
    hook_gen: u64,
    /// Entries before a PC is compiled (`0` disables compilation).
    pub(crate) threshold: u32,
    pub(crate) stats: JitStats,
}

impl Jit {
    /// A JIT for the host ISA, or one that never compiles when Cranelift does
    /// not support the host.
    pub(crate) fn new() -> Self {
        let mut flags = settings::builder();
        let _ = flags.set("opt_level", "speed");
        let _ = flags.set("enable_verifier", &cfg!(debug_assertions).to_string());
        let module = cranelift_native::builder()
            .ok()
            .and_then(|isa| isa.finish(settings::Flags::new(flags)).ok())
            .map(|isa| JITModule::new(JITBuilder::with_isa(isa, default_libcall_names())));
        let threshold = DEFAULT_THRESHOLD * u32::from(module.is_some());
        let context = module
            .as_ref()
            .map_or_else(Context::new, Module::make_context);
        Self {
            module,
            context,
            builder_context: FunctionBuilderContext::new(),
            ctx: JitCtx::new(),
            blocks: Vec::new(),
            by_pc: HashMap::new(),
            never: HashSet::new(),
            slots: vec![
                Slot {
                    pc: u64::MAX,
                    state: SlotState::Never,
                };
                SLOTS
            ],
            code_pages: HashMap::new(),
            epoch: 0,
            hook_gen: 0,
            threshold,
            stats: JitStats::default(),
        }
    }

    /// Forgets every TLB entry (call after mapping or unmapping guest memory).
    pub(crate) fn flush_tlb(&mut self) {
        self.ctx.tlb = [EMPTY_ENTRY; TLB_ENTRIES];
    }

    /// Drops every compiled block and profile count.
    fn flush_blocks(&mut self) {
        self.stats.invalidated += self.by_pc.len() as u64;
        self.by_pc.clear();
        self.never.clear();
        self.code_pages.clear();
        for slot in &mut self.slots {
            slot.pc = u64::MAX;
        }
        self.flush_tlb();
    }

    /// Drops the blocks on `page` (their code changed or is being written).
    fn invalidate_page(&mut self, page: u64) {
        for index in self.code_pages.remove(&page).unwrap_or_default() {
            let start = self.blocks[index as usize].start;
            if self.by_pc.get(&start) == Some(&index) {
                self.by_pc.remove(&start);
                self.stats.invalidated += 1;
                let slot = &mut self.slots[slot_index(start)];
                if slot.pc == start {
                    slot.pc = u64::MAX;
                }
            }
        }
        self.never.retain(|pc| pc & !(PAGE_SIZE - 1) != page);
    }

    /// Runs compiled code from the CPU's PC, if a block is (or just became)
    /// compiled there. Returns the number of guest instructions executed, or
    /// `None` when the interpreter must run the instruction at PC.
    ///
    /// `budget` caps the instructions run; `until` is never passed through;
    /// `hook_gen` changes whenever a hook is added; `hooked(pc)` tells whether
    /// a code hook covers `pc`.
    pub(crate) fn try_run(
        &mut self,
        cpu: &mut NativeCpu,
        until: u64,
        budget: usize,
        hook_gen: u64,
        hooked: &dyn Fn(u64) -> bool,
    ) -> Option<usize> {
        if hook_gen != self.hook_gen {
            self.hook_gen = hook_gen;
            self.flush_blocks();
        }
        let mut index = self.entry(cpu.pc, &cpu.mem, hooked)?;
        self.epoch += 1;
        self.stats.sessions += 1;
        self.ctx.load(cpu);
        let quota = budget.min(SESSION_QUOTA);
        let mut ran = 0usize;
        loop {
            let block = &mut self.blocks[index as usize];
            if (block.start < until && until < block.end) || block.len > quota - ran {
                break;
            }
            if block.verified != self.epoch {
                if !verify(&cpu.mem, block) {
                    let page = block.start & !(PAGE_SIZE - 1);
                    self.invalidate_page(page);
                    break;
                }
                block.verified = self.epoch;
            }
            self.ctx.budget = (quota - ran) as u64;
            let status = exec::call_block(block.code, &mut self.ctx);
            ran += self.ctx.count as usize;
            if status != EXIT_OK {
                self.miss(&mut cpu.mem, status == EXIT_WRITE_MISS);
                break;
            }
            let next = self.ctx.pc;
            if next == until {
                break;
            }
            match self.entry(next, &cpu.mem, hooked) {
                Some(next_index) => index = next_index,
                None => break,
            }
        }
        self.ctx.store(cpu);
        self.stats.executed += ran as u64;
        (ran > 0).then_some(ran)
    }

    /// Handles a memory-miss exit: invalidates code on a written page and
    /// fills the TLB entry (when the page is mapped).
    fn miss(&mut self, mem: &mut Memory, write: bool) {
        self.stats.misses += 1;
        let page = self.ctx.miss_addr & !(PAGE_SIZE - 1);
        if write && self.code_pages.contains_key(&page) {
            self.invalidate_page(page);
        }
        if let Some(host) = mem.host_page(page) {
            let write_tag = if self.code_pages.contains_key(&page) {
                NO_PAGE
            } else {
                page
            };
            self.ctx.tlb[tlb_index(page)] = TlbEntry {
                read_tag: page,
                write_tag,
                host,
                _pad: 0,
            };
        }
    }

    /// The compiled block at `pc`, profiling (and compiling once hot) when
    /// there is none yet.
    fn entry(&mut self, pc: u64, mem: &Memory, hooked: &dyn Fn(u64) -> bool) -> Option<u32> {
        let slot = &mut self.slots[slot_index(pc)];
        if slot.pc == pc {
            match slot.state {
                SlotState::Block(index) => return Some(index),
                SlotState::Never => return None,
                SlotState::Count(count) => slot.state = SlotState::Count(count + 1),
            }
        } else if let Some(&index) = self.by_pc.get(&pc) {
            *slot = Slot {
                pc,
                state: SlotState::Block(index),
            };
            return Some(index);
        } else {
            let state = if self.never.contains(&pc) {
                SlotState::Never
            } else {
                SlotState::Count(1)
            };
            *slot = Slot { pc, state };
        }
        match slot.state {
            SlotState::Count(count) if self.threshold != 0 && count >= self.threshold => {
                self.compile(pc, mem, hooked)
            }
            _ => None,
        }
    }

    /// Decodes and compiles the block at `pc`; remembers failures.
    fn compile(&mut self, pc: u64, mem: &Memory, hooked: &dyn Fn(u64) -> bool) -> Option<u32> {
        let started = Instant::now();
        let compiled = self.compile_block(pc, mem, hooked);
        self.stats.compile_time += started.elapsed();
        let slot = &mut self.slots[slot_index(pc)];
        if let Some(index) = compiled {
            slot.state = SlotState::Block(index);
            self.by_pc.insert(pc, index);
        } else {
            slot.state = SlotState::Never;
            self.never.insert(pc);
        }
        compiled
    }

    fn compile_block(
        &mut self,
        pc: u64,
        mem: &Memory,
        hooked: &dyn Fn(u64) -> bool,
    ) -> Option<u32> {
        if hooked(pc) {
            return None;
        }
        let decoded = translate::decode_block(mem, pc, hooked)?;
        let module = self.module.as_mut()?;
        let index = self.blocks.len() as u32;
        let func = translate::compile(
            module,
            &mut self.context,
            &mut self.builder_context,
            &decoded,
            index,
        )?;
        module.finalize_definitions().ok()?;
        let code = module.get_finalized_function(func);
        let end = decoded.end();
        let mut page = decoded.start & !(PAGE_SIZE - 1);
        while page < end {
            self.code_pages.entry(page).or_default().push(index);
            let entry = &mut self.ctx.tlb[tlb_index(page)];
            if entry.write_tag == page {
                entry.write_tag = NO_PAGE;
            }
            page += PAGE_SIZE;
        }
        self.stats.compiled += 1;
        self.stats.compiled_insns += decoded.ops.len() as u64;
        self.blocks.push(Block {
            start: decoded.start,
            end,
            len: decoded.ops.len(),
            words: decoded.words,
            code,
            verified: 0,
        });
        Some(index)
    }
}

/// Whether guest memory still holds the words `block` was compiled from.
fn verify(mem: &Memory, block: &Block) -> bool {
    let mut bytes = [0u8; MAX_BLOCK_INSNS * INSN_SIZE as usize];
    let bytes = &mut bytes[..block.words.len() * INSN_SIZE as usize];
    mem.read(block.start, bytes).is_ok()
        && bytes
            .as_chunks::<{ INSN_SIZE as usize }>()
            .0
            .iter()
            .zip(&block.words)
            .all(|(chunk, word)| *chunk == word.to_le_bytes())
}

impl Drop for Jit {
    fn drop(&mut self) {
        if let Some(module) = self.module.take() {
            exec::release(module);
        }
    }
}
