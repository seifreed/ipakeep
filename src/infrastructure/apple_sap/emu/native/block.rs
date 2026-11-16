//! Pre-decoded basic-block cache for the native interpreter.
//!
//! The first time the run loop reaches a guest PC it decodes a straight-line
//! block — up to and including the first branch/exception/system instruction,
//! [`MAX_BLOCK_OPS`] instructions, the end of the page, or the instruction
//! before a hooked address — into compact [`Op`]s. Later visits run the ops
//! without fetching or re-decoding.
//!
//! Invariants the engine relies on:
//! * A block never crosses a page, so one code-page flag in [`Memory`] covers
//!   every byte it was decoded from; the first write to that page (guest store,
//!   host write or unmap) is reported and the engine drops the page's blocks.
//! * A block never contains a hooked address except at its start, so code
//!   hooks only need to fire at block entry.
//! * Every op reproduces exactly what [`NativeCpu::step`] does for its word
//!   (encodings without a fast path run through [`NativeCpu::execute`]).

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use super::super::decode::{A64Class, classify};
use super::predecode::{Op, predecode, run_op};
use super::{INSN_SIZE, Memory, NativeCpu, NativeError, PAGE_SIZE, Step};

/// Upper bound on the instructions in one block. It also bounds how far the
/// run loop can overshoot its per-block deadline check.
pub(super) const MAX_BLOCK_OPS: usize = 64;

/// How a block run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Exit {
    /// Continue at this PC (fall-through, taken branch, or the stop point).
    Next(u64),
    /// A `brk` at this PC; it did not complete.
    Break(u64),
    /// The instruction at `pc` failed; nothing after it ran.
    Fault { pc: u64, error: NativeError },
}

/// Successor slots per block: enough for both static exits (fall-through and
/// taken) and a few targets of an indirect branch.
const LINKS: usize = 4;

/// A decoded straight-line block.
pub(super) struct Block {
    start: u64,
    ops: Box<[Op]>,
    /// Recently taken exits `(target pc, block id)`, so the next block is
    /// found without a hash lookup. Only a cache: an entry is used only if
    /// that slot still holds a live block starting at the target.
    links: [(u64, BlockId); LINKS],
    /// Next link slot to overwrite (round robin).
    next_link: usize,
}

impl Block {
    /// Number of instructions in the block.
    pub(super) fn len(&self) -> usize {
        self.ops.len()
    }
}

/// Runs at most `max` ops of `block` (`max >= 1`) and returns how many
/// instructions completed plus where execution goes next.
///
/// A completed store that hits a page holding cached code ends the block right
/// after that instruction (the op reports a branch to the next PC), so the
/// rest of the possibly rewritten code is fetched again — exactly what the
/// per-instruction loop would observe.
pub(super) fn run_block(cpu: &mut NativeCpu, block: &Block, max: usize) -> (usize, Exit) {
    let ops = &block.ops[..max.min(block.ops.len())];
    let mut pc = block.start;
    for (done, op) in ops.iter().enumerate() {
        match run_op(cpu, op, pc) {
            Ok(Step::Next) => pc += INSN_SIZE,
            Ok(Step::Branch(target)) => return (done + 1, Exit::Next(target)),
            Ok(Step::Break(_)) => return (done, Exit::Break(pc)),
            Err(error) => return (done, Exit::Fault { pc, error }),
        }
    }
    (ops.len(), Exit::Next(pc))
}

/// Hasher for instruction addresses (4-byte aligned): Fibonacci hashing of
/// the word index.
#[derive(Default)]
pub(super) struct PcHasher(u64);

impl Hasher for PcHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(byte)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        let h = (value >> 2).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.0 = h ^ (h >> 32);
    }
}

type PcMap<V> = HashMap<u64, V, BuildHasherDefault<PcHasher>>;

/// Index of a block in [`BlockCache`].
pub(super) type BlockId = usize;

/// The block cache: blocks by start PC plus the blocks decoded from each page.
#[derive(Default)]
pub(super) struct BlockCache {
    blocks: Vec<Option<Block>>,
    by_pc: PcMap<BlockId>,
    by_page: PcMap<Vec<BlockId>>,
    /// Slots emptied by invalidation (reused by later builds).
    free: Vec<BlockId>,
}

impl BlockCache {
    /// The live block with this id.
    pub(super) fn get(&self, id: BlockId) -> &Block {
        match &self.blocks[id] {
            Some(block) => block,
            None => unreachable!("dangling block id"),
        }
    }

    /// Whether `id` names a live block starting at `pc`.
    fn holds(&self, id: BlockId, pc: u64) -> bool {
        matches!(self.blocks.get(id), Some(Some(block)) if block.start == pc)
    }

    /// The block starting at `pc`, decoding it on first use. `from` is the
    /// block that just exited to `pc` (if any): its links are tried first and
    /// learn `pc` on a miss. `hooked` tells whether a code hook covers an
    /// address; such an address only ever starts a block. `pc` must be 4-byte
    /// aligned.
    pub(super) fn lookup(
        &mut self,
        mem: &mut Memory,
        from: Option<BlockId>,
        pc: u64,
        hooked: impl Fn(u64) -> bool,
    ) -> Result<BlockId, NativeError> {
        let from = from.filter(|&id| matches!(self.blocks.get(id), Some(Some(_))));
        if let Some(prev) = from {
            for &(target, id) in &self.get(prev).links {
                if target == pc && self.holds(id, pc) {
                    return Ok(id);
                }
            }
        }
        let id = self.find_or_build(mem, pc, hooked)?;
        if let Some(Some(prev)) = from.map(|prev| self.blocks[prev].as_mut()) {
            prev.links[prev.next_link] = (pc, id);
            prev.next_link = (prev.next_link + 1) % LINKS;
        }
        Ok(id)
    }

    fn find_or_build(
        &mut self,
        mem: &mut Memory,
        pc: u64,
        hooked: impl Fn(u64) -> bool,
    ) -> Result<BlockId, NativeError> {
        if let Some(&id) = self.by_pc.get(&pc) {
            return Ok(id);
        }
        let block = build(mem, pc, hooked)?;
        mem.mark_code(pc);
        let id = if let Some(id) = self.free.pop() {
            self.blocks[id] = Some(block);
            id
        } else {
            self.blocks.push(Some(block));
            self.blocks.len() - 1
        };
        self.by_pc.insert(pc, id);
        self.by_page
            .entry(pc & !(PAGE_SIZE - 1))
            .or_default()
            .push(id);
        Ok(id)
    }

    /// Drops every block decoded from one of `pages`.
    pub(super) fn invalidate_pages(&mut self, pages: &[u64]) {
        for page in pages {
            for id in self.by_page.remove(page).unwrap_or_default() {
                if let Some(block) = self.blocks[id].take() {
                    self.by_pc.remove(&block.start);
                    self.free.push(id);
                }
            }
        }
    }

    /// Drops every block (the hook layout changed).
    pub(super) fn clear(&mut self) {
        self.blocks.clear();
        self.by_pc.clear();
        self.by_page.clear();
        self.free.clear();
    }

    /// Number of live blocks.
    pub(super) fn live(&self) -> usize {
        self.by_pc.len()
    }
}

/// Decodes the block starting at `start`.
fn build(mem: &Memory, start: u64, hooked: impl Fn(u64) -> bool) -> Result<Block, NativeError> {
    let mut ops = Vec::new();
    let mut pc = start;
    loop {
        let word = mem.read_u32(pc)?;
        ops.push(predecode(word, pc));
        pc += INSN_SIZE;
        if classify(word) == A64Class::BranchSystem
            || ops.len() == MAX_BLOCK_OPS
            || pc & (PAGE_SIZE - 1) == 0
            || hooked(pc)
        {
            break;
        }
    }
    Ok(Block {
        start,
        ops: ops.into_boxed_slice(),
        links: [(u64::MAX, usize::MAX); LINKS],
        next_link: 0,
    })
}
