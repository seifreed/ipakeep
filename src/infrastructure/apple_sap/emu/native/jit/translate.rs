//! Translation of a decoded guest block into one Cranelift function.
//!
//! Generated signature: `extern "C" fn(ctx: *mut JitCtx) -> u32`. The function
//! keeps guest registers in Cranelift variables (loaded from the context in a
//! prologue, stored back at every exit), evaluates NZCV lazily (a flag-setting
//! instruction only records its operands; conditions compile to one `icmp`
//! where possible, and packed NZCV is materialised only at exits and loop
//! back-edges) and reaches guest memory through the context's direct-mapped
//! TLB. A TLB miss, a page-crossing access or a store to a page holding
//! compiled code leaves the block *before* the instruction with an
//! [`EXIT_READ_MISS`]/[`EXIT_WRITE_MISS`] status, so the interpreter re-runs it
//! exactly (including any fault).

use std::mem::offset_of;

use cranelift_codegen::Context;
use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{
    AbiParam, Block, Endianness, InstBuilder, MemFlagsData, Type, UserFuncName, Value, types,
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::JITModule;
use cranelift_module::{FuncId, Linkage, Module};

use super::super::{INSN_SIZE, Memory, PAGE_SIZE};
use super::decode::{Address, Csel, Logic, Mul, OneSrc, Op, Shift, Transfer, decode};
use super::{EXIT_OK, EXIT_READ_MISS, EXIT_WRITE_MISS, JitCtx, TLB_ENTRIES, TlbEntry};

/// Longest block (in guest instructions) compiled as one function.
pub(super) const MAX_BLOCK_INSNS: usize = 96;

/// Variable slots: X0..X30, then these.
const SP: usize = 31;
const NZCV: usize = 32;
const ITER: usize = 33;
const BUDGET: usize = 34;
const VARS: usize = 35;

/// The decoded instructions of one block, ready to compile.
pub(super) struct Decoded {
    pub(super) start: u64,
    pub(super) ops: Vec<Op>,
    pub(super) words: Vec<u32>,
}

impl Decoded {
    /// One past the last guest address covered.
    pub(super) fn end(&self) -> u64 {
        self.start + self.ops.len() as u64 * INSN_SIZE
    }

    /// Whether the block's final branch can jump back to its own start (it is
    /// then compiled as a loop).
    fn self_loop(&self) -> bool {
        match self.ops.last() {
            Some(
                Op::Branch {
                    target,
                    link: false,
                }
                | Op::BranchCond { target, .. }
                | Op::CompareBranch { target, .. }
                | Op::TestBranch { target, .. },
            ) => *target == self.start,
            _ => false,
        }
    }
}

/// Decodes the block starting at `start`: translatable instructions up to and
/// including the first branch, stopping before an untranslatable word, an
/// unmapped fetch or a hooked address. `None` when the first instruction is
/// not translatable.
pub(super) fn decode_block(
    mem: &Memory,
    start: u64,
    hooked: &dyn Fn(u64) -> bool,
) -> Option<Decoded> {
    let mut ops = Vec::new();
    let mut words = Vec::new();
    let mut pc = start;
    while ops.len() < MAX_BLOCK_INSNS {
        if pc != start && hooked(pc) {
            break;
        }
        let Ok(word) = mem.read_u32(pc) else { break };
        let Some(op) = decode(word, pc) else { break };
        ops.push(op);
        words.push(word);
        if op.is_terminator() {
            break;
        }
        pc = pc.wrapping_add(INSN_SIZE);
    }
    (!ops.is_empty()).then_some(Decoded { start, ops, words })
}

/// Lazily evaluated NZCV.
#[derive(Clone, Copy)]
enum Flags {
    /// Packed `[31:28]` in the `NZCV` variable.
    Packed,
    /// `SUBS a, b` (`res = a - b`).
    Sub { a: Value, b: Value, res: Value },
    /// `ADDS a, b`, or `ADCS` with carry-in `cin` (type of `a`, 0/1).
    Add {
        a: Value,
        b: Value,
        cin: Option<Value>,
        res: Value,
    },
    /// Logical result: N/Z from `res`, C = V = 0.
    Logic { res: Value },
}

/// Next guest PC of an exit.
#[derive(Clone, Copy)]
enum Pc {
    Const(u64),
    Val(Value),
}

/// An exit recorded during translation and emitted once all variable
/// definitions are known.
struct Exit {
    block: Block,
    pc: Pc,
    /// Instructions completed (on top of finished loop iterations).
    done: u32,
    flags: Flags,
    status: u32,
    miss: Option<Value>,
}

/// Field offsets inside [`JitCtx`].
fn x_offset(n: usize) -> i32 {
    (offset_of!(JitCtx, x) + 8 * n) as i32
}

fn var_offset(var: usize) -> i32 {
    match var {
        SP => offset_of!(JitCtx, sp) as i32,
        NZCV => offset_of!(JitCtx, nzcv) as i32,
        BUDGET => offset_of!(JitCtx, budget) as i32,
        n => x_offset(n),
    }
}

fn ctx_flags() -> MemFlagsData {
    MemFlagsData::trusted()
}

fn guest_flags() -> MemFlagsData {
    MemFlagsData::new()
        .with_notrap()
        .with_endianness(Endianness::Little)
}

struct Emitter<'a, 'b> {
    b: &'a mut FunctionBuilder<'b>,
    ctx: Value,
    vars: Vec<Variable>,
    touched: [bool; VARS],
    written: [bool; VARS],
    flags: Flags,
    flags_written: bool,
    exits: Vec<Exit>,
    looping: bool,
    /// Guest address and IR block of the loop header (block start).
    start: u64,
    header: Block,
}

fn ty_of(sf: bool) -> Type {
    if sf { types::I64 } else { types::I32 }
}

fn bits_of(ty: Type) -> i64 {
    i64::from(ty.bits())
}

impl Emitter<'_, '_> {
    // --- variables ---

    fn get(&mut self, var: usize) -> Value {
        self.touched[var] = true;
        self.b.use_var(self.vars[var])
    }

    fn put(&mut self, var: usize, value: Value) {
        self.touched[var] = true;
        self.written[var] = true;
        self.b.def_var(self.vars[var], value);
    }

    fn iconst(&mut self, ty: Type, value: u64) -> Value {
        let value = if ty == types::I32 {
            value & 0xffff_ffff
        } else {
            value
        };
        self.b.ins().iconst(ty, value as i64)
    }

    /// `X[n]` with register 31 reading as zero.
    fn x(&mut self, n: u32) -> Value {
        if n == 31 {
            self.iconst(types::I64, 0)
        } else {
            self.get(n as usize)
        }
    }

    /// `X[n]` with register 31 as the stack pointer.
    fn x_sp(&mut self, n: u32) -> Value {
        self.get(n as usize)
    }

    /// Narrows a 64-bit value to the operation width.
    fn narrow(&mut self, value: Value, sf: bool) -> Value {
        if sf {
            value
        } else {
            self.b.ins().ireduce(types::I32, value)
        }
    }

    /// Widens an operation-width value to 64 bits (zero-extending W results).
    fn widen(&mut self, value: Value) -> Value {
        if self.b.func.dfg.value_type(value) == types::I64 {
            value
        } else {
            self.b.ins().uextend(types::I64, value)
        }
    }

    fn xw(&mut self, n: u32, sf: bool) -> Value {
        let v = self.x(n);
        self.narrow(v, sf)
    }

    fn xw_sp(&mut self, n: u32, sf: bool) -> Value {
        let v = self.x_sp(n);
        self.narrow(v, sf)
    }

    /// Writes a ZR-form result (register 31 discards).
    fn set_x(&mut self, n: u32, value: Value) {
        if n != 31 {
            let v = self.widen(value);
            self.put(n as usize, v);
        }
    }

    /// Writes an SP-form result.
    fn set_x_sp(&mut self, n: u32, value: Value) {
        let v = self.widen(value);
        self.put(n as usize, v);
    }

    fn set_flags(&mut self, flags: Flags) {
        self.touched[NZCV] = true;
        self.flags_written = true;
        self.flags = flags;
    }

    // --- flags ---

    fn bool_to_i32(&mut self, cond: Value, bit: i64) -> Value {
        let v = self.b.ins().uextend(types::I32, cond);
        self.b.ins().ishl_imm_u(v, bit)
    }

    fn sign_bit(&mut self, value: Value) -> Value {
        self.b.ins().icmp_imm_u(IntCC::SignedLessThan, value, 0)
    }

    /// Carry flag as an `i8` boolean.
    fn carry_of(&mut self, flags: Flags) -> Value {
        match flags {
            Flags::Sub { a, b, .. } => self.b.ins().icmp(IntCC::UnsignedGreaterThanOrEqual, a, b),
            Flags::Add {
                a, cin: None, res, ..
            } => self.b.ins().icmp(IntCC::UnsignedLessThan, res, a),
            Flags::Add {
                a,
                cin: Some(cin),
                res,
                ..
            } => {
                let le = self.b.ins().icmp(IntCC::UnsignedLessThanOrEqual, res, a);
                let lt = self.b.ins().icmp(IntCC::UnsignedLessThan, res, a);
                self.b.ins().select(cin, le, lt)
            }
            Flags::Logic { .. } => self.b.ins().iconst(types::I8, 0),
            Flags::Packed => {
                let p = self.get(NZCV);
                let c = self.b.ins().band_imm_u(p, 1 << 29);
                self.b.ins().icmp_imm_u(IntCC::NotEqual, c, 0)
            }
        }
    }

    /// Packs `flags` into an `i32` NZCV word.
    fn materialize(&mut self, flags: Flags) -> Value {
        let (res, carry, overflow) = match flags {
            Flags::Packed => return self.get(NZCV),
            Flags::Logic { res } => (res, None, None),
            Flags::Sub { a, b, res } => {
                let x = self.b.ins().bxor(a, b);
                let y = self.b.ins().bxor(a, res);
                let v = self.b.ins().band(x, y);
                (res, Some(self.carry_of(flags)), Some(self.sign_bit(v)))
            }
            Flags::Add { a, b, res, .. } => {
                let x = self.b.ins().bxor(a, res);
                let y = self.b.ins().bxor(b, res);
                let v = self.b.ins().band(x, y);
                (res, Some(self.carry_of(flags)), Some(self.sign_bit(v)))
            }
        };
        let n = self.sign_bit(res);
        let z = self.b.ins().icmp_imm_u(IntCC::Equal, res, 0);
        let n = self.bool_to_i32(n, 31);
        let z = self.bool_to_i32(z, 30);
        let mut packed = self.b.ins().bor(n, z);
        if let (Some(c), Some(v)) = (carry, overflow) {
            let c = self.bool_to_i32(c, 29);
            let v = self.bool_to_i32(v, 28);
            let cv = self.b.ins().bor(c, v);
            packed = self.b.ins().bor(packed, cv);
        }
        packed
    }

    /// `ConditionHolds(cond)` as an `i8` boolean (mirrors `cond_holds`).
    fn cond(&mut self, cond: u8) -> Value {
        if cond >> 1 == 0b111 {
            return self.b.ins().iconst(types::I8, 1);
        }
        let base = match self.flags {
            Flags::Sub { a, b, res } => {
                let cc = match cond >> 1 {
                    0b000 => IntCC::Equal,
                    0b001 => IntCC::UnsignedGreaterThanOrEqual,
                    0b100 => IntCC::UnsignedGreaterThan,
                    0b101 => IntCC::SignedGreaterThanOrEqual,
                    0b110 => IntCC::SignedGreaterThan,
                    0b010 => {
                        let n = self.sign_bit(res);
                        return self.invert(cond, n);
                    }
                    _ => {
                        let flags = self.flags;
                        return self.packed_cond(flags, cond);
                    }
                };
                self.b.ins().icmp(cc, a, b)
            }
            Flags::Logic { res } => match cond >> 1 {
                0b000 => self.b.ins().icmp_imm_u(IntCC::Equal, res, 0),
                0b010 => self.sign_bit(res),
                0b101 => self
                    .b
                    .ins()
                    .icmp_imm_u(IntCC::SignedGreaterThanOrEqual, res, 0),
                0b110 => self.b.ins().icmp_imm_u(IntCC::SignedGreaterThan, res, 0),
                // C (CS/CC), V (VS/VC) and C && !Z (HI/LS) are all false.
                _ => self.b.ins().iconst(types::I8, 0),
            },
            flags => return self.packed_cond(flags, cond),
        };
        self.invert(cond, base)
    }

    fn invert(&mut self, cond: u8, base: Value) -> Value {
        if cond & 1 == 1 {
            self.b.ins().icmp_imm_u(IntCC::Equal, base, 0)
        } else {
            base
        }
    }

    /// Generic condition from packed NZCV.
    fn packed_cond(&mut self, flags: Flags, cond: u8) -> Value {
        let p = self.materialize(flags);
        let n = self.b.ins().ushr_imm_u(p, 31);
        let z = self.b.ins().ushr_imm_u(p, 30);
        let z = self.b.ins().band_imm_u(z, 1);
        let c = self.b.ins().ushr_imm_u(p, 29);
        let c = self.b.ins().band_imm_u(c, 1);
        let v = self.b.ins().ushr_imm_u(p, 28);
        let v = self.b.ins().band_imm_u(v, 1);
        let base = match cond >> 1 {
            0b000 => self.b.ins().icmp_imm_u(IntCC::NotEqual, z, 0),
            0b001 => self.b.ins().icmp_imm_u(IntCC::NotEqual, c, 0),
            0b010 => self.b.ins().icmp_imm_u(IntCC::NotEqual, n, 0),
            0b011 => self.b.ins().icmp_imm_u(IntCC::NotEqual, v, 0),
            0b100 => {
                // C && !Z  <=>  c > z
                self.b.ins().icmp(IntCC::UnsignedGreaterThan, c, z)
            }
            0b101 => self.b.ins().icmp(IntCC::Equal, n, v),
            _ => {
                let nv = self.b.ins().bxor(n, v);
                let any = self.b.ins().bor(nv, z);
                self.b.ins().icmp_imm_u(IntCC::Equal, any, 0)
            }
        };
        self.invert(cond, base)
    }

    // --- exits ---

    fn exit_here(&mut self, pc: Pc, done: u32, status: u32, miss: Option<Value>) -> Block {
        let block = self.b.create_block();
        self.exits.push(Exit {
            block,
            pc,
            done,
            flags: self.flags,
            status,
            miss,
        });
        block
    }

    /// Host address of a guest access of `bytes` at `addr`, branching to a
    /// miss exit (before instruction `index` at `pc`) when the TLB does not
    /// cover it.
    fn host(&mut self, addr: Value, bytes: u32, write: bool, pc: u64, index: u32) -> Value {
        let page = self.b.ins().band_imm_u(addr, !(PAGE_SIZE as i64 - 1));
        let slot = self.b.ins().ushr_imm_u(addr, 12);
        let slot = self.b.ins().band_imm_u(slot, TLB_ENTRIES as i64 - 1);
        let slot = self.b.ins().imul_imm_u(slot, size_of::<TlbEntry>() as i64);
        let entry = self.b.ins().iadd(self.ctx, slot);
        let tlb = offset_of!(JitCtx, tlb) as i32;
        let tag_offset = if write {
            offset_of!(TlbEntry, write_tag)
        } else {
            offset_of!(TlbEntry, read_tag)
        } as i32;
        let tag = self
            .b
            .ins()
            .load(types::I64, ctx_flags(), entry, tlb + tag_offset);
        let offset = self.b.ins().band_imm_u(addr, PAGE_SIZE as i64 - 1);
        let hit = self.b.ins().icmp(IntCC::Equal, tag, page);
        let fits = self.b.ins().icmp_imm_u(
            IntCC::UnsignedLessThanOrEqual,
            offset,
            (PAGE_SIZE - u64::from(bytes)) as i64,
        );
        let ok = self.b.ins().band(hit, fits);
        let status = if write {
            EXIT_WRITE_MISS
        } else {
            EXIT_READ_MISS
        };
        let miss = self.exit_here(Pc::Const(pc), index, status, Some(addr));
        let cont = self.b.create_block();
        self.b.ins().brif(ok, cont, &[], miss, &[]);
        self.b.seal_block(miss);
        self.b.seal_block(cont);
        self.b.switch_to_block(cont);
        let host = self.b.ins().load(
            types::I64,
            ctx_flags(),
            entry,
            tlb + offset_of!(TlbEntry, host) as i32,
        );
        self.b.ins().iadd(host, offset)
    }

    fn load(&mut self, host: Value, bytes: u32, signed: bool) -> Value {
        let f = guest_flags();
        let ins = self.b.ins();
        match (bytes, signed) {
            (1, false) => ins.uload8(types::I64, f, host, 0),
            (2, false) => ins.uload16(types::I64, f, host, 0),
            (4, false) => ins.uload32(f, host, 0),
            (1, true) => ins.sload8(types::I64, f, host, 0),
            (2, true) => ins.sload16(types::I64, f, host, 0),
            (4, true) => ins.sload32(f, host, 0),
            _ => ins.load(types::I64, f, host, 0),
        }
    }

    fn store(&mut self, host: Value, bytes: u32, value: Value) {
        let f = guest_flags();
        let ins = self.b.ins();
        match bytes {
            1 => ins.istore8(f, value, host, 0),
            2 => ins.istore16(f, value, host, 0),
            4 => ins.istore32(f, value, host, 0),
            _ => ins.store(f, value, host, 0),
        };
    }

    // --- operand helpers ---

    fn shifted(&mut self, n: u32, sf: bool, shift: Shift, amount: u32) -> Value {
        let v = self.xw(n, sf);
        if amount == 0 {
            return v;
        }
        let amount = i64::from(amount);
        let ins = self.b.ins();
        match shift {
            Shift::Lsl => ins.ishl_imm_u(v, amount),
            Shift::Lsr => ins.ushr_imm_u(v, amount),
            Shift::Asr => ins.sshr_imm_u(v, amount),
            Shift::Ror => ins.rotr_imm_u(v, amount),
        }
    }

    /// `dpreg::extend_reg` on `X[m]`.
    fn extended(&mut self, m: u32, option: u32, shift: u32, sf: bool) -> Value {
        let datasize = if sf { 64 } else { 32 };
        let (base_len, unsigned) = match option & 0b111 {
            0b000 => (8, true),
            0b001 => (16, true),
            0b010 => (32, true),
            0b011 => (64, true),
            0b100 => (8, false),
            0b101 => (16, false),
            0b110 => (32, false),
            _ => (64, false),
        };
        let len: u32 = base_len.min(datasize - shift);
        let mut v = self.x(m);
        if len < 64 {
            v = self.b.ins().band_imm_u(v, ((1u64 << len) - 1) as i64);
        }
        if shift > 0 {
            v = self.b.ins().ishl_imm_u(v, i64::from(shift));
        }
        let total = len + shift;
        if !unsigned && total < 64 {
            let s = i64::from(64 - total);
            v = self.b.ins().ishl_imm_u(v, s);
            v = self.b.ins().sshr_imm_u(v, s);
        }
        self.narrow(v, sf)
    }

    /// `ldst::extend_reg` for register-offset addressing.
    fn index_reg(&mut self, m: u32, option: u32, shift: u32) -> Value {
        let v = self.x(m);
        let v = if option & 1 == 0 {
            let w = self.b.ins().ireduce(types::I32, v);
            if option & 0b100 != 0 {
                self.b.ins().sextend(types::I64, w)
            } else {
                self.b.ins().uextend(types::I64, w)
            }
        } else {
            v
        };
        if shift == 0 {
            v
        } else {
            self.b.ins().ishl_imm_u(v, i64::from(shift))
        }
    }

    fn add_sub(&mut self, a: Value, b: Value, sub: bool) -> (Value, Flags) {
        if sub {
            let res = self.b.ins().isub(a, b);
            (res, Flags::Sub { a, b, res })
        } else {
            let res = self.b.ins().iadd(a, b);
            (
                res,
                Flags::Add {
                    a,
                    b,
                    cin: None,
                    res,
                },
            )
        }
    }

    fn logic(&mut self, op: Logic, a: Value, b: Value) -> Value {
        match op {
            Logic::And | Logic::Ands => self.b.ins().band(a, b),
            Logic::Orr => self.b.ins().bor(a, b),
            Logic::Eor => self.b.ins().bxor(a, b),
        }
    }

    /// Base address and written-back base of a load/store address.
    fn address(&mut self, addr: Address) -> (Value, Option<(u32, Value)>) {
        match addr {
            Address::Offset { rn, offset } => {
                let base = self.x_sp(rn);
                (self.b.ins().iadd_imm_u(base, offset as i64), None)
            }
            Address::Pre { rn, offset } => {
                let base = self.x_sp(rn);
                let a = self.b.ins().iadd_imm_u(base, offset as i64);
                (a, Some((rn, a)))
            }
            Address::Post { rn, offset } => {
                let base = self.x_sp(rn);
                let next = self.b.ins().iadd_imm_u(base, offset as i64);
                (base, Some((rn, next)))
            }
            Address::Reg {
                rn,
                rm,
                option,
                shift,
            } => {
                let base = self.x_sp(rn);
                let index = self.index_reg(rm, option, shift);
                (self.b.ins().iadd(base, index), None)
            }
        }
    }

    // --- instructions ---

    /// Emits instruction `op` (number `index` of the block, at `pc`).
    #[allow(clippy::too_many_lines)]
    fn op(&mut self, op: Op, pc: u64, index: u32) {
        match op {
            Op::Nop => {}
            Op::MovConst { rd, value } => {
                let v = self.iconst(types::I64, value);
                self.set_x(rd, v);
            }
            Op::AddSubImm {
                sf,
                sub,
                s,
                rd,
                rn,
                imm,
            } => {
                let a = self.xw_sp(rn, sf);
                let b = self.iconst(ty_of(sf), imm);
                let (res, flags) = self.add_sub(a, b, sub);
                if s {
                    self.set_flags(flags);
                    self.set_x(rd, res);
                } else {
                    self.set_x_sp(rd, res);
                }
            }
            Op::LogicImm {
                sf,
                op,
                rd,
                rn,
                imm,
            } => {
                let a = self.xw(rn, sf);
                let b = self.iconst(ty_of(sf), imm);
                let res = self.logic(op, a, b);
                if op == Logic::Ands {
                    self.set_flags(Flags::Logic { res });
                    self.set_x(rd, res);
                } else {
                    self.set_x_sp(rd, res);
                }
            }
            Op::Movk {
                sf,
                rd,
                imm16,
                shift,
            } => {
                let old = self.x(rd);
                let keep = self.b.ins().band_imm_u(old, !(0xffffi64 << shift));
                let res = self.b.ins().bor_imm_u(keep, (imm16 << shift) as i64);
                let res = self.narrow(res, sf);
                self.set_x(rd, res);
            }
            Op::Bitfield {
                sf,
                opc,
                rd,
                rn,
                immr,
                imms,
                wmask,
                tmask,
            } => {
                let ty = ty_of(sf);
                let bits = bits_of(ty);
                let src = self.xw(rn, sf);
                let rotated = self.b.ins().rotr_imm_u(src, i64::from(immr) % bits);
                let low = self.b.ins().band_imm_u(rotated, wmask as i64);
                let bot = if opc == 1 {
                    let dst = self.xw(rd, sf);
                    let kept = self.b.ins().band_imm_u(dst, !wmask as i64);
                    self.b.ins().bor(kept, low)
                } else {
                    low
                };
                let bot = self.b.ins().band_imm_u(bot, tmask as i64);
                let res = match opc {
                    0 => {
                        let up = self.b.ins().ishl_imm_u(src, bits - 1 - i64::from(imms));
                        let top = self.b.ins().sshr_imm_u(up, bits - 1);
                        let top = self.b.ins().band_imm_u(top, !tmask as i64);
                        self.b.ins().bor(top, bot)
                    }
                    1 => {
                        let dst = self.xw(rd, sf);
                        let top = self.b.ins().band_imm_u(dst, !tmask as i64);
                        self.b.ins().bor(top, bot)
                    }
                    _ => bot,
                };
                self.set_x(rd, res);
            }
            Op::Extr {
                sf,
                rd,
                rn,
                rm,
                lsb,
            } => {
                let lo = self.xw(rm, sf);
                let res = if lsb == 0 {
                    lo
                } else {
                    let hi = self.xw(rn, sf);
                    let bits = bits_of(ty_of(sf));
                    let l = self.b.ins().ushr_imm_u(lo, i64::from(lsb));
                    let h = self.b.ins().ishl_imm_u(hi, bits - i64::from(lsb));
                    self.b.ins().bor(l, h)
                };
                self.set_x(rd, res);
            }
            Op::LogicReg {
                sf,
                op,
                invert,
                shift,
                amount,
                rd,
                rn,
                rm,
            } => {
                let mut b = self.shifted(rm, sf, shift, amount);
                if invert {
                    b = self.b.ins().bnot(b);
                }
                let a = self.xw(rn, sf);
                let res = self.logic(op, a, b);
                if op == Logic::Ands {
                    self.set_flags(Flags::Logic { res });
                }
                self.set_x(rd, res);
            }
            Op::AddSubReg {
                sf,
                sub,
                s,
                shift,
                amount,
                rd,
                rn,
                rm,
            } => {
                let b = self.shifted(rm, sf, shift, amount);
                let a = self.xw(rn, sf);
                let (res, flags) = self.add_sub(a, b, sub);
                if s {
                    self.set_flags(flags);
                }
                self.set_x(rd, res);
            }
            Op::AddSubExt {
                sf,
                sub,
                s,
                option,
                shift,
                rd,
                rn,
                rm,
            } => {
                let b = self.extended(rm, option, shift, sf);
                let a = self.xw_sp(rn, sf);
                let (res, flags) = self.add_sub(a, b, sub);
                if s {
                    self.set_flags(flags);
                    self.set_x(rd, res);
                } else {
                    self.set_x_sp(rd, res);
                }
            }
            Op::AdcSbc {
                sf,
                sub,
                s,
                rd,
                rn,
                rm,
            } => {
                let flags = self.flags;
                let carry = self.carry_of(flags);
                let cin = self.b.ins().uextend(ty_of(sf), carry);
                let a = self.xw(rn, sf);
                let mut b = self.xw(rm, sf);
                if sub {
                    b = self.b.ins().bnot(b);
                }
                let sum = self.b.ins().iadd(a, b);
                let res = self.b.ins().iadd(sum, cin);
                if s {
                    self.set_flags(Flags::Add {
                        a,
                        b,
                        cin: Some(carry),
                        res,
                    });
                }
                self.set_x(rd, res);
            }
            Op::CondCmp {
                sf,
                sub,
                imm,
                rm,
                cond,
                rn,
                nzcv,
            } => {
                let holds = self.cond(cond);
                let b = match imm {
                    Some(imm) => self.iconst(ty_of(sf), imm),
                    None => self.xw(rm, sf),
                };
                let a = self.xw(rn, sf);
                let (_, flags) = self.add_sub(a, b, sub);
                let taken = self.materialize(flags);
                let other = self.iconst(types::I32, u64::from(nzcv << 28));
                let packed = self.b.ins().select(holds, taken, other);
                self.put(NZCV, packed);
                self.set_flags(Flags::Packed);
            }
            Op::CondSel {
                sf,
                op,
                cond,
                rd,
                rn,
                rm,
            } => {
                let holds = self.cond(cond);
                let n = self.xw(rn, sf);
                let m = self.xw(rm, sf);
                let other = match op {
                    Csel::Csel => m,
                    Csel::Csinc => self.b.ins().iadd_imm_u(m, 1),
                    Csel::Csinv => self.b.ins().bnot(m),
                    Csel::Csneg => self.b.ins().ineg(m),
                };
                let res = self.b.ins().select(holds, n, other);
                self.set_x(rd, res);
            }
            Op::Div {
                sf,
                signed,
                rd,
                rn,
                rm,
            } => {
                let ty = ty_of(sf);
                let n = self.xw(rn, sf);
                let m = self.xw(rm, sf);
                let zero = self.b.ins().icmp_imm_u(IntCC::Equal, m, 0);
                let one = self.iconst(ty, 1);
                let res = if signed {
                    // Guard the two trapping cases: m == 0 (result 0) and
                    // MIN / -1 (wraps to MIN, which MIN / 1 also yields).
                    let min = if sf { i64::MIN } else { i64::from(i32::MIN) };
                    let is_min = self.b.ins().icmp_imm_u(IntCC::Equal, n, min);
                    let is_neg1 = self.b.ins().icmp_imm_u(IntCC::Equal, m, -1);
                    let ovf = self.b.ins().band(is_min, is_neg1);
                    let unsafe_div = self.b.ins().bor(zero, ovf);
                    let d = self.b.ins().select(unsafe_div, one, m);
                    self.b.ins().sdiv(n, d)
                } else {
                    let d = self.b.ins().select(zero, one, m);
                    self.b.ins().udiv(n, d)
                };
                let z = self.iconst(ty, 0);
                let res = self.b.ins().select(zero, z, res);
                self.set_x(rd, res);
            }
            Op::ShiftV {
                sf,
                shift,
                rd,
                rn,
                rm,
            } => {
                let n = self.xw(rn, sf);
                let m = self.xw(rm, sf);
                let ins = self.b.ins();
                let res = match shift {
                    Shift::Lsl => ins.ishl(n, m),
                    Shift::Lsr => ins.ushr(n, m),
                    Shift::Asr => ins.sshr(n, m),
                    Shift::Ror => ins.rotr(n, m),
                };
                self.set_x(rd, res);
            }
            Op::MulAdd {
                sf,
                op,
                rd,
                rn,
                rm,
                ra,
            } => {
                let res = self.mul_add(sf, op, rn, rm, ra);
                self.set_x(rd, res);
            }
            Op::OneSrc { sf, op, rd, rn } => {
                let res = self.one_src(sf, op, rn);
                self.set_x(rd, res);
            }
            Op::LdSt {
                bytes,
                kind,
                rt,
                addr,
            } => {
                let (address, writeback) = self.address(addr);
                match kind {
                    Transfer::Prefetch => {}
                    Transfer::Store => {
                        let value = self.x(rt);
                        let host = self.host(address, bytes, true, pc, index);
                        self.store(host, bytes, value);
                    }
                    Transfer::Load | Transfer::LoadSx | Transfer::LoadSw => {
                        let host = self.host(address, bytes, false, pc, index);
                        let mut v = self.load(host, bytes, kind != Transfer::Load);
                        if kind == Transfer::LoadSw {
                            v = self.b.ins().band_imm_u(v, 0xffff_ffff);
                        }
                        self.set_x(rt, v);
                    }
                }
                if let Some((rn, value)) = writeback {
                    self.set_x_sp(rn, value);
                }
            }
            Op::Pair {
                bytes,
                load,
                signed,
                rt,
                rt2,
                addr,
            } => {
                let (address, writeback) = self.address(addr);
                let second = self.b.ins().iadd_imm_u(address, i64::from(bytes));
                // Both accesses are checked before either takes effect.
                let h1 = self.host(address, bytes, !load, pc, index);
                let h2 = self.host(second, bytes, !load, pc, index);
                if load {
                    let v1 = self.load(h1, bytes, signed);
                    let v2 = self.load(h2, bytes, signed);
                    self.set_x(rt, v1);
                    self.set_x(rt2, v2);
                } else {
                    let v1 = self.x(rt);
                    let v2 = self.x(rt2);
                    self.store(h1, bytes, v1);
                    self.store(h2, bytes, v2);
                }
                if let Some((rn, value)) = writeback {
                    self.set_x_sp(rn, value);
                }
            }
            Op::Literal {
                bytes,
                signed,
                rt,
                addr,
            } => {
                let address = self.iconst(types::I64, addr);
                let host = self.host(address, bytes, false, pc, index);
                let v = self.load(host, bytes, signed);
                self.set_x(rt, v);
            }
            Op::Branch { target, link } => self.branch(target, link, pc, index),
            Op::BranchReg { rn, link } => self.branch_reg(rn, link, pc, index),
            Op::BranchCond { cond, target } => {
                let holds = self.cond(cond);
                self.cond_branch(holds, target, pc, index);
            }
            Op::CompareBranch {
                sf,
                nonzero,
                rt,
                target,
            } => {
                let v = self.xw(rt, sf);
                let holds = self.zero_test(v, nonzero);
                self.cond_branch(holds, target, pc, index);
            }
            Op::TestBranch {
                nonzero,
                bit,
                rt,
                target,
            } => {
                let v = self.x(rt);
                let masked = self.b.ins().band_imm_u(v, (1u64 << bit) as i64);
                let holds = self.zero_test(masked, nonzero);
                self.cond_branch(holds, target, pc, index);
            }
        }
    }

    fn mul_add(&mut self, sf: bool, op: Mul, rn: u32, rm: u32, ra: u32) -> Value {
        match op {
            Mul::Madd | Mul::Msub => {
                let n = self.xw(rn, sf);
                let m = self.xw(rm, sf);
                let a = self.xw(ra, sf);
                let p = self.b.ins().imul(n, m);
                if op == Mul::Madd {
                    self.b.ins().iadd(a, p)
                } else {
                    self.b.ins().isub(a, p)
                }
            }
            Mul::Smulh | Mul::Umulh => {
                let n = self.x(rn);
                let m = self.x(rm);
                if op == Mul::Smulh {
                    self.b.ins().smulhi(n, m)
                } else {
                    self.b.ins().umulhi(n, m)
                }
            }
            _ => {
                let signed = matches!(op, Mul::Smaddl | Mul::Smsubl);
                let n = self.xw(rn, false);
                let m = self.xw(rm, false);
                let (n, m) = if signed {
                    (
                        self.b.ins().sextend(types::I64, n),
                        self.b.ins().sextend(types::I64, m),
                    )
                } else {
                    (
                        self.b.ins().uextend(types::I64, n),
                        self.b.ins().uextend(types::I64, m),
                    )
                };
                let p = self.b.ins().imul(n, m);
                let a = self.x(ra);
                if matches!(op, Mul::Smaddl | Mul::Umaddl) {
                    self.b.ins().iadd(a, p)
                } else {
                    self.b.ins().isub(a, p)
                }
            }
        }
    }

    fn one_src(&mut self, sf: bool, op: OneSrc, rn: u32) -> Value {
        let v = self.xw(rn, sf);
        let ins = self.b.ins();
        match op {
            OneSrc::Rbit => ins.bitrev(v),
            OneSrc::Rev16 => {
                let mask = if sf {
                    0x00ff_00ff_00ff_00ffu64 as i64
                } else {
                    0x00ff_00ff
                };
                let lo = self.b.ins().band_imm_u(v, mask);
                let lo = self.b.ins().ishl_imm_u(lo, 8);
                let hi = self.b.ins().ushr_imm_u(v, 8);
                let hi = self.b.ins().band_imm_u(hi, mask);
                self.b.ins().bor(lo, hi)
            }
            OneSrc::Rev32 => {
                let swapped = ins.bswap(v);
                if sf {
                    self.b.ins().rotr_imm_u(swapped, 32)
                } else {
                    swapped
                }
            }
            OneSrc::Rev64 => ins.bswap(v),
            OneSrc::Clz => ins.clz(v),
            OneSrc::Cls => ins.cls(v),
        }
    }

    /// `B` / `BL` (instruction `index` at `pc`).
    fn branch(&mut self, target: u64, link: bool, pc: u64, index: u32) {
        if link {
            let ret = self.iconst(types::I64, pc.wrapping_add(INSN_SIZE));
            self.set_x(30, ret);
        }
        if self.looping {
            self.back_edge(index + 1);
        } else {
            self.leave(Pc::Const(target), index + 1);
        }
    }

    /// `BR` / `BLR` / `RET`.
    fn branch_reg(&mut self, rn: u32, link: bool, pc: u64, index: u32) {
        let target = self.x(rn);
        if link {
            let ret = self.iconst(types::I64, pc.wrapping_add(INSN_SIZE));
            self.set_x(30, ret);
        }
        self.leave(Pc::Val(target), index + 1);
    }

    /// Jumps to a normal exit continuing at `pc` after `done` instructions.
    fn leave(&mut self, pc: Pc, done: u32) {
        let exit = self.exit_here(pc, done, EXIT_OK, None);
        self.b.ins().jump(exit, &[]);
        self.b.seal_block(exit);
    }

    /// A conditional branch to `target` taken when `cond` (an `i8`) holds.
    fn cond_branch(&mut self, cond: Value, target: u64, pc: u64, index: u32) {
        let done = index + 1;
        let fall = pc.wrapping_add(INSN_SIZE);
        if self.looping {
            let not_taken = self.exit_here(Pc::Const(fall), done, EXIT_OK, None);
            let again = self.b.create_block();
            self.b.ins().brif(cond, again, &[], not_taken, &[]);
            self.b.seal_block(again);
            self.b.seal_block(not_taken);
            self.b.switch_to_block(again);
            self.back_edge(done);
        } else {
            // Both outcomes leave the block: one exit with a selected PC.
            let t = self.iconst(types::I64, target);
            let f = self.iconst(types::I64, fall);
            let next = self.b.ins().select(cond, t, f);
            self.leave(Pc::Val(next), done);
        }
    }

    /// `CBZ`/`CBNZ` and `TBZ`/`TBNZ` condition: `value` (non)zero.
    fn zero_test(&mut self, value: Value, nonzero: bool) -> Value {
        let cc = if nonzero {
            IntCC::NotEqual
        } else {
            IntCC::Equal
        };
        self.b.ins().icmp_imm_u(cc, value, 0)
    }

    /// Loops back to `header` while the budget allows another full pass of
    /// `len` instructions; otherwise exits at `start`.
    fn back_edge(&mut self, len: u32) {
        let (start, header) = (self.start, self.header);
        let flags = self.flags;
        let packed = self.materialize(flags);
        if self.flags_written {
            self.put(NZCV, packed);
        }
        self.flags = Flags::Packed;
        let iter = self.get(ITER);
        let iter = self.b.ins().iadd_imm_u(iter, i64::from(len));
        self.put(ITER, iter);
        let needed = self.b.ins().iadd_imm_u(iter, i64::from(len));
        let budget = self.get(BUDGET);
        let fits = self
            .b
            .ins()
            .icmp(IntCC::UnsignedLessThanOrEqual, needed, budget);
        let exit = self.exit_here(Pc::Const(start), 0, EXIT_OK, None);
        self.b.ins().brif(fits, header, &[], exit, &[]);
        self.b.seal_block(exit);
    }

    /// Emits every recorded exit: stores the written registers and flags, the
    /// next PC, the instruction count and the miss address, then returns the
    /// status.
    fn emit_exits(&mut self) {
        let exits = std::mem::take(&mut self.exits);
        for exit in exits {
            self.b.switch_to_block(exit.block);
            for var in 0..=SP {
                if self.written[var] {
                    let v = self.b.use_var(self.vars[var]);
                    self.b
                        .ins()
                        .store(ctx_flags(), v, self.ctx, var_offset(var));
                }
            }
            if self.flags_written {
                let packed = self.materialize(exit.flags);
                self.b
                    .ins()
                    .store(ctx_flags(), packed, self.ctx, var_offset(NZCV));
            }
            let pc = match exit.pc {
                Pc::Const(pc) => self.iconst(types::I64, pc),
                Pc::Val(v) => v,
            };
            self.b
                .ins()
                .store(ctx_flags(), pc, self.ctx, offset_of!(JitCtx, pc) as i32);
            let count = if self.looping {
                let iter = self.b.use_var(self.vars[ITER]);
                self.b.ins().iadd_imm_u(iter, i64::from(exit.done))
            } else {
                self.iconst(types::I64, u64::from(exit.done))
            };
            self.b.ins().store(
                ctx_flags(),
                count,
                self.ctx,
                offset_of!(JitCtx, count) as i32,
            );
            if let Some(addr) = exit.miss {
                self.b.ins().store(
                    ctx_flags(),
                    addr,
                    self.ctx,
                    offset_of!(JitCtx, miss_addr) as i32,
                );
            }
            let status = self.b.ins().iconst(types::I32, i64::from(exit.status));
            self.b.ins().return_(&[status]);
        }
    }
}

/// Compiles `block` into `module`, returning the (not yet finalized) function.
pub(super) fn compile(
    module: &mut JITModule,
    context: &mut Context,
    builder_context: &mut FunctionBuilderContext,
    block: &Decoded,
    index: u32,
) -> Option<FuncId> {
    let mut sig = module.make_signature();
    sig.params.push(AbiParam::new(types::I64));
    sig.returns.push(AbiParam::new(types::I32));
    let func = module
        .declare_function(&format!("b{index}"), Linkage::Local, &sig)
        .ok()?;
    let target = module.target_config();
    context.func.signature = sig;
    context.func.name = UserFuncName::user(0, func.as_u32());
    {
        let mut b = FunctionBuilder::new(&mut context.func, builder_context);
        let vars = (0..VARS)
            .map(|var| b.declare_var(if var == NZCV { types::I32 } else { types::I64 }))
            .collect();
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        let prologue = b.create_block();
        let header = b.create_block();
        b.switch_to_block(entry);
        let ctx = b.block_params(entry)[0];
        b.ins().jump(prologue, &[]);
        b.seal_block(entry);
        b.seal_block(prologue);

        let mut e = Emitter {
            b: &mut b,
            ctx,
            vars,
            touched: [false; VARS],
            written: [false; VARS],
            flags: Flags::Packed,
            flags_written: false,
            exits: Vec::new(),
            looping: block.self_loop(),
            start: block.start,
            header,
        };
        e.b.switch_to_block(header);
        let last = block.ops.len() - 1;
        for (i, op) in block.ops.iter().enumerate() {
            let pc = block.start + i as u64 * INSN_SIZE;
            e.op(*op, pc, i as u32);
        }
        if !block.ops[last].is_terminator() {
            // The block stopped before an untranslated instruction.
            e.leave(Pc::Const(block.end()), last as u32 + 1);
        }
        e.emit_exits();

        // Prologue: load every variable the body touched.
        e.b.switch_to_block(prologue);
        for var in 0..=NZCV {
            if e.touched[var] {
                let ty = if var == NZCV { types::I32 } else { types::I64 };
                let v = e.b.ins().load(ty, ctx_flags(), ctx, var_offset(var));
                e.b.def_var(e.vars[var], v);
            }
        }
        if e.looping {
            let zero = e.b.ins().iconst(types::I64, 0);
            e.b.def_var(e.vars[ITER], zero);
            let budget =
                e.b.ins()
                    .load(types::I64, ctx_flags(), ctx, var_offset(BUDGET));
            e.b.def_var(e.vars[BUDGET], budget);
        }
        e.b.ins().jump(header, &[]);
        b.seal_all_blocks();
        b.finalize(target);
    }
    let result = module.define_function(func, context);
    module.clear_context(context);
    result.ok().map(|()| func)
}
