//! Decoding of the JIT-translatable A64 subset into [`Op`].
//!
//! Every function here mirrors the dispatch and field extraction of the
//! interpreter module named in its comment (`dpimm`, `dpreg`, `branch`,
//! `ldst`). Anything the JIT does not translate — or that the interpreter
//! treats specially (reserved encodings, SIMD, exclusives/atomics, system
//! registers, `brk`) — decodes to `None`, which ends the block so the
//! interpreter executes that instruction with its exact semantics.

use super::super::super::decode::{A64Class, classify};
use super::super::dpimm::decode_bit_masks;

/// A width flag: `true` for 64-bit (`sf == 1`) operations.
pub(super) type Sf = bool;

/// A shift applied to a register operand (`ShiftReg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

impl Shift {
    fn from_bits(bits: u32) -> Self {
        match bits & 3 {
            0 => Self::Lsl,
            1 => Self::Lsr,
            2 => Self::Asr,
            _ => Self::Ror,
        }
    }
}

/// Logical operation of the logical (immediate / shifted register) groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Logic {
    And,
    Orr,
    Eor,
    Ands,
}

impl Logic {
    fn from_opc(opc: u32) -> Self {
        match opc & 3 {
            0 => Self::And,
            1 => Self::Orr,
            2 => Self::Eor,
            _ => Self::Ands,
        }
    }
}

/// Multiply(-accumulate) flavours of data-processing (3 source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mul {
    Madd,
    Msub,
    Smaddl,
    Smsubl,
    Smulh,
    Umaddl,
    Umsubl,
    Umulh,
}

/// Data-processing (1 source) operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OneSrc {
    Rbit,
    Rev16,
    /// `REV` (32-bit) or `REV32` (64-bit): byte-swap each 32-bit word.
    Rev32,
    /// `REV` (64-bit).
    Rev64,
    Clz,
    Cls,
}

/// Conditional-select flavours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Csel {
    Csel,
    Csinc,
    Csinv,
    Csneg,
}

/// Register load/store transfer kind (`integer_transfer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transfer {
    Store,
    /// Zero-extending load into X.
    Load,
    /// Sign-extending load into X.
    LoadSx,
    /// Sign-extending load into W (zero-extended to X).
    LoadSw,
    /// `PRFM`: no memory access (writeback still applies, as in `ldst`).
    Prefetch,
}

/// Address of a register load/store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Address {
    /// `X[n|SP] + offset`, optionally written back (pre-index when
    /// `writeback`, the address itself is the written value).
    Offset { rn: u32, offset: u64 },
    /// Pre-indexed: address = base + offset, base := address.
    Pre { rn: u32, offset: u64 },
    /// Post-indexed: address = base, base := base + offset.
    Post { rn: u32, offset: u64 },
    /// Register offset: base + `ExtendRegister(X[m], option, shift)`.
    Reg {
        rn: u32,
        rm: u32,
        option: u32,
        shift: u32,
    },
}

/// One decoded, translatable instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    /// Hints and barriers.
    Nop,
    /// `ADR`/`ADRP`: writes a constant.
    MovConst {
        rd: u32,
        value: u64,
    },
    AddSubImm {
        sf: Sf,
        sub: bool,
        s: bool,
        rd: u32,
        rn: u32,
        imm: u64,
    },
    LogicImm {
        sf: Sf,
        op: Logic,
        rd: u32,
        rn: u32,
        imm: u64,
    },
    /// `MOVK`: inserts `imm16 << shift`.
    Movk {
        sf: Sf,
        rd: u32,
        imm16: u64,
        shift: u32,
    },
    Bitfield {
        sf: Sf,
        /// 0 = SBFM, 1 = BFM, 2 = UBFM.
        opc: u32,
        rd: u32,
        rn: u32,
        immr: u32,
        imms: u32,
        wmask: u64,
        tmask: u64,
    },
    Extr {
        sf: Sf,
        rd: u32,
        rn: u32,
        rm: u32,
        lsb: u32,
    },
    LogicReg {
        sf: Sf,
        op: Logic,
        invert: bool,
        shift: Shift,
        amount: u32,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    AddSubReg {
        sf: Sf,
        sub: bool,
        s: bool,
        shift: Shift,
        amount: u32,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    AddSubExt {
        sf: Sf,
        sub: bool,
        s: bool,
        option: u32,
        shift: u32,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    AdcSbc {
        sf: Sf,
        sub: bool,
        s: bool,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    CondCmp {
        sf: Sf,
        sub: bool,
        /// `Some(imm5)` for the immediate form, else `Rm` is in `rm`.
        imm: Option<u64>,
        rm: u32,
        cond: u8,
        rn: u32,
        nzcv: u32,
    },
    CondSel {
        sf: Sf,
        op: Csel,
        cond: u8,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    Div {
        sf: Sf,
        signed: bool,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    ShiftV {
        sf: Sf,
        shift: Shift,
        rd: u32,
        rn: u32,
        rm: u32,
    },
    MulAdd {
        sf: Sf,
        op: Mul,
        rd: u32,
        rn: u32,
        rm: u32,
        ra: u32,
    },
    OneSrc {
        sf: Sf,
        op: OneSrc,
        rd: u32,
        rn: u32,
    },
    LdSt {
        /// Access width in bytes (1/2/4/8).
        bytes: u32,
        kind: Transfer,
        rt: u32,
        addr: Address,
    },
    Pair {
        /// Element width in bytes (4/8).
        bytes: u32,
        load: bool,
        signed: bool,
        rt: u32,
        rt2: u32,
        addr: Address,
    },
    /// PC-relative load: `LDR Wt`/`LDR Xt`/`LDRSW` (`PRFM` decodes to `Nop`).
    Literal {
        bytes: u32,
        signed: bool,
        rt: u32,
        addr: u64,
    },
    // --- terminators ---
    /// `B` / `BL` (`link` writes `X30 = pc + 4`).
    Branch {
        target: u64,
        link: bool,
    },
    BranchCond {
        cond: u8,
        target: u64,
    },
    /// `CBZ` / `CBNZ`.
    CompareBranch {
        sf: Sf,
        nonzero: bool,
        rt: u32,
        target: u64,
    },
    /// `TBZ` / `TBNZ`.
    TestBranch {
        nonzero: bool,
        bit: u32,
        rt: u32,
        target: u64,
    },
    /// `BR` / `BLR` / `RET`.
    BranchReg {
        rn: u32,
        link: bool,
    },
}

impl Op {
    /// Whether the instruction ends a block (a branch of any kind).
    pub(super) fn is_terminator(&self) -> bool {
        matches!(
            self,
            Op::Branch { .. }
                | Op::BranchCond { .. }
                | Op::CompareBranch { .. }
                | Op::TestBranch { .. }
                | Op::BranchReg { .. }
        )
    }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

fn mask_width(value: u64, sf: Sf) -> u64 {
    if sf { value } else { value & 0xffff_ffff }
}

/// Decodes `word` at `pc`, or `None` when the JIT leaves it to the interpreter.
pub(super) fn decode(word: u32, pc: u64) -> Option<Op> {
    match classify(word) {
        A64Class::DataProcImm => dp_imm(word, pc),
        A64Class::DataProcReg => dp_reg(word),
        A64Class::BranchSystem => branch(word, pc),
        A64Class::LoadStore => load_store(word, pc),
        _ => None,
    }
}

// --- data processing (immediate): mirrors `dpimm::run` ---

fn dp_imm(word: u32, pc: u64) -> Option<Op> {
    let sf = (word >> 31) & 1 == 1;
    let rd = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    match (word >> 23) & 0b111 {
        0b000 | 0b001 => {
            let immlo = u64::from((word >> 29) & 0b11);
            let immhi = u64::from((word >> 5) & 0x7_ffff);
            let imm21 = (immhi << 2) | immlo;
            let value = if (word >> 31) & 1 == 0 {
                pc.wrapping_add(sign_extend(imm21, 21))
            } else {
                (pc & !0xfff).wrapping_add(sign_extend(imm21 << 12, 33))
            };
            Some(Op::MovConst { rd, value })
        }
        0b010 => {
            let imm12 = u64::from((word >> 10) & 0xfff);
            let imm = if (word >> 22) & 1 == 1 {
                imm12 << 12
            } else {
                imm12
            };
            Some(Op::AddSubImm {
                sf,
                sub: (word >> 30) & 1 == 1,
                s: (word >> 29) & 1 == 1,
                rd,
                rn,
                imm,
            })
        }
        0b100 => {
            let n = (word >> 22) & 1;
            let immr = (word >> 16) & 0x3f;
            let imms = (word >> 10) & 0x3f;
            if !sf && n == 1 {
                return None;
            }
            let (imm, _) = decode_bit_masks(n, imms, immr, true, if sf { 64 } else { 32 })?;
            Some(Op::LogicImm {
                sf,
                op: Logic::from_opc(word >> 29),
                rd,
                rn,
                imm: mask_width(imm, sf),
            })
        }
        0b101 => {
            let opc = (word >> 29) & 0b11;
            let hw = (word >> 21) & 0b11;
            let imm16 = u64::from((word >> 5) & 0xffff);
            if !sf && hw > 1 {
                return None;
            }
            let shift = hw * 16;
            match opc {
                0b10 => Some(Op::MovConst {
                    rd,
                    value: mask_width(imm16 << shift, sf),
                }),
                0b00 => Some(Op::MovConst {
                    rd,
                    value: mask_width(!(imm16 << shift), sf),
                }),
                0b11 => Some(Op::Movk {
                    sf,
                    rd,
                    imm16,
                    shift,
                }),
                _ => None,
            }
        }
        0b110 => {
            let opc = (word >> 29) & 0b11;
            let n = (word >> 22) & 1;
            let immr = (word >> 16) & 0x3f;
            let imms = (word >> 10) & 0x3f;
            // opc 0b11 is unallocated (the interpreter runs it as UBFM), and
            // 32-bit forms with immr/imms >= 32 are reserved.
            if n != u32::from(sf) || opc == 0b11 || (!sf && (immr >= 32 || imms >= 32)) {
                return None;
            }
            let (wmask, tmask) = decode_bit_masks(n, imms, immr, false, if sf { 64 } else { 32 })?;
            Some(Op::Bitfield {
                sf,
                opc,
                rd,
                rn,
                immr,
                imms,
                wmask,
                tmask,
            })
        }
        0b111 => {
            let lsb = (word >> 10) & 0x3f;
            if !sf && lsb >= 32 {
                return None;
            }
            Some(Op::Extr {
                sf,
                rd,
                rn,
                rm: (word >> 16) & 0x1f,
                lsb,
            })
        }
        _ => None,
    }
}

// --- data processing (register): mirrors `dpreg::run` ---

fn dp_reg(word: u32) -> Option<Op> {
    let sf = (word >> 31) & 1 == 1;
    let rd = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rm = (word >> 16) & 0x1f;
    let op2 = (word >> 21) & 0xf;
    if (word >> 28) & 1 == 0 {
        let amount = (word >> 10) & 0x3f;
        if op2 & 0b1000 == 0 {
            if !sf && amount >= 32 {
                return None;
            }
            return Some(Op::LogicReg {
                sf,
                op: Logic::from_opc(word >> 29),
                invert: (word >> 21) & 1 == 1,
                shift: Shift::from_bits(word >> 22),
                amount,
                rd,
                rn,
                rm,
            });
        }
        let sub = (word >> 30) & 1 == 1;
        let s = (word >> 29) & 1 == 1;
        if op2 & 1 == 0 {
            let shift = Shift::from_bits(word >> 22);
            if shift == Shift::Ror || (!sf && amount >= 32) {
                return None;
            }
            return Some(Op::AddSubReg {
                sf,
                sub,
                s,
                shift,
                amount,
                rd,
                rn,
                rm,
            });
        }
        let shift = (word >> 10) & 0b111;
        if shift > 4 {
            return None;
        }
        return Some(Op::AddSubExt {
            sf,
            sub,
            s,
            option: (word >> 13) & 0b111,
            shift,
            rd,
            rn,
            rm,
        });
    }
    let op0 = (word >> 30) & 1;
    match op2 {
        0b0110 if op0 == 0 => {
            let shift = match (word >> 10) & 0x3f {
                0b000010 => {
                    return Some(Op::Div {
                        sf,
                        signed: false,
                        rd,
                        rn,
                        rm,
                    });
                }
                0b000011 => {
                    return Some(Op::Div {
                        sf,
                        signed: true,
                        rd,
                        rn,
                        rm,
                    });
                }
                0b001000 => Shift::Lsl,
                0b001001 => Shift::Lsr,
                0b001010 => Shift::Asr,
                0b001011 => Shift::Ror,
                _ => return None,
            };
            Some(Op::ShiftV {
                sf,
                shift,
                rd,
                rn,
                rm,
            })
        }
        0b0110 => {
            if (word >> 16) & 0x1f != 0 {
                return None;
            }
            let op = match ((word >> 10) & 0x3f, sf) {
                (0b000000, _) => OneSrc::Rbit,
                (0b000001, _) => OneSrc::Rev16,
                (0b000010, _) => OneSrc::Rev32,
                (0b000011, true) => OneSrc::Rev64,
                (0b000100, _) => OneSrc::Clz,
                (0b000101, _) => OneSrc::Cls,
                _ => return None,
            };
            Some(Op::OneSrc { sf, op, rd, rn })
        }
        0b0000 => {
            if (word >> 10) & 0x3f != 0 {
                return None;
            }
            Some(Op::AdcSbc {
                sf,
                sub: op0 == 1,
                s: (word >> 29) & 1 == 1,
                rd,
                rn,
                rm,
            })
        }
        0b0010 => {
            let is_imm = (word >> 11) & 1 == 1;
            Some(Op::CondCmp {
                sf,
                sub: op0 == 1,
                imm: is_imm.then_some(u64::from(rm)),
                rm,
                cond: ((word >> 12) & 0xf) as u8,
                rn,
                nzcv: word & 0xf,
            })
        }
        0b0100 => {
            let op = match (op0, (word >> 10) & 0b11) {
                (0, 0b00) => Csel::Csel,
                (0, 0b01) => Csel::Csinc,
                (1, 0b00) => Csel::Csinv,
                (1, 0b01) => Csel::Csneg,
                _ => return None,
            };
            Some(Op::CondSel {
                sf,
                op,
                cond: ((word >> 12) & 0xf) as u8,
                rd,
                rn,
                rm,
            })
        }
        o if o & 0b1000 != 0 => {
            let op = match ((word >> 21) & 0b111, (word >> 15) & 1) {
                (0b000, 0) => Mul::Madd,
                (0b000, 1) => Mul::Msub,
                (0b001, 0) => Mul::Smaddl,
                (0b001, 1) => Mul::Smsubl,
                (0b010, 0) => Mul::Smulh,
                (0b101, 0) => Mul::Umaddl,
                (0b101, 1) => Mul::Umsubl,
                (0b110, 0) => Mul::Umulh,
                _ => return None,
            };
            // The widening/high forms only exist with sf == 1.
            if !sf && !matches!(op, Mul::Madd | Mul::Msub) {
                return None;
            }
            Some(Op::MulAdd {
                sf,
                op,
                rd,
                rn,
                rm,
                ra: (word >> 10) & 0x1f,
            })
        }
        _ => None,
    }
}

// --- branches / system: mirrors `branch::run` ---

fn branch(word: u32, pc: u64) -> Option<Op> {
    match (word >> 26) & 0x3f {
        0b000101 | 0b100101 => {
            let offset = sign_extend(u64::from(word & 0x03ff_ffff) << 2, 28);
            return Some(Op::Branch {
                target: pc.wrapping_add(offset),
                link: (word >> 31) & 1 == 1,
            });
        }
        _ => {}
    }
    let imm19_target = pc.wrapping_add(sign_extend(u64::from((word >> 5) & 0x7_ffff) << 2, 21));
    match (word >> 25) & 0x3f {
        0b011010 => {
            return Some(Op::CompareBranch {
                sf: (word >> 31) & 1 == 1,
                nonzero: (word >> 24) & 1 == 1,
                rt: word & 0x1f,
                target: imm19_target,
            });
        }
        0b011011 => {
            let imm14 = u64::from((word >> 5) & 0x3fff);
            return Some(Op::TestBranch {
                nonzero: (word >> 24) & 1 == 1,
                bit: (((word >> 31) & 1) << 5) | ((word >> 19) & 0x1f),
                rt: word & 0x1f,
                target: pc.wrapping_add(sign_extend(imm14 << 2, 16)),
            });
        }
        _ => {}
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        return Some(Op::BranchCond {
            cond: (word & 0xf) as u8,
            target: imm19_target,
        });
    }
    if (word >> 25) & 0x7f == 0b1101011 {
        let rn = (word >> 5) & 0x1f;
        return match (word >> 21) & 0xf {
            0b0000 | 0b0010 => Some(Op::BranchReg { rn, link: false }),
            0b0001 => Some(Op::BranchReg { rn, link: true }),
            _ => None,
        };
    }
    // Exception generation (`brk`, `svc`, ...) stays with the interpreter.
    if (word >> 24) & 0xff == 0b1101_0100 {
        return None;
    }
    // Hints and barriers are no-ops; system-register moves are not translated.
    let system = word & 0xffff_f01f;
    (system == 0xd503_201f || system == 0xd503_301f).then_some(Op::Nop)
}

// --- loads and stores: mirrors `ldst::run` ---

fn load_store(word: u32, pc: u64) -> Option<Op> {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;
    // Exclusive / ordered forms and LSE atomics stay with the interpreter.
    if (word >> 24) & 0x3f == 0b001000 || v == 1 {
        return None;
    }
    let group = (word >> 27) & 0x7;
    let op24 = (word >> 24) & 0x3;
    let op10 = (word >> 10) & 0x3;
    if group == 0b111 && op24 == 0b00 && (word >> 21) & 1 == 1 && op10 == 0b00 {
        return None;
    }
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    match group {
        0b111 => register(word, size, rt, rn),
        0b101 => pair(word, rt, rn),
        0b011 if op24 == 0b00 => {
            let addr = pc.wrapping_add(sign_extend(u64::from((word >> 5) & 0x7_ffff), 19) << 2);
            Some(match (word >> 30) & 0x3 {
                0b00 => Op::Literal {
                    bytes: 4,
                    signed: false,
                    rt,
                    addr,
                },
                0b01 => Op::Literal {
                    bytes: 8,
                    signed: false,
                    rt,
                    addr,
                },
                0b10 => Op::Literal {
                    bytes: 4,
                    signed: true,
                    rt,
                    addr,
                },
                _ => Op::Nop, // PRFM (literal)
            })
        }
        _ => None,
    }
}

fn register(word: u32, size: u32, rt: u32, rn: u32) -> Option<Op> {
    let opc = (word >> 22) & 0x3;
    let kind = match (size, opc) {
        (0b11, 0b10) => Transfer::Prefetch,
        (0b10, 0b11) | (0b11, 0b11) => return None,
        (_, 0b00) => Transfer::Store,
        (_, 0b01) => Transfer::Load,
        (_, 0b10) => Transfer::LoadSx,
        _ => Transfer::LoadSw,
    };
    let addr = if (word >> 24) & 1 == 1 {
        Address::Offset {
            rn,
            offset: u64::from((word >> 10) & 0xfff) << size,
        }
    } else if (word >> 21) & 1 == 1 {
        if (word >> 10) & 0x3 != 0b10 {
            return None;
        }
        Address::Reg {
            rn,
            rm: (word >> 16) & 0x1f,
            option: (word >> 13) & 0x7,
            shift: if (word >> 12) & 1 == 1 { size } else { 0 },
        }
    } else {
        let offset = sign_extend(u64::from((word >> 12) & 0x1ff), 9);
        match (word >> 10) & 0x3 {
            0b00 => Address::Offset { rn, offset },
            0b01 => Address::Post { rn, offset },
            0b11 => Address::Pre { rn, offset },
            _ => return None,
        }
    };
    Some(Op::LdSt {
        bytes: 1 << size,
        kind,
        rt,
        addr,
    })
}

fn pair(word: u32, rt: u32, rn: u32) -> Option<Op> {
    let load = (word >> 22) & 1 == 1;
    let (bytes, signed) = match (word >> 30) & 0x3 {
        0b00 => (4, false),
        // LDPSW; the store form (STGP) is left to the interpreter.
        0b01 if load => (4, true),
        0b10 => (8, false),
        _ => return None,
    };
    let offset = sign_extend(u64::from((word >> 15) & 0x7f), 7).wrapping_mul(u64::from(bytes));
    let addr = match (word >> 23) & 0x3 {
        0b01 => Address::Post { rn, offset },
        0b11 => Address::Pre { rn, offset },
        _ => Address::Offset { rn, offset },
    };
    Some(Op::Pair {
        bytes,
        load,
        signed,
        rt,
        rt2: (word >> 10) & 0x1f,
        addr,
    })
}
