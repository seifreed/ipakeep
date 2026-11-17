//! Pre-decoded instruction forms for the block cache.
//!
//! [`predecode`] turns the hot integer encodings of the guest (the top of the
//! kbsync opcode histogram: LDR/STR, ADD/SUB, UBFM, ORR/EOR/AND, MOVZ/MOVK,
//! UMADDL/MADD, SUBS, CSINC and the branches) into an [`Op`] with every field
//! extracted, immediates and bit masks precomputed and the operand width folded
//! into a mask. Everything else becomes [`Op::Fallback`], which runs the word
//! through the full decoder.
//!
//! The routing below mirrors the group decoders (`dpimm`/`dpreg`/`ldst`/
//! `branch`) bit for bit, and every op computes exactly what the decoder's leaf
//! computes for that word — including the encodings the leaves accept without
//! checking reserved bits. Anything the leaf would reject is left to the
//! fallback, so `Unsupported` errors keep their pc/word/what. The equivalence
//! is checked by `block_tests` against [`NativeCpu::execute`].

// The decoders are flat bit-field tables and `run_op` is one dispatch `match`
// (splitting either would only add indirection); the field tests read like
// the Arm ARM encoding diagrams, so keep them as masks.
#![allow(clippy::too_many_lines, clippy::verbose_bit_mask)]

use super::super::decode::{A64Class, classify};
use super::dpimm::decode_bit_masks;
use super::dpreg::{extend_reg, shift_reg};
use super::ldst::{extend_reg as index_reg, load_bytes, store_bytes};
use super::{NativeCpu, NativeError, SLOT_SINK, SLOT_SP, Step, cond_holds};

/// The value mask of a 32-bit (`sf == 0`) or 64-bit operation.
const fn width_mask(sf: u32) -> u64 {
    if sf == 1 { u64::MAX } else { 0xffff_ffff }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Operand width of a 32/64-bit operation (keeps [`Op`] at 16 bytes where a
/// `u64` value mask would not fit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Width {
    /// 32-bit (`sf == 0`).
    W,
    /// 64-bit (`sf == 1`).
    X,
}

impl Width {
    fn of(sf: u32) -> Self {
        if sf == 1 { Self::X } else { Self::W }
    }

    /// The width's value mask.
    #[inline]
    fn mask(self) -> u64 {
        match self {
            Self::W => 0xffff_ffff,
            Self::X => u64::MAX,
        }
    }
}

/// How a loaded value is extended into `Rt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ext {
    /// Zero-extend into X.
    Zero,
    /// Sign-extend into X.
    SignX,
    /// Sign-extend to 32 bits, zero-extend into X.
    SignW,
}

/// One pre-decoded instruction. Register operands are register-file slots
/// (see [`NativeCpu::slot`]) with register 31 already resolved to the zero
/// slot, the write sink or SP, as the instruction's encoding demands; `mask`
/// is the operation width's value mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    /// No fast path: run the word through the full decoder.
    Fallback(u32),
    /// Architectural no-op that cannot fault (`PRFM`).
    Nop,
    /// `Xd(ZR) = value` (MOVZ/MOVN, ADR/ADRP).
    Mov { rd: u8, value: u64 },
    /// `MOVK`: `Xd = ((Xs & !(0xffff << shift)) | bits) & mask` (`rs`/`rd`
    /// both name Rd, as a source and as a destination slot).
    MovK {
        rd: u8,
        rs: u8,
        shift: u8,
        bits: u64,
        width: Width,
    },
    /// `ADD (imm)`: `Xd(SP) = (Xn(SP) + imm) & mask`.
    AddImm {
        rd: u8,
        rn: u8,
        imm: u64,
        width: Width,
    },
    /// `SUB (imm)`: `Xd(SP) = (Xn(SP) - imm) & mask`.
    SubImm {
        rd: u8,
        rn: u8,
        imm: u64,
        width: Width,
    },
    /// `ADDS/SUBS (imm)`; `Xd` is ZR-form.
    AddSubImmS {
        rd: u8,
        rn: u8,
        imm: u64,
        sub: bool,
        sf: u8,
    },
    /// `AND (imm)`: `Xd(SP) = (Xn(ZR) & mask) & imm`.
    AndImm {
        rd: u8,
        rn: u8,
        imm: u64,
        width: Width,
    },
    /// `ORR (imm)`.
    OrrImm {
        rd: u8,
        rn: u8,
        imm: u64,
        width: Width,
    },
    /// `EOR (imm)`.
    EorImm {
        rd: u8,
        rn: u8,
        imm: u64,
        width: Width,
    },
    /// 64-bit `UBFM` (LSL/LSR/UBFX/UXT*): `Xd = ror(Xn, r) & mask`.
    Ubfm64 { rd: u8, rn: u8, r: u8, mask: u64 },
    /// 32-bit `UBFM`: `Xd = ror32(Wn, r) & mask`.
    Ubfm32 { rd: u8, rn: u8, r: u8, mask: u64 },
    /// `MOV (register)` = `ORR Xd, XZR, Xm`: `Xd = Xm & mask`.
    MovReg { rd: u8, rm: u8, width: Width },
    /// `AND/BIC (shifted register)` (no flags).
    AndReg {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        invert: bool,
        sf: u8,
    },
    /// `ORR/ORN (shifted register)`.
    OrrReg {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        invert: bool,
        sf: u8,
    },
    /// `EOR/EON (shifted register)`.
    EorReg {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        invert: bool,
        sf: u8,
    },
    /// `ADD (shifted register)`, no flags.
    AddReg {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        sf: u8,
    },
    /// `SUB (shifted register)`, no flags.
    SubReg {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        sf: u8,
    },
    /// `ADDS/SUBS (shifted register)` (CMP/CMN).
    AddSubRegS {
        rd: u8,
        rn: u8,
        rm: u8,
        shift: u8,
        amount: u8,
        sub: bool,
        sf: u8,
    },
    /// `ADD/SUB(S) (extended register)`.
    AddSubExt {
        rd: u8,
        rn: u8,
        rm: u8,
        option: u8,
        amount: u8,
        sub: bool,
        flags: bool,
        sf: u8,
    },
    /// `CSEL/CSINC/CSINV/CSNEG` (`kind` = `op:op2`, 0..=3).
    CondSel {
        rd: u8,
        rn: u8,
        rm: u8,
        cond: u8,
        kind: u8,
        width: Width,
    },
    /// `MADD`: `Xd = (Xa + Xn * Xm) & mask`.
    Madd {
        rd: u8,
        rn: u8,
        rm: u8,
        ra: u8,
        width: Width,
    },
    /// `UMADDL`: `Xd = (Xa + Wn * Wm) & mask`.
    Umaddl {
        rd: u8,
        rn: u8,
        rm: u8,
        ra: u8,
        width: Width,
    },
    /// Integer load, `[Xn(SP) + offset]`.
    Load {
        rt: u8,
        rn: u8,
        offset: u64,
        bytes: u8,
        ext: Ext,
    },
    /// Integer store, `[Xn(SP) + offset]`.
    Store {
        rt: u8,
        rn: u8,
        offset: u64,
        bytes: u8,
    },
    /// Integer load, `[Xn(SP) + extend(Xm) << shift]`.
    LoadReg {
        rt: u8,
        rn: u8,
        rm: u8,
        option: u8,
        shift: u8,
        bytes: u8,
        ext: Ext,
    },
    /// Integer store, `[Xn(SP) + extend(Xm) << shift]`.
    StoreReg {
        rt: u8,
        rn: u8,
        rm: u8,
        option: u8,
        shift: u8,
        bytes: u8,
    },
    /// `B target`.
    B { target: u64 },
    /// `BL target`.
    Bl { target: u64 },
    /// `B.cond target`.
    BCond { cond: u8, target: u64 },
    /// `CBZ/CBNZ`: branch when `(Xt & mask == 0) != nonzero`.
    Cbz {
        rt: u8,
        width: Width,
        nonzero: bool,
        target: u64,
    },
    /// `TBZ/TBNZ`: branch when `bit(Xt, bit) == set`.
    Tbz {
        rt: u8,
        bit: u8,
        set: bool,
        target: u64,
    },
    /// `BR/RET Xn`.
    Br { rn: u8 },
    /// `BLR Xn`.
    Blr { rn: u8 },
}

/// Decodes `word` (located at `pc`) into its [`Op`].
pub(super) fn predecode(word: u32, pc: u64) -> Op {
    let op = match classify(word) {
        A64Class::DataProcImm => dp_imm(word, pc),
        A64Class::DataProcReg => dp_reg(word),
        A64Class::LoadStore => load_store(word),
        A64Class::BranchSystem => branch(word, pc),
        _ => None,
    };
    op.unwrap_or(Op::Fallback(word))
}

/// Register field at `shift`, read as a source (register 31 = XZR, whose
/// slot always reads zero).
fn reg(word: u32, shift: u32) -> u8 {
    ((word >> shift) & 0x1f) as u8
}

/// Register field at `shift` as a destination where 31 is XZR (the sink).
fn dst(word: u32, shift: u32) -> u8 {
    match reg(word, shift) {
        31 => SLOT_SINK as u8,
        n => n,
    }
}

/// Register field at `shift` where 31 is SP.
fn sp(word: u32, shift: u32) -> u8 {
    match reg(word, shift) {
        31 => SLOT_SP as u8,
        n => n,
    }
}

// --- data processing (immediate): mirrors `dpimm::run` ---

fn dp_imm(word: u32, pc: u64) -> Option<Op> {
    let sf = (word >> 31) & 1;
    let mask = width_mask(sf);
    let rd = dst(word, 0);
    let rn = reg(word, 5);
    match (word >> 23) & 0b111 {
        0b000 | 0b001 => {
            let immlo = u64::from((word >> 29) & 0b11);
            let immhi = u64::from((word >> 5) & 0x7_ffff);
            let imm21 = (immhi << 2) | immlo;
            let value = if sf == 0 {
                pc.wrapping_add(sign_extend(imm21, 21)) // ADR
            } else {
                (pc & !0xfff).wrapping_add(sign_extend(imm21 << 12, 33)) // ADRP
            };
            Some(Op::Mov { rd, value })
        }
        0b010 => {
            let imm12 = u64::from((word >> 10) & 0xfff);
            let imm = if (word >> 22) & 1 == 1 {
                imm12 << 12
            } else {
                imm12
            };
            let sub = (word >> 30) & 1 == 1;
            let (rn, rd_sp) = (sp(word, 5), sp(word, 0));
            Some(match ((word >> 29) & 1, sub) {
                (0, false) => Op::AddImm {
                    rd: rd_sp,
                    rn,
                    imm,
                    width: Width::of(sf),
                },
                (0, true) => Op::SubImm {
                    rd: rd_sp,
                    rn,
                    imm,
                    width: Width::of(sf),
                },
                _ => Op::AddSubImmS {
                    rd,
                    rn,
                    imm,
                    sub,
                    sf: sf as u8,
                },
            })
        }
        0b100 => {
            let n = (word >> 22) & 1;
            if sf == 0 && n == 1 {
                return None;
            }
            let datasize = if sf == 1 { 64 } else { 32 };
            let immr = (word >> 16) & 0x3f;
            let imms = (word >> 10) & 0x3f;
            let (imm, _) = decode_bit_masks(n, imms, immr, true, datasize)?;
            let imm = imm & mask;
            let rd = sp(word, 0);
            match (word >> 29) & 0b11 {
                0b00 => Some(Op::AndImm {
                    rd,
                    rn,
                    imm,
                    width: Width::of(sf),
                }),
                0b01 => Some(Op::OrrImm {
                    rd,
                    rn,
                    imm,
                    width: Width::of(sf),
                }),
                0b10 => Some(Op::EorImm {
                    rd,
                    rn,
                    imm,
                    width: Width::of(sf),
                }),
                _ => None, // ANDS
            }
        }
        0b101 => {
            let hw = (word >> 21) & 0b11;
            if sf == 0 && hw > 1 {
                return None;
            }
            let shift = hw * 16;
            let bits = u64::from((word >> 5) & 0xffff) << shift;
            match (word >> 29) & 0b11 {
                0b10 => Some(Op::Mov {
                    rd,
                    value: bits & mask,
                }),
                0b00 => Some(Op::Mov {
                    rd,
                    value: !bits & mask,
                }),
                0b11 => Some(Op::MovK {
                    rd,
                    rs: reg(word, 0),
                    shift: shift as u8,
                    bits,
                    width: Width::of(sf),
                }),
                _ => None,
            }
        }
        0b110 => {
            // Only the UBFM shape (opc 10, and 11 which the decoder runs the
            // same way); SBFM/BFM fall back.
            let n = (word >> 22) & 1;
            if (word >> 29) & 0b11 < 0b10 || n != sf {
                return None;
            }
            let datasize = if sf == 1 { 64 } else { 32 };
            let immr = (word >> 16) & 0x3f;
            let imms = (word >> 10) & 0x3f;
            let (wmask, tmask) = decode_bit_masks(n, imms, immr, false, datasize)?;
            let (r, mask) = ((immr % datasize) as u8, wmask & tmask & mask);
            Some(if sf == 1 {
                Op::Ubfm64 { rd, rn, r, mask }
            } else {
                Op::Ubfm32 { rd, rn, r, mask }
            })
        }
        _ => None,
    }
}

// --- data processing (register): mirrors `dpreg::run` ---

fn dp_reg(word: u32) -> Option<Op> {
    let sf = (word >> 31) & 1;
    let rd = dst(word, 0);
    let rn = reg(word, 5);
    let rm = reg(word, 16);
    let op2 = (word >> 21) & 0xf;
    let sub = (word >> 30) & 1 == 1;
    let flags = (word >> 29) & 1 == 1;
    let shift = ((word >> 22) & 0b11) as u8;
    let amount = ((word >> 10) & 0x3f) as u8;
    let sf8 = sf as u8;
    if (word >> 28) & 1 == 0 {
        if op2 & 0b1000 == 0 {
            // Logical (shifted register); ANDS/BICS fall back.
            let invert = (word >> 21) & 1 == 1;
            return match (word >> 29) & 0b11 {
                0b01 if rn == 31 && shift == 0 && amount == 0 && !invert => Some(Op::MovReg {
                    rd,
                    rm,
                    width: Width::of(sf),
                }),
                0b00 => Some(Op::AndReg {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    invert,
                    sf: sf8,
                }),
                0b01 => Some(Op::OrrReg {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    invert,
                    sf: sf8,
                }),
                0b10 => Some(Op::EorReg {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    invert,
                    sf: sf8,
                }),
                _ => None,
            };
        }
        if op2 & 1 == 0 {
            return Some(match (flags, sub) {
                (false, false) => Op::AddReg {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    sf: sf8,
                },
                (false, true) => Op::SubReg {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    sf: sf8,
                },
                _ => Op::AddSubRegS {
                    rd,
                    rn,
                    rm,
                    shift,
                    amount,
                    sub,
                    sf: sf8,
                },
            });
        }
        let option = ((word >> 13) & 0b111) as u8;
        let amount = ((word >> 10) & 0b111) as u8;
        let (rd, rn) = (if flags { rd } else { sp(word, 0) }, sp(word, 5));
        return Some(Op::AddSubExt {
            rd,
            rn,
            rm,
            option,
            amount,
            sub,
            flags,
            sf: sf8,
        });
    }
    match op2 {
        0b0100 => {
            let kind = (((word >> 30) & 1) << 1 | ((word >> 10) & 0b11)) as u8;
            if (word >> 11) & 1 == 1 {
                return None; // unallocated op2: the decoder rejects it
            }
            let cond = ((word >> 12) & 0xf) as u8;
            Some(Op::CondSel {
                rd,
                rn,
                rm,
                cond,
                kind,
                width: Width::of(sf),
            })
        }
        o if o & 0b1000 != 0 => {
            let ra = reg(word, 10);
            match ((word >> 21) & 0b111, (word >> 15) & 1) {
                (0b000, 0) => Some(Op::Madd {
                    rd,
                    rn,
                    rm,
                    ra,
                    width: Width::of(sf),
                }),
                (0b101, 0) => Some(Op::Umaddl {
                    rd,
                    rn,
                    rm,
                    ra,
                    width: Width::of(sf),
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

// --- loads and stores: mirrors `ldst::run` / `ldst::register` ---

fn load_store(word: u32) -> Option<Op> {
    let size = (word >> 30) & 0x3;
    if (word >> 24) & 0x3f == 0b001000 // exclusive / ordered
        || (word >> 27) & 0x7 != 0b111 // pair, literal, other groups
        || (word >> 26) & 1 == 1 // SIMD&FP
        || (word >> 24) & 0x3 == 0 && (word >> 21) & 1 == 1 && (word >> 10) & 0x3 == 0
    // LSE atomics
    {
        return None;
    }
    let opc = (word >> 22) & 0x3;
    let rn = sp(word, 5);
    let bytes = 1u8 << size;
    // The addressing mode is validated before the transfer (as `register`).
    let register = if (word >> 24) & 1 == 1 {
        None
    } else if (word >> 21) & 1 == 1 {
        if (word >> 10) & 0x3 != 0b10 {
            return None;
        }
        Some((reg(word, 16), ((word >> 13) & 0x7) as u8, (word >> 12) & 1))
    } else if (word >> 10) & 0x3 == 0 {
        None
    } else {
        return None; // pre/post-indexed (writeback), unprivileged
    };
    // Loads write Rt (31 = XZR, the sink); stores read it.
    let rt = if opc == 0 { reg(word, 0) } else { dst(word, 0) };
    let ext = match (size, opc) {
        (0b11, 0b10) => return Some(Op::Nop), // PRFM
        (0b10 | 0b11, 0b11) => return None,   // unallocated
        (_, 0b00) => None,
        (_, 0b01) => Some(Ext::Zero),
        (_, 0b10) => Some(Ext::SignX),
        _ => Some(Ext::SignW),
    };
    if let Some((rm, option, s)) = register {
        let shift = if s == 1 { size as u8 } else { 0 };
        return Some(match ext {
            Some(ext) => Op::LoadReg {
                rt,
                rn,
                rm,
                option,
                shift,
                bytes,
                ext,
            },
            None => Op::StoreReg {
                rt,
                rn,
                rm,
                option,
                shift,
                bytes,
            },
        });
    }
    let offset = if (word >> 24) & 1 == 1 {
        u64::from((word >> 10) & 0xfff) << size // unsigned offset
    } else {
        sign_extend(u64::from((word >> 12) & 0x1ff), 9) // unscaled
    };
    Some(match ext {
        Some(ext) => Op::Load {
            rt,
            rn,
            offset,
            bytes,
            ext,
        },
        None => Op::Store {
            rt,
            rn,
            offset,
            bytes,
        },
    })
}

// --- branches: mirrors `branch::run` ---

fn branch(word: u32, pc: u64) -> Option<Op> {
    let rel = |imm: u32, bits: u32| pc.wrapping_add(sign_extend(u64::from(imm) << 2, bits + 2));
    match (word >> 26) & 0x3f {
        0b000101 => {
            return Some(Op::B {
                target: rel(word & 0x03ff_ffff, 26),
            });
        }
        0b100101 => {
            return Some(Op::Bl {
                target: rel(word & 0x03ff_ffff, 26),
            });
        }
        _ => {}
    }
    let rt = reg(word, 0);
    match (word >> 25) & 0x3f {
        0b011010 => {
            return Some(Op::Cbz {
                rt,
                width: Width::of((word >> 31) & 1),
                nonzero: (word >> 24) & 1 == 1,
                target: rel((word >> 5) & 0x7_ffff, 19),
            });
        }
        0b011011 => {
            return Some(Op::Tbz {
                rt,
                bit: (((word >> 31) & 1) << 5 | ((word >> 19) & 0x1f)) as u8,
                set: (word >> 24) & 1 == 1,
                target: rel((word >> 5) & 0x3fff, 14),
            });
        }
        _ => {}
    }
    if word & 0xff00_0010 == 0x5400_0000 {
        let target = rel((word >> 5) & 0x7_ffff, 19);
        return Some(Op::BCond {
            cond: (word & 0xf) as u8,
            target,
        });
    }
    if (word >> 25) & 0x7f == 0b1101011 {
        let rn = reg(word, 5);
        return match (word >> 21) & 0xf {
            0b0000 | 0b0010 => Some(Op::Br { rn }),
            0b0001 => Some(Op::Blr { rn }),
            _ => None,
        };
    }
    None
}

// --- execution ---

/// `a + b` (`sub == false`) or `a - b` on width-masked operands, with the
/// NZCV that `dpimm::add_with_carry(a, b, false)` /
/// `add_with_carry(a, !b & mask, true)` produce, without 128-bit arithmetic.
#[inline]
#[allow(clippy::many_single_char_names)] // a, b, n, z, v: the ARM ARM names
pub(super) fn add_sub_flags(a: u64, b: u64, sub: bool, sf: u32) -> (u64, u32) {
    let (mask, top) = if sf == 1 {
        (u64::MAX, 63)
    } else {
        (0xffff_ffff, 31)
    };
    let (result, carry, overflow) = if sub {
        let r = a.wrapping_sub(b) & mask;
        (r, a >= b, (a ^ b) & (a ^ r))
    } else {
        let wide = a.wrapping_add(b);
        let r = wide & mask;
        let carry = if sf == 1 { wide < a } else { wide > mask };
        (r, carry, !(a ^ b) & (a ^ r))
    };
    let n = ((result >> top) & 1) as u32;
    let z = u32::from(result == 0);
    let v = ((overflow >> top) & 1) as u32;
    let nzcv = (n << 31) | (z << 30) | (u32::from(carry) << 29) | (v << 28);
    (result, nzcv)
}

/// The width-masked shifted second operand of `ADD`/`SUB (shifted register)`.
#[inline]
fn shifted_operand(cpu: &NativeCpu, rm: u8, shift: u8, amount: u8, sf: u8) -> u64 {
    shift_reg(
        cpu.slot(rm),
        u32::from(shift),
        u32::from(amount),
        u32::from(sf),
    )
}

/// The second operand of a logical shifted-register op.
#[inline]
fn logical_operand(cpu: &NativeCpu, rm: u8, shift: u8, amount: u8, invert: bool, sf: u8) -> u64 {
    let operand = shift_reg(
        cpu.slot(rm),
        u32::from(shift),
        u32::from(amount),
        u32::from(sf),
    );
    if invert {
        operand ^ width_mask(u32::from(sf))
    } else {
        operand
    }
}

#[inline]
fn finish_load(cpu: &mut NativeCpu, rt: u8, raw: u64, bytes: u8, ext: Ext) {
    let bits = u32::from(bytes) * 8;
    let value = match ext {
        Ext::Zero => raw,
        Ext::SignX => sign_extend(raw, bits),
        Ext::SignW => sign_extend(raw, bits) & 0xffff_ffff,
    };
    cpu.set_slot(rt, value);
}

/// After an instruction at `pc` that may write memory: if it hit a page
/// holding cached code, report a "branch" to the next instruction so the block
/// ends right here and the following code is fetched afresh.
#[inline]
fn after_write(cpu: &NativeCpu, pc: u64) -> Step {
    if cpu.mem.code_written() {
        Step::Branch(pc.wrapping_add(4))
    } else {
        Step::Next
    }
}

/// Runs one op located at `pc`, with the same effects as [`NativeCpu::step`]
/// on the op's word. The result is also the same, except that an instruction
/// that wrote to a page holding cached code reports `Branch(pc + 4)` instead of
/// `Next` (see [`after_write`]).
#[inline]
// One arm per op on a single-line pattern, and a block arm opens its first
// statement on that line. Since Rust 1.100, LLVM gives a binding pattern no
// coverage region of its own, while cargo-tarpaulin (0.37.6) still reports
// every line of an `#[inline]` body: a pattern line without code would read as
// a miss. rustfmt would split both the patterns and these arms.
#[rustfmt::skip]
pub(super) fn run_op(cpu: &mut NativeCpu, op: &Op, pc: u64) -> Result<Step, NativeError> {
    let x = |cpu: &NativeCpu, slot: u8| cpu.slot(slot);
    match *op {
        Op::Fallback(word) => { cpu.set_pc(pc);
            return match cpu.execute(word)? {
                Step::Next => Ok(after_write(cpu, pc)),
                other => Ok(other),
            };
        }
        Op::Nop => {}
        Op::Mov { rd, value } => cpu.set_slot(rd, value),
        Op::MovK { rd, rs, shift, bits, width } => cpu.set_slot(rd, ((x(cpu, rs) & !(0xffffu64 << shift)) | bits) & width.mask()),
        Op::AddImm { rd, rn, imm, width } => cpu.set_slot(rd, x(cpu, rn).wrapping_add(imm) & width.mask()),
        Op::SubImm { rd, rn, imm, width } => cpu.set_slot(rd, x(cpu, rn).wrapping_sub(imm) & width.mask()),
        Op::AddSubImmS { rd, rn, imm, sub, sf } => { let sf = u32::from(sf);
            let a = cpu.slot(rn) & width_mask(sf);
            let (result, nzcv) = add_sub_flags(a, imm & width_mask(sf), sub, sf);
            cpu.set_nzcv(nzcv);
            cpu.set_slot(rd, result);
        }
        Op::AndImm { rd, rn, imm, width } => cpu.set_slot(rd, x(cpu, rn) & width.mask() & imm),
        Op::OrrImm { rd, rn, imm, width } => cpu.set_slot(rd, (x(cpu, rn) & width.mask()) | imm),
        Op::EorImm { rd, rn, imm, width } => cpu.set_slot(rd, (x(cpu, rn) & width.mask()) ^ imm),
        Op::Ubfm64 { rd, rn, r, mask } => cpu.set_slot(rd, x(cpu, rn).rotate_right(u32::from(r)) & mask),
        Op::Ubfm32 { rd, rn, r, mask } => cpu.set_slot(rd, u64::from((x(cpu, rn) as u32).rotate_right(u32::from(r))) & mask),
        Op::MovReg { rd, rm, width } => cpu.set_slot(rd, x(cpu, rm) & width.mask()),
        Op::AndReg { rd, rn, rm, shift, amount, invert, sf } => { let b = logical_operand(cpu, rm, shift, amount, invert, sf);
            cpu.set_slot(rd, x(cpu, rn) & width_mask(u32::from(sf)) & b);
        }
        Op::OrrReg { rd, rn, rm, shift, amount, invert, sf } => { let b = logical_operand(cpu, rm, shift, amount, invert, sf);
            cpu.set_slot(rd, (x(cpu, rn) & width_mask(u32::from(sf))) | b);
        }
        Op::EorReg { rd, rn, rm, shift, amount, invert, sf } => { let b = logical_operand(cpu, rm, shift, amount, invert, sf);
            cpu.set_slot(rd, (x(cpu, rn) & width_mask(u32::from(sf))) ^ b);
        }
        Op::AddReg { rd, rn, rm, shift, amount, sf } => { let b = shifted_operand(cpu, rm, shift, amount, sf);
            let mask = width_mask(u32::from(sf));
            cpu.set_slot(rd, x(cpu, rn).wrapping_add(b) & mask);
        }
        Op::SubReg { rd, rn, rm, shift, amount, sf } => { let b = shifted_operand(cpu, rm, shift, amount, sf);
            let mask = width_mask(u32::from(sf));
            cpu.set_slot(rd, x(cpu, rn).wrapping_sub(b) & mask);
        }
        Op::AddSubRegS { rd, rn, rm, shift, amount, sub, sf } => { let b = shifted_operand(cpu, rm, shift, amount, sf);
            let a = x(cpu, rn) & width_mask(u32::from(sf));
            let (result, nzcv) = add_sub_flags(a, b, sub, u32::from(sf));
            cpu.set_nzcv(nzcv);
            cpu.set_slot(rd, result);
        }
        Op::AddSubExt { rd, rn, rm, option, amount, sub, flags, sf } => { let sf = u32::from(sf);
            let mask = width_mask(sf);
            let operand2 = extend_reg(x(cpu, rm), u32::from(option), u32::from(amount), sf);
            let a = cpu.slot(rn) & mask;
            let (result, nzcv) = add_sub_flags(a, operand2, sub, sf);
            if flags {
                cpu.set_nzcv(nzcv);
                cpu.set_slot(rd, result);
            } else {
                cpu.set_slot(rd, result);
            }
        }
        Op::CondSel { rd, rn, rm, cond, kind, width } => { let mask = width.mask();
            let result = if cond_holds(cpu.nzcv(), cond) {
                x(cpu, rn)
            } else {
                let m = x(cpu, rm);
                match kind {
                    0 => m,
                    1 => m.wrapping_add(1),
                    2 => !m,
                    _ => (!m).wrapping_add(1),
                }
            };
            cpu.set_slot(rd, result & mask);
        }
        Op::Madd { rd, rn, rm, ra, width } => { let mask = width.mask();
            let product = (x(cpu, rn) & mask).wrapping_mul(x(cpu, rm) & mask);
            cpu.set_slot(rd, (x(cpu, ra) & mask).wrapping_add(product) & mask);
        }
        Op::Umaddl { rd, rn, rm, ra, width } => { let mask = width.mask();
            let product = u64::from(x(cpu, rn) as u32) * u64::from(x(cpu, rm) as u32);
            cpu.set_slot(rd, x(cpu, ra).wrapping_add(product) & mask);
        }
        Op::Load { rt, rn, offset, bytes, ext } => { let addr = cpu.slot(rn).wrapping_add(offset);
            let raw = load_bytes(cpu, addr, usize::from(bytes))?;
            finish_load(cpu, rt, raw, bytes, ext);
        }
        Op::Store { rt, rn, offset, bytes } => { let addr = cpu.slot(rn).wrapping_add(offset);
            store_bytes(cpu, addr, usize::from(bytes), x(cpu, rt))?;
            return Ok(after_write(cpu, pc));
        }
        Op::LoadReg { rt, rn, rm, option, shift, bytes, ext } => { let index = index_reg(x(cpu, rm), u32::from(option), u32::from(shift));
            let addr = cpu.slot(rn).wrapping_add(index);
            let raw = load_bytes(cpu, addr, usize::from(bytes))?;
            finish_load(cpu, rt, raw, bytes, ext);
        }
        Op::StoreReg { rt, rn, rm, option, shift, bytes } => { let index = index_reg(x(cpu, rm), u32::from(option), u32::from(shift));
            let addr = cpu.slot(rn).wrapping_add(index);
            store_bytes(cpu, addr, usize::from(bytes), x(cpu, rt))?;
            return Ok(after_write(cpu, pc));
        }
        Op::B { target } => return Ok(Step::Branch(target)),
        Op::Bl { target } => { cpu.set_slot(30, pc.wrapping_add(4));
            return Ok(Step::Branch(target));
        }
        Op::BCond { cond, target } => if cond_holds(cpu.nzcv(), cond) {
            return Ok(Step::Branch(target));
        },
        Op::Cbz { rt, width, nonzero, target } => if (x(cpu, rt) & width.mask() == 0) != nonzero {
            return Ok(Step::Branch(target));
        },
        Op::Tbz { rt, bit, set, target } => if ((x(cpu, rt) >> bit) & 1 == 1) == set {
            return Ok(Step::Branch(target));
        },
        Op::Br { rn } => return Ok(Step::Branch(x(cpu, rn))),
        Op::Blr { rn } => { let target = x(cpu, rn);
            cpu.set_slot(30, pc.wrapping_add(4));
            return Ok(Step::Branch(target));
        }
    }
    Ok(Step::Next)
}
