//! Data-processing -- immediate (ARM ARM C4.1.2): PC-rel, add/sub immediate,
//! logical immediate, move wide, bitfield, extract.

use super::{NativeCpu, NativeError, Step, nzcv_bits};

/// Runs a data-processing-immediate instruction.
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let op1 = (word >> 23) & 0b111; // bits [25:23]
    match op1 {
        0b000 | 0b001 => pc_rel(cpu, word),
        0b010 => add_sub_imm(cpu, word),
        0b100 => logical_imm(cpu, word),
        0b101 => move_wide(cpu, word),
        0b110 => bitfield(cpu, word),
        0b111 => extract(cpu, word),
        // 0b011 = add/sub with tags (MTE) — not emitted by the guest.
        _ => Err(unsupported(cpu, word, "dpimm/tagged")),
    }
}

fn unsupported(cpu: &NativeCpu, word: u32, what: &'static str) -> NativeError {
    NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what,
    }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

fn mask_width(value: u64, sf: u32) -> u64 {
    if sf == 1 { value } else { value & 0xffff_ffff }
}

/// ARM `AddWithCarry` for a 32- or 64-bit operation; returns (result, NZCV).
pub(super) fn add_with_carry(a: u64, b: u64, carry_in: bool, sf: u32) -> (u64, u32) {
    let cin = u128::from(carry_in);
    if sf == 1 {
        let usum = u128::from(a) + u128::from(b) + cin;
        let ssum = i128::from(a as i64) + i128::from(b as i64) + cin as i128;
        let result = usum as u64;
        let carry = (usum >> 64) != 0;
        let overflow = i128::from(result as i64) != ssum;
        (result, nzcv_bits(result, carry, overflow))
    } else {
        let a = a & 0xffff_ffff;
        let b = b & 0xffff_ffff;
        let usum = a as u128 + b as u128 + cin;
        let ssum = i128::from(a as i32) + i128::from(b as i32) + cin as i128;
        let result = usum as u32;
        let carry = (usum >> 32) != 0;
        let overflow = i128::from(result as i32) != ssum;
        let n = (result >> 31) & 1;
        let z = u32::from(result == 0);
        (
            u64::from(result),
            (n << 31) | (z << 30) | (u32::from(carry) << 29) | (u32::from(overflow) << 28),
        )
    }
}

fn pc_rel(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let op = (word >> 31) & 1;
    let immlo = u64::from((word >> 29) & 0b11);
    let immhi = u64::from((word >> 5) & 0x7_ffff);
    let rd = word & 0x1f;
    let imm21 = (immhi << 2) | immlo;
    if op == 0 {
        // ADR
        let offset = sign_extend(imm21, 21);
        cpu.set_x(rd, cpu.pc().wrapping_add(offset));
    } else {
        // ADRP
        let offset = sign_extend(imm21 << 12, 33);
        let base = cpu.pc() & !0xfff;
        cpu.set_x(rd, base.wrapping_add(offset));
    }
    Ok(Step::Next)
}

fn add_sub_imm(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1; // 0 add, 1 sub
    let s = (word >> 29) & 1;
    let sh = (word >> 22) & 1;
    let imm12 = u64::from((word >> 10) & 0xfff);
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let imm = if sh == 1 { imm12 << 12 } else { imm12 };

    let a = mask_width(cpu.x_sp(rn), sf);
    let (result, nzcv) = if op == 0 {
        add_with_carry(a, imm, false, sf)
    } else {
        add_with_carry(a, mask_width(!imm, sf), true, sf)
    };

    if s == 1 {
        cpu.set_nzcv(nzcv);
        if sf == 1 {
            cpu.set_x(rd, result);
        } else {
            cpu.set_w(rd, result as u32);
        }
    } else if sf == 1 {
        cpu.set_x_sp(rd, result);
    } else {
        cpu.set_x_sp(rd, u64::from(result as u32));
    }
    Ok(Step::Next)
}

/// ARM `DecodeBitMasks(immN, imms, immr)` → (wmask, tmask); None if reserved.
pub(super) fn decode_bit_masks(
    immn: u32,
    imms: u32,
    immr: u32,
    immediate: bool,
    datasize: u32,
) -> Option<(u64, u64)> {
    let combined = ((immn & 1) << 6) | ((!imms) & 0x3f);
    if combined == 0 {
        return None;
    }
    let len = combined.ilog2(); // index of the highest set bit
    if len == 0 {
        return None;
    }
    let esize = 1u32 << len;
    if esize > datasize {
        return None;
    }
    let levels = esize - 1; // `len` ones
    let s = imms & levels;
    let r = immr & levels;
    // `s == levels` is reserved only for logical-immediate decoding, not for
    // bitfield moves (where it is the common lsr/asr/lsl form).
    if immediate && s == levels {
        return None;
    }
    let welem = ones(s + 1);
    let telem = ones(r_diff(s, r, levels) + 1);
    let wmask = replicate(ror_in(welem, r, esize), esize, datasize);
    let tmask = replicate(telem, esize, datasize);
    Some((wmask, tmask))
}

fn r_diff(s: u32, r: u32, levels: u32) -> u32 {
    s.wrapping_sub(r) & levels
}

fn ones(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

fn ror_in(value: u64, amount: u32, width: u32) -> u64 {
    let mask = ones(width);
    let value = value & mask;
    let amount = amount % width;
    if amount == 0 {
        value
    } else {
        ((value >> amount) | (value << (width - amount))) & mask
    }
}

fn replicate(pattern: u64, element: u32, datasize: u32) -> u64 {
    let pattern = pattern & ones(element);
    let mut result = 0u64;
    let mut shift = 0u32;
    while shift < datasize {
        result |= pattern << shift;
        shift += element;
    }
    result & ones(datasize)
}

fn logical_imm(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let opc = (word >> 29) & 0b11; // 00 AND, 01 ORR, 10 EOR, 11 ANDS
    let n = (word >> 22) & 1;
    let immr = (word >> 16) & 0x3f;
    let imms = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let datasize = if sf == 1 { 64 } else { 32 };
    if sf == 0 && n == 1 {
        return Err(unsupported(cpu, word, "logical-imm/N"));
    }
    let Some((imm, _)) = decode_bit_masks(n, imms, immr, true, datasize) else {
        return Err(unsupported(cpu, word, "logical-imm/reserved"));
    };
    let a = mask_width(cpu.x(rn), sf);
    let imm = mask_width(imm, sf);
    let result = match opc {
        0b00 | 0b11 => a & imm,
        0b01 => a | imm,
        0b10 => a ^ imm,
        _ => unreachable!(),
    };
    let result = mask_width(result, sf);
    if opc == 0b11 {
        // ANDS: NZ from result, C=V=0; Rd is ZR-form.
        let n_flag = if sf == 1 {
            (result >> 63) & 1
        } else {
            (result >> 31) & 1
        };
        let z_flag = u64::from(result == 0);
        cpu.set_nzcv(((n_flag << 31) | (z_flag << 30)) as u32);
        cpu.set_x(rd, result);
    } else {
        // AND/ORR/EOR: Rd is SP-form, no flags.
        cpu.set_x_sp(rd, result);
    }
    Ok(Step::Next)
}

fn move_wide(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let opc = (word >> 29) & 0b11; // 00 MOVN, 10 MOVZ, 11 MOVK
    let hw = (word >> 21) & 0b11;
    let imm16 = u64::from((word >> 5) & 0xffff);
    let rd = word & 0x1f;
    if sf == 0 && hw > 1 {
        return Err(unsupported(cpu, word, "movw/hw"));
    }
    let shift = hw * 16;
    let shifted = imm16 << shift;
    let result = match opc {
        0b10 => shifted,  // MOVZ
        0b00 => !shifted, // MOVN
        0b11 => {
            // MOVK: keep other bits of Rd.
            let keep = cpu.x(rd) & !(0xffffu64 << shift);
            keep | shifted
        }
        _ => return Err(unsupported(cpu, word, "movw/opc")),
    };
    if sf == 1 {
        cpu.set_x(rd, result);
    } else {
        cpu.set_w(rd, result as u32);
    }
    Ok(Step::Next)
}

fn bitfield(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let opc = (word >> 29) & 0b11; // 00 SBFM, 01 BFM, 10 UBFM
    let n = (word >> 22) & 1;
    let immr = (word >> 16) & 0x3f;
    let imms = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let datasize = if sf == 1 { 64 } else { 32 };
    if n != sf {
        return Err(unsupported(cpu, word, "bitfield/N"));
    }
    let Some((wmask, tmask)) = decode_bit_masks(n, imms, immr, false, datasize) else {
        return Err(unsupported(cpu, word, "bitfield/reserved"));
    };
    let src = mask_width(cpu.x(rn), sf);
    let dst = if opc == 0b01 {
        mask_width(cpu.x(rd), sf) // BFM keeps destination bits
    } else {
        0
    };
    let bot = (dst & !wmask) | (ror_in(src, immr, datasize) & wmask);
    // Top bits: SBFM replicates the sign bit at position `imms`; BFM keeps the
    // original destination bits; UBFM zero-fills.
    let top = match opc {
        0b00 => {
            if (src >> imms) & 1 == 1 {
                ones(datasize)
            } else {
                0
            }
        }
        0b01 => dst,
        _ => 0,
    };
    let result = (top & !tmask) | (bot & tmask);
    let result = mask_width(result, sf);
    if sf == 1 {
        cpu.set_x(rd, result);
    } else {
        cpu.set_w(rd, result as u32);
    }
    Ok(Step::Next)
}

fn extract(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let rm = (word >> 16) & 0x1f;
    let imms = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let lsb = imms;
    let result = if sf == 1 {
        let hi = u128::from(cpu.x(rn));
        let lo = u128::from(cpu.x(rm));
        (((hi << 64) | lo) >> lsb) as u64
    } else {
        let hi = u64::from(cpu.w(rn));
        let lo = u64::from(cpu.w(rm));
        (((hi << 32) | lo) >> lsb) as u32 as u64
    };
    if sf == 1 {
        cpu.set_x(rd, result);
    } else {
        cpu.set_w(rd, result as u32);
    }
    Ok(Step::Next)
}
