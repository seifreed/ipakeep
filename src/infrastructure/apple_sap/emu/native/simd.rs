//! SIMD/FP + crypto-extension (NEON, scalar FP, `eor3`) — the small vector
//! surface the OTP whitebox uses (~0.01% of executed instructions).
//!
//! This implements exactly the Advanced-SIMD / scalar-FP / crypto encodings the
//! Apple ADI whitebox exercises, validated differentially against Unicorn. It is
//! deliberately partial: any encoding outside that set reports
//! [`NativeError::Unsupported`].

use super::{NativeCpu, NativeError, Step};

fn unsupported(cpu: &NativeCpu, word: u32, what: &'static str) -> NativeError {
    NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what,
    }
}

// ---------------------------------------------------------------------------
// Lane helpers (packed little-endian; lane 0 = least-significant bits)
// ---------------------------------------------------------------------------

/// Extracts lane `idx` of width `esize` bits (`esize <= 64`) from `value`.
fn get_lane(value: u128, idx: u32, esize: u32) -> u64 {
    let mask: u128 = (1u128 << esize) - 1;
    ((value >> (idx * esize)) & mask) as u64
}

/// Inserts `lane` into lane `idx` of width `esize` bits (`esize <= 64`).
fn set_lane(acc: &mut u128, idx: u32, esize: u32, lane: u64) {
    let mask: u128 = (1u128 << esize) - 1;
    let shift = idx * esize;
    *acc = (*acc & !(mask << shift)) | (((lane as u128) & mask) << shift);
}

/// Sign-extends the low `bits` of `value` to 64 bits.
fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    ((value << shift) as i64 >> shift) as u64
}

/// Applies `ExtendRegister` (option/shift) for register-offset addressing.
fn extend_reg(value: u64, option: u32, shift: u32) -> u64 {
    let extended = if option & 1 == 0 {
        if option & 0b100 != 0 {
            (value as u32 as i32 as i64) as u64 // SXTW
        } else {
            value & 0xffff_ffff // UXTW
        }
    } else {
        value // UXTX / SXTX (LSL)
    };
    extended.wrapping_shl(shift)
}

// ---------------------------------------------------------------------------
// Integer -> floating-point conversion (round to nearest, ties to even),
// computed with integer arithmetic so no precision-losing float cast is needed.
// ---------------------------------------------------------------------------

/// Converts an unsigned integer to IEEE-754 `binary32` bits (RNE).
fn u_to_f32_bits(value: u64) -> u32 {
    if value == 0 {
        return 0;
    }
    let nbits = 64 - value.leading_zeros();
    let (mantissa, exp_unbiased) = if nbits <= 24 {
        ((value << (24 - nbits)) as u32, (nbits as i32) - 1)
    } else {
        let shift = nbits - 24;
        let truncated = (value >> shift) as u32;
        let remainder = value & ((1u64 << shift) - 1);
        let halfway = 1u64 << (shift - 1);
        let mut mantissa = truncated;
        if remainder > halfway || (remainder == halfway && (truncated & 1) == 1) {
            mantissa += 1;
        }
        let mut exp = (nbits as i32) - 1;
        if mantissa >> 24 != 0 {
            mantissa >>= 1;
            exp += 1;
        }
        (mantissa, exp)
    };
    let exp_field = (exp_unbiased + 127) as u32;
    (exp_field << 23) | (mantissa & 0x7f_ffff)
}

/// Converts an unsigned integer to IEEE-754 `binary64` bits (RNE).
fn u_to_f64_bits(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let nbits = 64 - value.leading_zeros();
    let (mantissa, exp_unbiased) = if nbits <= 53 {
        (value << (53 - nbits), (nbits as i32) - 1)
    } else {
        let shift = nbits - 53;
        let truncated = value >> shift;
        let remainder = value & ((1u64 << shift) - 1);
        let halfway = 1u64 << (shift - 1);
        let mut mantissa = truncated;
        if remainder > halfway || (remainder == halfway && (truncated & 1) == 1) {
            mantissa += 1;
        }
        let mut exp = (nbits as i32) - 1;
        if mantissa >> 53 != 0 {
            mantissa >>= 1;
            exp += 1;
        }
        (mantissa, exp)
    };
    let exp_field = (exp_unbiased + 1023) as u64;
    (exp_field << 52) | (mantissa & 0xf_ffff_ffff_ffff)
}

/// `VFPExpandImm` for a 32-bit float immediate (`imm8` from the encoding).
fn vfp_expand_imm32(imm8: u32) -> u32 {
    let sign = (imm8 >> 7) & 1;
    let b = (imm8 >> 6) & 1;
    let b5 = if b == 1 { 0b1_1111 } else { 0 };
    // exp[7:0] = NOT(b) : b*5 : imm8<5:4>
    let exp = ((b ^ 1) << 7) | (b5 << 2) | ((imm8 >> 4) & 3);
    let frac = (imm8 & 0xf) << 19;
    (sign << 31) | (exp << 23) | frac
}

/// `VFPExpandImm` for a 64-bit float immediate (`imm8` from the encoding).
fn vfp_expand_imm64(imm8: u32) -> u64 {
    let sign = u64::from((imm8 >> 7) & 1);
    let b = u64::from((imm8 >> 6) & 1);
    let b8: u64 = if b == 1 { 0xff } else { 0 };
    // exp[10:0] = NOT(b) : b*8 : imm8<5:4>
    let exp = ((b ^ 1) << 10) | (b8 << 2) | u64::from((imm8 >> 4) & 3);
    let frac = u64::from(imm8 & 0xf) << 48;
    (sign << 63) | (exp << 52) | frac
}

// ---------------------------------------------------------------------------
// Top-level dispatch
// ---------------------------------------------------------------------------

/// Runs a data-processing SIMD/FP instruction.
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    // EOR3 (SHA3 four-register crypto): bits[31:21] == 11001110000, bit15 == 0.
    if word & 0xffe0_8000 == 0xce00_0000 {
        return eor3(cpu, word);
    }

    let op = (word >> 24) & 0x1f; // bits[28:24]
    // Scalar floating-point: bits[28:24] == 11110, bit30 == 0.
    if op == 0b11110 && (word >> 30) & 1 == 0 {
        return scalar_fp(cpu, word);
    }

    // Advanced SIMD vector classes all have bit31 == 0.
    if (word >> 31) & 1 == 0 {
        match op {
            0b01110 => return simd_three_copy_table(cpu, word),
            0b01111 => return simd_imm_or_shift(cpu, word),
            _ => {}
        }
    }

    Err(unsupported(cpu, word, "simd/fp"))
}

fn eor3(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let rm = (word >> 16) & 0x1f;
    let ra = (word >> 10) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let res = cpu.v(rn) ^ cpu.v(rm) ^ cpu.v(ra);
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

// ---------------------------------------------------------------------------
// Advanced SIMD: three-same / three-different / copy (DUP) / table (TBL)
// bits[28:24] == 01110
// ---------------------------------------------------------------------------

fn simd_three_copy_table(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let bit21 = (word >> 21) & 1;
    let low2 = (word >> 10) & 3; // bits[11:10]
    let size = (word >> 22) & 3;
    if bit21 == 1 {
        if (word >> 10) & 1 == 1 {
            return three_same(cpu, word);
        }
        if low2 == 0 {
            return three_different(cpu, word);
        }
        return Err(unsupported(cpu, word, "simd/three"));
    }
    // bit21 == 0: copy (DUP) and table (TBL) share size==00, bit15==0.
    if size == 0 && (word >> 15) & 1 == 0 {
        if (word >> 10) & 1 == 1 {
            return copy_dup(cpu, word);
        }
        return table_tbl(cpu, word);
    }
    Err(unsupported(cpu, word, "simd/three"))
}

fn three_same(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let size = (word >> 22) & 3;
    let rm = (word >> 16) & 0x1f;
    let opcode = (word >> 11) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let vn = cpu.v(rn);
    let vm = cpu.v(rm);
    let esize = 8u32 << size;
    let lanes = if q == 1 { 128 / esize } else { 64 / esize };
    let mut res: u128 = 0;

    match opcode {
        // Logical by (U, size) — operate on the full register width.
        0b00011 => {
            res = match (u, size) {
                (0, 0b00) => vn & vm, // AND
                (0, 0b10) => vn | vm, // ORR / MOV
                (1, 0b00) => vn ^ vm, // EOR
                _ => return Err(unsupported(cpu, word, "simd/three")),
            };
        }
        // ADD (U==0) / SUB (U==1).
        0b10000 => {
            for idx in 0..lanes {
                let lhs = get_lane(vn, idx, esize);
                let rhs = get_lane(vm, idx, esize);
                let lane = if u == 0 {
                    lhs.wrapping_add(rhs)
                } else {
                    lhs.wrapping_sub(rhs)
                };
                set_lane(&mut res, idx, esize, lane);
            }
        }
        // MUL (U==0).
        0b10011 if u == 0 => {
            for idx in 0..lanes {
                let lane = get_lane(vn, idx, esize).wrapping_mul(get_lane(vm, idx, esize));
                set_lane(&mut res, idx, esize, lane);
            }
        }
        // MLA (U==0) / MLS (U==1).
        0b10010 => {
            let vd = cpu.v(rd);
            for idx in 0..lanes {
                let prod = get_lane(vn, idx, esize).wrapping_mul(get_lane(vm, idx, esize));
                let acc = get_lane(vd, idx, esize);
                let lane = if u == 0 {
                    acc.wrapping_add(prod)
                } else {
                    acc.wrapping_sub(prod)
                };
                set_lane(&mut res, idx, esize, lane);
            }
        }
        // USHL (U==1): per-lane logical shift by the signed low byte of Vm.
        0b01000 if u == 1 => {
            for idx in 0..lanes {
                let lane = ushl_lane(
                    get_lane(vn, idx, esize),
                    get_lane(vm, idx, esize) as u8 as i8,
                    esize,
                );
                set_lane(&mut res, idx, esize, lane);
            }
        }
        _ => return Err(unsupported(cpu, word, "simd/three")),
    }

    if q == 0 {
        res &= (1u128 << 64) - 1;
    }
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

/// Unsigned register shift of one lane (USHL semantics).
fn ushl_lane(value: u64, shift: i8, esize: u32) -> u64 {
    let mask = if esize == 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };
    let value = value & mask;
    if shift >= 0 {
        let amount = shift as u32;
        if amount >= esize {
            0
        } else {
            (value << amount) & mask
        }
    } else {
        let amount = (-(i32::from(shift))) as u32;
        if amount >= esize { 0 } else { value >> amount }
    }
}

fn three_different(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let size = (word >> 22) & 3;
    let rm = (word >> 16) & 0x1f;
    let opcode = (word >> 12) & 0xf;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    // UMULL / UMULL2 only (U==1, opcode==1100).
    if !(u == 1 && opcode == 0b1100) {
        return Err(unsupported(cpu, word, "simd/three-diff"));
    }
    let esize = 8u32 << size; // source element: 8/16/32
    let dsize = esize * 2;
    let lanes = 64 / esize;
    let base = if q == 1 { lanes } else { 0 }; // UMULL2 reads the high half
    let vn = cpu.v(rn);
    let vm = cpu.v(rm);
    let mut res: u128 = 0;
    for idx in 0..lanes {
        let prod = get_lane(vn, base + idx, esize).wrapping_mul(get_lane(vm, base + idx, esize));
        set_lane(&mut res, idx, dsize, prod);
    }
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

fn copy_dup(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let imm5 = (word >> 16) & 0x1f;
    let imm4 = (word >> 11) & 0xf;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let size = if imm5 & 1 != 0 {
        0
    } else if imm5 & 2 != 0 {
        1
    } else if imm5 & 4 != 0 {
        2
    } else if imm5 & 8 != 0 {
        3
    } else {
        return Err(unsupported(cpu, word, "simd/dup"));
    };
    let esize = 8u32 << size;
    let lanes = if q == 1 { 128 / esize } else { 64 / esize };

    // UMOV / SMOV: move one vector element into a general-purpose register.
    if imm4 == 0b0111 || imm4 == 0b0101 {
        let index = imm5 >> (size + 1);
        let elem = get_lane(cpu.v(rn), index, esize);
        let value = if imm4 == 0b0101 {
            // SMOV: sign-extend the element.
            let shift = 64 - esize;
            (((elem << shift) as i64) >> shift) as u64
        } else {
            elem // UMOV: zero-extend.
        };
        if q == 1 {
            cpu.set_x(rd, value);
        } else {
            cpu.set_w(rd, value as u32);
        }
        return Ok(Step::Next);
    }

    // INS (general): insert a general-purpose register into one vector lane.
    if imm4 == 0b0011 {
        let index = imm5 >> (size + 1);
        let elem = match size {
            0 => u64::from(cpu.w(rn) & 0xff),
            1 => u64::from(cpu.w(rn) & 0xffff),
            2 => u64::from(cpu.w(rn)),
            _ => cpu.x(rn),
        };
        let mut vreg = cpu.v(rd);
        set_lane(&mut vreg, index, esize, elem);
        cpu.set_v(rd, vreg);
        return Ok(Step::Next);
    }

    let element = match imm4 {
        0b0000 => get_lane(cpu.v(rn), imm5 >> (size + 1), esize), // DUP element
        0b0001 => match size {
            0 => u64::from(cpu.w(rn) & 0xff),
            1 => u64::from(cpu.w(rn) & 0xffff),
            2 => u64::from(cpu.w(rn)),
            _ => cpu.x(rn),
        },
        _ => return Err(unsupported(cpu, word, "simd/dup")),
    };

    let mut res: u128 = 0;
    for idx in 0..lanes {
        set_lane(&mut res, idx, esize, element);
    }
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

fn table_tbl(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let rm = (word >> 16) & 0x1f;
    let len = (word >> 13) & 3;
    let op = (word >> 12) & 1;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let count = if q == 1 { 16 } else { 8 };
    let numregs = len + 1;
    let indices = cpu.v(rm);
    let old = cpu.v(rd);
    let mut res: u128 = 0;
    for i in 0..count {
        let index = ((indices >> (i * 8)) & 0xff) as u32;
        let byte = if index < 16 * numregs {
            let reg = (rn + index / 16) % 32;
            ((cpu.v(reg) >> ((index % 16) * 8)) & 0xff) as u8
        } else if op == 1 {
            ((old >> (i * 8)) & 0xff) as u8 // TBX keeps the old byte
        } else {
            0 // TBL writes zero
        };
        res |= u128::from(byte) << (i * 8);
    }
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

// ---------------------------------------------------------------------------
// Advanced SIMD: modified immediate (MOVI) / shift-by-immediate
// bits[28:24] == 01111
// ---------------------------------------------------------------------------

fn simd_imm_or_shift(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    if (word >> 10) & 1 == 0 {
        return Err(unsupported(cpu, word, "simd/imm")); // vector x indexed element
    }
    // Modified immediate when immh (bits[22:19]) == 0; otherwise shift by imm.
    let immh = (word >> 19) & 0xf;
    if immh == 0 {
        modified_immediate(cpu, word)
    } else {
        shift_immediate(cpu, word)
    }
}

/// `AdvSIMDExpandImm` plus the MOVI/MVNI/FMOV operation select, returning the
/// 64-bit lane pattern (`None` for the ORR/BIC immediate forms we don't model).
fn adv_simd_expand_imm(op: u32, cmode: u32, imm8: u64) -> Option<u64> {
    match cmode {
        // 32-bit shifted immediate (MOVI / MVNI, lsl #0/8/16/24).
        0b0000 | 0b0010 | 0b0100 | 0b0110 => {
            let shift = ((cmode >> 1) & 3) * 8;
            let value = imm8 << shift;
            let lane = if op == 1 {
                !value & 0xffff_ffff
            } else {
                value & 0xffff_ffff
            };
            Some(lane | (lane << 32))
        }
        // 16-bit shifted immediate (MOVI / MVNI, lsl #0/8).
        0b1000 | 0b1010 => {
            let shift = ((cmode >> 1) & 1) * 8;
            let value = (imm8 << shift) & 0xffff;
            let lane = if op == 1 { !value & 0xffff } else { value };
            Some(lane | (lane << 16) | (lane << 32) | (lane << 48))
        }
        // 32-bit, MSL #8.
        0b1100 => {
            let value = ((imm8 << 8) | 0xff) & 0xffff_ffff;
            let lane = if op == 1 { !value & 0xffff_ffff } else { value };
            Some(lane | (lane << 32))
        }
        // 32-bit, MSL #16.
        0b1101 => {
            let value = ((imm8 << 16) | 0xffff) & 0xffff_ffff;
            let lane = if op == 1 { !value & 0xffff_ffff } else { value };
            Some(lane | (lane << 32))
        }
        // 8-bit (op==0) or 64-bit byte-expand (op==1, MOVI Dn / .2d).
        0b1110 => {
            if op == 0 {
                let byte = imm8 & 0xff;
                let mut lane = 0u64;
                for i in 0..8 {
                    lane |= byte << (i * 8);
                }
                Some(lane)
            } else {
                let mut lane = 0u64;
                for i in 0..8 {
                    if (imm8 >> i) & 1 == 1 {
                        lane |= 0xffu64 << (i * 8);
                    }
                }
                Some(lane)
            }
        }
        // FMOV vector immediate (single when op==0, double when op==1).
        0b1111 => {
            if op == 0 {
                let lane = u64::from(vfp_expand_imm32(imm8 as u32));
                Some(lane | (lane << 32))
            } else {
                Some(vfp_expand_imm64(imm8 as u32))
            }
        }
        // ORR/BIC (vector, immediate) — not modelled.
        _ => None,
    }
}

fn modified_immediate(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let op = (word >> 29) & 1;
    let cmode = (word >> 12) & 0xf;
    let abc = (word >> 16) & 0x7;
    let defgh = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let imm8 = u64::from((abc << 5) | defgh);

    let Some(lane) = adv_simd_expand_imm(op, cmode, imm8) else {
        return Err(unsupported(cpu, word, "simd/movi"));
    };
    let res = if q == 1 {
        u128::from(lane) | (u128::from(lane) << 64)
    } else {
        u128::from(lane)
    };
    cpu.set_v(rd, res);
    Ok(Step::Next)
}

/// Element width (bits) selected by `immh`, or `None` when `immh == 0`.
fn esize_from_immh(immh: u32) -> Option<u32> {
    if immh & 0b1000 != 0 {
        Some(64)
    } else if immh & 0b0100 != 0 {
        Some(32)
    } else if immh & 0b0010 != 0 {
        Some(16)
    } else if immh & 0b0001 != 0 {
        Some(8)
    } else {
        None
    }
}

fn shift_immediate(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let immh = (word >> 19) & 0xf;
    let immb = (word >> 16) & 0x7;
    let opcode = (word >> 11) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let immhb = (immh << 3) | immb;
    let Some(esize) = esize_from_immh(immh) else {
        return Err(unsupported(cpu, word, "simd/shift"));
    };
    let vn = cpu.v(rn);

    match (u, opcode) {
        // USHR (U==1): per-lane logical right shift.
        (1, 0b00000) => {
            let shift = 2 * esize - immhb;
            let lanes = if q == 1 { 128 / esize } else { 64 / esize };
            let mut res: u128 = 0;
            for idx in 0..lanes {
                let lane = if shift >= esize {
                    0
                } else {
                    get_lane(vn, idx, esize) >> shift
                };
                set_lane(&mut res, idx, esize, lane);
            }
            cpu.set_v(rd, res);
        }
        // SHRN / SHRN2 (U==0): narrow (2*esize -> esize) with right shift.
        (0, 0b10000) => {
            let shift = 2 * esize - immhb;
            let lanes = 64 / esize;
            let mut narrow: u128 = 0;
            for idx in 0..lanes {
                let lane = get_lane(vn, idx, 2 * esize) >> shift;
                set_lane(&mut narrow, idx, esize, lane);
            }
            if q == 0 {
                cpu.set_v(rd, narrow);
            } else {
                let low = cpu.v(rd) & ((1u128 << 64) - 1);
                cpu.set_v(rd, low | (narrow << 64));
            }
        }
        // USHLL / USHLL2 (U==1): widen (esize -> 2*esize) with left shift.
        (1, 0b10100) => {
            let shift = immhb - esize;
            let dsize = esize * 2;
            let lanes = 64 / esize;
            let base = if q == 1 { lanes } else { 0 };
            let mut res: u128 = 0;
            for idx in 0..lanes {
                let lane = get_lane(vn, base + idx, esize) << shift;
                set_lane(&mut res, idx, dsize, lane);
            }
            cpu.set_v(rd, res);
        }
        _ => return Err(unsupported(cpu, word, "simd/shift")),
    }
    Ok(Step::Next)
}

// ---------------------------------------------------------------------------
// Scalar floating-point (single/double) — bits[28:24] == 11110
// ---------------------------------------------------------------------------

fn scalar_fp(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    if (word >> 21) & 1 != 1 {
        return Err(unsupported(cpu, word, "simd/fp-scalar"));
    }
    // Conversion between FP and integer: bits[15:10] == 000000.
    let low6 = (word >> 10) & 0x3f;
    if low6 == 0 {
        return fp_convert(cpu, word);
    }
    // FP data-processing (1 source): bits[14:10] == 10000.
    if (word >> 10) & 0x1f == 0b10000 {
        return fp_one_source(cpu, word);
    }
    // FP data-processing (2 source): bits[11:10] == 10.
    if (word >> 10) & 0x3 == 0b10 {
        return fp_two_source(cpu, word);
    }
    // FP immediate: bits[12:10] == 100.
    if (word >> 10) & 0x7 == 0b100 {
        return fp_immediate(cpu, word);
    }
    // FP compare: bits[13:10] == 1000 (bits[15:14] == 00).
    let op1514 = (word >> 14) & 0x3;
    if (word >> 10) & 0xf == 0b1000 && op1514 == 0 {
        return fp_compare(cpu, word);
    }
    Err(unsupported(cpu, word, "simd/fp-scalar"))
}

fn fp_convert(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let ptype = (word >> 22) & 3;
    let rmode = (word >> 19) & 3;
    let opcode = (word >> 16) & 7;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    match opcode {
        // UCVTF (unsigned integer -> floating-point), rmode == 00.
        0b011 if rmode == 0 => {
            let int = if sf == 1 {
                cpu.x(rn)
            } else {
                u64::from(cpu.w(rn))
            };
            match ptype {
                0b00 => cpu.set_v(rd, u128::from(u_to_f32_bits(int))),
                0b01 => cpu.set_v(rd, u128::from(u_to_f64_bits(int))),
                _ => return Err(unsupported(cpu, word, "simd/ucvtf")),
            }
        }
        // FMOV between a general register and a SIMD/FP register.
        0b110 | 0b111 => {
            let to_vec = opcode == 0b111;
            if rmode == 0 && ptype == 0b00 && sf == 0 {
                // 32-bit: Sn <-> Wn.
                if to_vec {
                    let src = cpu.w(rn);
                    cpu.set_v(rd, u128::from(src));
                } else {
                    let src = cpu.v(rn) as u32;
                    cpu.set_w(rd, src);
                }
            } else if rmode == 0 && ptype == 0b01 && sf == 1 {
                // 64-bit: Dn <-> Xn.
                if to_vec {
                    let src = cpu.x(rn);
                    cpu.set_v(rd, u128::from(src));
                } else {
                    let src = cpu.v(rn) as u64;
                    cpu.set_x(rd, src);
                }
            } else if rmode == 0b01 && ptype == 0b10 && sf == 1 {
                // High 64 bits: Vn.d[1] <-> Xn.
                if to_vec {
                    let low = cpu.v(rd) & ((1u128 << 64) - 1);
                    let src = u128::from(cpu.x(rn));
                    cpu.set_v(rd, low | (src << 64));
                } else {
                    let src = (cpu.v(rn) >> 64) as u64;
                    cpu.set_x(rd, src);
                }
            } else {
                return Err(unsupported(cpu, word, "simd/fmov"));
            }
        }
        _ => return Err(unsupported(cpu, word, "simd/fp-convert")),
    }
    Ok(Step::Next)
}

fn fp_one_source(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let ptype = (word >> 22) & 3;
    let opcode = (word >> 15) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    match opcode {
        // FMOV (register).
        0b000000 => match ptype {
            0b00 => cpu.set_v(rd, u128::from(cpu.v(rn) as u32)),
            0b01 => cpu.set_v(rd, u128::from(cpu.v(rn) as u64)),
            _ => return Err(unsupported(cpu, word, "simd/fmov")),
        },
        // FNEG — flip the sign bit (exact, no NaN canonicalisation).
        0b000010 => match ptype {
            0b00 => {
                let bits = (cpu.v(rn) as u32) ^ 0x8000_0000;
                cpu.set_v(rd, u128::from(bits));
            }
            0b01 => {
                let bits = (cpu.v(rn) as u64) ^ 0x8000_0000_0000_0000;
                cpu.set_v(rd, u128::from(bits));
            }
            _ => return Err(unsupported(cpu, word, "simd/fneg")),
        },
        _ => return Err(unsupported(cpu, word, "simd/fp-1src")),
    }
    Ok(Step::Next)
}

fn fp_two_source(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let ptype = (word >> 22) & 3;
    let rm = (word >> 16) & 0x1f;
    let opcode = (word >> 12) & 0xf;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    // FMUL only.
    if opcode != 0b0000 {
        return Err(unsupported(cpu, word, "simd/fp-2src"));
    }
    match ptype {
        0b00 => {
            let lhs = f32::from_bits(cpu.v(rn) as u32);
            let rhs = f32::from_bits(cpu.v(rm) as u32);
            cpu.set_v(rd, u128::from((lhs * rhs).to_bits()));
        }
        0b01 => {
            let lhs = f64::from_bits(cpu.v(rn) as u64);
            let rhs = f64::from_bits(cpu.v(rm) as u64);
            cpu.set_v(rd, u128::from((lhs * rhs).to_bits()));
        }
        _ => return Err(unsupported(cpu, word, "simd/fmul")),
    }
    Ok(Step::Next)
}

fn fp_immediate(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let ptype = (word >> 22) & 3;
    let imm8 = (word >> 13) & 0xff;
    let rd = word & 0x1f;
    match ptype {
        0b00 => cpu.set_v(rd, u128::from(vfp_expand_imm32(imm8))),
        0b01 => cpu.set_v(rd, u128::from(vfp_expand_imm64(imm8))),
        _ => return Err(unsupported(cpu, word, "simd/fmov-imm")),
    }
    Ok(Step::Next)
}

/// NZCV (bits [31:28]) for a floating-point compare of `lhs` against `rhs`.
fn fcmp_flags32(lhs: f32, rhs: f32) -> u32 {
    if lhs.is_nan() || rhs.is_nan() {
        0x3000_0000 // unordered: C, V
    } else if lhs < rhs {
        0x8000_0000 // N
    } else if lhs > rhs {
        0x2000_0000 // C
    } else {
        0x6000_0000 // equal: Z, C
    }
}

fn fcmp_flags64(lhs: f64, rhs: f64) -> u32 {
    if lhs.is_nan() || rhs.is_nan() {
        0x3000_0000
    } else if lhs < rhs {
        0x8000_0000
    } else if lhs > rhs {
        0x2000_0000
    } else {
        0x6000_0000
    }
}

fn fp_compare(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let ptype = (word >> 22) & 3;
    let rm = (word >> 16) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let opcode2 = word & 0x1f;
    let cmp_zero = opcode2 & 0b01000 != 0; // compare against #0.0

    let nzcv = match ptype {
        0b00 => {
            let lhs = f32::from_bits(cpu.v(rn) as u32);
            let rhs = if cmp_zero {
                0.0
            } else {
                f32::from_bits(cpu.v(rm) as u32)
            };
            fcmp_flags32(lhs, rhs)
        }
        0b01 => {
            let lhs = f64::from_bits(cpu.v(rn) as u64);
            let rhs = if cmp_zero {
                0.0
            } else {
                f64::from_bits(cpu.v(rm) as u64)
            };
            fcmp_flags64(lhs, rhs)
        }
        _ => return Err(unsupported(cpu, word, "simd/fcmp")),
    };
    cpu.set_nzcv(nzcv);
    Ok(Step::Next)
}

// ---------------------------------------------------------------------------
// Vector load/store (the V == 1 forms delegated by `ldst::run`)
// ---------------------------------------------------------------------------

/// Runs a SIMD/FP load/store.
pub(super) fn load_store(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let group = (word >> 27) & 0x7; // bits[29:27]
    let op24 = (word >> 24) & 3;
    match group {
        0b111 => ldst_register(cpu, word),
        0b101 => ldst_pair(cpu, word),
        0b011 if op24 == 0 => ldst_literal(cpu, word),
        _ => Err(unsupported(cpu, word, "simd/ldst")),
    }
}

/// Stores the low `bytes` of `value` to `addr`.
fn store_vec(cpu: &mut NativeCpu, addr: u64, bytes: usize, value: u128) -> Result<(), NativeError> {
    let buf = value.to_le_bytes();
    cpu.mem.write(addr, &buf[..bytes])
}

/// Loads `bytes` from `addr` into a zero-extended 128-bit value.
fn load_vec(cpu: &NativeCpu, addr: u64, bytes: usize) -> Result<u128, NativeError> {
    let mut buf = [0u8; 16];
    cpu.mem.read(addr, &mut buf[..bytes])?;
    Ok(u128::from_le_bytes(buf))
}

fn ldst_register(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let size = (word >> 30) & 3;
    let opc = (word >> 22) & 3;
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let log2 = ((opc >> 1) << 2) | size; // transfer width (log2 bytes)
    if log2 > 4 {
        return Err(unsupported(cpu, word, "simd/ldst"));
    }
    let bytes = 1usize << log2;
    let is_load = opc & 1 == 1;

    let base = cpu.x_sp(rn);
    let (addr, writeback) = if (word >> 24) & 1 == 1 {
        // Unsigned offset (scaled imm12).
        let imm12 = u64::from((word >> 10) & 0xfff);
        (base.wrapping_add(imm12 << log2), None)
    } else if (word >> 21) & 1 == 1 {
        // Register offset (bits[11:10] == 10).
        if (word >> 10) & 3 != 0b10 {
            return Err(unsupported(cpu, word, "simd/ldst"));
        }
        let rm = (word >> 16) & 0x1f;
        let option = (word >> 13) & 7;
        let scale = if (word >> 12) & 1 == 1 { log2 } else { 0 };
        let index = extend_reg(cpu.x(rm), option, scale);
        (base.wrapping_add(index), None)
    } else {
        // imm9 unscaled / pre- / post-indexed.
        let imm9 = sign_extend(u64::from((word >> 12) & 0x1ff), 9);
        match (word >> 10) & 3 {
            0b00 => (base.wrapping_add(imm9), None),       // LDUR/STUR
            0b01 => (base, Some(base.wrapping_add(imm9))), // post-indexed
            0b11 => {
                let a = base.wrapping_add(imm9);
                (a, Some(a)) // pre-indexed
            }
            _ => return Err(unsupported(cpu, word, "simd/ldst")),
        }
    };

    if is_load {
        let value = load_vec(cpu, addr, bytes)?;
        cpu.set_v(rt, value);
    } else {
        store_vec(cpu, addr, bytes, cpu.v(rt))?;
    }
    if let Some(new_base) = writeback {
        cpu.set_x_sp(rn, new_base);
    }
    Ok(Step::Next)
}

fn ldst_pair(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let opc = (word >> 30) & 3;
    let l = (word >> 22) & 1;
    let rt = word & 0x1f;
    let rt2 = (word >> 10) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let bytes = match opc {
        0b00 => 4usize,
        0b01 => 8,
        0b10 => 16,
        _ => return Err(unsupported(cpu, word, "simd/ldp")),
    };
    let imm7 = sign_extend(u64::from((word >> 15) & 0x7f), 7);
    let offset = imm7.wrapping_mul(bytes as u64);

    let base = cpu.x_sp(rn);
    let (addr, writeback) = match (word >> 23) & 3 {
        0b00 => (base.wrapping_add(offset), None), // STNP/LDNP
        0b01 => (base, Some(base.wrapping_add(offset))), // post-indexed
        0b10 => (base.wrapping_add(offset), None), // signed offset
        0b11 => {
            let a = base.wrapping_add(offset);
            (a, Some(a)) // pre-indexed
        }
        _ => unreachable!(),
    };
    let addr2 = addr.wrapping_add(bytes as u64);

    if l == 0 {
        store_vec(cpu, addr, bytes, cpu.v(rt))?;
        store_vec(cpu, addr2, bytes, cpu.v(rt2))?;
    } else {
        let v1 = load_vec(cpu, addr, bytes)?;
        let v2 = load_vec(cpu, addr2, bytes)?;
        cpu.set_v(rt, v1);
        cpu.set_v(rt2, v2);
    }
    if let Some(new_base) = writeback {
        cpu.set_x_sp(rn, new_base);
    }
    Ok(Step::Next)
}

fn ldst_literal(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let opc = (word >> 30) & 3;
    let rt = word & 0x1f;
    let imm19 = (word >> 5) & 0x7_ffff;
    let offset = sign_extend(u64::from(imm19), 19) << 2;
    let addr = cpu.pc().wrapping_add(offset);
    let bytes = match opc {
        0b00 => 4usize,
        0b01 => 8,
        0b10 => 16,
        _ => return Err(unsupported(cpu, word, "simd/ldr-lit")),
    };
    let value = load_vec(cpu, addr, bytes)?;
    cpu.set_v(rt, value);
    Ok(Step::Next)
}

#[cfg(all(test, feature = "unicorn"))]
mod tests {
    use super::super::diff::{Init, check, init_x};

    const DATA: u64 = 0x2_0000;

    fn init_v(pairs: &[(usize, u128)]) -> Init {
        let mut init = Init::default();
        for (n, value) in pairs {
            init.v[*n] = *value;
        }
        init
    }

    // --- crypto -----------------------------------------------------------

    #[test]
    fn eor3_xors_three_registers() {
        // eor3 v0.16b, v1.16b, v2.16b, v3.16b
        let v1 = 0x1111_1111_2222_2222_3333_3333_4444_4444u128;
        let v2 = 0x0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0f_0f0fu128;
        let v3 = 0x00ff_00ff_00ff_00ff_00ff_00ff_00ff_00ffu128;
        let d = check(&[0xce02_0c20], init_v(&[(1, v1), (2, v2), (3, v3)]));
        assert_eq!(d.v[0], v1 ^ v2 ^ v3);
    }

    // --- vector three-same ------------------------------------------------

    #[test]
    fn add_sub_4s() {
        // add v0.4s, v1.4s, v2.4s ; sub v3.4s, v1.4s, v2.4s
        check(
            &[0x4ea2_8420, 0x6ea2_8423],
            init_v(&[
                (1, 0x0000_0005_0000_0004_0000_0003_0000_0002),
                (2, 0x0000_0001_0000_0001_0000_0001_0000_0001),
            ]),
        );
    }

    #[test]
    fn add_2d_and_16b() {
        // add v0.2d, v1.2d, v2.2d ; add v3.16b, v1.16b, v2.16b
        check(
            &[0x4ee2_8420, 0x4e22_8423],
            init_v(&[
                (1, 0xdead_beef_cafe_f00d_0123_4567_89ab_cdef),
                (2, 0x1111_1111_1111_1111_0101_0101_0101_0101),
            ]),
        );
    }

    #[test]
    fn mul_8h() {
        // mul v0.8h, v1.8h, v2.8h
        check(
            &[0x4e62_9c20],
            init_v(&[
                (1, 0x0007_0006_0005_0004_0003_0002_0001_0009),
                (2, 0x0002_0002_0002_0002_0002_0002_0002_0003),
            ]),
        );
    }

    #[test]
    fn mla_mls_4s() {
        // mla v0.4s, v1.4s, v2.4s ; mls v3.4s, v1.4s, v2.4s
        check(
            &[0x4ea2_9420, 0x6ea2_9423],
            init_v(&[
                (0, 0x0000_0100_0000_0100_0000_0100_0000_0100),
                (1, 0x0000_0002_0000_0003_0000_0004_0000_0005),
                (2, 0x0000_0003_0000_0003_0000_0003_0000_0003),
                (3, 0x0000_1000_0000_1000_0000_1000_0000_1000),
            ]),
        );
    }

    #[test]
    fn logical_and_orr_eor_16b() {
        // and v0.16b,v1,v2 ; orr v3.16b,v1,v2 ; eor v4.16b,v1,v2
        check(
            &[0x4e22_1c20, 0x4ea2_1c23, 0x6e22_1c24],
            init_v(&[
                (1, 0xf0f0_f0f0_ffff_0000_aaaa_5555_1234_5678),
                (2, 0x0ff0_0ff0_0f0f_f0f0_5555_aaaa_8765_4321),
            ]),
        );
    }

    #[test]
    fn mov_is_orr_same_reg_8b() {
        // mov v3.16b, v1.16b  (ORR Vd,Vn,Vn)
        let d = check(
            &[0x4ea1_1c23],
            init_v(&[(1, 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00)]),
        );
        assert_eq!(d.v[3], 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00);
    }

    #[test]
    fn ushl_register_4s_and_2d() {
        // ushl v0.4s, v1.4s, v2.4s ; ushl v3.2d, v1.2d, v2.2d
        check(
            &[0x6ea2_4420, 0x6ee2_4423],
            init_v(&[
                (1, 0x0000_00ff_8000_0001_0000_0001_ffff_ffff),
                // shift amounts (low byte of each lane): +4, -4, +8, -40
                (2, 0x0000_0004_0000_00fc_0000_0008_0000_00d8),
            ]),
        );
    }

    // --- widening multiply ------------------------------------------------

    #[test]
    fn umull_umull2_8h() {
        // umull v0.8h, v1.8b, v2.8b ; umull2 v3.8h, v1.16b, v2.16b
        check(
            &[0x2e22_c020, 0x6e22_c023],
            init_v(&[
                (1, 0x1020_3040_5060_7080_0102_0304_0506_0708),
                (2, 0x0203_0405_0607_0809_0a0b_0c0d_0e0f_1011),
            ]),
        );
    }

    #[test]
    fn umull_4s_from_4h() {
        // umull v5.4s, v1.4h, v2.4h
        check(
            &[0x2e62_c025],
            init_v(&[
                (1, 0x0000_0000_0000_0000_1111_2222_3333_4444),
                (2, 0x0000_0000_0000_0000_0002_0003_0004_0005),
            ]),
        );
    }

    // --- table lookup -----------------------------------------------------

    #[test]
    fn tbl_single_register() {
        // tbl v0.16b, {v1.16b}, v2.16b
        let d = check(
            &[0x4e02_0020],
            init_v(&[
                (1, 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100),
                // indices: 0,1,2,...,15 in low bytes but with some >=16 -> zero
                (2, 0xff00_1010_0e0c_0a08_0706_0503_0201_000f),
            ]),
        );
        // byte 0 of result = table[0x0f] = 0x0f
        assert_eq!(d.v[0] & 0xff, 0x0f);
        // top byte index 0xff >= 16 -> 0
        assert_eq!((d.v[0] >> 120) & 0xff, 0x00);
    }

    // --- DUP --------------------------------------------------------------

    #[test]
    fn dup_element_4s_and_16b() {
        // dup v0.4s, v1.s[1] ; dup v3.16b, v1.b[3]
        check(
            &[0x4e0c_0420, 0x4e07_0423],
            init_v(&[(1, 0xaabb_ccdd_1122_3344_5566_7788_99aa_bbcc)]),
        );
    }

    #[test]
    fn dup_general_4s_8h_2d() {
        // dup v0.4s, w1 ; dup v2.8h, w1 ; dup v3.2d, x1
        let d = check(
            &[0x4e04_0c20, 0x4e02_0c22, 0x4e08_0c23],
            init_x(&[(1, 0x1234_5678_9abc_def0)]),
        );
        assert_eq!(d.v[0], 0x9abc_def0_9abc_def0_9abc_def0_9abc_def0);
        assert_eq!(d.v[3], 0x1234_5678_9abc_def0_1234_5678_9abc_def0);
    }

    // --- MOVI -------------------------------------------------------------

    #[test]
    fn movi_32bit_lanes_shifts() {
        // movi v0.4s,#1 ; movi v1.4s,#0x11,lsl#8 ; movi v2.4s,#0x22,lsl#16 ; movi v3.4s,#0x33,lsl#24
        let d = check(
            &[0x4f00_0420, 0x4f00_2621, 0x4f01_4442, 0x4f01_6663],
            Init::default(),
        );
        assert_eq!(d.v[0], 0x0000_0001_0000_0001_0000_0001_0000_0001);
        assert_eq!(d.v[1], 0x0000_1100_0000_1100_0000_1100_0000_1100);
        assert_eq!(d.v[3], 0x3300_0000_3300_0000_3300_0000_3300_0000);
    }

    #[test]
    fn movi_byte_and_msl_and_2d() {
        // movi v0.16b,#0xaa ; movi v1.4s,#0x11,msl#8 ; movi v2.2d,#0xff00ff00ff00ff00
        let d = check(&[0x4f05_e540, 0x4f00_c621, 0x6f05_e542], Init::default());
        assert_eq!(d.v[0], 0xaaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa_aaaa);
        assert_eq!(d.v[1], 0x0000_11ff_0000_11ff_0000_11ff_0000_11ff);
        assert_eq!(d.v[2], 0xff00_ff00_ff00_ff00_ff00_ff00_ff00_ff00);
    }

    #[test]
    fn fmov_vector_immediate() {
        // fmov v0.4s, #1.0
        let d = check(&[0x4f03_f600], Init::default());
        assert_eq!(d.v[0], 0x3f80_0000_3f80_0000_3f80_0000_3f80_0000);
    }

    // --- shift by immediate ----------------------------------------------

    #[test]
    fn ushr_4s_16b_2d() {
        // ushr v0.4s,v1,#5 ; ushr v2.16b,v1,#2 ; ushr v3.2d,v1,#10
        check(
            &[0x6f3b_0420, 0x6f0e_0422, 0x6f76_0423],
            init_v(&[(1, 0xffff_ffff_8000_0001_1234_5678_9abc_def0)]),
        );
    }

    #[test]
    fn shrn_and_shrn2() {
        // shrn v0.8b,v1.8h,#3 ; shrn2 v0.16b,v1.8h,#3
        check(
            &[0x0f0d_8420, 0x4f0d_8420],
            init_v(&[(1, 0x00f8_01f0_02e8_03e0_7777_8888_9999_aaaa)]),
        );
    }

    #[test]
    fn ushll_and_ushll2() {
        // ushll v0.8h,v1.8b,#3 ; ushll2 v2.8h,v1.16b,#3
        check(
            &[0x2f0b_a420, 0x6f0b_a422],
            init_v(&[(1, 0x8090_a0b0_c0d0_e0f0_0102_0304_0506_0708)]),
        );
    }

    // --- scalar FP --------------------------------------------------------

    #[test]
    fn fmov_reg_and_gpr() {
        // fmov s0,s1 ; fmov d2,d3 ; fmov s4,w1 ; fmov w2,s5 ; fmov d6,x3 ; fmov x4,d7
        check(
            &[
                0x1e20_4020,
                0x1e60_4062,
                0x1e27_0024,
                0x1e26_00a2,
                0x9e67_0066,
                0x9e66_00e4,
            ],
            {
                let mut init = init_x(&[(1, 0xaaaa_bbbb_1234_5678), (3, 0x0fed_cba9_8765_4321)]);
                init.v[1] = 0x1111_2222_3333_4444;
                init.v[3] = 0x5555_6666_7777_8888;
                init.v[5] = 0x0000_0000_dead_beef;
                init.v[7] = 0x9999_aaaa_bbbb_cccc;
                init
            },
        );
    }

    #[test]
    fn fmov_high_half() {
        // fmov x1, v0.d[1] ; fmov v2.d[1], x3
        let d = check(&[0x9eae_0001, 0x9eaf_0062], {
            let mut init = init_x(&[(3, 0xcafe_babe_0bad_f00d)]);
            init.v[0] = 0x1122_3344_5566_7788_0000_0000_0000_0000;
            init.v[2] = 0x0000_0000_0000_0000_dddd_eeee_ffff_0000;
            init
        });
        assert_eq!(d.x[1], 0x1122_3344_5566_7788);
        assert_eq!(d.v[2], 0xcafe_babe_0bad_f00d_dddd_eeee_ffff_0000);
    }

    #[test]
    fn fmov_immediate_scalar() {
        // fmov s0, #1.0 ; fmov d1, #2.5 ; fmov s2, #-1.0
        let d = check(&[0x1e2e_1000, 0x1e60_9001, 0x1e3e_1002], Init::default());
        assert_eq!(d.v[0] as u32, 1.0f32.to_bits());
        assert_eq!(d.v[1] as u64, 2.5f64.to_bits());
        assert_eq!(d.v[2] as u32, (-1.0f32).to_bits());
    }

    #[test]
    fn fneg_single_and_double() {
        // fneg s0,s1 ; fneg d2,d3
        let d = check(&[0x1e21_4020, 0x1e61_4062], {
            let mut init = Init::default();
            init.v[1] = u128::from(3.5f32.to_bits());
            init.v[3] = u128::from(6.25f64.to_bits());
            init
        });
        assert_eq!(d.v[0] as u32, (-3.5f32).to_bits());
        assert_eq!(d.v[2] as u64, (-6.25f64).to_bits());
    }

    #[test]
    fn fmul_single_and_double() {
        // fmul s0,s1,s2 ; fmul d3,d4,d5
        let d = check(&[0x1e22_0820, 0x1e65_0883], {
            let mut init = Init::default();
            init.v[1] = u128::from(3.0f32.to_bits());
            init.v[2] = u128::from(1.5f32.to_bits());
            init.v[4] = u128::from(2.5f64.to_bits());
            init.v[5] = u128::from(4.0f64.to_bits());
            init
        });
        assert_eq!(d.v[0] as u32, 4.5f32.to_bits());
        assert_eq!(d.v[3] as u64, 10.0f64.to_bits());
    }

    #[test]
    fn ucvtf_word_and_doubleword() {
        // ucvtf s0,w1 ; ucvtf d2,x3 ; ucvtf s4,x5 ; ucvtf d6,w7
        let d = check(
            &[0x1e23_0020, 0x9e63_0062, 0x9e23_00a4, 0x1e63_00e6],
            init_x(&[
                (1, 123),
                (3, 0x0000_0000_1000_0000),
                (5, 0xffff_ffff_ffff_ffff),
                (7, 4_000_000_000),
            ]),
        );
        assert_eq!(d.v[0] as u32, 123.0f32.to_bits());
    }

    #[test]
    fn fcmp_single_orders() {
        // fcmp s0,s1 (less) ; fcmp s0,s2 (equal) ; fcmp s3,#0.0 (greater)
        let d = check(&[0x1e21_2000, 0x1e22_2000, 0x1e20_2068], {
            let mut init = Init::default();
            init.v[0] = u128::from(1.0f32.to_bits());
            init.v[1] = u128::from(2.0f32.to_bits());
            init.v[2] = u128::from(1.0f32.to_bits());
            init.v[3] = u128::from(5.0f32.to_bits());
            init
        });
        // last compare: 5.0 > 0.0 -> C set (0x2000_0000)
        assert_eq!(d.nzcv, 0x2000_0000);
    }

    #[test]
    fn fcmp_double_and_zero() {
        // fcmp d1,d2 ; fcmp d0,#0.0
        check(&[0x1e62_2020, 0x1e60_2008], {
            let mut init = Init::default();
            init.v[0] = u128::from(0.0f64.to_bits());
            init.v[1] = u128::from(7.5f64.to_bits());
            init.v[2] = u128::from(7.5f64.to_bits());
            init
        });
    }

    // --- vector load/store ------------------------------------------------

    #[test]
    fn str_ldr_q_roundtrip() {
        // str q0,[x1] ; ldr q2,[x1]
        let d = check(&[0x3d80_0020, 0x3dc0_0022], {
            let mut init = init_x(&[(1, DATA)]);
            init.v[0] = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff;
            init
        });
        assert_eq!(d.v[2], 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
    }

    #[test]
    fn str_ldr_scalar_widths() {
        // str d0,[x1] ; ldr d2,[x1] ; str s0,[x1,#16] ; ldr s3,[x1,#16] ;
        // str b0,[x1,#32] ; ldr b4,[x1,#32] ; str h0,[x1,#40] ; ldr h5,[x1,#40]
        let d = check(
            &[
                0xfd00_0020,
                0xfd40_0022,
                0xbd00_1020,
                0xbd40_1023,
                0x3d00_8020,
                0x3d40_8024,
                0x7d00_5020,
                0x7d40_5025,
            ],
            {
                let mut init = init_x(&[(1, DATA)]);
                init.v[0] = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00;
                init
            },
        );
        assert_eq!(d.v[2], 0x99aa_bbcc_ddee_ff00); // D (low 64)
        assert_eq!(d.v[3], 0xddee_ff00); // S (low 32)
        assert_eq!(d.v[4], 0x00); // B (low 8)
        assert_eq!(d.v[5], 0xff00); // H (low 16)
    }

    #[test]
    fn unscaled_and_pre_post_index() {
        // stur q0,[x1,#5] ; ldur q2,[x1,#5]
        let d = check(&[0x3c80_5020, 0x3cc0_5022], {
            let mut init = init_x(&[(1, DATA)]);
            init.v[0] = 0xfedc_ba98_7654_3210_0f1e_2d3c_4b5a_6978;
            init
        });
        assert_eq!(d.v[2], 0xfedc_ba98_7654_3210_0f1e_2d3c_4b5a_6978);
    }

    #[test]
    fn pre_and_post_index_writeback() {
        // str q0,[x1,#16]! ; ldr q2,[x1] ; str q0,[x3],#16 ; ldr q4,[x3,#-16]
        let d = check(&[0x3c81_0c20, 0x3dc0_0022, 0x3c81_0460, 0x3cdf_0064], {
            let mut init = init_x(&[(1, DATA), (3, DATA + 0x100)]);
            init.v[0] = 0x1111_2222_3333_4444_5555_6666_7777_8888;
            init
        });
        assert_eq!(d.x[1], DATA + 16);
        assert_eq!(d.v[2], 0x1111_2222_3333_4444_5555_6666_7777_8888);
        assert_eq!(d.x[3], DATA + 0x100 + 16);
        assert_eq!(d.v[4], 0x1111_2222_3333_4444_5555_6666_7777_8888);
    }

    #[test]
    fn stp_ldp_q_and_d_and_s() {
        // stp q0,q1,[x2] ; ldp q3,q4,[x2] ; stp d0,d1,[x2,#64] ; ldp d5,d6,[x2,#64]
        let d = check(&[0xad00_0440, 0xad40_1043, 0x6d04_0440, 0x6d44_1845], {
            let mut init = init_x(&[(2, DATA)]);
            init.v[0] = 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10;
            init.v[1] = 0x1112_1314_1516_1718_191a_1b1c_1d1e_1f20;
            init
        });
        assert_eq!(d.v[3], 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        assert_eq!(d.v[4], 0x1112_1314_1516_1718_191a_1b1c_1d1e_1f20);
        assert_eq!(d.v[5], 0x090a_0b0c_0d0e_0f10); // d0 low 64
    }

    #[test]
    fn stp_ldp_pre_post_index() {
        // stp q0,q1,[x2,#32]! ; ldp q3,q4,[x2] ; stp q0,q1,[x5],#32 ; ldp q6,q7,[x5,#-32]
        let d = check(&[0xad81_0440, 0xad40_1043, 0xac81_04a0, 0xad7f_1ca6], {
            let mut init = init_x(&[(2, DATA), (5, DATA + 0x200)]);
            init.v[0] = 0xaaaa_aaaa_bbbb_bbbb_cccc_cccc_dddd_dddd;
            init.v[1] = 0x1234_5678_9abc_def0_0f1e_2d3c_4b5a_6978;
            init
        });
        assert_eq!(d.x[2], DATA + 32);
        assert_eq!(d.v[3], 0xaaaa_aaaa_bbbb_bbbb_cccc_cccc_dddd_dddd);
        assert_eq!(d.x[5], DATA + 0x200 + 32);
        assert_eq!(d.v[7], 0x1234_5678_9abc_def0_0f1e_2d3c_4b5a_6978);
    }

    #[test]
    fn ldr_literal_vector() {
        // ldr q0, #8 ; then two words of payload reached as literal data.
        // The two instructions after the ldr form the 16 bytes loaded.
        let d = check(
            &[
                0x9c00_0040,
                0x9100_039c,
                0x9100_037b,
                0x9100_035a,
                0x9100_0339,
            ],
            Init::default(),
        );
        // low 64 bits at pc+8: words [0x9100_037b, 0x9100_035a] little-endian
        assert_eq!(d.v[0] as u64, 0x9100_035a_9100_037b);
    }

    #[test]
    fn ldr_literal_s_and_d() {
        // ldr s0,#8 ; ldr d1,#4
        let d = check(
            &[0x1c00_0040, 0x5c00_0021, 0x9100_039c, 0x9100_037b],
            Init::default(),
        );
        assert_eq!(d.v[0] as u32, 0x9100_039c);
    }
}
