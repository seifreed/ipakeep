//! Data-processing -- register (ARM ARM C4.1.3)

use super::dpimm::add_with_carry;
use super::{NativeCpu, NativeError, Step, cond_holds};

/// Runs a data-processing-register instruction. These never branch.
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let op1 = (word >> 28) & 1;
    let op2 = (word >> 21) & 0xf;
    if op1 == 0 {
        if op2 & 0b1000 == 0 {
            logical_shifted(cpu, word) // 0xxx
        } else if op2 & 1 == 0 {
            add_sub_shifted(cpu, word) // 1xx0
        } else {
            add_sub_extended(cpu, word) // 1xx1
        }
    } else {
        let op0 = (word >> 30) & 1;
        match op2 {
            0b0110 if op0 == 0 => data_proc_2src(cpu, word),
            0b0110 => data_proc_1src(cpu, word),
            0b0000 => add_sub_carry(cpu, word),
            0b0010 => cond_compare(cpu, word),
            0b0100 => cond_select(cpu, word),
            o if o & 0b1000 != 0 => data_proc_3src(cpu, word),
            _ => Err(unsupported(cpu, word, "dpreg/op2")),
        }
    }
}

fn unsupported(cpu: &NativeCpu, word: u32, what: &'static str) -> NativeError {
    NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what,
    }
}

// --- width helpers ---

fn ones(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

fn mask_width(value: u64, sf: u32) -> u64 {
    if sf == 1 { value } else { value & 0xffff_ffff }
}

fn sign_extend(value: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 {
        return value;
    }
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Writes a ZR-form result, zero-extending 32-bit results to 64 bits.
fn write_reg(cpu: &mut NativeCpu, rd: u32, result: u64, sf: u32) {
    if sf == 1 {
        cpu.set_x(rd, result);
    } else {
        cpu.set_w(rd, result as u32);
    }
}

/// Logical N,Z flags from a result (C and V cleared), packed into [31:28].
fn logical_nz(result: u64, sf: u32) -> u32 {
    let n = if sf == 1 {
        (result >> 63) & 1
    } else {
        (result >> 31) & 1
    };
    let z = u64::from(result == 0);
    ((n << 31) | (z << 30)) as u32
}

/// `ShiftReg`: applies shift `type` of `amount` to a datasize-wide value.
fn shift_reg(value: u64, shift_type: u32, amount: u32, sf: u32) -> u64 {
    let datasize = if sf == 1 { 64 } else { 32 };
    let v = mask_width(value, sf);
    let result = match shift_type {
        0b00 => v << amount,
        0b01 => v >> amount,
        0b10 => {
            if sf == 1 {
                ((v as i64) >> amount) as u64
            } else {
                ((v as i32) >> amount) as u64
            }
        }
        _ => {
            let a = amount % datasize;
            if a == 0 {
                v
            } else {
                (v >> a) | (v << (datasize - a))
            }
        }
    };
    mask_width(result, sf)
}

/// `ExtendReg`: extends the low bits of `value` per `option`, then LSL by `shift`.
fn extend_reg(value: u64, option: u32, shift: u32, sf: u32) -> u64 {
    let datasize = if sf == 1 { 64 } else { 32 };
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
    let len = base_len.min(datasize - shift);
    let field = value & ones(len);
    let combined = field << shift;
    let total = len + shift;
    let extended = if unsigned {
        combined
    } else {
        sign_extend(combined, total)
    };
    mask_width(extended, sf)
}

// --- Logical (shifted register) ---

fn logical_shifted(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let opc = (word >> 29) & 0b11;
    let shift_type = (word >> 22) & 0b11;
    let n = (word >> 21) & 1;
    let rm = (word >> 16) & 0x1f;
    let imm6 = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let operand2 = shift_reg(cpu.x(rm), shift_type, imm6, sf);
    let operand2 = if n == 1 {
        mask_width(!operand2, sf)
    } else {
        operand2
    };
    let a = mask_width(cpu.x(rn), sf);
    let result = match opc {
        0b00 | 0b11 => a & operand2, // AND/BIC, ANDS/BICS
        0b01 => a | operand2,        // ORR/ORN
        _ => a ^ operand2,           // EOR/EON
    };
    let result = mask_width(result, sf);
    if opc == 0b11 {
        cpu.set_nzcv(logical_nz(result, sf));
    }
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

// --- Add/subtract (shifted register) ---

fn add_sub_shifted(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1;
    let s = (word >> 29) & 1;
    let shift_type = (word >> 22) & 0b11;
    let rm = (word >> 16) & 0x1f;
    let imm6 = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let operand2 = shift_reg(cpu.x(rm), shift_type, imm6, sf);
    let a = mask_width(cpu.x(rn), sf);
    let (result, nzcv) = if op == 0 {
        add_with_carry(a, operand2, false, sf)
    } else {
        add_with_carry(a, mask_width(!operand2, sf), true, sf)
    };
    if s == 1 {
        cpu.set_nzcv(nzcv);
    }
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

// --- Add/subtract (extended register) ---

fn add_sub_extended(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1;
    let s = (word >> 29) & 1;
    let rm = (word >> 16) & 0x1f;
    let option = (word >> 13) & 0b111;
    let imm3 = (word >> 10) & 0b111;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let operand2 = extend_reg(cpu.x(rm), option, imm3, sf);
    let a = mask_width(cpu.x_sp(rn), sf);
    let (result, nzcv) = if op == 0 {
        add_with_carry(a, operand2, false, sf)
    } else {
        add_with_carry(a, mask_width(!operand2, sf), true, sf)
    };
    if s == 1 {
        cpu.set_nzcv(nzcv);
        write_reg(cpu, rd, result, sf);
    } else if sf == 1 {
        cpu.set_x_sp(rd, result);
    } else {
        cpu.set_x_sp(rd, u64::from(result as u32));
    }
    Ok(Step::Next)
}

// --- Add/subtract (with carry) ---

fn add_sub_carry(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    if (word >> 10) & 0x3f != 0 {
        return Err(unsupported(cpu, word, "dpreg/flagops"));
    }
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1;
    let s = (word >> 29) & 1;
    let rm = (word >> 16) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let carry_in = (cpu.nzcv() >> 29) & 1 == 1;
    let a = mask_width(cpu.x(rn), sf);
    let b = mask_width(cpu.x(rm), sf);
    let (result, nzcv) = if op == 0 {
        add_with_carry(a, b, carry_in, sf)
    } else {
        add_with_carry(a, mask_width(!b, sf), carry_in, sf)
    };
    if s == 1 {
        cpu.set_nzcv(nzcv);
    }
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

// --- Conditional compare (register and immediate) ---

fn cond_compare(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1; // 0 CCMN, 1 CCMP
    let is_imm = (word >> 11) & 1 == 1;
    let field = (word >> 16) & 0x1f; // Rm or imm5
    let cond = ((word >> 12) & 0xf) as u8;
    let rn = (word >> 5) & 0x1f;
    let nzcv_imm = word & 0xf;

    if cond_holds(cpu.nzcv(), cond) {
        let operand2 = if is_imm {
            u64::from(field)
        } else {
            mask_width(cpu.x(field), sf)
        };
        let a = mask_width(cpu.x(rn), sf);
        let (_, nzcv) = if op == 0 {
            add_with_carry(a, operand2, false, sf)
        } else {
            add_with_carry(a, mask_width(!operand2, sf), true, sf)
        };
        cpu.set_nzcv(nzcv);
    } else {
        cpu.set_nzcv(nzcv_imm << 28);
    }
    Ok(Step::Next)
}

// --- Conditional select ---

fn cond_select(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 30) & 1;
    let rm = (word >> 16) & 0x1f;
    let cond = ((word >> 12) & 0xf) as u8;
    let op2 = (word >> 10) & 0b11;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let result = if cond_holds(cpu.nzcv(), cond) {
        cpu.x(rn)
    } else {
        let m = cpu.x(rm);
        match (op, op2) {
            (0, 0b00) => m,                    // CSEL
            (0, 0b01) => m.wrapping_add(1),    // CSINC
            (1, 0b00) => !m,                   // CSINV
            (1, 0b01) => (!m).wrapping_add(1), // CSNEG
            _ => return Err(unsupported(cpu, word, "dpreg/csel")),
        }
    };
    let result = mask_width(result, sf);
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

// --- Data-processing (2 source) ---

fn data_proc_2src(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let rm = (word >> 16) & 0x1f;
    let opcode = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    let datasize = if sf == 1 { 64 } else { 32 };

    let n = mask_width(cpu.x(rn), sf);
    let m = mask_width(cpu.x(rm), sf);
    let result = match opcode {
        0b000010 => udiv(n, m, sf),
        0b000011 => sdiv(n, m, sf),
        0b001000 => shift_reg(n, 0b00, m as u32 % datasize, sf), // LSLV
        0b001001 => shift_reg(n, 0b01, m as u32 % datasize, sf), // LSRV
        0b001010 => shift_reg(n, 0b10, m as u32 % datasize, sf), // ASRV
        0b001011 => shift_reg(n, 0b11, m as u32 % datasize, sf), // RORV
        _ => return Err(unsupported(cpu, word, "dpreg/2src")),
    };
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

fn udiv(n: u64, m: u64, sf: u32) -> u64 {
    if sf == 1 {
        n.checked_div(m).unwrap_or(0)
    } else {
        u64::from((n as u32).checked_div(m as u32).unwrap_or(0))
    }
}

fn sdiv(n: u64, m: u64, sf: u32) -> u64 {
    if sf == 1 {
        let b = m as i64;
        if b == 0 {
            0
        } else {
            (n as i64).wrapping_div(b) as u64
        }
    } else {
        let b = m as i32;
        if b == 0 {
            0
        } else {
            u64::from((n as i32).wrapping_div(b) as u32)
        }
    }
}

// --- Data-processing (3 source) ---

fn data_proc_3src(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op31 = (word >> 21) & 0b111;
    let rm = (word >> 16) & 0x1f;
    let o0 = (word >> 15) & 1;
    let ra = (word >> 10) & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;

    let result = match (op31, o0) {
        (0b000, 0) => mask_width(cpu.x(ra), sf)
            .wrapping_add(mask_width(cpu.x(rn), sf).wrapping_mul(mask_width(cpu.x(rm), sf))),
        (0b000, 1) => mask_width(cpu.x(ra), sf)
            .wrapping_sub(mask_width(cpu.x(rn), sf).wrapping_mul(mask_width(cpu.x(rm), sf))),
        (0b001, 0) => (cpu.x(ra) as i64).wrapping_add(smull(cpu.x(rn), cpu.x(rm))) as u64,
        (0b001, 1) => (cpu.x(ra) as i64).wrapping_sub(smull(cpu.x(rn), cpu.x(rm))) as u64,
        (0b010, 0) => ((i128::from(cpu.x(rn) as i64) * i128::from(cpu.x(rm) as i64)) >> 64) as u64,
        (0b101, 0) => cpu.x(ra).wrapping_add(umull(cpu.x(rn), cpu.x(rm))),
        (0b101, 1) => cpu.x(ra).wrapping_sub(umull(cpu.x(rn), cpu.x(rm))),
        (0b110, 0) => ((u128::from(cpu.x(rn)) * u128::from(cpu.x(rm))) >> 64) as u64,
        _ => return Err(unsupported(cpu, word, "dpreg/3src")),
    };
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

/// Signed 32x32 -> 64-bit product of the low words.
fn smull(n: u64, m: u64) -> i64 {
    i64::from(n as i32) * i64::from(m as i32)
}

/// Unsigned 32x32 -> 64-bit product of the low words.
fn umull(n: u64, m: u64) -> u64 {
    u64::from(n as u32) * u64::from(m as u32)
}

// --- Data-processing (1 source) ---

fn data_proc_1src(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let opcode2 = (word >> 16) & 0x1f;
    let opcode = (word >> 10) & 0x3f;
    let rn = (word >> 5) & 0x1f;
    let rd = word & 0x1f;
    if opcode2 != 0 {
        return Err(unsupported(cpu, word, "dpreg/1src"));
    }
    let datasize = if sf == 1 { 64 } else { 32 };
    let v = mask_width(cpu.x(rn), sf);
    let result = match opcode {
        0b000000 => rbit(v, sf),
        0b000001 => rev16(v, datasize),
        0b000010 => {
            if sf == 0 {
                u64::from((v as u32).swap_bytes()) // REV (32-bit)
            } else {
                rev32(v) // REV32 (64-bit)
            }
        }
        0b000011 if sf == 1 => v.swap_bytes(), // REV (64-bit)
        0b000100 => u64::from(clz(v, datasize)),
        0b000101 => u64::from(cls(v, datasize)),
        _ => return Err(unsupported(cpu, word, "dpreg/1src")),
    };
    write_reg(cpu, rd, result, sf);
    Ok(Step::Next)
}

fn rbit(v: u64, sf: u32) -> u64 {
    if sf == 1 {
        v.reverse_bits()
    } else {
        u64::from((v as u32).reverse_bits())
    }
}

fn rev16(v: u64, datasize: u32) -> u64 {
    let mut result = 0u64;
    let mut i = 0;
    while i < datasize {
        let h = (v >> i) & 0xffff;
        let swapped = ((h & 0xff) << 8) | ((h >> 8) & 0xff);
        result |= swapped << i;
        i += 16;
    }
    result
}

fn rev32(v: u64) -> u64 {
    let lo = u64::from((v as u32).swap_bytes());
    let hi = u64::from(((v >> 32) as u32).swap_bytes());
    lo | (hi << 32)
}

fn clz(v: u64, datasize: u32) -> u32 {
    if datasize == 64 {
        v.leading_zeros()
    } else {
        (v as u32).leading_zeros()
    }
}

fn cls(v: u64, datasize: u32) -> u32 {
    let sign = (v >> (datasize - 1)) & 1;
    let mut count = 0u32;
    let mut i = datasize as i32 - 2;
    while i >= 0 {
        if (v >> i) & 1 == sign {
            count += 1;
            i -= 1;
        } else {
            break;
        }
    }
    count
}

#[cfg(all(test, feature = "unicorn"))]
mod tests {
    use super::super::diff::{check, check_zero, init_x};

    // --- Logical (shifted register) ---

    #[test]
    fn logical_and_orr_eor_variants() {
        // and x0, x1, x2 ; orr x3, x1, x2, lsl #4 ; eor x4, x1, x2, lsr #8
        check(
            &[0x8a02_0020, 0xaa02_1023, 0xca42_2024],
            init_x(&[(1, 0x1234_5678_9abc_def0), (2, 0x0f0f_0f0f_0f0f_0f0f)]),
        );
    }

    #[test]
    fn logical_bic_orn_eon_and_ror() {
        // bic x0, x1, x2 ; orn x3, x1, x2, asr #4 ; eon x4, x1, x2, ror #16
        check(
            &[0x8a22_0020, 0xaaa2_1023, 0xcae2_4024],
            init_x(&[(1, 0xffff_0000_ffff_0000), (2, 0x8000_0000_0000_00ff)]),
        );
    }

    #[test]
    fn ands_bics_set_flags() {
        // ands x0, x1, x2 (nonzero) ; bics x3, x4, x5 (zero result)
        check(
            &[0xea02_0020, 0xea25_0083],
            init_x(&[(1, 0xff), (2, 0x0f), (4, 0x0f), (5, 0x0f)]),
        );
    }

    #[test]
    fn logical_32bit_zero_extends() {
        // and w0, w1, w2, lsl #4
        check(
            &[0x0a02_1020],
            init_x(&[(1, 0xffff_ffff_ffff_ffff), (2, 0x0000_0000_1234_5678)]),
        );
    }

    // --- Add/subtract (shifted register) ---

    #[test]
    fn add_sub_shifted_basic() {
        // add x0, x1, x2, lsl #2 ; sub x3, x1, x2, asr #1
        check(
            &[0x8b02_0820, 0xcb82_0423],
            init_x(&[(1, 0x1_0000), (2, 0xffff_ffff_ffff_fff0)]),
        );
    }

    #[test]
    fn adds_subs_shifted_flags_overflow() {
        // adds x0, x1, x2 (overflow) ; subs x3, x4, x5
        check(
            &[0xab02_0020, 0xeb05_0083],
            init_x(&[(1, 0x7fff_ffff_ffff_ffff), (2, 0x1), (4, 0x0), (5, 0x1)]),
        );
    }

    #[test]
    fn subs_32bit_carry() {
        // subs w0, w1, w2
        check(&[0x6b02_0020], init_x(&[(1, 0x10), (2, 0x20)]));
    }

    // --- Add/subtract (extended register) ---

    #[test]
    fn add_extended_uxtb_sxth() {
        // add x0, x1, w2, uxtb #2 ; add x3, x1, w2, sxth #0
        check(
            &[0x8b22_0820, 0x8b22_a023],
            init_x(&[(1, 0x1000), (2, 0xffff_ff85)]),
        );
    }

    #[test]
    fn add_extended_sxtx_and_sp() {
        // add sp, x1, x2, sxtx #3 ; subs x0, x3, w4, uxtw #1
        check(
            &[0x8b22_ec3f, 0xeb24_4460],
            init_x(&[(1, 0x5_0000), (2, 0x40), (3, 0x1_0000), (4, 0x8000_0001)]),
        );
    }

    // --- Add/subtract (with carry) ---

    #[test]
    fn adc_sbc_use_carry() {
        // adc x0, x1, x2 ; sbc x3, x4, x5  (carry set via subs below)
        // subs xzr, x6, x7 sets C=1 (no borrow), then adc/sbc consume it.
        check(
            &[0xeb07_00df, 0x9a02_0020, 0xda05_0083],
            init_x(&[
                (1, 0x10),
                (2, 0x20),
                (4, 0x100),
                (5, 0x1),
                (6, 0x5),
                (7, 0x3),
            ]),
        );
    }

    #[test]
    fn adcs_sbcs_set_flags() {
        // adcs x0, x1, x2 ; sbcs x3, x4, x5
        check(
            &[0xba02_0020, 0xfa05_0083],
            init_x(&[(1, 0xffff_ffff_ffff_ffff), (2, 0x1), (4, 0x0), (5, 0x0)]),
        );
    }

    // --- Conditional compare ---

    #[test]
    fn ccmp_register_and_immediate() {
        // cmp x1, x2 (sets lt) ; ccmp x3, x4, #0, ne ; ccmp x5, #7, #0xf, eq
        check(
            &[0xeb02_003f, 0xfa44_1060, 0xfa47_08af],
            init_x(&[(1, 0x1), (2, 0x9), (3, 0x5), (4, 0x5), (5, 0x7)]),
        );
    }

    #[test]
    fn ccmn_condition_false_uses_imm() {
        // cmp x1, x2 (eq) ; ccmn x3, x4, #7, ne (false -> nzcv=7)
        check(
            &[0xeb02_003f, 0xba44_1067],
            init_x(&[(1, 0x5), (2, 0x5), (3, 0x1), (4, 0x1)]),
        );
    }

    // --- Conditional select ---

    #[test]
    fn csel_csinc_csinv_csneg() {
        // cmp x1, x2 ; csel x0, x3, x4, eq ; csinc x5, x3, x4, ne
        // csinv x6, x3, x4, lt ; csneg x7, x3, x4, ge
        check(
            &[
                0xeb02_003f,
                0x9a84_0060,
                0x9a84_1465,
                0xda84_b066,
                0xda84_a467,
            ],
            init_x(&[(1, 0x9), (2, 0x1), (3, 0x1234), (4, 0x5678_9abc_def0_1234)]),
        );
    }

    #[test]
    fn cset_via_csinc_32bit() {
        // cmp w1, w2 ; cset w0, eq (csinc w0, wzr, wzr, ne)
        check(&[0x6b02_003f, 0x1a9f_17e0], init_x(&[(1, 0x3), (2, 0x3)]));
    }

    // --- Data-processing (2 source) ---

    #[test]
    fn udiv_sdiv_including_div_by_zero() {
        // udiv x0, x1, x2 ; sdiv x3, x1, x4 ; udiv x5, x1, xzr (->0)
        check(
            &[0x9ac2_0820, 0x9ac4_0c23, 0x9adf_0825],
            init_x(&[
                (1, 0xffff_ffff_ffff_fff0),
                (2, 0x7),
                (4, 0xffff_ffff_ffff_fffe),
            ]),
        );
    }

    #[test]
    fn sdiv_int_min_overflow() {
        // sdiv x0, x1, x2  with x1=INT64_MIN, x2=-1
        check(
            &[0x9ac2_0c20],
            init_x(&[(1, 0x8000_0000_0000_0000), (2, 0xffff_ffff_ffff_ffff)]),
        );
    }

    #[test]
    fn variable_shifts_lslv_lsrv_asrv_rorv() {
        // lslv x0, x1, x2 ; lsrv x3, x1, x2 ; asrv x4, x1, x2 ; rorv x5, x1, x2
        check(
            &[0x9ac2_2020, 0x9ac2_2423, 0x9ac2_2824, 0x9ac2_2c25],
            init_x(&[(1, 0x8000_0000_0000_00ff), (2, 68)]), // 68 mod 64 = 4
        );
    }

    #[test]
    fn variable_shift_32bit() {
        // lslv w0, w1, w2  (shift amount mod 32)
        check(&[0x1ac2_2020], init_x(&[(1, 0x1), (2, 33)])); // 33 mod 32 = 1
    }

    // --- Data-processing (3 source) ---

    #[test]
    fn madd_msub() {
        // madd x0, x1, x2, x3 ; msub x4, x1, x2, x3
        check(
            &[0x9b02_0c20, 0x9b02_8c24],
            init_x(&[(1, 0x100), (2, 0x3), (3, 0x7)]),
        );
    }

    #[test]
    fn smaddl_umaddl_long_multiply() {
        // smaddl x0, w1, w2, x3 ; umaddl x4, w1, w2, x3 ; smsubl x5, w1, w2, x3
        check(
            &[0x9b22_0c20, 0x9ba2_0c24, 0x9b22_8c25],
            init_x(&[(1, 0xffff_ffff), (2, 0x2), (3, 0x1000)]),
        );
    }

    #[test]
    fn smulh_umulh_high_product() {
        // smulh x0, x1, x2 ; umulh x3, x1, x2
        check(
            &[0x9b42_7c20, 0x9bc2_7c23],
            init_x(&[(1, 0xffff_ffff_ffff_ffff), (2, 0x2)]),
        );
    }

    // --- Data-processing (1 source) ---

    #[test]
    fn rbit_rev_rev16_rev32() {
        // rbit x0, x1 ; rev x2, x1 ; rev16 x3, x1 ; rev32 x4, x1
        check(
            &[0xdac0_0020, 0xdac0_0c22, 0xdac0_0423, 0xdac0_0824],
            init_x(&[(1, 0x0123_4567_89ab_cdef)]),
        );
    }

    #[test]
    fn rev_rbit_32bit() {
        // rev w0, w1 ; rbit w2, w1 ; rev16 w3, w1
        check(
            &[0x5ac0_0820, 0x5ac0_0022, 0x5ac0_0423],
            init_x(&[(1, 0x1234_5678)]),
        );
    }

    #[test]
    fn clz_cls_counts() {
        // clz x0, x1 ; cls x2, x1 ; clz x3, x4 (zero)
        check(
            &[0xdac0_1020, 0xdac0_1422, 0xdac0_1083],
            init_x(&[(1, 0x0000_ffff_ffff_ffff), (4, 0x0)]),
        );
    }

    #[test]
    fn cls_32bit_negative() {
        // cls w0, w1  with a negative 32-bit value (leading ones)
        check_zero(&[0x5ac0_1420]);
    }
}
