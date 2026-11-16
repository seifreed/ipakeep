//! Loads and stores (ARM ARM C4.1.5)
//!
//! Covers the integer load/store surface the SAP/ADI guest exercises:
//! register (unsigned-offset, unscaled, pre/post-indexed and register-offset),
//! load/store pair, load-literal, the load/store-exclusive + load-acquire /
//! store-release ordered forms, compare-and-swap (`CAS*`) and the LSE `SWP`. No SIMD/FP or
//! system state is touched, so the `V == 1` vectors and the unmodelled LSE
//! read-modify-write ops report [`NativeError::Unsupported`].
//!
//! The exclusive/ordered forms are executed on a single-threaded model: the
//! monitor always succeeds, so `STXR`/`STLXR` behave as a plain store and write
//! the "success" status `0` to their `Ws` register.

use super::{NativeCpu, NativeError, Step};

fn unsupported(cpu: &NativeCpu, word: u32, what: &'static str) -> NativeError {
    NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what,
    }
}

/// Sign-extends the low `bits` of `value` to 64 bits.
fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    ((value << shift) as i64 >> shift) as u64
}

/// Reads `bytes` (1/2/4/8) from guest memory, zero-extended into a `u64`.
pub(super) fn load_bytes(cpu: &NativeCpu, addr: u64, bytes: usize) -> Result<u64, NativeError> {
    let mut buf = [0u8; 8];
    cpu.mem.read(addr, &mut buf[..bytes])?;
    Ok(u64::from_le_bytes(buf))
}

/// Writes the low `bytes` of `value` to guest memory.
pub(super) fn store_bytes(
    cpu: &mut NativeCpu,
    addr: u64,
    bytes: usize,
    value: u64,
) -> Result<(), NativeError> {
    let buf = value.to_le_bytes();
    cpu.mem.write(addr, &buf[..bytes])
}

/// Applies the `ExtendRegister` (option/shift) used by register-offset
/// addressing: `UXTW`/`SXTW` take the low 32 bits, `LSL`/`SXTX` the full 64,
/// then shift left by `shift`.
pub(super) fn extend_reg(value: u64, option: u32, shift: u32) -> u64 {
    // option low bit: 0 -> 32-bit source (UXTW/SXTW), 1 -> 64-bit (UXTX/SXTX).
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

/// Performs the integer transfer for a register load/store of the given
/// `size` (log2 of the access width) and `opc` at `addr`.
fn integer_transfer(
    cpu: &mut NativeCpu,
    rt: u32,
    size: u32,
    opc: u32,
    addr: u64,
    word: u32,
) -> Result<Step, NativeError> {
    let bytes = 1usize << size;
    match (size, opc) {
        // PRFM (prefetch) — architecturally a hint; modelled as a no-op.
        (0b11, 0b10) => return Ok(Step::Next),
        // Unallocated signed-load encodings.
        (0b10, 0b11) | (0b11, 0b11) => return Err(unsupported(cpu, word, "ldst/unalloc")),
        _ => {}
    }
    if opc == 0b00 {
        let value = cpu.x(rt);
        store_bytes(cpu, addr, bytes, value)?;
    } else {
        let raw = load_bytes(cpu, addr, bytes)?;
        match opc {
            0b01 => cpu.set_x(rt, raw), // zero-extend
            0b10 => cpu.set_x(rt, sign_extend(raw, (bytes * 8) as u32)), // signed -> X
            0b11 => cpu.set_w(rt, sign_extend(raw, (bytes * 8) as u32) as u32), // signed -> W
            _ => unreachable!(),
        }
    }
    Ok(Step::Next)
}

/// Runs a load/store instruction.
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let size = (word >> 30) & 0x3;
    let v = (word >> 26) & 1;

    // Load/store exclusive + load/store ordered share word[29:24] == 001000.
    if (word >> 24) & 0x3f == 0b001000 {
        return exclusive(cpu, word, size);
    }

    let group = (word >> 27) & 0x7; // word[29:27]
    let op24 = (word >> 24) & 0x3; // word[25:24]
    let op10 = (word >> 10) & 0x3; // word[11:10]

    // LSE atomic (only SWP is modelled): group=111, V=0, word[25:24]=00,
    // word[21]=1, word[11:10]=00.
    if group == 0b111 && v == 0 && op24 == 0b00 && (word >> 21) & 1 == 1 && op10 == 0b00 {
        return atomic(cpu, word, size);
    }

    match group {
        0b111 => register(cpu, word, size, v),
        0b101 => pair(cpu, word, size, v),
        0b011 if op24 == 0b00 => literal(cpu, word),
        _ => Err(unsupported(cpu, word, "ldst/group")),
    }
}

/// Load/store register: unsigned-offset, unscaled, pre/post-indexed and
/// register-offset forms.
fn register(cpu: &mut NativeCpu, word: u32, size: u32, v: u32) -> Result<Step, NativeError> {
    if v == 1 {
        return super::simd::load_store(cpu, word);
    }
    let opc = (word >> 22) & 0x3;
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;

    // Unsigned offset (scaled imm12): word[24] == 1.
    if (word >> 24) & 1 == 1 {
        let imm12 = (word >> 10) & 0xfff;
        let addr = cpu.x_sp(rn).wrapping_add(u64::from(imm12) << size);
        return integer_transfer(cpu, rt, size, opc, addr, word);
    }

    // Register offset: word[21] == 1 and word[11:10] == 10.
    if (word >> 21) & 1 == 1 {
        if (word >> 10) & 0x3 != 0b10 {
            return Err(unsupported(cpu, word, "ldst/reg-unalloc"));
        }
        let rm = (word >> 16) & 0x1f;
        let option = (word >> 13) & 0x7;
        let s = (word >> 12) & 1;
        let shift = if s == 1 { size } else { 0 };
        let index = extend_reg(cpu.x(rm), option, shift);
        let addr = cpu.x_sp(rn).wrapping_add(index);
        return integer_transfer(cpu, rt, size, opc, addr, word);
    }

    // imm9 forms: word[11:10] selects the addressing mode.
    let imm9 = sign_extend(u64::from((word >> 12) & 0x1ff), 9);
    let base = cpu.x_sp(rn);
    let (addr, writeback) = match (word >> 10) & 0x3 {
        0b00 => (base.wrapping_add(imm9), None), // unscaled LDUR/STUR
        0b01 => (base, Some(base.wrapping_add(imm9))), // post-indexed
        0b11 => {
            let a = base.wrapping_add(imm9);
            (a, Some(a)) // pre-indexed
        }
        // word[11:10] == 10 is the unprivileged LDTR/STTR form (not modelled).
        _ => return Err(unsupported(cpu, word, "ldst/unpriv")),
    };
    let step = integer_transfer(cpu, rt, size, opc, addr, word)?;
    if let Some(new_base) = writeback {
        cpu.set_x_sp(rn, new_base);
    }
    Ok(step)
}

/// Load/store register pair (STP/LDP/STNP/LDNP, incl. LDPSW).
fn pair(cpu: &mut NativeCpu, word: u32, _size: u32, v: u32) -> Result<Step, NativeError> {
    if v == 1 {
        return super::simd::load_store(cpu, word);
    }
    let opc = (word >> 30) & 0x3;
    let l = (word >> 22) & 1;
    let rt = word & 0x1f;
    let rt2 = (word >> 10) & 0x1f;
    let rn = (word >> 5) & 0x1f;

    let (elem, signed_load) = match opc {
        0b00 => (4usize, false),
        0b01 => (4usize, true), // LDPSW (load form only)
        0b10 => (8usize, false),
        _ => return Err(unsupported(cpu, word, "ldst/pair-unalloc")),
    };
    let imm7 = sign_extend(u64::from((word >> 15) & 0x7f), 7);
    let offset = imm7.wrapping_mul(elem as u64);

    let base = cpu.x_sp(rn);
    let (addr, writeback) = match (word >> 23) & 0x3 {
        0b00 => (base.wrapping_add(offset), None), // no-allocate (STNP/LDNP)
        0b01 => (base, Some(base.wrapping_add(offset))), // post-indexed
        0b10 => (base.wrapping_add(offset), None), // signed offset
        0b11 => {
            let a = base.wrapping_add(offset);
            (a, Some(a)) // pre-indexed
        }
        _ => unreachable!(),
    };
    let addr2 = addr.wrapping_add(elem as u64);

    if l == 0 {
        let v1 = cpu.x(rt);
        let v2 = cpu.x(rt2);
        store_bytes(cpu, addr, elem, v1)?;
        store_bytes(cpu, addr2, elem, v2)?;
    } else {
        let r1 = load_bytes(cpu, addr, elem)?;
        let r2 = load_bytes(cpu, addr2, elem)?;
        if signed_load {
            cpu.set_x(rt, sign_extend(r1, 32));
            cpu.set_x(rt2, sign_extend(r2, 32));
        } else {
            cpu.set_x(rt, r1);
            cpu.set_x(rt2, r2);
        }
    }
    if let Some(new_base) = writeback {
        cpu.set_x_sp(rn, new_base);
    }
    Ok(Step::Next)
}

/// Load register (literal): PC-relative LDR/LDRSW, with PRFM as a no-op.
fn literal(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    if (word >> 26) & 1 == 1 {
        return super::simd::load_store(cpu, word);
    }
    let opc = (word >> 30) & 0x3;
    let rt = word & 0x1f;
    let imm19 = (word >> 5) & 0x7_ffff;
    let offset = sign_extend(u64::from(imm19), 19) << 2;
    let addr = cpu.pc().wrapping_add(offset);
    match opc {
        0b00 => {
            let raw = load_bytes(cpu, addr, 4)?;
            cpu.set_x(rt, raw); // LDR Wt (zero-extend)
        }
        0b01 => {
            let raw = load_bytes(cpu, addr, 8)?;
            cpu.set_x(rt, raw); // LDR Xt
        }
        0b10 => {
            let raw = load_bytes(cpu, addr, 4)?;
            cpu.set_x(rt, sign_extend(raw, 32)); // LDRSW
        }
        // opc == 0b11 is PRFM (literal) — a no-op.
        _ => {}
    }
    Ok(Step::Next)
}

/// Load/store exclusive and load-acquire / store-release ordered forms.
fn exclusive(cpu: &mut NativeCpu, word: u32, size: u32) -> Result<Step, NativeError> {
    let o2 = (word >> 23) & 1;
    let l = (word >> 22) & 1;
    let o1 = (word >> 21) & 1;
    let rs = (word >> 16) & 0x1f;
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let bytes = 1usize << size;
    let addr = cpu.x_sp(rn);

    match (o2, o1) {
        // Single-register exclusive: LDXR/LDAXR, STXR/STLXR.
        (0, 0) => {
            if l == 1 {
                let raw = load_bytes(cpu, addr, bytes)?;
                cpu.set_x(rt, raw);
            } else {
                let value = cpu.x(rt);
                store_bytes(cpu, addr, bytes, value)?;
                cpu.set_w(rs, 0); // monitor always succeeds
            }
            Ok(Step::Next)
        }
        // Load-acquire / store-release (ordered): LDAR/LDLAR, STLR/STLLR.
        (1, 0) => {
            if l == 1 {
                let raw = load_bytes(cpu, addr, bytes)?;
                cpu.set_x(rt, raw);
            } else {
                let value = cpu.x(rt);
                store_bytes(cpu, addr, bytes, value)?;
            }
            Ok(Step::Next)
        }
        // Compare-and-swap: CAS/CASA/CASL/CASAL (B/H/W/X by `size`). `Rs`
        // holds the compare value and receives the old memory value
        // (zero-extended); `Rt` is the new value and is never written.
        (1, 1) => {
            let old = load_bytes(cpu, addr, bytes)?;
            let mask = if bytes == 8 {
                u64::MAX
            } else {
                (1u64 << (bytes * 8)) - 1
            };
            if old == cpu.x(rs) & mask {
                let value = cpu.x(rt);
                store_bytes(cpu, addr, bytes, value)?;
            }
            cpu.set_x(rs, old);
            Ok(Step::Next)
        }
        // Exclusive pair: LDXP/STXP/LDAXP/STLXP (single-threaded model). With
        // `size` 0x the same o2/o1 encoding is CASP, which is not modelled.
        (0, 1) if size >= 2 => {
            let rt2 = (word >> 10) & 0x1f;
            if l == 1 {
                let lo = load_bytes(cpu, addr, bytes)?;
                let hi = load_bytes(cpu, addr + bytes as u64, bytes)?;
                cpu.set_x(rt, lo);
                cpu.set_x(rt2, hi);
            } else {
                let lo = cpu.x(rt);
                let hi = cpu.x(rt2);
                store_bytes(cpu, addr, bytes, lo)?;
                store_bytes(cpu, addr + bytes as u64, bytes, hi)?;
                cpu.set_w(rs, 0); // monitor always succeeds
            }
            Ok(Step::Next)
        }
        // Compare-and-swap pair (CASP*) is not modelled.
        _ => Err(unsupported(cpu, word, "ldst/exclusive")),
    }
}

/// LSE atomic — only `SWP` (the single atomic the guest uses) is modelled.
fn atomic(cpu: &mut NativeCpu, word: u32, size: u32) -> Result<Step, NativeError> {
    let o3 = (word >> 15) & 1;
    let opc = (word >> 12) & 0x7;
    if !(o3 == 1 && opc == 0b000) {
        return Err(unsupported(cpu, word, "ldst/atomic"));
    }
    let rs = (word >> 16) & 0x1f;
    let rt = word & 0x1f;
    let rn = (word >> 5) & 0x1f;
    let bytes = 1usize << size;
    let addr = cpu.x_sp(rn);

    let old = load_bytes(cpu, addr, bytes)?;
    let new_value = cpu.x(rs);
    store_bytes(cpu, addr, bytes, new_value)?;
    cpu.set_x(rt, old); // old value, zero-extended
    Ok(Step::Next)
}

#[cfg(all(test, feature = "unicorn"))]
mod tests {
    use super::super::diff::{check, init_x};

    const DATA: u64 = 0x2_0000;

    #[test]
    fn str_ldr_doubleword_roundtrip() {
        // str x1,[x0] ; ldr x2,[x0]
        let d = check(
            &[0xf900_0001, 0xf940_0002],
            init_x(&[(0, DATA), (1, 0xdead_beef_cafe_f00d)]),
        );
        assert_eq!(d.x[2], 0xdead_beef_cafe_f00d);
    }

    #[test]
    fn str_ldr_word_truncates_and_zero_extends() {
        // str w1,[x0] ; ldr w2,[x0]
        let d = check(
            &[0xb900_0001, 0xb940_0002],
            init_x(&[(0, DATA), (1, 0x1122_3344_5566_7788)]),
        );
        assert_eq!(d.x[2], 0x5566_7788);
    }

    #[test]
    fn byte_store_load_and_sign_extend() {
        // strb w1,[x0] ; ldrb w2,[x0] ; ldrsb x3,[x0] ; ldrsb w4,[x0]
        let d = check(
            &[0x3900_0001, 0x3940_0002, 0x3980_0003, 0x39c0_0004],
            init_x(&[(0, DATA), (1, 0x80)]),
        );
        assert_eq!(d.x[2], 0x80);
        assert_eq!(d.x[3], 0xffff_ffff_ffff_ff80);
        assert_eq!(d.x[4], 0xffff_ff80);
    }

    #[test]
    fn halfword_store_load_and_sign_extend() {
        // strh w1,[x0] ; ldrh w2,[x0] ; ldrsh x3,[x0] ; ldrsh w4,[x0]
        let d = check(
            &[0x7900_0001, 0x7940_0002, 0x7980_0003, 0x79c0_0004],
            init_x(&[(0, DATA), (1, 0x8000)]),
        );
        assert_eq!(d.x[2], 0x8000);
        assert_eq!(d.x[3], 0xffff_ffff_ffff_8000);
        assert_eq!(d.x[4], 0xffff_8000);
    }

    #[test]
    fn ldrsw_sign_extends_word() {
        // str w1,[x0] ; ldrsw x2,[x0]
        let d = check(
            &[0xb900_0001, 0xb980_0002],
            init_x(&[(0, DATA), (1, 0x8000_0000)]),
        );
        assert_eq!(d.x[2], 0xffff_ffff_8000_0000);
    }

    #[test]
    fn unsigned_scaled_offset() {
        // str x1,[x0,#16] ; ldr x2,[x0,#16]
        let d = check(
            &[0xf900_0801, 0xf940_0802],
            init_x(&[(0, DATA), (1, 0xaabb_ccdd_eeff_0011)]),
        );
        assert_eq!(d.x[2], 0xaabb_ccdd_eeff_0011);
    }

    #[test]
    fn unscaled_ldur_stur() {
        // stur x1,[x0,#5] ; ldur x2,[x0,#5]
        let d = check(
            &[0xf800_5001, 0xf840_5002],
            init_x(&[(0, DATA), (1, 0x0123_4567_89ab_cdef)]),
        );
        assert_eq!(d.x[2], 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn pre_indexed_writeback() {
        // str x1,[x0,#8]! ; ldr x2,[x0]
        let d = check(
            &[0xf800_8c01, 0xf940_0002],
            init_x(&[(0, DATA), (1, 0x0000_0000_0000_cafe)]),
        );
        assert_eq!(d.x[0], DATA + 8);
        assert_eq!(d.x[2], 0xcafe);
    }

    #[test]
    fn post_indexed_writeback() {
        // str x1,[x0],#8 ; ldr x2,[x0,#-8]
        let d = check(
            &[0xf800_8401, 0xf85f_8002],
            init_x(&[(0, DATA), (1, 0x0000_0000_0000_beef)]),
        );
        assert_eq!(d.x[0], DATA + 8);
        assert_eq!(d.x[2], 0xbeef);
    }

    #[test]
    fn register_offset_lsl() {
        // str x1,[x0,x2,lsl #3] ; ldr x3,[x0,x2,lsl #3]
        let d = check(
            &[0xf822_7801, 0xf862_7803],
            init_x(&[(0, DATA), (1, 0x7777), (2, 2)]),
        );
        assert_eq!(d.x[3], 0x7777);
    }

    #[test]
    fn register_offset_uxtw_zero_extends_index() {
        // str x1,[x0,w2,uxtw] ; ldr x3,[x0,w2,uxtw]  (high bits of X2 ignored)
        let d = check(
            &[0xf822_4801, 0xf862_4803],
            init_x(&[(0, DATA), (1, 0x9999), (2, 0xffff_ffff_0000_0010)]),
        );
        assert_eq!(d.x[3], 0x9999);
    }

    #[test]
    fn register_offset_sxtw_negative_index() {
        // str x1,[x0] ; ldr x3,[x5,w2,sxtw]  (w2 = -8 -> addr = DATA+8-8)
        let d = check(
            &[0xf900_0001, 0xf862_c8a3],
            init_x(&[
                (0, DATA),
                (5, DATA + 8),
                (1, 0x5555),
                (2, 0x0000_0000_ffff_fff8),
            ]),
        );
        assert_eq!(d.x[3], 0x5555);
    }

    #[test]
    fn store_load_pair_doubleword() {
        // stp x1,x2,[x0] ; ldp x3,x4,[x0]
        let d = check(
            &[0xa900_0801, 0xa940_1003],
            init_x(&[
                (0, DATA),
                (1, 0x1111_1111_1111_1111),
                (2, 0x2222_2222_2222_2222),
            ]),
        );
        assert_eq!(d.x[3], 0x1111_1111_1111_1111);
        assert_eq!(d.x[4], 0x2222_2222_2222_2222);
    }

    #[test]
    fn store_load_pair_word() {
        // stp w1,w2,[x0] ; ldp w3,w4,[x0]
        let d = check(
            &[0x2900_0801, 0x2940_1003],
            init_x(&[(0, DATA), (1, 0xaaaa_bbbb), (2, 0xcccc_dddd)]),
        );
        assert_eq!(d.x[3], 0xaaaa_bbbb);
        assert_eq!(d.x[4], 0xcccc_dddd);
    }

    #[test]
    fn store_load_pair_pre_indexed() {
        // stp x1,x2,[x0,#16]! ; ldp x3,x4,[x0]
        let d = check(
            &[0xa981_0801, 0xa940_1003],
            init_x(&[(0, DATA), (1, 0xa1), (2, 0xb2)]),
        );
        assert_eq!(d.x[0], DATA + 16);
        assert_eq!(d.x[3], 0xa1);
        assert_eq!(d.x[4], 0xb2);
    }

    #[test]
    fn store_load_pair_post_indexed() {
        // stp x1,x2,[x0],#16 ; ldp x3,x4,[x0,#-16]
        let d = check(
            &[0xa881_0801, 0xa97f_1003],
            init_x(&[(0, DATA), (1, 0xc3), (2, 0xd4)]),
        );
        assert_eq!(d.x[0], DATA + 16);
        assert_eq!(d.x[3], 0xc3);
        assert_eq!(d.x[4], 0xd4);
    }

    #[test]
    fn load_literal_word() {
        // ldr w0,#4 ; add x28,x28,#0  (literal word == the add encoding, run as a nop)
        let d = check(&[0x1800_0020, 0x9100_039c], init_x(&[]));
        assert_eq!(d.x[0], 0x9100_039c);
    }

    #[test]
    fn load_literal_doubleword() {
        // ldr x0,#4 ; add x28,x28,#0 ; add x27,x27,#0  (two words form the literal)
        let d = check(&[0x5800_0020, 0x9100_039c, 0x9100_037b], init_x(&[]));
        assert_eq!(d.x[0], 0x9100_037b_9100_039c);
    }

    #[test]
    fn load_literal_signed_word() {
        // ldrsw x0,#4 ; add x28,x28,#0  (literal has bit31 set -> sign-extended)
        let d = check(&[0x9800_0020, 0x9100_039c], init_x(&[]));
        assert_eq!(d.x[0], 0xffff_ffff_9100_039c);
    }

    #[test]
    fn exclusive_ldxr_stxr_roundtrip() {
        // ldxr x2,[x0] ; stxr w5,x1,[x0] ; ldr x3,[x0]
        let d = check(
            &[0xc85f_7c02, 0xc805_7c01, 0xf940_0003],
            init_x(&[(0, DATA), (1, 0x4242)]),
        );
        assert_eq!(d.x[2], 0); // old (zeroed) memory
        assert_eq!(d.x[3], 0x4242); // stored value
        assert_eq!(d.x[5], 0); // success status
    }

    #[test]
    fn exclusive_ldaxr_stlxr_roundtrip() {
        // ldaxr x2,[x0] ; stlxr w5,x1,[x0] ; ldr x3,[x0]
        let d = check(
            &[0xc85f_fc02, 0xc805_fc01, 0xf940_0003],
            init_x(&[(0, DATA), (1, 0x4343)]),
        );
        assert_eq!(d.x[3], 0x4343);
        assert_eq!(d.x[5], 0);
    }

    #[test]
    fn ordered_stlr_ldar_roundtrip() {
        // stlr x1,[x0] ; ldar x2,[x0]
        let d = check(
            &[0xc89f_fc01, 0xc8df_fc02],
            init_x(&[(0, DATA), (1, 0x4444)]),
        );
        assert_eq!(d.x[2], 0x4444);
    }

    #[test]
    fn casal_word_leaves_rt_untouched() {
        // Regression: CAS shares the o2/o1 == 1/1 slot of the exclusive group
        // and was executed as LDAXP, clobbering Rt with the loaded value.
        // str x1,[x0] ; casal w15,w11,[x0] (match) ; ldr x4,[x0]
        let d = check(
            &[0xf900_0001, 0x88ef_fc0b, 0xf940_0004],
            init_x(&[
                (0, DATA),
                (1, 0x1111_2222_0000_5d96),
                (11, 0xa94ef),
                (15, 0xffff_ffff_0000_5d96), // upper half ignored by the W compare
            ]),
        );
        assert_eq!(d.x[11], 0xa94ef); // Rt (new value) is not written
        assert_eq!(d.x[15], 0x5d96); // Rs receives the old word, zero-extended
        assert_eq!(d.x[4], 0x1111_2222_000a_94ef); // only the low word stored
    }

    #[test]
    fn cas_mismatch_and_byte_halfword_doubleword_forms() {
        // str x1,[x0] ; cas w2,w3,[x0] (mismatch) ; casb w5,w6,[x0] (match) ;
        // cash w7,w8,[x0] (mismatch) ; casal x9,x10,[x0] (mismatch) ; ldr x4,[x0]
        let d = check(
            &[
                0xf900_0001,
                0x88a2_7c03,
                0x08a5_7c06,
                0x48a7_7c08,
                0xc8e9_fc0a,
                0xf940_0004,
            ],
            init_x(&[
                (0, DATA),
                (1, 0x8877_6655_4433_2211),
                (2, 0x1234),
                (3, 0xdead),
                (5, 0x11),
                (6, 0xab),
                (7, 0x9999),
                (8, 0xcdef),
                (9, 0x42),
                (10, 0x4343),
            ]),
        );
        assert_eq!(d.x[2], 0x4433_2211);
        assert_eq!(d.x[5], 0x11);
        assert_eq!(d.x[4], 0x8877_6655_4433_22ab);
    }

    #[test]
    fn swpal_swaps_memory_and_register() {
        // str x1,[x0] ; swpal x2,x3,[x0] ; ldr x4,[x0]
        let d = check(
            &[0xf900_0001, 0xf8e2_8003, 0xf940_0004],
            init_x(&[(0, DATA), (1, 0x1000), (2, 0x2000)]),
        );
        assert_eq!(d.x[3], 0x1000); // old value read out
        assert_eq!(d.x[4], 0x2000); // new value in memory
    }
}
