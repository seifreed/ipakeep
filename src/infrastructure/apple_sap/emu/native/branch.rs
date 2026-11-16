//! Branches, exception generating and system (ARM ARM C4.1.4).
//!
//! Sub-groups implemented:
//! * Unconditional branch (immediate): `B`, `BL`.
//! * Conditional branch (immediate): `B.cond`.
//! * Compare-and-branch (immediate): `CBZ`, `CBNZ`.
//! * Test-and-branch (immediate): `TBZ`, `TBNZ`.
//! * Unconditional branch (register): `BR`, `BLR`, `RET`. The PAC-authenticated
//!   variants (`BRAA`/`BLRAA`/`RETAA` …) are rewritten to these plain forms at
//!   load time, so only the plain encodings are decoded here.
//! * Exception generating: `BRK` (→ [`Step::Break`]). `SVC`/`HVC`/`SMC`/`HLT`
//!   are not emitted by the guest and are rejected.
//! * System: `HINT`/`NOP` and the barriers (`DSB`/`DMB`/`ISB`/`CLREX`/`SB`) are
//!   no-ops here; `MRS`/`MSR` touch system state this interpreter does not model
//!   and are rejected.

use super::{NativeCpu, NativeError, Step};

/// Runs a branch / exception / system instruction.
pub(super) fn run(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    // Unconditional branch (immediate): word[30:26] == 00101, word[31] = op.
    match (word >> 26) & 0x3f {
        0b000101 => return branch_imm(cpu, word, false), // B
        0b100101 => return branch_imm(cpu, word, true),  // BL
        _ => {}
    }

    // Compare-and-branch / test-and-branch: word[30:25].
    match (word >> 25) & 0x3f {
        0b011010 => return compare_branch(cpu, word), // CBZ / CBNZ
        0b011011 => return test_branch(cpu, word),    // TBZ / TBNZ
        _ => {}
    }

    // Conditional branch (immediate): word[31:24] == 0x54, word[4] == 0.
    if word & 0xff00_0010 == 0x5400_0000 {
        return cond_branch(cpu, word);
    }

    // Unconditional branch (register): word[31:25] == 1101011.
    if (word >> 25) & 0x7f == 0b1101011 {
        return branch_reg(cpu, word);
    }

    // Exception generation: word[31:24] == 11010100.
    if (word >> 24) & 0xff == 0b1101_0100 {
        return exception(cpu, word);
    }

    // System: hints and barriers are no-ops; everything else is unsupported.
    system(cpu, word)
}

fn unsupported(cpu: &NativeCpu, word: u32, what: &'static str) -> NativeError {
    NativeError::Unsupported {
        pc: cpu.pc(),
        word,
        what,
    }
}

/// Sign-extends the low `bits` bits of `value` to 64 bits.
fn sign_extend(value: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// PC-relative target: this instruction's address plus a scaled, sign-extended
/// immediate.
fn pc_rel_target(cpu: &NativeCpu, offset: u64) -> u64 {
    cpu.pc().wrapping_add(offset)
}

/// `B` / `BL` — unconditional branch (immediate). `imm26 << 2`, sign-extended.
fn branch_imm(cpu: &mut NativeCpu, word: u32, link: bool) -> Result<Step, NativeError> {
    let imm26 = u64::from(word & 0x03ff_ffff);
    let offset = sign_extend(imm26 << 2, 28);
    let target = pc_rel_target(cpu, offset);
    if link {
        cpu.set_x(30, cpu.pc().wrapping_add(4));
    }
    Ok(Step::Branch(target))
}

/// `B.cond` — conditional branch (immediate). `imm19 << 2`, sign-extended.
fn cond_branch(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let cond = (word & 0xf) as u8;
    if super::cond_holds(cpu.nzcv(), cond) {
        let imm19 = u64::from((word >> 5) & 0x0007_ffff);
        let offset = sign_extend(imm19 << 2, 21);
        Ok(Step::Branch(pc_rel_target(cpu, offset)))
    } else {
        Ok(Step::Next)
    }
}

/// `CBZ` / `CBNZ` — compare register against zero and branch.
fn compare_branch(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let sf = (word >> 31) & 1;
    let op = (word >> 24) & 1; // 0 = CBZ, 1 = CBNZ
    let rt = word & 0x1f;
    let value = if sf == 1 {
        cpu.x(rt)
    } else {
        u64::from(cpu.w(rt))
    };
    let is_zero = value == 0;
    let take = if op == 0 { is_zero } else { !is_zero };
    if take {
        let imm19 = u64::from((word >> 5) & 0x0007_ffff);
        let offset = sign_extend(imm19 << 2, 21);
        Ok(Step::Branch(pc_rel_target(cpu, offset)))
    } else {
        Ok(Step::Next)
    }
}

/// `TBZ` / `TBNZ` — test one register bit and branch.
fn test_branch(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let b5 = (word >> 31) & 1;
    let op = (word >> 24) & 1; // 0 = TBZ, 1 = TBNZ
    let b40 = (word >> 19) & 0x1f;
    let rt = word & 0x1f;
    let bit_pos = (b5 << 5) | b40;
    let bit_set = (cpu.x(rt) >> bit_pos) & 1 == 1;
    let take = if op == 0 { !bit_set } else { bit_set };
    if take {
        let imm14 = u64::from((word >> 5) & 0x3fff);
        let offset = sign_extend(imm14 << 2, 16);
        Ok(Step::Branch(pc_rel_target(cpu, offset)))
    } else {
        Ok(Step::Next)
    }
}

/// `BR` / `BLR` / `RET` — unconditional branch (register). PAC variants are
/// pre-stripped to these plain forms, so only `opc` 0/1/2 are accepted.
fn branch_reg(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let opc = (word >> 21) & 0xf;
    let rn = (word >> 5) & 0x1f;
    match opc {
        0b0000 => Ok(Step::Branch(cpu.x(rn))), // BR
        0b0001 => {
            // BLR: capture the target before X30 is overwritten (Rn may be 30).
            let target = cpu.x(rn);
            cpu.set_x(30, cpu.pc().wrapping_add(4));
            Ok(Step::Branch(target))
        }
        0b0010 => Ok(Step::Branch(cpu.x(rn))), // RET
        _ => Err(unsupported(cpu, word, "branch-reg (eret/drps/pac)")),
    }
}

/// Exception generation. Only `BRK #imm16` is handled; the rest are not used by
/// the guest.
fn exception(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    let opc = (word >> 21) & 0x7;
    let ll = word & 0x3;
    match (opc, ll) {
        (0b001, 0b00) => {
            let imm16 = (word >> 5) & 0xffff;
            Ok(Step::Break(imm16 as u16))
        }
        _ => Err(unsupported(cpu, word, "exception (svc/hvc/smc/hlt)")),
    }
}

/// System instructions. Hints and barriers are architectural no-ops for this
/// interpreter (no system registers are modelled); system-register moves are
/// rejected.
fn system(cpu: &mut NativeCpu, word: u32) -> Result<Step, NativeError> {
    // Hints (CRn == 0010, Rt == 11111), including NOP/YIELD/WFE/WFI/SEV.
    if word & 0xffff_f01f == 0xd503_201f {
        return Ok(Step::Next);
    }
    // Barriers (CRn == 0011, Rt == 11111): DSB/DMB/ISB/CLREX/SB.
    if word & 0xffff_f01f == 0xd503_301f {
        return Ok(Step::Next);
    }
    // MRS/MSR (system register) and MSR (immediate) to PSTATE touch state we do
    // not model.
    Err(unsupported(cpu, word, "system register / msr"))
}

#[cfg(all(test, feature = "unicorn"))]
mod tests {
    use super::super::diff::{Init, check, init_x};
    use super::super::{NativeCpu, Step};

    /// CODE base used by the differential harness.
    const CODE: u64 = 0x1_0000;
    /// `b #-4` — recirculates to the previous instruction (keeps bounded tests
    /// inside mapped CODE for a fixed step count).
    const B_BACK_4: u32 = 0x17ff_ffff;
    const NOP: u32 = 0xd503_201f;

    fn with_nzcv(nzcv: u32) -> Init {
        Init {
            nzcv,
            ..Init::default()
        }
    }

    // --- Unconditional branch (immediate) -----------------------------------

    #[test]
    fn b_taken_forward_and_backward() {
        // b #8 (skip the movz x9) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0x1400_0002, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            Init::default(),
        );
        assert_eq!(dump.x[9], 0, "skipped instruction must not run");
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn bl_sets_x30_and_ret_returns() {
        // bl #8 ; movz x0 ; movz x1 ; ret
        let dump = check(
            &[0x9400_0002, 0xd280_1540, 0xd280_1761, 0xd65f_03c0],
            Init::default(),
        );
        assert_eq!(dump.x[30], CODE + 4, "BL links to pc+4");
        assert_eq!(dump.x[0], 0xaa);
        assert_eq!(dump.x[1], 0xbb);
    }

    // --- Conditional branch (immediate) -------------------------------------

    #[test]
    fn bcond_taken_when_condition_holds() {
        // b.eq #8 (Z=1 -> taken) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0x5400_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            with_nzcv(0x4000_0000),
        );
        assert_eq!(dump.x[9], 0);
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn bcond_not_taken_falls_through() {
        // b.eq #8 (Z=0 -> not taken) ; movz x0 ; movz x1 ; nop
        let dump = check(
            &[0x5400_0040, 0xd280_0220, 0xd280_0441, NOP],
            Init::default(),
        );
        assert_eq!(dump.x[0], 0x11);
        assert_eq!(dump.x[1], 0x22);
    }

    // --- Compare-and-branch -------------------------------------------------

    #[test]
    fn cbz_taken_when_zero() {
        // cbz x0 #8 (x0=0 -> taken) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0xb400_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            Init::default(),
        );
        assert_eq!(dump.x[9], 0);
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn cbnz_taken_when_nonzero() {
        // cbnz x0 #8 (x0=7 -> taken) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0xb500_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            init_x(&[(0, 7)]),
        );
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn cbz_w_form_compares_low_32_bits() {
        // cbz w0 #8 with x0=0xffffffff00000000 -> w0==0 -> taken
        let dump = check(
            &[0x3400_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            init_x(&[(0, 0xffff_ffff_0000_0000)]),
        );
        assert_eq!(dump.x[9], 0, "W-form ignores the high 32 bits");
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn cbz_not_taken_falls_through() {
        // cbz x0 #8 (x0=5 -> not taken) ; movz x1 ; movz x2 ; nop
        let dump = check(
            &[0xb400_0040, 0xd280_0661, 0xd280_0882, NOP],
            init_x(&[(0, 5)]),
        );
        assert_eq!(dump.x[1], 0x33);
        assert_eq!(dump.x[2], 0x44);
    }

    // --- Test-and-branch ----------------------------------------------------

    #[test]
    fn tbz_taken_when_bit_clear() {
        // tbz x0 #0 #8 (bit0=0 -> taken) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0x3600_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            Init::default(),
        );
        assert_eq!(dump.x[9], 0);
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn tbnz_taken_on_high_bit() {
        // tbnz x0 #40 #8 (bit 40 set -> taken) ; movz x9 ; movz x2 ; b #-4
        let dump = check(
            &[0xb740_0040, 0xd281_75a9, 0xd281_59c2, B_BACK_4],
            init_x(&[(0, 1u64 << 40)]),
        );
        assert_eq!(dump.x[9], 0, "b5 bit selects bit index >= 32");
        assert_eq!(dump.x[2], 0xace);
    }

    #[test]
    fn tbz_not_taken_when_bit_set() {
        // tbz x0 #3 #8 (bit3 set -> not taken) ; movz x1 ; movz x2 ; nop
        let dump = check(
            &[0x3618_0040, 0xd280_0aa1, 0xd280_0cc2, NOP],
            init_x(&[(0, 8)]),
        );
        assert_eq!(dump.x[1], 0x55);
        assert_eq!(dump.x[2], 0x66);
    }

    // --- Unconditional branch (register) ------------------------------------

    #[test]
    fn br_to_computed_address() {
        // adr x5, #8 ; br x5 ; movz x1 ; b #-4
        let dump = check(
            &[0x1000_0045, 0xd61f_00a0, 0xd280_1761, B_BACK_4],
            Init::default(),
        );
        assert_eq!(dump.x[5], CODE + 8);
        assert_eq!(dump.x[1], 0xbb);
    }

    #[test]
    fn blr_links_and_ret_returns() {
        // adr x6, #12 ; blr x6 ; movz x0 ; movz x1 ; ret
        let dump = check(
            &[
                0x1000_0066,
                0xd63f_00c0,
                0xd280_1540,
                0xd280_1761,
                0xd65f_03c0,
            ],
            Init::default(),
        );
        assert_eq!(dump.x[6], CODE + 12);
        assert_eq!(dump.x[30], CODE + 8, "BLR links to pc+4");
        assert_eq!(dump.x[0], 0xaa);
        assert_eq!(dump.x[1], 0xbb);
    }

    // --- System -------------------------------------------------------------

    #[test]
    fn hints_and_barriers_are_noops() {
        // nop ; dmb ish ; isb ; movz x0
        let dump = check(
            &[NOP, 0xd503_3bbf, 0xd503_3fdf, 0xd280_0ee0],
            Init::default(),
        );
        assert_eq!(dump.x[0], 0x77);
        assert_eq!(dump.pc, CODE + 16);
    }

    // --- Exception generation (native only: Unicorn traps on BRK) -----------

    #[test]
    fn brk_returns_break_with_immediate() {
        let mut cpu = NativeCpu::new();
        cpu.mem.map(CODE, 0x1000);
        cpu.set_pc(CODE);
        // brk #0x42
        cpu.mem.write(CODE, &0xd420_0840u32.to_le_bytes()).unwrap();
        assert_eq!(cpu.step().unwrap(), Step::Break(0x42));
    }

    #[test]
    fn brk_zero_immediate() {
        let mut cpu = NativeCpu::new();
        cpu.mem.map(CODE, 0x1000);
        cpu.set_pc(CODE);
        // brk #0
        cpu.mem.write(CODE, &0xd420_0000u32.to_le_bytes()).unwrap();
        assert_eq!(cpu.step().unwrap(), Step::Break(0));
    }
}
