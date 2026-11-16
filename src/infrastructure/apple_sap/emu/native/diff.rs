//! Differential test harness: runs the same A64 code on the native interpreter
//! and on the Unicorn backend and asserts identical architectural state.
//!
//! This is the oracle for every instruction group: a group is correct when its
//! encodings produce byte-identical registers/flags on both engines.

use std::time::Duration;

use super::super::{Engine, Register};
use super::NativeCpu;

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const DATA_SIZE: u64 = 0x1_0000;
const STACK: u64 = 0x5_0000;
const SENTINEL: u64 = 0xdead_0000;

/// Initial architectural state for a differential run.
#[derive(Clone)]
pub(super) struct Init {
    pub x: [u64; 31],
    pub sp: u64,
    pub nzcv: u32,
    pub v: [u128; 32],
}

impl Default for Init {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp: STACK,
            nzcv: 0,
            v: [0; 32],
        }
    }
}

/// A snapshot of comparable architectural state.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Dump {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u32,
    pub v: [u128; 32],
}

fn run_unicorn(code: &[u32], init: &Init, steps: usize) -> Dump {
    let mut e = Engine::new().expect("engine");
    e.mem_map(CODE, 0x4000).unwrap();
    e.mem_map(DATA, DATA_SIZE).unwrap();
    e.mem_map(STACK & !0xfff, 0x4000).unwrap();
    for (i, word) in code.iter().enumerate() {
        e.write_u32(CODE + (i as u64) * 4, *word).unwrap();
    }
    for (n, value) in init.x.iter().enumerate() {
        e.reg_write(Register::X(n as u8), *value).unwrap();
    }
    e.reg_write(Register::Sp, init.sp).unwrap();
    e.reg_write(Register::Nzcv, u64::from(init.nzcv)).unwrap();
    for (n, value) in init.v.iter().enumerate() {
        e.vreg_write(n as u8, value.to_le_bytes()).unwrap();
    }
    e.start_bounded(CODE, SENTINEL, Duration::from_secs(10), steps)
        .expect("unicorn run");
    let mut x = [0u64; 31];
    for (n, slot) in x.iter_mut().enumerate() {
        *slot = e.reg_read(Register::X(n as u8)).unwrap();
    }
    let mut v = [0u128; 32];
    for (n, slot) in v.iter_mut().enumerate() {
        *slot = u128::from_le_bytes(e.vreg_read(n as u8).unwrap());
    }
    Dump {
        x,
        sp: e.reg_read(Register::Sp).unwrap(),
        pc: e.reg_read(Register::Pc).unwrap(),
        nzcv: (e.reg_read(Register::Nzcv).unwrap() as u32) & 0xf000_0000,
        v,
    }
}

fn run_native(code: &[u32], init: &Init, steps: usize) -> Dump {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(CODE, 0x4000);
    cpu.mem.map(DATA, DATA_SIZE);
    cpu.mem.map(STACK & !0xfff, 0x4000);
    let mut bytes = Vec::with_capacity(code.len() * 4);
    for word in code {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    cpu.mem.write(CODE, &bytes).unwrap();
    for (n, value) in init.x.iter().enumerate() {
        cpu.set_x(n as u32, *value);
    }
    cpu.set_sp(init.sp);
    cpu.set_nzcv(init.nzcv);
    for (n, value) in init.v.iter().enumerate() {
        cpu.set_v(n as u32, *value);
    }
    cpu.set_pc(CODE);
    cpu.run(SENTINEL, steps).expect("native run");
    let mut x = [0u64; 31];
    for (n, slot) in x.iter_mut().enumerate() {
        *slot = cpu.x(n as u32);
    }
    let mut v = [0u128; 32];
    for (n, slot) in v.iter_mut().enumerate() {
        *slot = cpu.v(n as u32);
    }
    Dump {
        x,
        sp: cpu.sp(),
        pc: cpu.pc(),
        nzcv: cpu.nzcv() & 0xf000_0000,
        v,
    }
}

/// Runs `code` (whose length is the step count) on both engines with `init`
/// and asserts identical state. Returns the agreed dump for value assertions.
#[track_caller]
pub(super) fn check(code: &[u32], init: Init) -> Dump {
    let steps = code.len();
    let native = run_native(code, &init, steps);
    let unicorn = run_unicorn(code, &init, steps);
    assert_eq!(
        native, unicorn,
        "native vs unicorn divergence for code {code:08x?}"
    );
    native
}

/// Convenience: run with all-zero initial state.
#[track_caller]
pub(super) fn check_zero(code: &[u32]) -> Dump {
    check(code, Init::default())
}

/// Builds an `Init` with specific X registers set.
pub(super) fn init_x(pairs: &[(usize, u64)]) -> Init {
    let mut init = Init::default();
    for (n, v) in pairs {
        init.x[*n] = *v;
    }
    init
}

// ---------------------------------------------------------------------------
// Data-processing -- immediate tests
// ---------------------------------------------------------------------------

#[test]
fn movz_movk_build_a_64bit_constant() {
    // movz x0, #0x1234 ; movk x0, #0x5678, lsl #16
    let dump = check_zero(&[0xd282_4680, 0xf2aa_cf00]);
    assert_eq!(dump.x[0], 0x5678_1234);
}

#[test]
fn movn_inverts() {
    // movn x1, #0 -> 0xffff_ffff_ffff_ffff
    check_zero(&[0x9280_0001]);
}

#[test]
fn add_sub_immediate_with_and_without_flags() {
    // add x0, x0, #1 ; subs x1, x0, #2 (sets flags)
    check(&[0x9100_0400, 0xf100_0801], init_x(&[(0, 10)]));
}

#[test]
fn add_immediate_shifted() {
    // add x0, x0, #1, lsl #12
    check(&[0x9140_0400], init_x(&[(0, 0)]));
}

#[test]
fn logical_immediate_and_orr_eor() {
    // and x0, x1, #0xff ; orr x2, x1, #0xf00 ; eor x3, x1, #0xffff
    check(
        &[0x9240_1c20, 0xb278_0c22, 0xd240_3c23],
        init_x(&[(1, 0x1234_5678)]),
    );
}

#[test]
fn ands_immediate_sets_flags() {
    // ands x0, x1, #0xf (nonzero) then ands x2, x3, #0xf (zero)
    check(&[0xf240_0c20, 0xf240_0c62], init_x(&[(1, 0xff), (3, 0x10)]));
}

#[test]
fn ubfm_lsr_and_lsl_forms() {
    // lsr x0, x1, #4 (ubfm) ; lsl x2, x1, #8 (ubfm) ; ubfx x3, x1, #8, #8
    check(
        &[0xd344_fc20, 0xd378_dc22, 0xd348_3c23],
        init_x(&[(1, 0x1234_5678_9abc_def0)]),
    );
}

#[test]
fn sbfm_asr_and_sign_extend() {
    // asr x0, x1, #4 (sbfm) ; sxtb x2, w1 (sbfm)
    check(
        &[0x9344_fc20, 0x9340_1c22],
        init_x(&[(1, 0xffff_ffff_ffff_ff80)]),
    );
}

#[test]
fn bfm_insert_keeps_other_bits() {
    // bfi x0, x1, #8, #8  (bfm)
    check(
        &[0xb378_1c20],
        init_x(&[(0, 0xffff_ffff_ffff_ffff), (1, 0xab)]),
    );
}

#[test]
fn extr_concatenates_and_rotates() {
    // extr x0, x1, x2, #16
    check(
        &[0x93c2_4020],
        init_x(&[(1, 0x1111_2222_3333_4444), (2, 0xaaaa_bbbb_cccc_dddd)]),
    );
}

#[test]
fn adr_and_adrp_are_pc_relative() {
    // adr x0, #0 ; adrp x1, #0
    let dump = check_zero(&[0x1000_0000, 0x9000_0001]);
    assert_eq!(dump.x[0], CODE);
    assert_eq!(dump.x[1], CODE & !0xfff);
}

#[test]
fn thirtytwo_bit_ops_zero_extend() {
    // add w0, w0, #1 ; movz w1, #0xffff, lsl #16 (w-form zero-extends to x)
    let dump = check(
        &[0x1100_0400, 0x52bf_ffe1],
        init_x(&[(0, 0xffff_ffff_0000_0000)]),
    );
    assert_eq!(dump.x[0], 0x1); // w-add wraps and zero-extends
    assert_eq!(dump.x[1], 0xffff_0000);
}
