//! Differential test harness: runs A64 code on the native interpreter and
//! asserts the architectural state Unicorn produced for the same case.
//!
//! This is the oracle for every instruction group: a group is correct when its
//! encodings produce byte-identical registers/flags to the Unicorn backend.
//! Unicorn's results are frozen in `tests/fixtures/native_oracle/` (see
//! [`super::frozen`]), so the comparison needs no Unicorn at test time. With
//! the `unicorn` feature the live [`UnicornEngine`] (never the selected
//! `Engine`) is run as well and must agree with both.

use std::fmt::Write as _;
#[cfg(feature = "unicorn")]
use std::time::Duration;

#[cfg(feature = "unicorn")]
use super::super::{Register, UnicornEngine};
use super::NativeCpu;
use super::frozen;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Dump {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u32,
    pub v: [u128; 32],
}

#[cfg(feature = "unicorn")]
fn run_unicorn(code: &[u32], init: &Init, steps: usize) -> Dump {
    let mut e = UnicornEngine::new().expect("engine");
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

/// Fixture key of a case: the code words, then the non-default `init` fields.
fn case_key(code: &[u32], init: &Init) -> String {
    let mut key = code
        .iter()
        .map(|word| format!("{word:08x}"))
        .collect::<Vec<_>>()
        .join(" ");
    key.push_str(" |");
    let start = key.len();
    for (n, value) in init.x.iter().enumerate().filter(|(_, v)| **v != 0) {
        write!(key, " x{n}={value:x}").unwrap();
    }
    if init.sp != STACK {
        write!(key, " sp={:x}", init.sp).unwrap();
    }
    if init.nzcv != 0 {
        write!(key, " nzcv={:x}", init.nzcv).unwrap();
    }
    for (n, value) in init.v.iter().enumerate().filter(|(_, v)| **v != 0) {
        write!(key, " v{n}={value:x}").unwrap();
    }
    if key.len() == start {
        key.push_str(" -");
    }
    key
}

/// The state a run would end in if it changed nothing but the PC.
fn baseline(init: &Init) -> Dump {
    Dump {
        x: init.x,
        sp: init.sp,
        pc: CODE,
        nzcv: init.nzcv & 0xf000_0000,
        v: init.v,
    }
}

/// Encodes `dump` as its delta from [`baseline`]: `pc` always, then every
/// other field that changed.
#[cfg(feature = "unicorn")]
fn encode_dump(init: &Init, dump: &Dump) -> String {
    let base = baseline(init);
    let mut text = format!("pc={:x}", dump.pc);
    if dump.sp != base.sp {
        write!(text, " sp={:x}", dump.sp).unwrap();
    }
    if dump.nzcv != base.nzcv {
        write!(text, " nzcv={:x}", dump.nzcv).unwrap();
    }
    for (n, (value, old)) in dump.x.iter().zip(base.x).enumerate() {
        if *value != old {
            write!(text, " x{n}={value:x}").unwrap();
        }
    }
    for (n, (value, old)) in dump.v.iter().zip(base.v).enumerate() {
        if *value != old {
            write!(text, " v{n}={value:x}").unwrap();
        }
    }
    text
}

/// Rebuilds the full [`Dump`] from `init` and an [`encode_dump`] delta.
fn decode_dump(init: &Init, text: &str) -> Dump {
    let mut dump = baseline(init);
    for field in text.split_whitespace() {
        let parsed = field.split_once('=').and_then(|(name, hex)| {
            let value = u128::from_str_radix(hex, 16).ok()?;
            let index = |prefix: char| name.strip_prefix(prefix)?.parse::<usize>().ok();
            match name {
                "pc" => dump.pc = u64::try_from(value).ok()?,
                "sp" => dump.sp = u64::try_from(value).ok()?,
                "nzcv" => dump.nzcv = u32::try_from(value).ok()?,
                _ if name.starts_with('x') => {
                    *dump.x.get_mut(index('x')?)? = u64::try_from(value).ok()?;
                }
                _ => *dump.v.get_mut(index('v')?)? = value,
            }
            Some(())
        });
        assert!(
            parsed.is_some(),
            "malformed oracle field `{field}` in `{text}`"
        );
    }
    dump
}

/// Runs `code` (whose length is the step count) natively with `init` and
/// asserts the state Unicorn produced for it (frozen; also live with the
/// `unicorn` feature). Returns that state for value assertions.
#[track_caller]
pub(super) fn check(code: &[u32], init: Init) -> Dump {
    let steps = code.len();
    let fixture = frozen::fixture_name(std::panic::Location::caller().file());
    let key = case_key(code, &init);
    let native = run_native(code, &init, steps);
    #[cfg(feature = "unicorn")]
    {
        let unicorn = run_unicorn(code, &init, steps);
        frozen::record(&fixture, &key, &encode_dump(&init, &unicorn));
        assert_eq!(
            native, unicorn,
            "native vs unicorn divergence for code {code:08x?}"
        );
        if frozen::recording() {
            return native;
        }
    }
    let Some(expected) = frozen::lookup(&fixture, &key) else {
        frozen::missing(&fixture, &key)
    };
    assert_eq!(
        native,
        decode_dump(&init, &expected),
        "native vs frozen Unicorn divergence for code {code:08x?}"
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
