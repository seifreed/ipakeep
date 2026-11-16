//! Native-vs-Unicorn divergences found while closing coverage. Each test is
//! the differential reproduction of a real interpreter bug: the encoding is
//! *not* rejected as `Unsupported` but decoded as a neighbouring instruction
//! and executed with the wrong semantics. They are `#[ignore]`d until the
//! interpreter is fixed; run them with
//! `cargo test --lib --all-features coverage_tests::diff_bugs -- --ignored`.

use super::super::diff::{Init, check, init_x};

const DATA: u64 = 0x2_0000;
const V1: u128 = 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
const V2: u128 = 0x8899_aabb_ccdd_eeff_1122_3344_5566_7788;

fn init_v(pairs: &[(usize, u128)]) -> Init {
    let mut init = Init::default();
    for (n, value) in pairs {
        init.v[*n] = *value;
    }
    init
}

#[test]
#[ignore = "bug: CASAL (o2=1,o1=1) runs as LDAXP instead of Unsupported/compare-and-swap"]
fn casal_is_not_executed_as_an_exclusive_pair() {
    // casal x1, x2, [x0] — Unicorn: x1 = old [x0] (0), [x0] = x2, x2 kept (5).
    // Native: loads [x0] into x2 (and XZR), stores nothing.
    let d = check(&[0xc8e1_fc02], init_x(&[(0, DATA), (1, 0), (2, 5)]));
    assert_eq!(d.x[2], 5);
}

#[test]
#[ignore = "bug: EXT (bit29=1) is decoded as TBL"]
fn ext_is_not_executed_as_tbl() {
    // ext v0.16b, v1.16b, v2.16b, #3 — Unicorn 0x6677880f0e0d0c0b0a09080706050403,
    // native 0 (a TBL lookup with V2 as the index vector).
    check(&[0x6e02_1820], init_v(&[(1, V1), (2, V2)]));
}

#[test]
#[ignore = "bug: ZIP1/UZP*/TRN* (permute, bits[11:10]=10) are decoded as TBL"]
fn zip1_is_not_executed_as_tbl() {
    // zip1 v0.16b, v1.16b, v2.16b — Unicorn 0x11072206330544045503660277018800,
    // native 0x00000000000000007700000000000000.
    check(&[0x4e02_3820], init_v(&[(1, V1), (2, V2)]));
}

#[test]
#[ignore = "bug: FRECPE (size<1>=1, opcode 11101) is decoded as SCVTF"]
fn frecpe_is_not_executed_as_scvtf() {
    // frecpe v0.4s, v1.4s on {8.0, 4.0, 1.0, 2.0} — Unicorn
    // 0x3eff80003f7f80003e7f80003dff8000, native 0x4e8000004e7e00004e8100004e820000.
    check(
        &[0x4ea1_d820],
        init_v(&[(1, 0x4000_0000_3f80_0000_4080_0000_4100_0000)]),
    );
}

#[test]
#[ignore = "bug: INS (element) (op=1, imm4=0000) is decoded as DUP (element)"]
fn ins_element_index0_is_not_executed_as_dup() {
    // mov v0.s[1], v1.s[0] — Unicorn 0x8899aabbccddeeff0302010055667788,
    // native 0x07060504070605040706050407060504.
    check(&[0x6e0c_0420], init_v(&[(0, V2), (1, V1)]));
}

#[test]
#[ignore = "bug: INS (element) (op=1, imm4=0011) is decoded as INS (general)"]
fn ins_element_index3_is_not_executed_as_ins_general() {
    // mov v0.b[1], v1.b[3] — Unicorn 0x8899aabbccddeeff1122334455660388,
    // native 0x8899aabbccddeeff1122334455660088 (inserts W1's low byte).
    check(&[0x6e03_1c20], init_v(&[(0, V2), (1, V1)]));
}
