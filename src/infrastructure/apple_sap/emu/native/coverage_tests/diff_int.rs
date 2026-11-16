//! Differential (native vs Unicorn) tests for integer data-processing paths
//! the per-group tests leave unexercised: condition codes, 32-bit forms,
//! extend options and division corner cases.

use super::super::diff::{Init, check, init_x};

fn with_nzcv(mut init: Init, nzcv: u32) -> Init {
    init.nzcv = nzcv;
    init
}

/// `csinc x<cond>, xzr, xzr, <cond>` for every condition code 0..=15: X[cond]
/// ends up 0 when the condition holds and 1 otherwise.
fn csinc_every_condition() -> Vec<u32> {
    (0..16)
        .map(|cond| 0x9a9f_07e0 | (cond << 12) | cond)
        .collect()
}

#[test]
fn every_condition_code_under_every_flag_combination() {
    let code = csinc_every_condition();
    for flags in 0..16u32 {
        let d = check(&code, with_nzcv(Init::default(), flags << 28));
        // AL and NV always hold.
        assert_eq!((d.x[14], d.x[15]), (0, 0), "flags {flags:04b}");
        // Each condition pair is the inverse of the other.
        for cond in (0..14).step_by(2) {
            assert_ne!(d.x[cond], d.x[cond + 1], "flags {flags:04b} cond {cond}");
        }
    }
}

#[test]
fn thirty_two_bit_immediate_forms() {
    // adds w0, w1, #1 ; ands w2, w3, #0x80000000 ; sxtb x4, w5 (positive)
    // ubfx w6, w7, #4, #8 ; extr w8, w9, w10, #8
    let d = check(
        &[
            0x3100_0420,
            0x7201_0062,
            0x9340_1ca4,
            0x5304_2ce6,
            0x138a_2128,
        ],
        init_x(&[
            (1, 0xffff_ffff_7fff_ffff),
            (3, 0x1_8000_0001),
            (5, 0xffff_ff7f),
            (7, 0xffff_ffff_ffff_abcd),
            (9, 0x1122_3344),
            (10, 0xaabb_ccdd),
        ]),
    );
    assert_eq!(d.x[0], 0x8000_0000);
    assert_eq!(d.x[2], 0x8000_0000);
    assert_eq!(d.x[4], 0x7f, "sign bit clear: no sign fill");
    assert_eq!(d.x[6], 0xbc);
    assert_eq!(d.x[8], 0x44aa_bbcc);
}

#[test]
fn thirty_two_bit_register_forms_and_ror_by_zero() {
    // ands w0, w1, w2 ; add w3, w1, w2, asr #3 ; asr w4, w1, w2 ; ror x5, x1, x6
    let d = check(
        &[0x6a02_0020, 0x0b82_0c23, 0x1ac2_2824, 0x9ac6_2c25],
        init_x(&[(1, 0x8000_00f0), (2, 0x8000_0004), (6, 64)]),
    );
    assert_eq!(d.x[0], 0x8000_0000);
    assert_eq!(d.x[5], 0x8000_00f0, "ror by 64 % 64 == 0 is the identity");
}

#[test]
fn extended_register_options() {
    // add x0, x1, w2, uxth ; add x3, x1, x2, uxtx ; add x4, x1, w2, sxtb
    // add x5, x1, w2, sxtw ; add w6, w1, w2, uxtb ; add wsp, w1, w2, uxtb
    let d = check(
        &[
            0x8b22_2020,
            0x8b22_6023,
            0x8b22_8024,
            0x8b22_c025,
            0x0b22_0026,
            0x0b22_003f,
        ],
        init_x(&[(1, 0x1_0000_0000), (2, 0xffff_ffff_8001_8081)]),
    );
    assert_eq!(d.x[0], 0x1_0000_8081);
    assert_eq!(d.x[4], 0x1_0000_0000 - 0x7f);
    assert_eq!(d.sp, 0x81);
}

#[test]
fn ccmn_with_condition_true_and_csneg_with_condition_false() {
    // ccmn x1, x2, #0, eq (Z set: compares) ; csneg x0, x1, x2, ne (Z set: negates)
    let d = check(
        &[0xba42_0020, 0xda82_1420],
        with_nzcv(init_x(&[(1, 1), (2, u64::MAX)]), 0x4000_0000),
    );
    assert_eq!(d.nzcv, 0x6000_0000, "1 + -1 == 0 sets Z and C");
}

#[test]
fn division_corner_cases() {
    // udiv w0, w1, w2 ; sdiv x3, x1, xzr ; sdiv w4, w1, w2 ; sdiv w5, w1, wzr
    let d = check(
        &[0x1ac2_0820, 0x9adf_0c23, 0x1ac2_0c24, 0x1adf_0c25],
        init_x(&[(1, 0xffff_ffff_ffff_fff0), (2, 0xffff_ffff_0000_0003)]),
    );
    assert_eq!(d.x[0], 0xffff_fff0 / 3);
    assert_eq!(d.x[3], 0);
    assert_eq!(d.x[4], (-16i32 / 3) as u32 as u64);
    assert_eq!(d.x[5], 0);
}

#[test]
fn umsubl_and_clz_32() {
    // umsubl x6, w1, w2, x3 ; clz w7, w1
    let d = check(
        &[0x9ba2_8c26, 0x5ac0_1027],
        init_x(&[(1, 0xffff_ffff_0000_1000), (2, 0x10), (3, 0x2_0000)]),
    );
    assert_eq!(d.x[6], 0x1_0000);
    assert_eq!(d.x[7], 19);
}
