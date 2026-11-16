//! Differential (native vs Unicorn) tests for the Advanced SIMD / scalar FP
//! paths the per-group tests in `simd.rs` leave unexercised. Encodings come
//! from `llvm-mc -triple=aarch64 --show-encoding`.

use super::super::diff::{Init, check, init_x};

const DATA: u64 = 0x2_0000;
/// Sixteen distinct bytes `0x00..=0x0f` (lane 0 = least significant).
const V1: u128 = 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100;
/// A mixed-sign pattern for the second operand.
const V2: u128 = 0x8899_aabb_ccdd_eeff_1122_3344_5566_7788;

fn init_v(pairs: &[(usize, u128)]) -> Init {
    let mut init = Init::default();
    for (n, value) in pairs {
        init.v[*n] = *value;
    }
    init
}

fn with_x(mut init: Init, pairs: &[(usize, u64)]) -> Init {
    for (n, value) in pairs {
        init.x[*n] = *value;
    }
    init
}

/// Packs four `f32` lanes (lane 0 first).
fn f32x4(lanes: [f32; 4]) -> u128 {
    lanes
        .iter()
        .enumerate()
        .fold(0, |acc, (i, f)| acc | (u128::from(f.to_bits()) << (32 * i)))
}

/// Packs two `f64` lanes (lane 0 first).
fn f64x2(lo: f64, hi: f64) -> u128 {
    u128::from(lo.to_bits()) | (u128::from(hi.to_bits()) << 64)
}

// --- three-same -------------------------------------------------------------

#[test]
fn add_8b_clears_the_upper_half() {
    // add v0.8b, v1.8b, v2.8b (Q == 0: the high 64 bits of Vd are zeroed)
    let d = check(&[0x0e22_8420], init_v(&[(0, u128::MAX), (1, V1), (2, V2)]));
    assert_eq!(d.v[0] >> 64, 0);
}

#[test]
fn ushl_by_esize_or_more_is_zero() {
    // ushl v0.4s, v1.4s, v2.4s with shifts {32, 40, -32, 1}
    let shifts = 0x0000_0001_0000_00e0_0000_0028_0000_0020u128;
    let d = check(&[0x6ea2_4420], init_v(&[(1, u128::MAX), (2, shifts)]));
    assert_eq!(d.v[0], 0xffff_fffeu128 << 96);
}

#[test]
fn sshl_2d_and_4s_saturating_shift_amounts() {
    // sshl v0.2d, v1.2d, v2.2d with shifts {64, -64}
    check(
        &[0x4ee2_4420],
        init_v(&[
            (1, 0x8000_0000_0000_0001_8000_0000_0000_0001),
            (2, 0x0000_0000_0000_00c0_0000_0000_0000_0040),
        ]),
    );
    // sshl v0.4s, v1.4s, v2.4s with shifts {32, 33, -33, 4}
    check(
        &[0x4ea2_4420],
        init_v(&[
            (1, 0x8000_0001_8000_0001_7fff_ffff_0000_0011),
            (2, 0x0000_0004_0000_00df_0000_0021_0000_0020),
        ]),
    );
}

// --- copy: UMOV / SMOV / INS (general) / DUP (general) ------------------------

#[test]
fn umov_and_smov_move_one_lane_to_a_gpr() {
    // umov w0, v1.b[3] ; umov w2, v1.h[5] ; mov w3, v1.s[2] ; mov x4, v1.d[1]
    // smov w5, v1.b[9] ; smov x6, v1.h[6] ; smov x7, v1.s[1]
    let v1 = 0x8000_7fff_80ff_8002_ff00_0000_8070_6050u128;
    let d = check(
        &[
            0x0e07_3c20,
            0x0e16_3c22,
            0x0e14_3c23,
            0x4e18_3c24,
            0x0e13_2c25,
            0x4e1a_2c26,
            0x4e0c_2c27,
        ],
        with_x(init_v(&[(1, v1)]), &[(0, u64::MAX), (5, u64::MAX)]),
    );
    assert_eq!(d.x[0], 0x80, "umov w zero-extends into X");
    assert_eq!(d.x[4], 0x8000_7fff_80ff_8002);
    assert_eq!(d.x[5], 0xffff_ff80, "smov w sign-extends to 32 bits only");
}

#[test]
fn ins_general_inserts_one_lane_of_each_width() {
    // mov v0.b[3], w1 ; mov v2.h[5], w1 ; mov v3.s[2], w1 ; mov v4.d[1], x1
    let d = check(
        &[0x4e07_1c20, 0x4e16_1c22, 0x4e14_1c23, 0x4e18_1c24],
        with_x(
            init_v(&[(0, V2), (2, V2), (3, V2), (4, V2)]),
            &[(1, 0x1122_3344_5566_7788)],
        ),
    );
    assert_eq!(d.v[4] >> 64, 0x1122_3344_5566_7788);
    assert_eq!(d.v[4] as u64, V2 as u64, "the other lane is preserved");
}

#[test]
fn dup_general_byte_replicates_the_low_byte() {
    // dup v0.16b, w1
    let d = check(&[0x4e01_0c20], init_x(&[(1, 0x1234_56ab)]));
    assert_eq!(d.v[0], 0xabab_abab_abab_abab_abab_abab_abab_abab);
}

#[test]
fn tbx_keeps_the_old_byte_for_out_of_range_indices() {
    // tbx v0.16b, {v1.16b}, v2.16b (indices >= 16 keep Vd's byte)
    let indices = 0xff10_2030_0f0e_0d0c_0b0a_0908_0706_0100u128;
    let d = check(&[0x4e02_1020], init_v(&[(0, V2), (1, V1), (2, indices)]));
    assert_eq!(d.v[0] >> 96, V2 >> 96);
}

// --- modified immediate -----------------------------------------------------

#[test]
fn movi_mvni_shifted_and_msl_forms() {
    // mvni v0.4s, #0x12, lsl #8 ; movi v2.8h, #0x34, lsl #8 ; mvni v1.4h, #0x56
    // movi v3.4s, #0x12, msl #16 ; mvni v4.2s, #0x12, msl #16
    // fmov v5.2d, #1.5 ; movi v6.2s, #1
    let d = check(
        &[
            0x6f00_2640,
            0x4f01_a682,
            0x2f02_86c1,
            0x4f00_d643,
            0x2f00_d644,
            0x6f03_f705,
            0x0f00_0426,
        ],
        init_v(&[(1, u128::MAX), (4, u128::MAX), (6, u128::MAX)]),
    );
    assert_eq!(d.v[1] >> 64, 0, "Q == 0 clears the upper half");
    assert_eq!(d.v[5], f64x2(1.5, 1.5));
    assert_eq!(d.v[6], 0x0000_0001_0000_0001);
}

// --- shift by immediate -----------------------------------------------------

#[test]
fn ushr_and_sri_by_the_full_element_width() {
    // ushr v0.4s, v1.4s, #32 (all zero) ; sri v2.4s, v1.4s, #32 (Vd unchanged)
    let d = check(
        &[0x6f20_0420, 0x6f20_4422],
        init_v(&[(0, V2), (1, V1), (2, V2)]),
    );
    assert_eq!(d.v[0], 0);
    assert_eq!(d.v[2], V2);
}

// --- two-register misc (FP) -------------------------------------------------

#[test]
fn fabs_2s_clears_the_upper_half() {
    // fabs v0.2s, v1.2s
    let d = check(
        &[0x0ea0_f820],
        init_v(&[(0, u128::MAX), (1, f32x4([-1.5, 2.0, -3.0, -4.0]))]),
    );
    assert_eq!(d.v[0], f32x4([1.5, 2.0, 0.0, 0.0]) & u128::from(u64::MAX));
}

#[test]
fn fp_compare_against_zero_single_and_double() {
    let singles = f32x4([-1.0, 0.0, 2.5, -0.0]);
    // fcmge v0.4s, v1.4s, #0.0 ; fcmle v2.4s, v1.4s, #0.0
    check(&[0x6ea0_c820, 0x6ea0_d822], init_v(&[(1, singles)]));
    // fcmgt / fcmge / fcmeq / fcmle / fcmlt on .2d, for both signs of input
    let codes = [
        0x4ee0_c820,
        0x6ee0_c822,
        0x4ee0_d823,
        0x6ee0_d824,
        0x4ee0_e825,
    ];
    check(&codes, init_v(&[(1, f64x2(-2.0, 0.0))]));
    check(&codes, init_v(&[(1, f64x2(3.0, -0.0))]));
}

#[test]
fn ucvtf_vector_treats_lanes_as_unsigned() {
    // ucvtf v0.4s, v1.4s
    let d = check(
        &[0x6e21_d820],
        init_v(&[(1, 0xffff_ffff_8000_0000_0000_0001_0000_0000)]),
    );
    assert_eq!(d.v[0] as u32, 0);
    assert_eq!((d.v[0] >> 32) as u32, 1.0f32.to_bits());
}

// --- across lanes -----------------------------------------------------------

#[test]
fn saddlv_4s_accumulates_into_a_doubleword() {
    // saddlv d0, v1.4s
    let d = check(
        &[0x4eb0_3820],
        init_v(&[(1, 0x8000_0000_8000_0000_7fff_ffff_ffff_ffff)]),
    );
    assert_eq!(d.v[0] as u64 as i64, -(1i64 << 32) + 0x7fff_ffff - 1);
}

// --- scalar FP --------------------------------------------------------------

#[test]
fn ucvtf_scalar_zero_and_rounding_paths() {
    // ucvtf s0, w1 (0) ; ucvtf d0, x1 (0) ; ucvtf d1, x2 (round up) ;
    // ucvtf d2, x3 (u64::MAX rounds up into the next binade)
    let d = check(
        &[0x1e23_0020, 0x9e63_0020, 0x9e63_0041, 0x9e63_0062],
        init_x(&[(1, 0), (2, (1 << 60) + (1 << 7) + 1), (3, u64::MAX)]),
    );
    assert_eq!(d.v[0], 0);
    assert_eq!(
        d.v[2],
        u128::from(18_446_744_073_709_551_616.0f64.to_bits())
    );
}

#[test]
fn fcmp_single_nan_and_double_orderings() {
    // fcmp s0, s1 with a NaN operand -> unordered (C, V)
    let d = check(
        &[0x1e21_2000],
        init_v(&[(0, u128::from(f32::NAN.to_bits()))]),
    );
    assert_eq!(d.nzcv, 0x3000_0000);
    // fcmp d0, d1 : NaN ; less-than ; greater-than
    for (lhs, rhs, nzcv) in [
        (f64::NAN, 1.0, 0x3000_0000),
        (1.0, 2.0, 0x8000_0000),
        (2.0, 1.0, 0x2000_0000),
    ] {
        let init = init_v(&[(0, f64x2(lhs, 0.0)), (1, f64x2(rhs, 0.0))]);
        assert_eq!(check(&[0x1e61_2000], init).nzcv, nzcv);
    }
}

// --- SIMD/FP loads and stores -----------------------------------------------

#[test]
fn register_offset_vector_loads_and_stores() {
    // ldr q0, [x0, x1, lsl #4] ; str d2, [x0, w5, sxtw #3]
    // ldr s3, [x0, w6, uxtw] ; ldr b4, [x0, x1]
    // W5 = -2 (SXTW) and X6 has garbage above bit 31 (UXTW ignores it).
    let d = check(
        &[0x3ce1_7800, 0xfc25_d802, 0xbc66_4803, 0x3c61_6804],
        with_x(
            init_v(&[(2, V2)]),
            &[
                (0, DATA + 0x100),
                (1, 2),
                (5, 0xffff_fffe),
                (6, 0xdead_0000_0000_00f0),
            ],
        ),
    );
    assert_eq!(d.v[2], V2);
}

#[test]
fn vector_pairs_single_and_no_allocate() {
    // stp s2, s3, [x0, #-8]! ; ldp s0, s1, [x0, #8]
    // stnp d2, d3, [x0, #16] ; ldnp q4, q5, [x0]
    let d = check(
        &[0x2dbf_0c02, 0x2d41_0400, 0x6c01_0c02, 0xac40_1404],
        with_x(init_v(&[(2, V1), (3, V2)]), &[(0, DATA + 0x40)]),
    );
    assert_eq!(d.x[0], DATA + 0x38, "pre-index writes back");
}
