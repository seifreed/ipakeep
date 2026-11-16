//! Differential (native vs Unicorn) tests for integer load/store paths the
//! per-group tests leave unexercised.

use super::super::diff::{check, init_x};

const DATA: u64 = 0x2_0000;

#[test]
fn prefetches_are_no_ops() {
    // prfm pldl1keep, [x0] ; prfm pldl1keep, [x0, x1] ; prfm pldl1keep, #8
    let d = check(
        &[0xf980_0000, 0xf8a1_6800, 0xd800_0040],
        init_x(&[(0, DATA), (1, 8)]),
    );
    assert_eq!(d.x[0], DATA);
}

#[test]
fn ldpsw_sign_extends_and_no_allocate_pairs() {
    // stnp x3, x4, [x0, #16] ; ldnp x5, x6, [x0, #16] ; ldpsw x1, x2, [x0, #16]
    let d = check(
        &[0xa801_1003, 0xa841_1805, 0x6942_0801],
        init_x(&[(0, DATA), (3, 0x0000_0001_8000_0000), (4, 0x7fff_ffff)]),
    );
    assert_eq!(d.x[5], 0x0000_0001_8000_0000);
    assert_eq!(d.x[1], 0xffff_ffff_8000_0000);
    assert_eq!(d.x[2], 1);
}

#[test]
fn exclusive_pairs_load_then_store() {
    // ldxp x4, x5, [x0] ; stxp w3, x1, x2, [x0]
    // ldaxp w7, w8, [x0] ; stlxp w6, w1, w2, [x0]
    // Each store-exclusive follows a load-exclusive of the same address, so
    // the (always-succeeding) native monitor agrees with Unicorn's.
    let d = check(
        &[0xc87f_1404, 0xc823_0801, 0x887f_a007, 0x8826_8801],
        init_x(&[
            (0, DATA),
            (1, 0x1111_2222_3333_4444),
            (2, 0x5555_6666_7777_8888),
            (3, 9),
            (6, 9),
        ]),
    );
    assert_eq!((d.x[3], d.x[6]), (0, 0), "both store-exclusives succeed");
    assert_eq!((d.x[4], d.x[5]), (0, 0), "memory was zero before the stxp");
    assert_eq!((d.x[7], d.x[8]), (0x3333_4444, 0x1111_2222));
}
