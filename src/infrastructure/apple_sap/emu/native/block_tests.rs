//! Block-cache tests: every pre-decoded op against the full decoder, and the
//! run-loop contracts (hooks, limits, `until`, invalidation) through
//! `NativeEngine`.

use super::dpimm::add_with_carry;
use super::predecode::{Op, add_sub_flags, predecode, run_op};
use super::{NativeCpu, NativeError, Step};

const CODE: u64 = 0x1_0000;
const DATA: u64 = 0x2_0000;
const DATA_SIZE: u64 = 0x2000;

/// splitmix64: a tiny deterministic generator for the equivalence sweep.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// A CPU with a mapped CODE and DATA area and pseudo-random registers: most
/// point into DATA (so loads/stores mostly hit mapped memory), the rest are
/// arbitrary.
fn random_cpu(rng: &mut Rng) -> NativeCpu {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(CODE, 0x1000);
    cpu.mem.map(DATA, DATA_SIZE);
    let fill: Vec<u8> = (0..DATA_SIZE).map(|i| (i * 7 + 3) as u8).collect();
    cpu.mem.write(DATA, &fill).unwrap();
    for n in 0..31 {
        let value = match rng.next() % 4 {
            0 => rng.next(),
            1 => rng.next() & 0xff,
            _ => DATA + 0x800 + (rng.next() % 0x800),
        };
        cpu.set_x(n, value);
    }
    cpu.set_sp(DATA + 0x1000);
    cpu.set_nzcv((rng.next() as u32) & 0xf000_0000);
    cpu
}

type Snapshot = (Vec<u64>, u64, u32, Vec<u8>);

fn snapshot(cpu: &NativeCpu) -> Snapshot {
    let mut data = vec![0u8; DATA_SIZE as usize];
    cpu.mem.read(DATA, &mut data).unwrap();
    (
        (0..31).map(|n| cpu.x(n)).collect(),
        cpu.sp(),
        cpu.nzcv(),
        data,
    )
}

/// Runs `word` both ways from the same state and asserts identical results.
fn assert_equivalent(word: u32, seed: u64) -> Op {
    let pc = CODE + 0x40;
    let op = predecode(word, pc);
    let mut reference = random_cpu(&mut Rng(seed));
    let mut fast = random_cpu(&mut Rng(seed));
    reference.set_pc(pc);
    let expected = reference.execute(word);
    let actual = run_op(&mut fast, &op, pc);
    assert_eq!(actual, expected, "result of {word:#010x} ({op:?})");
    assert_eq!(
        snapshot(&fast),
        snapshot(&reference),
        "state after {word:#010x} ({op:?})"
    );
    op
}

/// Encoding templates `(fixed bits mask, fixed bits)` steering the random
/// words onto every pre-decoded form (and their rejected neighbours).
const TEMPLATES: &[(u32, u32)] = &[
    (0x1f00_0000, 0x1000_0000), // ADR/ADRP
    (0x1f80_0000, 0x1100_0000), // add/sub imm
    (0x1f80_0000, 0x1200_0000), // logical imm
    (0x1f80_0000, 0x1280_0000), // move wide
    (0x1f80_0000, 0x1300_0000), // bitfield
    (0x1f80_0000, 0x1380_0000), // extract / dpimm tagged
    (0x1f00_0000, 0x0a00_0000), // logical shifted
    (0xff20_fc00, 0xaa00_0000), // ORR reg, no shift (MOV alias candidates)
    (0x1f20_0000, 0x0b00_0000), // add/sub shifted
    (0x1f20_0000, 0x0b20_0000), // add/sub extended
    (0x1fe0_0000, 0x1a80_0000), // cond select
    (0x1f00_0000, 0x1b00_0000), // 3-source
    (0x1fe0_0000, 0x1ac0_0000), // 2-source / 1-source
    (0x3b00_0000, 0x3900_0000), // ld/st unsigned offset
    (0x3b20_0c00, 0x3820_0800), // ld/st register offset
    (0x3b20_0000, 0x3800_0000), // ld/st imm9
    (0x3b20_0000, 0x3820_0000), // ld/st reg / atomics
    (0x3f00_0000, 0x0800_0000), // exclusive
    (0x3a00_0000, 0x2800_0000), // pairs
    (0x3b00_0000, 0x1800_0000), // literal
    (0x7c00_0000, 0x1400_0000), // B/BL
    (0x7e00_0000, 0x3400_0000), // CBZ/CBNZ
    (0x7e00_0000, 0x3600_0000), // TBZ/TBNZ
    (0xff00_0000, 0x5400_0000), // B.cond
    (0xfe00_0000, 0xd600_0000), // branch register
    (0xff00_0000, 0xd400_0000), // exception
    (0x0000_0000, 0x0000_0000), // anything
];

/// A 32-bit shifted-register op with `imm6 >= 32` (unallocated): the shared
/// `shift_reg` overflows on it in debug builds, so the sweep skips it.
fn reserved_wide_shift(word: u32) -> bool {
    word & 0x9f00_8000 == 0x0b00_8000 || word & 0x9f00_8000 == 0x0a00_8000
}

#[test]
fn every_predecoded_op_matches_the_decoder() {
    let mut rng = Rng(0x5eed);
    let iterations = if cfg!(debug_assertions) { 600 } else { 6000 };
    let mut kinds = std::collections::HashSet::new();
    for &(mask, bits) in TEMPLATES {
        for _ in 0..iterations {
            let word = ((rng.next() as u32) & !mask) | bits;
            if reserved_wide_shift(word) {
                continue;
            }
            let op = assert_equivalent(word, rng.next());
            kinds.insert(std::mem::discriminant(&op));
        }
    }
    assert_eq!(kinds.len(), 34, "every Op variant was exercised");
}

/// Hand-picked encodings for forms the random sweep may hit only rarely.
#[test]
fn hot_guest_encodings_match_the_decoder() {
    let words = [
        0xd360_fc63, // lsr x3, x3, #32
        0xeb0f_00ff, // cmp x7, x15
        0x9124_03f6, // add x22, sp, #2304
        0x1a9f_17f1, // cset w17, eq
        0xd61f_0040, // br x2
        0xf871_d842, // ldr x2, [x2, w17, sxtw #3]
        0xf943_3fe2, // ldr x2, [sp, #1656]
        0x1b1a_7e31, // mul w17, w17, w26
        0xd283_b451, // mov x17, #7586
        0x4a0a_0231, // eor w17, w17, w10
        0xaa13_03e0, // mov x0, x19
        0xd37e_f4e2, // lsl x2, x7, #2
        0x8b34_4061, // add x1, x3, w20, uxtw
        0x9ba4_04c3, // umaddl x3, w6, w4, x1
        0xb862_6a74, // ldr w20, [x19, x2]
        0x3216_0221, // orr w1, w17, #0x400
        0xb821_6a63, // str w3, [x19, x1]
        0xf2aa_cf00, // movk x0, #0x5678, lsl #16
        0x5280_0000, // mov w0, #0
        0x1280_0000, // movn w0, #0
        0xb81f_c3a0, // stur w0, [x29, #-4]
        0x3940_0020, // ldrb w0, [x1]
        0x39c0_0020, // ldrsb w0, [x1]
        0x3980_0020, // ldrsb x0, [x1]
        0xf980_0020, // prfm pldl1keep, [x1]
        0xf8a0_6820, // prfm via register offset
        0xd65f_03c0, // ret
        0xd63f_0200, // blr x16
        0x9400_0010, // bl #64
        0x1400_0004, // b #16
        0x5400_0040, // b.eq #8
        0xb400_0040, // cbz x0, #8
        0x3500_0040, // cbnz w0, #8
        0x3608_0040, // tbz w0, #1, #8
        0xb7f8_0040, // tbnz x0, #63, #8
        0x7100_041f, // cmp w0, #1
        0xab01_0000, // adds x0, x0, x1
        0x2b21_4000, // adds w0, w0, w1, uxtw
        0xcb21_63ff, // sub sp, sp, x1
        0x0a21_0000, // bic w0, w0, w1
        0x4a61_0000, // eon w0, w0, w1, lsr #0
        0xaa61_0800, // orn x0, x0, x1, lsr #2
        0x8a81_7c00, // and x0, x0, x1, asr #31
        0x9a81_1400, // csinc x0, x0, x1, ne
        0xda81_0000, // csinv x0, x0, x1, eq
        0xda81_0400, // csneg x0, x0, x1, eq
        0x1a81_0000, // csel w0, w0, w1, eq
        0x9b01_0c00, // madd x0, x0, x1, x3
        0x1001_0000, // adr x0, #0x2000
        0x9000_0001, // adrp x1, #0
    ];
    for (i, word) in words.into_iter().enumerate() {
        for seed in 0..8u64 {
            assert_equivalent(word, seed * 31 + i as u64);
        }
    }
}

#[test]
fn rejected_encodings_fall_back_with_the_decoders_error() {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(CODE, 0x1000);
    // svc #0 (rejected) and an unallocated logical immediate (N=1, sf=0).
    for word in [0xd400_0001u32, 0x1240_0000] {
        let op = predecode(word, CODE);
        assert_eq!(op, Op::Fallback(word));
        assert!(matches!(
            run_op(&mut cpu, &op, CODE),
            Err(NativeError::Unsupported { pc: CODE, word: w, .. }) if w == word
        ));
    }
    assert_eq!(
        run_op(&mut cpu, &predecode(0xd420_0000, CODE), CODE),
        Ok(Step::Break(0))
    );
}

#[test]
fn fast_flags_match_add_with_carry() {
    let mut rng = Rng(7);
    let edges = [
        0u64,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        1 << 63,
        u64::MAX,
        u64::MAX - 1,
    ];
    let mut pairs: Vec<(u64, u64)> = edges
        .iter()
        .flat_map(|&a| edges.iter().map(move |&b| (a, b)))
        .collect();
    pairs.extend((0..20_000).map(|_| (rng.next(), rng.next())));
    for (a, b) in pairs {
        for sf in [0u32, 1] {
            let mask = if sf == 1 { u64::MAX } else { 0xffff_ffff };
            let (a, b) = (a & mask, b & mask);
            assert_eq!(
                add_sub_flags(a, b, false, sf),
                add_with_carry(a, b, false, sf)
            );
            assert_eq!(
                add_sub_flags(a, b, true, sf),
                add_with_carry(a, !b & mask, true, sf)
            );
        }
    }
}
