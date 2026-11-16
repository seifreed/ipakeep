//! Differential tests: every program runs on two engines — one with the JIT
//! compiling every block on first entry, one with the JIT disabled (pure
//! interpreter) — and the full architectural state (X0..X30, SP, PC, NZCV,
//! V0..V31, every mapped byte) and the run result must be identical.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::super::super::error::EmuError;
use super::super::super::register::Register;
use super::super::engine::NativeEngine;
use super::{DEFAULT_THRESHOLD, Jit, JitStats};

const CODE: u64 = 0x10_0000;
const CODE_SIZE: u64 = 0x1000;
const DATA: u64 = 0x20_0000;
const STACK: u64 = 0x30_0000;
const REGION: u64 = 0x2000;
const END: u64 = 0xdead_0000;

const BRK: u32 = 0xd420_0000;
const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;

/// Deterministic xorshift64* generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        (self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    fn next64(&mut self) -> u64 {
        (u64::from(self.next()) << 32) | u64::from(self.next())
    }

    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// Initial state of a differential run.
#[derive(Clone)]
struct Setup {
    code: Vec<u32>,
    x: [u64; 31],
    sp: u64,
    nzcv: u32,
    limit: usize,
}

impl Setup {
    fn new(code: &[u32]) -> Self {
        let mut x = [0u64; 31];
        x[28] = DATA + REGION / 2;
        Self {
            code: code.to_vec(),
            x,
            sp: STACK + REGION / 2,
            nzcv: 0,
            limit: 0,
        }
    }
}

/// Builds an engine with code, data and stack mapped and `setup` applied.
/// `threshold` 0 keeps the JIT off.
fn engine(setup: &Setup, threshold: u32) -> NativeEngine<'static> {
    let mut e = NativeEngine::new().unwrap();
    e.jit_mut().threshold = threshold;
    e.mem_map(CODE, CODE_SIZE).unwrap();
    e.mem_map(DATA, REGION).unwrap();
    e.mem_map(STACK, REGION).unwrap();
    let mut code: Vec<u8> = setup.code.iter().flat_map(|w| w.to_le_bytes()).collect();
    code.resize(CODE_SIZE as usize, 0);
    for chunk in code[setup.code.len() * 4..].as_chunks_mut::<4>().0 {
        chunk.copy_from_slice(&BRK.to_le_bytes());
    }
    e.mem_write(CODE, &code).unwrap();
    let data: Vec<u8> = (0..REGION / 8)
        .flat_map(|i| ((i.wrapping_mul(0x9e37_79b9_7f4a_7c15)) ^ 0x5555).to_le_bytes())
        .collect();
    e.mem_write(DATA, &data).unwrap();
    let stack: Vec<u8> = data.iter().map(|b| !b).collect();
    e.mem_write(STACK, &stack).unwrap();
    for (n, value) in setup.x.iter().enumerate() {
        e.reg_write(Register::X(n as u8), *value).unwrap();
    }
    e.reg_write(Register::Sp, setup.sp).unwrap();
    e.reg_write(Register::Nzcv, u64::from(setup.nzcv)).unwrap();
    e
}

/// Full architectural state + memory of an engine.
fn snapshot(e: &NativeEngine<'_>) -> (Vec<u64>, Vec<[u8; 16]>, Vec<u8>) {
    let mut regs: Vec<u64> = (0..31)
        .map(|n| e.reg_read(Register::X(n)).unwrap())
        .collect();
    regs.push(e.reg_read(Register::Sp).unwrap());
    regs.push(e.reg_read(Register::Pc).unwrap());
    regs.push(e.reg_read(Register::Nzcv).unwrap());
    let vregs = (0..32).map(|n| e.vreg_read(n).unwrap()).collect();
    let mut mem = e.mem_read(CODE, CODE_SIZE as usize).unwrap();
    mem.extend(e.mem_read(DATA, REGION as usize).unwrap());
    mem.extend(e.mem_read(STACK, REGION as usize).unwrap());
    (regs, vregs, mem)
}

fn result_text(result: &Result<(), EmuError>) -> String {
    format!("{result:?}")
}

/// Runs `setup` with and without the JIT and asserts identical outcomes.
/// Returns the JIT engine's statistics.
#[track_caller]
fn differential(setup: &Setup) -> JitStats {
    let mut jit = engine(setup, 1);
    let mut interp = engine(setup, 0);
    let a = jit.start_bounded(CODE, END, Duration::ZERO, setup.limit);
    let b = interp.start_bounded(CODE, END, Duration::ZERO, setup.limit);
    assert_eq!(
        result_text(&a),
        result_text(&b),
        "run result, code {:08x?}",
        setup.code
    );
    let (ra, va, ma) = snapshot(&jit);
    let (rb, vb, mb) = snapshot(&interp);
    assert_eq!(ra, rb, "registers, code {:08x?}", setup.code);
    assert_eq!(va, vb, "vector registers");
    assert!(ma == mb, "memory differs, code {:08x?}", setup.code);
    assert_eq!(interp.jit_mut().stats.executed, 0);
    jit.jit_mut().stats
}

// --- random instruction generators (fields constrained so most decode) ---

/// Destination registers stay below X28 so the data base survives.
fn rd(r: &mut Rng) -> u32 {
    r.below(28)
}

fn dp_imm(r: &mut Rng) -> u32 {
    (r.next() & !(0b111 << 26) & !0x1f) | (0b100 << 26) | rd(r)
}

fn dp_reg(r: &mut Rng) -> u32 {
    let mut w = (r.next() & !(0b111 << 25) & !0x1f) | (0b101 << 25) | rd(r);
    if (w >> 31) & 1 == 0 && (w >> 28) & 1 == 0 {
        // 32-bit shifted-register forms with imm6 >= 32 are reserved (the
        // interpreter would overflow a shift on them in debug builds).
        w &= !(1 << 15);
    }
    w
}

fn load_store(r: &mut Rng) -> u32 {
    let mut w = (r.next() & !(0b111 << 25)) | (0b100 << 25);
    // Base X28 or SP; keep immediate offsets inside the mapped region.
    let rn = if r.below(2) == 0 { 28 } else { 31 };
    w = (w & !(0x1f << 5)) | (rn << 5);
    if r.below(3) != 0 {
        // Small offsets: clear the high immediate bits of imm12 / imm9 / imm7.
        w &= !(0b1111 << 18);
    }
    if (w >> 22) & 1 == 1 || (w >> 22) & 3 != 0 {
        w = (w & !0x1f) | rd(r);
    }
    w
}

fn cond_branch(r: &mut Rng) -> u32 {
    let imm = 1 + r.below(3);
    match r.below(4) {
        0 => 0x5400_0000 | (imm << 5) | r.below(16),
        1 => (r.below(2) << 31) | 0x3400_0000 | (r.below(2) << 24) | (imm << 5) | r.below(32),
        2 => {
            (r.below(2) << 31)
                | 0x3600_0000
                | (r.below(2) << 24)
                | (r.below(32) << 19)
                | (imm << 5)
                | r.below(32)
        }
        _ => 0x1400_0000 | imm, // b +imm
    }
}

fn random_program(r: &mut Rng, len: usize) -> Setup {
    let code: Vec<u32> = (0..len)
        .map(|_| match r.below(10) {
            0..=2 => dp_imm(r),
            3..=6 => dp_reg(r),
            7 | 8 => load_store(r),
            _ => cond_branch(r),
        })
        .collect();
    let mut setup = Setup::new(&code);
    for n in 0..28 {
        setup.x[n] = match r.below(4) {
            0 => u64::from(r.next()),
            1 => r.below(64).into(),
            2 => (r.next64() as i64 >> r.below(64)) as u64,
            _ => r.next64(),
        };
    }
    setup.x[29] = r.next64();
    setup.x[30] = r.next64();
    setup.nzcv = r.next() & 0xf000_0000;
    setup
}

/// Runs `count` random 12-instruction programs from `seed`; returns the
/// instructions the JIT executed.
fn random_programs(seed: u64, count: usize) -> u64 {
    let mut r = Rng(seed);
    (0..count)
        .map(|_| differential(&random_program(&mut r, 12)).executed)
        .sum()
}

#[test]
fn random_programs_match_the_interpreter() {
    let executed = random_programs(0x1234_5678_9abc_def1, 1000);
    assert!(executed > 1000, "the JIT ran {executed} instructions");
}

#[test]
fn more_random_programs_match_the_interpreter() {
    let executed = random_programs(0x0fed_cba9_8765_4321, 1000);
    assert!(executed > 1000, "the JIT ran {executed} instructions");
}

#[test]
fn even_more_random_programs_match_the_interpreter() {
    let executed = random_programs(0x5eed_5eed_5eed_5eed, 1000);
    assert!(executed > 1000, "the JIT ran {executed} instructions");
}

#[test]
fn flag_heavy_programs_match_the_interpreter() {
    // cmp/cmn/tst/adds/subs/adcs/sbcs/ccmp/ccmn feeding every condition of
    // b.cond, csel/csinc/csinv/csneg, adc/sbc and ccmp.
    let mut r = Rng(0x0bad_cafe_f00d_0001);
    let setters = [
        0xeb01_001f, // cmp x0, x1
        0x6b01_001f, // cmp w0, w1
        0xab01_001f, // cmn x0, x1
        0x2b01_001f, // cmn w0, w1
        0xea01_001f, // tst x0, x1
        0x6a01_001f, // tst w0, w1
        0xf100_041f, // cmp x0, #1
        0x7100_041f, // cmp w0, #1
        0xba01_0002, // adcs x2, x0, x1
        0x3a01_0002, // adcs w2, w0, w1
        0xfa01_0002, // sbcs x2, x0, x1
        0x7a01_0002, // sbcs w2, w0, w1
        0xfa41_0004, // ccmp x0, x1, #4, eq
        0x7a41_a805, // ccmp w0, #1, #5, ge
        0xba41_c008, // ccmn x0, x1, #8, gt
        0xf240_001f, // tst x0, #1
        0x9a01_0002, // adc x2, x0, x1
        0xda01_0002, // sbc x2, x0, x1
    ];
    for _ in 0..1200 {
        let mut code = Vec::new();
        for _ in 0..3 {
            code.push(setters[r.below(setters.len() as u32) as usize]);
            let cond = r.below(16);
            code.push(match r.below(4) {
                0 => 0x9a81_0003 | (cond << 12) | (r.below(4) << 10 & 0x400) | (r.below(2) << 30),
                1 => 0x1a81_0003 | (cond << 12),
                2 => 0xfa41_0004 | (cond << 12) | r.below(16),
                _ => 0x5400_0040 | cond, // b.cond +8
            });
        }
        let mut setup = Setup::new(&code);
        let interesting = [
            0,
            1,
            u64::MAX,
            1 << 63,
            (1 << 63) - 1,
            0xffff_ffff,
            0x8000_0000,
            0x7fff_ffff,
        ];
        setup.x[0] = interesting[r.below(8) as usize] ^ u64::from(r.below(2));
        setup.x[1] = interesting[r.below(8) as usize];
        setup.nzcv = r.next() & 0xf000_0000;
        differential(&setup);
    }
}

#[test]
fn every_condition_against_packed_and_lazy_flags() {
    // b.cond after: no flag setter (packed from the context), cmp, tst, adds, adcs.
    let setters = [
        NOP,
        0xeb01_001f,
        0xea01_001f,
        0xab01_0002,
        0xba01_0002,
        0x6b01_001f,
    ];
    let values = [0u64, 1, u64::MAX, 1 << 63];
    for setter in setters {
        for cond in 0..16 {
            for &a in &values {
                for &b in &values {
                    for nzcv in [0u32, 0xf000_0000] {
                        let code = [
                            setter,
                            0x5400_0040 | cond,         // b.cond +8
                            0xd280_0023,                // movz x3, #1
                            0x9a83_1064 | (cond << 12), // csel x4, x3, x3/... (any)
                        ];
                        let mut setup = Setup::new(&code);
                        setup.x[0] = a;
                        setup.x[1] = b;
                        setup.nzcv = nzcv;
                        differential(&setup);
                    }
                }
            }
        }
    }
}

#[test]
fn arithmetic_edge_cases_match_the_interpreter() {
    let ops = [
        0x9ac1_0802, // udiv x2, x0, x1
        0x9ac1_0c02, // sdiv x2, x0, x1
        0x1ac1_0802, // udiv w2, w0, w1
        0x1ac1_0c02, // sdiv w2, w0, w1
        0x9ac1_2002, // lsl x2, x0, x1
        0x9ac1_2402, // lsr x2, x0, x1
        0x9ac1_2802, // asr x2, x0, x1
        0x9ac1_2c02, // ror x2, x0, x1
        0x1ac1_2802, // asr w2, w0, w1
        0x1ac1_2c02, // ror w2, w0, w1
        0x9b01_0c02, // madd x2, x0, x1, x3
        0x9b01_8c02, // msub x2, x0, x1, x3
        0x1b01_0c02, // madd w2, w0, w1, w3
        0x9b21_0c02, // smaddl x2, w0, w1, x3
        0x9b21_8c02, // smsubl x2, w0, w1, x3
        0x9b41_7c02, // smulh x2, x0, x1
        0x9ba1_0c02, // umaddl x2, w0, w1, x3
        0x9ba1_8c02, // umsubl x2, w0, w1, x3
        0x9bc1_7c02, // umulh x2, x0, x1
        0xdac0_0002, // rbit x2, x0
        0x5ac0_0002, // rbit w2, w0
        0xdac0_0402, // rev16 x2, x0
        0x5ac0_0402, // rev16 w2, w0
        0xdac0_0802, // rev32 x2, x0
        0x5ac0_0802, // rev w2, w0
        0xdac0_0c02, // rev x2, x0
        0xdac0_1002, // clz x2, x0
        0x5ac0_1002, // clz w2, w0
        0xdac0_1402, // cls x2, x0
        0x5ac0_1402, // cls w2, w0
        0x93c1_1002, // extr x2, x0, x1, #4
        0x93c1_0002, // extr x2, x0, x1, #0
        0x1381_7c02, // extr w2, w0, w1, #31
        0x9340_fc02, // asr x2, x0, #0 (sbfm)
        0x9341_fc02, // asr x2, x0, #1
        0x937f_0002, // sbfiz-style sbfm x2, x0, #63, #0
        0x1300_7c02, // sbfm w2, w0, #0, #31
        0xb340_1c02, // bfxil x2, x0, #0, #8
        0xb37c_0c02, // bfi x2, x0, #4, #4
        0x3301_1c02, // bfm w2, w0, #1, #7
        0xd37d_f002, // lsl x2, x0, #3 (ubfm)
        0x5304_7c02, // lsr w2, w0, #4
        0x8b21_c002, // add x2, x0, w1, sxtw
        0x8b21_6402, // add x2, x0, x1, uxtx #1
        0xcb21_8402, // sub x2, x0, w1, sxtb #1
        0x0b21_2c02, // add w2, w0, w1, uxth #3
        0xab21_ac02, // adds x2, x0, w1, sxth #3
        0x8b21_e3e2, // add x2, sp, x1, sxtx
        0x8b01_fc02, // add x2, x0, x1, lsl #63
        0x8b41_fc02, // add x2, x0, x1, lsr #63
        0x8b81_fc02, // add x2, x0, x1, asr #63
        0x0b81_7c02, // add w2, w0, w1, asr #31
        0xaa21_1c02, // orn x2, x0, x1, lsl #7
        0xca61_0402, // eon x2, x0, x1, lsr #1
        0x8ac1_0402, // and x2, x0, x1, ror #1
        0xea21_0402, // bics x2, x0, x1, lsl #1
        0x0a21_7c02, // bic w2, w0, w1, lsl #31
        0x9200_f002, // and x2, x0, #0x1fffff
        0x1200_0c02, // and w2, w0, #0xf
        0xf200_0002, // ands x2, x0, #1
        0x7200_0002, // ands w2, w0, #1
        0xb200_03e2, // orr x2, xzr, #1
        0xd200_0002, // eor x2, x0, #1
        0x9100_0402, // add x2, x0, #1
        0x9140_0402, // add x2, x0, #1, lsl #12
        0x1100_0402, // add w2, w0, #1
        0x5100_0402, // sub w2, w0, #1
        0x3100_0402, // adds w2, w0, #1
        0x9100_03ff, // mov sp, sp... (add sp, sp, #0)
        0xf2a0_0022, // movk x2, #1, lsl #16
        0x72a0_0022, // movk w2, #1, lsl #16
        0x12a0_0022, // movn w2, #1, lsl #16
        0x9280_0022, // movn x2, #1
        0x1000_0002, // adr x2, .
        0xb000_0002, // adrp x2, +4K
        0x9a81_0402, // csinc x2, x0, x1, eq
        0xda81_0402, // csneg x2, x0, x1, eq
        0x5a81_0002, // csinv w2, w0, w1, eq
        0x1a81_1402, // csinc w2, w0, w1, ne
    ];
    let values = [
        0u64,
        1,
        u64::MAX,
        1 << 63,
        (1 << 63) - 1,
        0x8000_0000,
        0x1234_5678_9abc_def0,
    ];
    for op in ops {
        for &a in &values {
            for &b in &values {
                let mut setup = Setup::new(&[op, op ^ 0x1 /* rd x3 */]);
                setup.x[0] = a;
                setup.x[1] = b;
                setup.x[3] = b.rotate_left(17);
                setup.nzcv = 0x4000_0000;
                differential(&setup);
            }
        }
    }
}

#[test]
fn loads_and_stores_match_the_interpreter() {
    let ops = [
        0xf940_0781, // ldr x1, [x28, #8]
        0xb940_0781, // ldr w1, [x28, #4]
        0x7940_0781, // ldrh w1, [x28, #2]
        0x3940_0781, // ldrb w1, [x28, #1]
        0x3980_0781, // ldrsb x1, [x28, #1]
        0x39c0_0781, // ldrsb w1, [x28, #1]
        0x7980_0781, // ldrsh x1, [x28, #2]
        0x79c0_0781, // ldrsh w1, [x28, #2]
        0xb980_0781, // ldrsw x1, [x28, #4]
        0xf900_0781, // str x1, [x28, #8]
        0xb900_0781, // str w1, [x28, #4]
        0x7900_0781, // strh w1, [x28, #2]
        0x3900_0781, // strb w1, [x28, #1]
        0xf85f_8381, // ldur x1, [x28, #-8]
        0xf81f_8381, // stur x1, [x28, #-8]
        0xf841_0781, // ldr x1, [x28], #16
        0xf841_0f81, // ldr x1, [x28, #16]!
        0xf81f_0f81, // str x1, [x28, #-16]!
        0xf841_0f9c, // ldr x28, [x28, #16]! (rt == rn)
        0xf841_079c, // ldr x28, [x28], #16 (rt == rn)
        0xf81f_0f9c, // str x28, [x28, #-16]!
        0xf862_6b81, // ldr x1, [x28, x2]
        0xf862_7b81, // ldr x1, [x28, x2, lsl #3]
        0xf862_db81, // ldr x1, [x28, w2, sxtw #3]
        0xb862_4b81, // ldr w1, [x28, w2, uxtw]
        0xf822_6b81, // str x1, [x28, x2]
        0xf980_0780, // prfm pldl1keep, [x28, #8]
        0xf890_0f80, // prfum (pre-index form)
        0xa940_8b81, // ldp x1, x2, [x28, #8]
        0x2940_8b81, // ldp w1, w2, [x28, #4]
        0x6940_8b81, // ldpsw x1, x2, [x28, #4]
        0xa900_8b81, // stp x1, x2, [x28, #8]
        0x2900_8b81, // stp w1, w2, [x28, #4]
        0xa8c1_0b81, // ldp x1, x2, [x28], #16
        0xa9bf_0b81, // stp x1, x2, [x28, #-16]!
        0xa9bf_7bfd, // stp x29, x30, [sp, #-16]!
        0xa8c1_7bfd, // ldp x29, x30, [sp], #16
        0xa940_8781, // ldp x1, x1, [x28, #8] (rt == rt2)
        0xa940_839c, // ldp x28, x0, [x28, #8] (rt == rn)
        0x5800_0041, // ldr x1, #8 (literal)
        0x1800_0041, // ldr w1, #8
        0x9800_0041, // ldrsw x1, #8
        0xd800_0040, // prfm (literal)
        0xf940_03e1, // ldr x1, [sp]
        0xf900_03e1, // str x1, [sp]
    ];
    for op in ops {
        for (x2, x28) in [
            (8u64, DATA + 0x100),
            (0xffff_fff8, DATA + 0x100),
            (16, DATA + REGION - 8), // crosses out of the region
            (0, DATA + 0x0ffc),      // page-crossing access
            (0, 0xdead_0000_0000),   // unmapped
            (24, STACK + 0x10),
        ] {
            let mut setup = Setup::new(&[op, op, NOP]);
            setup.x[1] = 0x0123_4567_89ab_cdef;
            setup.x[2] = x2;
            setup.x[28] = x28;
            differential(&setup);
        }
    }
}

/// Assembles `movz x0, #count; loop: ...body; subs x0, x0, #1; b.ne loop; brk`.
fn counted_loop(count: u16, body: &[u32]) -> Vec<u32> {
    let mut code = vec![0xd280_0000 | (u32::from(count) << 5)];
    code.extend_from_slice(body);
    code.push(0xf100_0400); // subs x0, x0, #1
    let back = -(body.len() as i32 + 1);
    code.push(0x5400_0001 | (((back as u32) & 0x7_ffff) << 5)); // b.ne loop
    code.push(BRK);
    code
}

#[test]
fn hot_loops_compile_once_and_match() {
    let body = [
        0xf940_0782, // ldr x2, [x28, #8]
        0x8b00_0042, // add x2, x2, x0
        0xf900_0782, // str x2, [x28, #8]
        0x9b00_7c43, // mul x3, x2, x0
        0xca03_0084, // eor x4, x4, x3
    ];
    let setup = Setup::new(&counted_loop(3000, &body));
    let stats = differential(&setup);
    assert!(stats.compiled >= 1);
    assert!(stats.executed > 10_000, "{stats:?}");
    assert!(
        stats.sessions < 100,
        "loops stay in compiled code: {stats:?}"
    );
}

#[test]
fn instruction_limits_are_exact() {
    let body = [0x8b00_0042, 0xf900_0782, 0x9100_0421];
    let code = counted_loop(500, &body);
    for limit in [
        1, 2, 3, 4, 5, 6, 7, 10, 33, 100, 1999, 2000, 2001, 4095, 4096, 4097, 5000,
    ] {
        let mut setup = Setup::new(&code);
        setup.limit = limit;
        differential(&setup);
    }
}

#[test]
fn indirect_calls_and_returns_match() {
    // main: loop 200 times calling f via blr; f increments x5 and returns.
    let code = vec![
        0xd280_1900, // 0: movz x0, #200
        0x1000_0109, // 4: adr x9, f (+0x20 → 0x24)
        0xd63f_0120, // 8: blr x9
        0xf100_0400, // c: subs x0, x0, #1
        0x54ff_ffc1, // 10: b.ne 8
        0xd61f_0140, // 14: br x10 (x10 = done)
        NOP,         // 18
        NOP,         // 1c
        NOP,         // 20
        0x9100_04a5, // 24: f: add x5, x5, #1
        RET,         // 28
    ];
    let mut setup = Setup::new(&code);
    setup.x[10] = CODE + 0x30; // brk padding
    let stats = differential(&setup);
    assert!(stats.compiled >= 3, "{stats:?}");
}

#[test]
fn hooks_inside_hot_code_are_honored() {
    let body = [0x9100_0421, 0x9100_0442, 0x9100_0463]; // add x1/x2/x3, #1
    let code = counted_loop(300, &body);
    let run = |threshold: u32| {
        let setup = Setup::new(&code);
        let mut e = engine(&setup, threshold);
        let fired = Rc::new(Cell::new(0u64));
        let seen = Rc::clone(&fired);
        // Hook the second body instruction: bump X7 every time it is reached.
        e.add_code_hook(CODE + 8, CODE + 8, move |engine, _, _| {
            seen.set(seen.get() + 1);
            let x7 = engine.reg_read(Register::X(7))?;
            engine.reg_write(Register::X(7), x7 + 3)
        })
        .unwrap();
        e.start(CODE, END).unwrap();
        (snapshot(&e), fired.get(), e.jit_mut().stats)
    };
    let (jit_state, jit_fired, stats) = run(1);
    let (interp_state, interp_fired, _) = run(0);
    assert_eq!(jit_fired, 300);
    assert_eq!(jit_fired, interp_fired);
    assert_eq!(jit_state, interp_state);
    assert!(stats.executed > 0);
}

#[test]
fn a_hook_added_later_flushes_compiled_blocks() {
    let code = counted_loop(100, &[0x9100_0421]);
    let setup = Setup::new(&code);
    let mut e = engine(&setup, 1);
    e.start(CODE, END).unwrap();
    assert!(e.jit_mut().stats.compiled > 0);
    let hits = Rc::new(Cell::new(0));
    let seen = Rc::clone(&hits);
    e.add_code_hook(CODE + 4, CODE + 4, move |_, _, _| {
        seen.set(seen.get() + 1);
        Ok(())
    })
    .unwrap();
    e.reg_write(Register::X(1), 0).unwrap();
    e.start(CODE, END).unwrap();
    assert_eq!(hits.get(), 100);
    assert_eq!(e.reg_read(Register::X(1)).unwrap(), 100);
    assert!(e.jit_mut().stats.invalidated > 0);
}

#[test]
fn an_all_addresses_hook_disables_compilation() {
    let code = counted_loop(50, &[0x9100_0421]);
    let mut e = engine(&Setup::new(&code), 1);
    e.add_code_hook(1, 0, |_, _, _| Ok(())).unwrap();
    e.start(CODE, END).unwrap();
    assert_eq!(e.jit_mut().stats.compiled, 0);
    assert_eq!(e.reg_read(Register::X(1)).unwrap(), 50);
}

#[test]
fn until_inside_a_compiled_block_stops_exactly() {
    let code = counted_loop(20, &[0x9100_0421, 0x9100_0442, 0x9100_0463]);
    for until in [CODE + 4, CODE + 8, CODE + 12, CODE + 16, CODE + 24] {
        let mut jit = engine(&Setup::new(&code), 1);
        let mut interp = engine(&Setup::new(&code), 0);
        // Warm the JIT up first so the block containing `until` is compiled.
        jit.start(CODE, END).unwrap();
        interp.start(CODE, END).unwrap();
        for e in [&mut jit, &mut interp] {
            e.reg_write(Register::X(0), 5).unwrap();
            e.start(CODE + 4, until).unwrap();
        }
        assert!(snapshot(&jit) == snapshot(&interp), "until {until:#x}");
    }
}

#[test]
fn self_modifying_code_is_recompiled() {
    // The loop rewrites its own `add x1, x1, #1` into `add x1, x1, #2` on the
    // last iteration.
    let patched: u32 = 0x9100_0821; // add x1, x1, #2
    let code = vec![
        0xd280_0140, // 0: movz x0, #10
        0x9100_0421, // 4: add x1, x1, #1
        0xf100_0400, // 8: subs x0, x0, #1
        0x54ff_ffc1, // c: b.ne 4
        0xb900_0389, // 10: str w9, [x28] (x28 = CODE + 4)
        0xd280_0140, // 14: movz x0, #10
        0x17ff_fffb, // 18: b 4  -> runs the patched loop, then
                     //          falls to 0x10 again (stores again)
    ];
    let mut setup = Setup::new(&code);
    setup.x[9] = u64::from(patched);
    setup.x[28] = CODE + 4;
    setup.limit = 120;
    let stats = differential(&setup);
    assert!(stats.invalidated > 0 || stats.misses > 0, "{stats:?}");
}

#[test]
fn host_writes_and_unmaps_between_runs_are_seen() {
    let code = counted_loop(10, &[0x9100_0421, 0xf940_0382]); // add x1, #1; ldr x2, [x28]
    let mut jit = engine(&Setup::new(&code), 1);
    let mut interp = engine(&Setup::new(&code), 0);
    for e in [&mut jit, &mut interp] {
        e.start(CODE, END).unwrap();
        // Host patches the loop body, then reruns it.
        e.write_u32(CODE + 4, 0x9100_1421).unwrap(); // add x1, x1, #5
        e.start(CODE, END).unwrap();
        // Unmapping the data page makes the load fault in both engines.
        e.mem_unmap(DATA, REGION).unwrap();
        let error = e.start(CODE, END).unwrap_err();
        assert!(matches!(error, EmuError::Unmapped { .. }), "{error:?}");
        e.mem_map(DATA, REGION).unwrap();
        e.start(CODE, END).unwrap();
    }
    assert_eq!(snapshot(&jit), snapshot(&interp));
    assert!(jit.jit_mut().stats.invalidated > 0);
}

#[test]
fn faults_report_the_interpreter_pc_and_address() {
    let code = [0x9100_0421, 0xf940_0382, 0x9100_0421]; // add; ldr x2, [x28]; add
    let mut setup = Setup::new(&code);
    setup.x[28] = 0xdead_0000_0000;
    let mut e = engine(&setup, 1);
    let error = e.start(CODE, END).unwrap_err();
    assert!(
        matches!(
            error,
            EmuError::Unmapped {
                address: 0xdead_0000_0000,
                pc: Some(pc),
                ..
            } if pc == CODE + 4
        ),
        "{error:?}"
    );
    assert_eq!(e.reg_read(Register::X(1)).unwrap(), 1);
}

#[test]
fn deadline_still_fires_in_compiled_loops() {
    let code = vec![0x9100_0421, 0x17ff_ffff]; // loop: add x1, #1; b loop
    let mut e = engine(&Setup::new(&code), 1);
    let error = e
        .start_bounded(CODE, END, Duration::from_millis(20), 0)
        .unwrap_err();
    assert!(matches!(error, EmuError::Timeout { .. }));
    assert!(e.jit_mut().stats.executed > 0);
}

#[test]
fn untranslated_instructions_fall_back_and_resume() {
    // SIMD (`movi v0.2d, #0`), `svc`, and a block ending before them.
    let code = [0x9100_0421, 0x6f00_e400, 0x9100_0421, BRK];
    let stats = differential(&Setup::new(&code));
    assert!(stats.executed >= 1);
    let svc = [0x9100_0421, 0xd400_0001];
    differential(&Setup::new(&svc));
}

#[test]
fn default_threshold_tiers_up_only_hot_code() {
    let code = counted_loop(3000, &[0x9100_0421]);
    let setup = Setup::new(&code);
    let mut e = engine(&setup, DEFAULT_THRESHOLD);
    e.start(CODE, END).unwrap();
    let stats = e.jit_mut().stats;
    assert_eq!(e.reg_read(Register::X(1)).unwrap(), 3000);
    assert_eq!(stats.compiled, 1, "only the loop body is hot: {stats:?}");
    assert!(stats.compile_time > Duration::ZERO);
    let fresh = Jit::new();
    assert_eq!(fresh.threshold, DEFAULT_THRESHOLD);
}

#[test]
fn direct_calls_long_blocks_and_code_page_ends_match() {
    // bl f; ...; f: 100 straight adds (longer than one compiled block); ret.
    let mut code = vec![
        0xd280_0140, // movz x0, #10
        0x9400_0005, // loop: bl f (+20)
        0xf100_0400, // subs x0, x0, #1
        0x54ff_ffc1, // b.ne loop
        BRK,
        NOP,
    ];
    code.extend(std::iter::repeat_n(0x9100_0421, 100)); // f: add x1, x1, #1
    code.push(RET);
    let stats = differential(&Setup::new(&code));
    assert!(stats.compiled >= 3, "{stats:?}");

    // Straight-line code running off the end of the mapped code region.
    let mut setup = Setup::new(&[]);
    setup.code = vec![BRK; (CODE_SIZE / 4) as usize];
    let last = setup.code.len() - 2;
    setup.code[last] = 0x9100_0421;
    setup.code[last + 1] = 0x9100_0421;
    let mut jit = engine(&setup, 1);
    let mut interp = engine(&setup, 0);
    let start = CODE + 4 * last as u64;
    let a = jit.start(start, END);
    let b = interp.start(start, END);
    assert_eq!(result_text(&a), result_text(&b));
    assert_eq!(snapshot(&jit), snapshot(&interp));
}

#[test]
fn colliding_profile_slots_resolve_through_the_maps() {
    // The loop at CODE+4 starts with an untranslatable `ldxr`, and `f` sits
    // exactly one profile-table span (SLOTS * 4 bytes) above it, so both PCs
    // share a slot and evict each other on every iteration.
    let f = CODE + 4 + 4 * super::SLOTS as u64;
    let code = [
        0xd280_0640, // movz x0, #50
        0xc85f_7f82, // loop: ldxr x2, [x28]
        0xd63f_0120, // blr x9
        0xf100_0400, // subs x0, x0, #1
        0x54ff_ffa1, // b.ne loop
        BRK,
    ];
    let mut setup = Setup::new(&code);
    setup.x[9] = f;
    let run = |threshold: u32| {
        let mut e = engine(&setup, threshold);
        e.mem_map(f & !0xfff, 0x1000).unwrap();
        e.write_u32(f, 0x9100_0421).unwrap(); // add x1, x1, #1
        e.write_u32(f + 4, RET).unwrap();
        e.start(CODE, END).unwrap();
        let state = (snapshot(&e), e.reg_read(Register::X(1)).unwrap());
        (state, e.jit_mut().stats)
    };
    let (jit, stats) = run(1);
    let (interp, _) = run(0);
    assert_eq!(jit, interp);
    assert_eq!(jit.1, 50);
    assert!(stats.executed > 0);
}

#[test]
fn unmodelled_branches_and_barriers_fall_back() {
    for word in [
        0xd69f_03e0, // eret (left to the interpreter: Unsupported)
        0xd503_3fbf, // dmb sy (translated as a no-op)
        0xd503_201f, // nop
        0x0a01_8002, // and w2, w0, w1, lsl #32 (reserved shift amount)
    ] {
        differential(&Setup::new(&[0x9100_0421, word, 0x9100_0421]));
    }
}
