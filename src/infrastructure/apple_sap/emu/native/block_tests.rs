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

// ---------------------------------------------------------------------------
// Run-loop contracts through `NativeEngine` (block path) against the
// per-instruction reference (`NativeCpu::run`).
// ---------------------------------------------------------------------------

mod engine {
    use std::cell::{Cell, RefCell};
    use std::hash::Hasher;
    use std::rc::Rc;
    use std::time::Duration;

    use super::super::super::error::EmuError;
    use super::super::super::register::Register;
    use super::super::block::{MAX_BLOCK_OPS, PcHasher};
    use super::super::engine::NativeEngine;
    use super::super::{NativeCpu, PAGE_SIZE, Step};
    use super::{CODE, DATA, DATA_SIZE, Rng};

    const END: u64 = 0xdead_0000;
    const ADD_X0_1: u32 = 0x9100_0400;
    const ADD_X0_5: u32 = 0x9100_1400;
    const STR_W1_X2: u32 = 0xb900_0041; // str w1, [x2]
    const STP_X3_X4_X2: u32 = 0xa900_1043; // stp x3, x4, [x2] (fallback op)
    const LDR_X0_X18: u32 = 0xf940_0240; // ldr x0, [x18]
    const BRK_0: u32 = 0xd420_0000;
    const NOP: u32 = 0xd503_201f;
    const B_BACK_4: u32 = 0x17ff_ffff; // b #-4
    const SVC_0: u32 = 0xd400_0001;

    fn engine_with(code: &[u32]) -> NativeEngine<'static> {
        let mut e = NativeEngine::new().unwrap();
        e.mem_map(CODE, 2 * PAGE_SIZE).unwrap();
        e.mem_map(DATA, DATA_SIZE).unwrap();
        write_code(&mut e, CODE, code);
        e
    }

    fn write_code(e: &mut NativeEngine<'_>, at: u64, code: &[u32]) {
        let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        e.mem_write(at, &bytes).unwrap();
    }

    fn x(e: &NativeEngine<'_>, n: u8) -> u64 {
        e.reg_read(Register::X(n)).unwrap()
    }

    fn pc(e: &NativeEngine<'_>) -> u64 {
        e.reg_read(Register::Pc).unwrap()
    }

    #[test]
    fn instruction_limit_stops_exactly_mid_block() {
        let mut e = engine_with(&[ADD_X0_1; 10]);
        e.start_bounded(CODE, END, Duration::ZERO, 3).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (3, CODE + 12));
        // Resuming mid-block runs a block that starts there.
        e.start_bounded(CODE + 12, END, Duration::ZERO, 4).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (7, CODE + 28));
    }

    #[test]
    fn until_inside_a_cached_block_stops_before_it() {
        let mut e = engine_with(&[ADD_X0_1, ADD_X0_1, ADD_X0_1, ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (4, CODE + 16), "ran to the brk");
        e.reg_write(Register::X(0), 0).unwrap();
        e.start(CODE, CODE + 8).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (2, CODE + 8));
        // An `until` that is not on an instruction boundary never matches.
        e.reg_write(Register::X(0), 0).unwrap();
        e.start(CODE, CODE + 6).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (4, CODE + 16));
    }

    #[test]
    fn a_hook_added_after_caching_splits_the_block() {
        let mut e = engine_with(&[ADD_X0_1, ADD_X0_1, ADD_X0_1, ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        let seen = Rc::new(Cell::new(u64::MAX));
        let probe = Rc::clone(&seen);
        let id = e
            .add_code_hook(CODE + 8, CODE + 8, move |engine, address, size| {
                assert_eq!((address, size), (CODE + 8, 4));
                probe.set(engine.reg_read(Register::X(0))?);
                Ok(())
            })
            .unwrap();
        e.reg_write(Register::X(0), 0).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(seen.get(), 2, "fired before the third add");
        assert_eq!(x(&e, 0), 4);
        e.remove_hook(id).unwrap();
        seen.set(u64::MAX);
        e.start(CODE, END).unwrap();
        assert_eq!(seen.get(), u64::MAX, "removed hooks no longer fire");
    }

    #[test]
    fn a_hook_added_from_inside_a_hook_fires_in_the_same_run() {
        let mut e = engine_with(&[ADD_X0_1, ADD_X0_1, ADD_X0_1, ADD_X0_1, BRK_0]);
        let hits = Rc::new(RefCell::new(Vec::new()));
        let outer = Rc::clone(&hits);
        e.add_code_hook(CODE, CODE, move |engine, address, _| {
            outer.borrow_mut().push(address);
            let inner = Rc::clone(&outer);
            engine.add_code_hook(CODE + 12, CODE + 12, move |engine, address, _| {
                inner.borrow_mut().push(address);
                // Redirect past the rest: the hooked add never runs.
                engine.reg_write(Register::Pc, CODE + 16)
            })?;
            Ok(())
        })
        .unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(*hits.borrow(), [CODE, CODE + 12]);
        assert_eq!((x(&e, 0), pc(&e)), (3, CODE + 16));
    }

    #[test]
    fn a_hook_can_stop_mid_block() {
        let mut e = engine_with(&[ADD_X0_1, ADD_X0_1, ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        e.add_code_hook(CODE + 4, CODE + 4, |engine, _, _| engine.stop())
            .unwrap();
        e.reg_write(Register::X(0), 0).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (1, CODE + 4));
    }

    #[test]
    fn a_guest_store_into_the_running_block_takes_effect() {
        // str w1, [x2] rewrites the instruction two slots ahead in its own block.
        let code = [STR_W1_X2, ADD_X0_1, ADD_X0_1, BRK_0];
        let mut e = engine_with(&code);
        e.reg_write(Register::X(2), DATA).unwrap();
        e.start(CODE, END).unwrap(); // caches the block
        assert_eq!(x(&e, 0), 2);
        for _ in 0..2 {
            write_code(&mut e, CODE, &code);
            e.reg_write(Register::X(0), 0).unwrap();
            e.reg_write(Register::X(1), u64::from(ADD_X0_5)).unwrap();
            e.reg_write(Register::X(2), CODE + 8).unwrap();
            e.start(CODE, END).unwrap();
            assert_eq!((x(&e, 0), pc(&e)), (6, CODE + 12));
        }
    }

    #[test]
    fn a_fallback_store_into_cached_code_takes_effect() {
        // stp x3, x4, [x2] (no fast path) overwrites the next two slots.
        let code = [STP_X3_X4_X2, ADD_X0_1, ADD_X0_1, ADD_X0_1, BRK_0];
        let mut e = engine_with(&code);
        e.reg_write(Register::X(2), DATA).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 3);
        let pair = u64::from(ADD_X0_5) | (u64::from(ADD_X0_5) << 32);
        e.reg_write(Register::X(0), 0).unwrap();
        e.reg_write(Register::X(2), CODE + 4).unwrap();
        e.reg_write(Register::X(3), pair).unwrap();
        e.reg_write(Register::X(4), u64::from(NOP) | (u64::from(BRK_0) << 32))
            .unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (10, CODE + 16));
    }

    #[test]
    fn host_writes_and_unmaps_invalidate_cached_blocks() {
        let mut e = engine_with(&[ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 1);
        e.write_u32(CODE, ADD_X0_5).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 6, "host write seen");
        e.write_return_stub(CODE).unwrap();
        e.reg_write(Register::X(30), CODE + 4).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(pc(&e), CODE + 4, "ret stub seen");
        e.mem_unmap(CODE, 2 * PAGE_SIZE).unwrap();
        let error = e.start(CODE, END).unwrap_err();
        assert!(matches!(
            error,
            EmuError::Unmapped {
                address: CODE,
                pc: Some(CODE),
                ..
            }
        ));
        e.mem_map(CODE, PAGE_SIZE).unwrap();
        write_code(&mut e, CODE, &[ADD_X0_5, BRK_0]);
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 11, "remapped code seen");
        // A host write that faults part-way still reports the code it hit.
        let error = e.mem_write(CODE + PAGE_SIZE - 4, &[0; 8]).unwrap_err();
        assert!(matches!(error, EmuError::Unmapped { pc: None, .. }));
    }

    #[test]
    fn invalidated_link_targets_are_rebuilt() {
        // Block A (page 1) branches to block B (page 2); rewriting B's page
        // leaves A's link pointing at a dropped block.
        let mut e = engine_with(&[0x1400_0400]); // b #0x1000
        write_code(&mut e, CODE + PAGE_SIZE, &[ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 1);
        write_code(&mut e, CODE + PAGE_SIZE, &[ADD_X0_5, BRK_0]);
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 6);
        // Another page's block is rebuilt into the freed slot and is linked.
        write_code(&mut e, CODE + PAGE_SIZE, &[ADD_X0_1, BRK_0]);
        e.start(CODE, END).unwrap();
        e.start(CODE, END).unwrap();
        assert_eq!(x(&e, 0), 8);
    }

    #[test]
    fn a_fault_mid_block_reports_its_pc_after_the_earlier_instructions() {
        let mut e = engine_with(&[ADD_X0_1, ADD_X0_1, LDR_X0_X18, ADD_X0_1]);
        e.reg_write(Register::X(18), 0xdead_0000_0000).unwrap();
        let error = e.start(CODE, END).unwrap_err();
        assert!(matches!(
            error,
            EmuError::Unmapped { address: 0xdead_0000_0000, pc: Some(p), .. } if p == CODE + 8
        ));
        assert_eq!((x(&e, 0), pc(&e)), (2, CODE + 8));
        let mut e = engine_with(&[ADD_X0_1, SVC_0]);
        assert!(e.start(CODE, END).is_err());
        assert_eq!((x(&e, 0), pc(&e)), (1, CODE + 4));
    }

    #[test]
    fn blocks_end_at_the_size_cap_and_the_page_end() {
        let count = MAX_BLOCK_OPS * 2 + 3;
        let mut code = vec![ADD_X0_1; count];
        code.push(BRK_0);
        let mut e = engine_with(&[]);
        let at = CODE + PAGE_SIZE - 8; // straddles the page boundary
        write_code(&mut e, at, &code);
        e.start(at, END).unwrap();
        assert_eq!(x(&e, 0), count as u64);
        assert_eq!(pc(&e), at + 4 * count as u64);
    }

    #[test]
    fn a_misaligned_pc_runs_single_instructions_as_the_decoder_does() {
        // Words at CODE+2: nop, b #8 (to CODE+14), svc / brk.
        let mut e = engine_with(&[]);
        let mut bytes = vec![0u8; 2];
        for word in [NOP, 0x1400_0002, SVC_0, BRK_0] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        e.mem_write(CODE, &bytes).unwrap();
        e.start(CODE + 2, END).unwrap();
        assert_eq!(pc(&e), CODE + 14, "nop, branch over the svc, brk");
        assert!(e.start(CODE + 10, END).is_err(), "svc is rejected");
        assert_eq!(pc(&e), CODE + 10);
    }

    #[test]
    fn a_redirecting_hook_loop_still_times_out() {
        let mut e = engine_with(&[NOP]);
        e.add_code_hook(CODE, CODE, |engine, _, _| {
            engine.reg_write(Register::Pc, CODE + 4)
        })
        .unwrap();
        e.add_code_hook(CODE + 4, CODE + 4, |engine, _, _| {
            engine.reg_write(Register::Pc, CODE)
        })
        .unwrap();
        let timeout = Duration::from_millis(5);
        let error = e.start_bounded(CODE, END, timeout, 0).unwrap_err();
        assert!(matches!(error, EmuError::Timeout { .. }));
    }

    #[test]
    fn an_endless_block_loop_honours_the_limit_and_the_timeout() {
        let mut e = engine_with(&[ADD_X0_1, B_BACK_4]);
        e.start_bounded(CODE, END, Duration::ZERO, 1001).unwrap();
        assert_eq!((x(&e, 0), pc(&e)), (501, CODE + 4));
        let error = e
            .start_bounded(CODE, END, Duration::from_millis(5), 0)
            .unwrap_err();
        assert!(matches!(error, EmuError::Timeout { .. }));
    }

    #[test]
    fn pc_hasher_byte_path_is_deterministic_and_order_sensitive() {
        let hash = |bytes: &[u8]| {
            let mut h = PcHasher::default();
            h.write(bytes);
            h.finish()
        };
        assert_eq!(hash(&[]), 0);
        assert_eq!(hash(&[1, 2, 3]), hash(&[1, 2, 3]));
        assert_ne!(hash(&[1, 2, 3]), hash(&[3, 2, 1]));
    }

    // --- random programs: block path vs per-instruction reference ---

    /// Program words: mostly hot fast-path forms, some branches, and a few
    /// arbitrary words (fallbacks, faults, unsupported encodings).
    fn random_word(rng: &mut Rng) -> u32 {
        use super::TEMPLATES;
        let r = rng.next();
        let (mask, bits) = TEMPLATES[(r % TEMPLATES.len() as u64) as usize];
        // Keep branch offsets short so control mostly stays in the program.
        let word = ((rng.next() as u32) & !mask) | bits;
        match bits {
            0x1400_0000 => (word & 0xfc00_0000) | ((r >> 8) as u32 & 0x1f),
            0x3400_0000 | 0x3600_0000 | 0x5400_0000 => {
                (word & !0x00ff_ffe0) | (((r >> 8) as u32 & 0x7) << 5)
            }
            _ => word,
        }
    }

    type State = (Vec<u64>, u64, u64, u64, Vec<u8>);

    fn engine_state(e: &NativeEngine<'_>) -> State {
        let regs = (0..31).map(|n| x(e, n)).collect();
        let mut memory = e.mem_read(CODE, PAGE_SIZE as usize).unwrap();
        memory.extend(e.mem_read(DATA, DATA_SIZE as usize).unwrap());
        let sp = e.reg_read(Register::Sp).unwrap();
        (regs, sp, pc(e), e.reg_read(Register::Nzcv).unwrap(), memory)
    }

    fn cpu_state(cpu: &NativeCpu) -> State {
        let regs = (0..31).map(|n| cpu.x(n)).collect();
        let mut memory = vec![0u8; (PAGE_SIZE + DATA_SIZE) as usize];
        let (code, data) = memory.split_at_mut(PAGE_SIZE as usize);
        cpu.mem.read(CODE, code).unwrap();
        cpu.mem.read(DATA, data).unwrap();
        (regs, cpu.sp(), cpu.pc(), u64::from(cpu.nzcv()), memory)
    }

    #[test]
    fn random_programs_match_the_per_instruction_path() {
        let programs = if cfg!(debug_assertions) { 300 } else { 3000 };
        let mut rng = Rng(0xb10c);
        for program in 0..programs {
            let code: Vec<u32> = (0..48).map(|_| random_word(&mut rng)).collect();
            if code.iter().any(|&w| super::reserved_wide_shift(w)) {
                continue;
            }
            let regs: Vec<u64> = (0..31)
                .map(|_| match rng.next() % 5 {
                    0 => rng.next(),
                    1 => CODE + (rng.next() % 0x100) * 4, // self-modifying stores
                    _ => DATA + 0x800 + rng.next() % 0x800,
                })
                .collect();
            let steps = (rng.next() % 200) as usize + 1;

            let mut reference = NativeCpu::new();
            reference.mem.map(CODE, PAGE_SIZE);
            reference.mem.map(DATA, DATA_SIZE);
            let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
            reference.mem.write(CODE, &bytes).unwrap();
            for (n, value) in regs.iter().enumerate() {
                reference.set_x(n as u32, *value);
            }
            reference.set_sp(DATA + 0x1000);
            reference.set_pc(CODE);
            let expected = reference.run(END, steps);

            let mut e = NativeEngine::new().unwrap();
            e.mem_map(CODE, PAGE_SIZE).unwrap();
            e.mem_map(DATA, DATA_SIZE).unwrap();
            e.mem_write(CODE, &bytes).unwrap();
            for (n, value) in regs.iter().enumerate() {
                e.reg_write(Register::X(n as u8), *value).unwrap();
            }
            e.reg_write(Register::Sp, DATA + 0x1000).unwrap();
            let actual = e.start_bounded(CODE, END, Duration::ZERO, steps);

            assert_eq!(
                actual.is_ok(),
                matches!(expected, Ok(Step::Next | Step::Break(_))),
                "program {program}: {expected:?} vs {actual:?} for {code:08x?}"
            );
            assert_eq!(
                engine_state(&e),
                cpu_state(&reference),
                "program {program} ({steps} steps) diverged: {code:08x?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Whole programs through `NativeEngine` (block cache) against Unicorn (its
// results frozen in `tests/fixtures/native_oracle/block_tests.oracle`, see
// `native/frozen.rs`; also run live with the `unicorn` feature).
// ---------------------------------------------------------------------------

mod frozen_diff {
    use std::cell::Cell;
    use std::fmt::Write as _;
    use std::rc::Rc;
    use std::time::Duration;

    #[cfg(feature = "unicorn")]
    use super::super::super::UnicornEngine;
    use super::super::super::register::Register;
    use super::super::engine::NativeEngine;
    use super::super::frozen;
    use super::{CODE, DATA, DATA_SIZE};

    /// One run's state: X0..X30, PC, NZCV, the DATA area and the first 0x100
    /// bytes of CODE.
    type RunDump = (Vec<u64>, u64, u64, Vec<u8>, Vec<u8>);

    /// Fixture of the frozen cases.
    const FIXTURE: &str = "block_tests.oracle";

    /// A loop over loads/stores and the hot ALU forms, a call (`bl`/`ret`),
    /// `cbz`/`tbnz`, ending at `CODE + 0x34`.
    const LOOP: [u32; 17] = [
        0xaa00_03f0, // 00 mov x16, x0
        0xf940_0528, // 04 ldr x8, [x9, #8]
        0xca48_1dad, // 08 eor x13, x13, x8, lsr #7
        0x9ba5_39ae, // 0c umaddl x14, w13, w5, x14
        0xf900_0928, // 10 str x8, [x9, #16]
        0xf86c_796a, // 14 ldr x10, [x11, x12, lsl #3]
        0x9100_0400, // 18 add x0, x0, #1
        0xf100_04a5, // 1c subs x5, x5, #1
        0x9a9f_05ef, // 20 csinc x15, x15, xzr, eq
        0x54ff_ff01, // 24 b.ne 0x04
        0x9400_0004, // 28 bl 0x38
        0xb400_0046, // 2c cbz x6, 0x34
        0x9100_1400, // 30 add x0, x0, #5
        0xd420_0000, // 34 (stop point)
        0x3718_0047, // 38 tbnz w7, #3, 0x40
        0x9100_1400, // 3c add x0, x0, #5
        0xd65f_03c0, // 40 ret
    ];
    const STOP: u64 = CODE + 0x34;
    // Self-modifying code is not compared here: without an ISB the outcome is
    // architecturally unpredictable and Unicorn keeps running its stale
    // translation, whereas the native contract is the per-instruction path's
    // (checked by `engine::a_guest_store_into_the_running_block_takes_effect`
    // and the random-program test).

    fn init() -> Vec<(u8, u64)> {
        vec![
            (5, 50),
            (6, 0),
            (7, 8),
            (9, DATA + 0x100),
            (11, DATA + 0x200),
            (12, 3),
            (13, 0x1234_5678_9abc_def0),
            (14, 7),
        ]
    }

    macro_rules! run {
        ($engine:expr, $code:expr, $until:expr, $hook:expr) => {{
            let mut e = $engine;
            e.mem_map(CODE, 0x1000).unwrap();
            e.mem_map(DATA, DATA_SIZE).unwrap();
            let fill: Vec<u8> = (0..DATA_SIZE).map(|i| (i * 13 + 5) as u8).collect();
            e.mem_write(DATA, &fill).unwrap();
            let bytes: Vec<u8> = $code.iter().flat_map(|w: &u32| w.to_le_bytes()).collect();
            e.mem_write(CODE, &bytes).unwrap();
            let hits = Rc::new(Cell::new(0u64));
            if $hook {
                let counter = Rc::clone(&hits);
                // Mid-block hook: accumulates x0 into x20 on every visit.
                e.add_code_hook(CODE + 0x18, CODE + 0x18, move |engine, _, _| {
                    counter.set(counter.get() + 1);
                    let sum =
                        engine.reg_read(Register::X(20))? + engine.reg_read(Register::X(0))?;
                    engine.reg_write(Register::X(20), sum)
                })
                .unwrap();
            }
            // Twice: the second run executes from warm caches.
            let mut dumps = Vec::new();
            for _ in 0..2 {
                for (n, value) in init() {
                    e.reg_write(Register::X(n), value).unwrap();
                }
                e.reg_write(Register::X(0), 0).unwrap();
                e.reg_write(Register::X(20), 0).unwrap();
                e.reg_write(Register::Nzcv, 0).unwrap();
                e.mem_write(CODE, &bytes).unwrap();
                e.start_bounded(CODE, $until, Duration::from_secs(10), 0)
                    .unwrap();
                let regs: Vec<u64> = (0..31)
                    .map(|n| e.reg_read(Register::X(n)).unwrap())
                    .collect();
                let pc = e.reg_read(Register::Pc).unwrap();
                let nzcv = e.reg_read(Register::Nzcv).unwrap() & 0xf000_0000;
                let mut data = vec![0u8; DATA_SIZE as usize];
                e.mem_read_into(DATA, &mut data).unwrap();
                let code = e.mem_read(CODE, 0x100).unwrap();
                let dump: RunDump = (regs, pc, nzcv, data, code);
                dumps.push(dump);
            }
            (dumps, hits.get())
        }};
    }

    /// The byte runs where `actual` differs from `base`, as ` <tag>+<offset>=<hex>`.
    fn byte_delta(text: &mut String, tag: &str, base: &[u8], actual: &[u8]) {
        assert_eq!(base.len(), actual.len());
        let mut i = 0;
        while i < actual.len() {
            if actual[i] == base[i] {
                i += 1;
                continue;
            }
            let start = i;
            while i < actual.len() && actual[i] != base[i] {
                i += 1;
            }
            write!(text, " {tag}+{start:x}=").unwrap();
            for byte in &actual[start..i] {
                write!(text, "{byte:02x}").unwrap();
            }
        }
    }

    /// Encodes a `run!` result for the fixture: per run the PC, NZCV, the
    /// nonzero X registers and the DATA/CODE bytes that differ from what was
    /// written before the run; then the hook hit count.
    fn encode(code: &[u32], (dumps, hits): &(Vec<RunDump>, u64)) -> String {
        let fill: Vec<u8> = (0..DATA_SIZE).map(|i| (i * 13 + 5) as u8).collect();
        let mut written: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        written.resize(0x100, 0);
        let mut text = String::new();
        for (n, (regs, pc, nzcv, data, code)) in dumps.iter().enumerate() {
            write!(text, "run{n}: pc={pc:x} nzcv={nzcv:x}").unwrap();
            for (r, value) in regs.iter().enumerate().filter(|(_, v)| **v != 0) {
                write!(text, " x{r}={value:x}").unwrap();
            }
            byte_delta(&mut text, "data", &fill, data);
            byte_delta(&mut text, "code", &written, code);
            text.push_str(" ; ");
        }
        write!(text, "hits={hits}").unwrap();
        text
    }

    #[test]
    fn programs_through_the_block_cache_match_unicorn() {
        for hook in [false, true] {
            let native = run!(NativeEngine::new().unwrap(), LOOP, STOP, hook);
            let words: Vec<String> = LOOP.iter().map(|w| format!("{w:08x}")).collect();
            let key = format!("{} | until={STOP:x} hook={hook}", words.join(" "));
            #[cfg(feature = "unicorn")]
            {
                let unicorn = run!(UnicornEngine::new().unwrap(), LOOP, STOP, hook);
                frozen::record(FIXTURE, &key, &encode(&LOOP, &unicorn));
                assert_eq!(native, unicorn, "hook: {hook}");
                if frozen::recording() {
                    continue;
                }
            }
            let Some(expected) = frozen::lookup(FIXTURE, &key) else {
                frozen::missing(FIXTURE, &key)
            };
            assert_eq!(
                encode(&LOOP, &native),
                expected,
                "native vs frozen Unicorn, hook: {hook}"
            );
        }
        let (dumps, hits) = run!(NativeEngine::new().unwrap(), LOOP, STOP, true);
        assert_eq!(
            hits, 100,
            "the mid-block hook fired on every iteration of both runs"
        );
        assert_eq!(
            dumps[0].0[0], 50,
            "both conditional branches skip their add"
        );
        assert_eq!(dumps[0].0[20], (0..50).sum::<u64>());
    }
}
