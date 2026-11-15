//! Engine tests running hand-encoded ARM64 programs.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use unicorn_engine::uc_error;

use super::*;

const PAGE: u64 = 0x1000;
const CODE: u64 = 0x1_0000;
const SHIM: u64 = 0x2_0000;
const DATA: u64 = 0x3_0000;
const STACK: u64 = 0x4_0000;
const UNMAPPED: u64 = 0x9_0000;
const TIMEOUT: Duration = Duration::from_secs(5);

const RET: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const BRANCH_SELF: u32 = 0x1400_0000;
const LDR_X1_X0: u32 = 0xf940_0001;
const STR_X1_X0: u32 = 0xf900_0001;
const ADD_X0_X0_1: u32 = 0x9100_0400;
const SVC_0X80: u32 = 0xd400_1001;
const CASAL_X1_X2_X0: u32 = 0xc8e1_fc02;
const CASAL_W1_W2_X3: u32 = 0x88e1_fc62;
const CASAL_XZR_X2_X0: u32 = 0xc8ff_fc02;
const SWPAL_X1_X2_X0: u32 = 0xf8e1_8002;
const SWPAL_W1_W2_SP: u32 = 0xb8e1_83e2;
const SWPAL_X1_XZR_X0: u32 = 0xf8e1_801f;
const EOR3_V0_V1_V2_V3: u32 = 0xce02_0c20;
const UDF_0: u32 = 0x0000_0000;
const EXCP_UDEF: u32 = 1;

fn movz(register: u32, immediate: u16) -> u32 {
    0xd280_0000 | (u32::from(immediate) << 5) | register
}

fn bl(from: u64, to: u64) -> u32 {
    let words = u32::try_from((to - from) / INSTRUCTION_SIZE).expect("forward branch");
    0x9400_0000 | words
}

fn byte(index: usize) -> u8 {
    u8::try_from(index).expect("small index")
}

fn assemble(instructions: &[u32]) -> Vec<u8> {
    instructions
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

fn engine_with(program: &[u32]) -> Engine<'static> {
    let mut engine = Engine::new().expect("engine");
    for base in [CODE, SHIM, DATA, STACK] {
        engine.mem_map(base, PAGE).expect("map");
    }
    engine.mem_write(CODE, &assemble(program)).expect("program");
    engine.reg_write(Register::Sp, STACK + PAGE).expect("sp");
    engine
}

fn end_of(program: &[u32]) -> u64 {
    CODE + program.len() as u64 * INSTRUCTION_SIZE
}

fn run(engine: &mut Engine<'_>, program: &[u32]) -> Result<(), EmuError> {
    engine.run(CODE, end_of(program), TIMEOUT)
}

#[test]
fn memory_round_trips_and_unmapped_access_fails() {
    let mut engine = engine_with(&[]);
    engine
        .write_u64(DATA + 8, 0x1122_3344_5566_7788)
        .expect("write");

    assert_eq!(engine.read_u64(DATA + 8).ok(), Some(0x1122_3344_5566_7788));
    assert_eq!(engine.read_u32(DATA + 12).ok(), Some(0x1122_3344));
    assert_eq!(engine.mem_read(DATA + 8, 2).ok(), Some(vec![0x88, 0x77]));
    assert_eq!(engine.mem_read(UNMAPPED, 0).ok(), Some(Vec::new()));
    let error = engine.read_u32(UNMAPPED).expect_err("unmapped");
    assert_eq!(error.unicorn_code(), Some(uc_error::READ_UNMAPPED));

    engine.mem_unmap(DATA, PAGE).expect("unmap");
    assert!(engine.read_u32(DATA).is_err());
    assert_eq!(
        engine
            .mem_map(CODE, PAGE)
            .err()
            .and_then(|e| e.unicorn_code()),
        Some(uc_error::MAP)
    );
}

#[test]
fn registers_round_trip() {
    let mut engine = engine_with(&[]);
    for index in 0..=LINK_REGISTER_INDEX {
        engine
            .reg_write(Register::X(index), 0x1000 + u64::from(index))
            .expect("write");
    }
    for index in 0..=LINK_REGISTER_INDEX {
        assert_eq!(
            engine.reg_read(Register::X(index)).ok(),
            Some(0x1000 + u64::from(index))
        );
    }
    assert_eq!(engine.reg_read(Register::LR).ok(), Some(0x1000 + 30));
    engine.reg_write(Register::Pc, CODE + 4).expect("pc");
    assert_eq!(engine.reg_read(Register::Pc).ok(), Some(CODE + 4));

    let vector: [u8; VECTOR_REGISTER_SIZE] = core::array::from_fn(byte);
    engine.vreg_write(31, vector).expect("v31");
    assert_eq!(engine.vreg_read(31).ok(), Some(vector));
    assert!(engine.reg_read(Register::X(31)).is_err());
    assert!(engine.vreg_read(VECTOR_REGISTER_COUNT).is_err());
}

#[test]
fn executes_straight_line_code() {
    let program = [movz(0, 41), ADD_X0_X0_1, NOP];
    let mut engine = engine_with(&program);

    run(&mut engine, &program).expect("run");

    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(42));
    assert_eq!(engine.reg_read(Register::Pc).ok(), Some(end_of(&program)));
}

#[test]
fn shim_stub_runs_handler_and_returns_to_link_register() {
    let program = [movz(0, 5), movz(1, 7), bl(CODE + 8, SHIM + 4), ADD_X0_X0_1];
    let mut engine = engine_with(&program);
    let calls = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&calls);
    engine.write_return_stub(SHIM).expect("stub 0");
    engine.write_return_stub(SHIM + 4).expect("stub 1");
    assert_eq!(engine.read_u32(SHIM + 4).ok(), Some(RET));
    engine
        .add_code_hook(SHIM, SHIM + PAGE - 1, move |engine, address, size| {
            seen.borrow_mut()
                .push((address, size, engine.reg_read(Register::LR)?));
            let product = engine.reg_read(Register::X(0))? * engine.reg_read(Register::X(1))?;
            engine.reg_write(Register::X(0), product)
        })
        .expect("hook");

    run(&mut engine, &program).expect("run");

    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(36));
    assert_eq!(*calls.borrow(), vec![(SHIM + 4, 4, CODE + 12)]);
}

#[test]
fn hook_error_stops_guest_and_is_returned() {
    let program = [bl(CODE, SHIM), movz(0, 9)];
    let mut engine = engine_with(&program);
    engine.write_return_stub(SHIM).expect("stub");
    let hook = engine
        .add_code_hook(SHIM, SHIM, |_, address, _| {
            Err(EmuError::guest(format!(
                "unsupported import at {address:#x}"
            )))
        })
        .expect("hook");

    let error = run(&mut engine, &program).expect_err("fault");

    assert_eq!(
        error.to_string(),
        format!("unsupported import at {SHIM:#x}")
    );
    assert_ne!(engine.reg_read(Register::X(0)).ok(), Some(9));
    engine.remove_hook(hook).expect("remove");
    run(&mut engine, &program).expect("fault does not persist into the next run");
    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(9));
}

#[test]
fn stop_from_hook_ends_run_successfully() {
    let program = [NOP, NOP, BRANCH_SELF];
    let mut engine = engine_with(&program);
    engine
        .add_code_hook(CODE + 8, CODE + 8, |engine, _, _| engine.stop())
        .expect("hook");

    engine.start(CODE, end_of(&program)).expect("stopped");
}

#[test]
fn removed_hook_no_longer_fires() {
    let program = [NOP, NOP];
    let mut engine = engine_with(&program);
    let count = Rc::new(Cell::new(0));
    let counter = Rc::clone(&count);
    let hook = engine
        .add_code_hook(CODE, CODE + 8, move |_, _, _| {
            counter.set(counter.get() + 1);
            Ok(())
        })
        .expect("hook");

    run(&mut engine, &program).expect("first run");
    engine.remove_hook(hook).expect("remove");
    run(&mut engine, &program).expect("second run");

    assert_eq!(count.get(), 2);
}

#[test]
fn bounded_runs_time_out_and_reject_zero_budget() {
    let program = [BRANCH_SELF];
    let mut engine = engine_with(&program);

    let error = engine
        .run(CODE, end_of(&program), Duration::from_millis(50))
        .expect_err("timeout");
    assert!(matches!(error, EmuError::Timeout { timeout } if timeout == Duration::from_millis(50)));
    assert!(matches!(
        engine.start_bounded(CODE, end_of(&program), Duration::ZERO, 0),
        Err(EmuError::InvalidTimeout)
    ));
}

#[test]
fn instruction_limit_stops_early() {
    let program = [ADD_X0_X0_1, ADD_X0_X0_1, ADD_X0_X0_1];
    let mut engine = engine_with(&program);

    engine
        .start_bounded(CODE, end_of(&program), TIMEOUT, 2)
        .expect("bounded");

    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(2));
}

#[test]
fn memory_fault_hook_maps_page_and_retries() {
    let program = [LDR_X1_X0];
    let mut engine = engine_with(&program);
    engine
        .reg_write(Register::X(0), UNMAPPED + 0x10)
        .expect("x0");
    let faults = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&faults);
    engine
        .add_memory_fault_hook(move |engine, access, address, size| {
            seen.borrow_mut().push((access, address, size));
            engine.mem_map(address & !(PAGE - 1), PAGE)?;
            engine.write_u64(address, 0xfeed)?;
            Ok(true)
        })
        .expect("hook");

    run(&mut engine, &program).expect("run");

    assert_eq!(engine.reg_read(Register::X(1)).ok(), Some(0xfeed));
    assert_eq!(
        *faults.borrow(),
        vec![(MemoryAccess::Read, UNMAPPED + 0x10, 8)]
    );
}

#[test]
fn unhandled_memory_fault_reports_unicorn_error() {
    let program = [STR_X1_X0];
    let mut engine = engine_with(&program);
    engine.reg_write(Register::X(0), UNMAPPED).expect("x0");
    engine
        .add_memory_fault_hook(|_, _, _, _| Ok(false))
        .expect("hook");

    let error = run(&mut engine, &program).expect_err("unmapped");

    assert_eq!(error.unicorn_code(), Some(uc_error::WRITE_UNMAPPED));
}

#[test]
fn memory_access_hook_reports_loads_and_stores() {
    let program = [LDR_X1_X0, STR_X1_X0];
    let mut engine = engine_with(&program);
    engine.reg_write(Register::X(0), DATA).expect("x0");
    engine.write_u64(DATA, 77).expect("data");
    let accesses = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&accesses);
    engine
        .add_memory_access_hook(
            DATA,
            DATA + PAGE - 1,
            move |_, access, address, size, value| {
                seen.borrow_mut().push((access, address, size, value));
                Ok(())
            },
        )
        .expect("hook");

    run(&mut engine, &program).expect("run");

    assert_eq!(
        *accesses.borrow(),
        vec![
            (MemoryAccess::Read, DATA, 8, 0),
            (MemoryAccess::Write, DATA, 8, 77)
        ]
    );
}

fn reject_data_page(address: u64, size: u64) -> Result<(), EmuError> {
    if address < DATA + PAGE && address + size > DATA {
        return Err(EmuError::MemoryRejected {
            address,
            size,
            reason: "protected".into(),
        });
    }
    Ok(())
}

#[test]
fn memory_guard_rejects_guest_and_host_accesses_permanently() {
    let program = [STR_X1_X0];
    let mut engine = engine_with(&program);
    engine.reg_write(Register::X(0), DATA + 0x20).expect("x0");
    engine.guard_memory(reject_data_page).expect("guard");

    let error = run(&mut engine, &program).expect_err("guest rejected");
    assert!(
        matches!(error, EmuError::MemoryRejected { address, size: 8, .. } if address == DATA + 0x20)
    );
    assert!(matches!(
        run(&mut engine, &[NOP]),
        Err(EmuError::MemoryRejected { .. })
    ));
    assert!(engine.read_u32(DATA).is_err());
    assert!(engine.mem_write(DATA, &[1]).is_err());
    assert!(engine.read_u32(CODE).is_ok());
    assert!(matches!(
        engine.guard_memory(|_, _| Ok(())),
        Err(EmuError::GuardAlreadyInstalled)
    ));
}

#[test]
fn memory_guard_validates_instruction_fetches() {
    let program = [NOP];
    let mut engine = engine_with(&program);
    engine
        .guard_memory(|address, size| {
            if address == CODE {
                Err(EmuError::MemoryRejected {
                    address,
                    size,
                    reason: "no exec".into(),
                })
            } else {
                Ok(())
            }
        })
        .expect("guard");

    assert!(matches!(
        run(&mut engine, &program),
        Err(EmuError::MemoryRejected { size: 4, .. })
    ));
}

#[test]
fn interrupt_hook_receives_exceptions() {
    let program = [SVC_0X80, movz(0, 3)];
    let mut engine = engine_with(&program);
    let numbers = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&numbers);
    engine
        .add_interrupt_hook(move |engine, number| {
            seen.borrow_mut()
                .push((number, engine.reg_read(Register::Pc)?));
            Ok(())
        })
        .expect("hook");

    run(&mut engine, &program).expect("run");

    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(3));
    assert_eq!(numbers.borrow().len(), 1);
    assert_eq!(numbers.borrow()[0].1, CODE + 4);
}

#[test]
fn invalid_instruction_without_emulation_fails() {
    let program = [UDF_0];
    let mut engine = engine_with(&program);

    let error = run(&mut engine, &program).expect_err("invalid");

    assert!(error.unicorn_code().is_some());
    assert_eq!(engine.reg_read(Register::Pc).ok(), Some(CODE));
}

#[test]
fn undefined_instruction_is_reported_to_interrupt_hook() {
    let program = [UDF_0, movz(0, 4)];
    let mut engine = engine_with(&program);
    let numbers = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&numbers);
    engine
        .add_interrupt_hook(move |engine, number| {
            let pc = engine.reg_read(Register::Pc)?;
            seen.borrow_mut().push((number, pc));
            engine.reg_write(Register::Pc, pc + INSTRUCTION_SIZE)
        })
        .expect("hook");

    run(&mut engine, &program).expect("run");

    assert_eq!(*numbers.borrow(), vec![(EXCP_UDEF, CODE)]);
    assert_eq!(engine.reg_read(Register::X(0)).ok(), Some(4));
}

/// Places `instruction` at `CODE`, prepares state, soft-emulates it and returns the engine.
fn soft_emulate(instruction: u32, prepare: impl FnOnce(&mut Engine<'static>)) -> Engine<'static> {
    let mut engine = engine_with(&[instruction]);
    engine.reg_write(Register::Pc, CODE).expect("pc");
    prepare(&mut engine);
    assert_eq!(engine.emulate_invalid_instruction().ok(), Some(true));
    assert_eq!(
        engine.reg_read(Register::Pc).ok(),
        Some(CODE + INSTRUCTION_SIZE)
    );
    engine
}

fn set(engine: &mut Engine<'_>, index: u8, value: u64) {
    engine
        .reg_write(Register::X(index), value)
        .expect("register");
}

fn x(engine: &Engine<'_>, index: u8) -> u64 {
    engine.reg_read(Register::X(index)).expect("register")
}

#[test]
fn casal_64_swaps_when_equal() {
    let engine = soft_emulate(CASAL_X1_X2_X0, |engine| {
        engine.write_u64(DATA, 0xaaaa_bbbb_cccc_dddd).expect("data");
        set(engine, 0, DATA);
        set(engine, 1, 0xaaaa_bbbb_cccc_dddd);
        set(engine, 2, 0x1234);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(0x1234));
    assert_eq!(x(&engine, 1), 0xaaaa_bbbb_cccc_dddd);
}

#[test]
fn casal_64_keeps_memory_when_different() {
    let engine = soft_emulate(CASAL_X1_X2_X0, |engine| {
        engine.write_u64(DATA, 7).expect("data");
        set(engine, 0, DATA);
        set(engine, 1, 8);
        set(engine, 2, 0x1234);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(7));
    assert_eq!(x(&engine, 1), 7);
}

#[test]
fn casal_32_compares_low_word_and_zero_extends() {
    let engine = soft_emulate(CASAL_W1_W2_X3, |engine| {
        engine.write_u64(DATA, 0xffff_ffff_8000_0001).expect("data");
        set(engine, 3, DATA);
        set(engine, 1, 0xdead_0000_8000_0001);
        set(engine, 2, 0xbeef_0000_0000_0002);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(0xffff_ffff_0000_0002));
    assert_eq!(x(&engine, 1), 0x8000_0001);
}

#[test]
fn casal_with_zero_register_compares_against_zero() {
    let engine = soft_emulate(CASAL_XZR_X2_X0, |engine| {
        set(engine, 0, DATA);
        set(engine, 2, 0x55);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(0x55));
}

#[test]
fn swpal_64_exchanges_register_and_memory() {
    let engine = soft_emulate(SWPAL_X1_X2_X0, |engine| {
        engine.write_u64(DATA, 0x0102_0304_0506_0708).expect("data");
        set(engine, 0, DATA);
        set(engine, 1, 0x1111_2222_3333_4444);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(0x1111_2222_3333_4444));
    assert_eq!(x(&engine, 2), 0x0102_0304_0506_0708);
}

#[test]
fn swpal_32_uses_stack_pointer_base_and_low_word() {
    let engine = soft_emulate(SWPAL_W1_W2_SP, |engine| {
        engine.reg_write(Register::Sp, DATA + 0x40).expect("sp");
        engine
            .write_u64(DATA + 0x40, 0x9999_9999_aabb_ccdd)
            .expect("data");
        set(engine, 1, 0x7777_7777_0000_0042);
        set(engine, 2, u64::MAX);
    });

    assert_eq!(
        engine.read_u64(DATA + 0x40).ok(),
        Some(0x9999_9999_0000_0042)
    );
    assert_eq!(x(&engine, 2), 0xaabb_ccdd);
}

#[test]
fn swpal_into_zero_register_discards_old_value() {
    let engine = soft_emulate(SWPAL_X1_XZR_X0, |engine| {
        engine.write_u64(DATA, 5).expect("data");
        set(engine, 0, DATA);
        set(engine, 1, 6);
    });

    assert_eq!(engine.read_u64(DATA).ok(), Some(6));
}

#[test]
fn eor3_xors_three_vectors() {
    let first: [u8; 16] = core::array::from_fn(byte);
    let second: [u8; 16] = core::array::from_fn(|index| byte(index) << 4);
    let third = [0xa5; 16];
    let engine = soft_emulate(EOR3_V0_V1_V2_V3, |engine| {
        engine.vreg_write(1, first).expect("v1");
        engine.vreg_write(2, second).expect("v2");
        engine.vreg_write(3, third).expect("v3");
    });

    let expected: [u8; 16] =
        core::array::from_fn(|index| first[index] ^ second[index] ^ third[index]);
    assert_eq!(engine.vreg_read(0).ok(), Some(expected));
}

#[test]
fn unrelated_instructions_are_not_emulated() {
    let mut engine = engine_with(&[NOP]);
    engine.reg_write(Register::Pc, CODE).expect("pc");
    assert_eq!(engine.emulate_invalid_instruction().ok(), Some(false));

    engine.reg_write(Register::Pc, UNMAPPED).expect("pc");
    assert_eq!(engine.emulate_invalid_instruction().ok(), Some(false));
}

/// Runs `program` natively and with every instruction soft-emulated, and checks
/// both produce the same registers and memory.
fn assert_native_matches_soft(instruction: u32) {
    let prepare = |engine: &mut Engine<'_>| {
        engine.write_u64(DATA, 0x0000_0000_cafe_f00d).expect("data");
        set(engine, 0, DATA);
        set(engine, 1, 0x0000_0000_cafe_f00d);
        set(engine, 2, 0x0123_4567_89ab_cdef);
    };
    let mut native = engine_with(&[instruction]);
    prepare(&mut native);
    native.start(CODE, CODE + INSTRUCTION_SIZE).expect("native");
    let soft = soft_emulate(instruction, prepare);

    for index in 0..3 {
        assert_eq!(
            x(&native, index),
            x(&soft, index),
            "x{index} for {instruction:#x}"
        );
    }
    assert_eq!(native.read_u64(DATA).ok(), soft.read_u64(DATA).ok());
}

#[test]
fn soft_atomics_match_unicorn_native_semantics() {
    for instruction in [CASAL_X1_X2_X0, SWPAL_X1_X2_X0, 0x88e1_fc02, 0xb8e1_8002] {
        assert_native_matches_soft(instruction);
    }
}

#[test]
fn soft_eor3_matches_unicorn_native_semantics() {
    let vectors: [[u8; 16]; 3] = [
        core::array::from_fn(|index| byte(index).wrapping_mul(37)),
        core::array::from_fn(|index| byte(index) ^ 0x5a),
        [0xc3; 16],
    ];
    let prepare = |engine: &mut Engine<'_>| {
        for (register, vector) in (1..).zip(vectors) {
            engine.vreg_write(register, vector).expect("vector");
        }
    };
    let mut native = engine_with(&[EOR3_V0_V1_V2_V3]);
    prepare(&mut native);
    native.start(CODE, CODE + INSTRUCTION_SIZE).expect("native");
    let soft = soft_emulate(EOR3_V0_V1_V2_V3, prepare);

    assert_eq!(native.vreg_read(0).ok(), soft.vreg_read(0).ok());
}

/// An ARMv8.0 core (Cortex-A57) rejects LSE atomics and SHA3, like the Unicorn
/// builds ipatool's compatibility layer was written for.
fn armv8_0_engine_with(program: &[u32]) -> Engine<'static> {
    let mut engine = Engine::with_cpu_model(unicorn_engine::Arm64CpuModel::A57).expect("engine");
    for base in [CODE, DATA] {
        engine.mem_map(base, PAGE).expect("map");
    }
    engine.mem_write(CODE, &assemble(program)).expect("program");
    engine
}

#[test]
fn run_resumes_after_soft_emulating_unsupported_instructions() {
    let program = [CASAL_X1_X2_X0, SWPAL_X1_X2_X0, EOR3_V0_V1_V2_V3, movz(5, 1)];
    let mut engine = armv8_0_engine_with(&program);
    engine.write_u64(DATA, 10).expect("data");
    set(&mut engine, 0, DATA);
    set(&mut engine, 1, 10);
    set(&mut engine, 2, 20);
    engine.vreg_write(1, [1; 16]).expect("v1");
    engine.vreg_write(2, [2; 16]).expect("v2");
    engine.vreg_write(3, [4; 16]).expect("v3");

    run(&mut engine, &program).expect("run");

    assert_eq!(engine.read_u64(DATA).ok(), Some(10));
    assert_eq!(x(&engine, 2), 20);
    assert_eq!(x(&engine, 5), 1);
    assert_eq!(engine.vreg_read(0).ok(), Some([7; 16]));
}

#[test]
fn armv8_0_core_rejects_lse_without_soft_emulation() {
    let program = [CASAL_X1_X2_X0];
    let mut engine = armv8_0_engine_with(&program);
    set(&mut engine, 0, DATA);

    let error = engine.start(CODE, end_of(&program)).expect_err("undefined");

    assert_eq!(error.unicorn_code(), Some(uc_error::EXCEPTION));
}

#[test]
fn exhausted_deadline_times_out_before_running() {
    let program = [NOP];
    let mut engine = engine_with(&program);

    let error = engine
        .run(CODE, end_of(&program), Duration::ZERO)
        .expect_err("timeout");

    assert!(matches!(error, EmuError::Timeout { timeout } if timeout == Duration::ZERO));
}

#[test]
fn condition_flags_round_trip() {
    let mut engine = engine_with(&[NOP]);
    let carry_and_zero = 0x6000_0000;

    engine
        .reg_write(Register::Nzcv, carry_and_zero)
        .expect("nzcv");

    assert_eq!(engine.reg_read(Register::Nzcv).ok(), Some(carry_and_zero));
}

#[test]
fn memory_fault_hook_reports_instruction_fetches() {
    let mut engine = engine_with(&[NOP]);
    let faults = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&faults);
    engine
        .add_memory_fault_hook(move |_, access, address, _| {
            seen.borrow_mut().push((access, address));
            Ok(false)
        })
        .expect("hook");

    let error = engine
        .run(UNMAPPED, UNMAPPED + INSTRUCTION_SIZE, TIMEOUT)
        .expect_err("unmapped fetch");

    assert_eq!(error.unicorn_code(), Some(uc_error::FETCH_UNMAPPED));
    assert_eq!(*faults.borrow(), vec![(MemoryAccess::Fetch, UNMAPPED)]);
}
