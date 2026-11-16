//! `NativeEngine` surface and run-loop exits not reached by the shim tests.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use super::super::super::error::{EmuError, EngineErrorCode};
use super::super::super::register::Register;
use super::super::engine::NativeEngine;
use super::CODE;

const NOP: u32 = 0xd503_201f;
const BRK_0: u32 = 0xd420_0000;
const B_SELF: u32 = 0x1400_0000; // b .
const SVC_0: u32 = 0xd400_0001;
const END: u64 = 0xdead_0000;

fn engine_with(code: &[u32]) -> NativeEngine<'static> {
    let mut e = NativeEngine::new().unwrap();
    e.mem_map(CODE, 0x1000).unwrap();
    for (i, word) in code.iter().enumerate() {
        e.write_u32(CODE + 4 * i as u64, *word).unwrap();
    }
    e
}

#[test]
fn nzcv_and_vector_registers_round_trip() {
    let mut e = engine_with(&[]);
    e.reg_write(Register::Nzcv, 0x6000_0000).unwrap();
    assert_eq!(e.reg_read(Register::Nzcv).unwrap(), 0x6000_0000);
    let bytes: [u8; 16] = std::array::from_fn(|i| i as u8);
    e.vreg_write(7, bytes).unwrap();
    assert_eq!(e.vreg_read(7).unwrap(), bytes);
    assert_eq!(e.vreg_read(8).unwrap(), [0; 16]);
}

#[test]
fn unsupported_instruction_surfaces_as_invalid_instruction() {
    let mut e = engine_with(&[SVC_0]);
    let error = e.start(CODE, END).unwrap_err();
    assert_eq!(
        error.engine_code(),
        Some(EngineErrorCode::InvalidInstruction)
    );
}

#[test]
fn start_runs_until_brk() {
    let mut e = engine_with(&[NOP, NOP, BRK_0]);
    e.start(CODE, END).unwrap();
    assert_eq!(e.reg_read(Register::Pc).unwrap(), CODE + 8);
}

#[test]
fn instruction_limit_stops_the_run() {
    let mut e = engine_with(&[NOP, NOP, NOP, BRK_0]);
    e.start_bounded(CODE, END, Duration::ZERO, 2).unwrap();
    assert_eq!(e.reg_read(Register::Pc).unwrap(), CODE + 8);
}

#[test]
fn wall_clock_timeout_ends_an_endless_loop() {
    let mut e = engine_with(&[B_SELF]);
    let timeout = Duration::from_millis(1);
    let error = e.start_bounded(CODE, END, timeout, 0).unwrap_err();
    assert!(matches!(error, EmuError::Timeout { timeout: t } if t == timeout));
}

#[test]
fn a_fault_recorded_before_the_run_is_returned_first() {
    let mut e = engine_with(&[NOP, BRK_0]);
    e.fail(EmuError::guest("pending"));
    let error = e.start(CODE, END).unwrap_err();
    assert_eq!(error.to_string(), "pending");
    assert_eq!(e.reg_read(Register::Pc).unwrap(), CODE, "nothing executed");
    // The fault was consumed: the next run proceeds normally.
    e.start(CODE, END).unwrap();
}

#[test]
fn a_hook_that_fails_the_engine_but_returns_ok_still_errors() {
    let mut e = engine_with(&[NOP, BRK_0]);
    e.add_code_hook(CODE, CODE, |engine, _pc, _size| {
        engine.fail(EmuError::guest("soft fault"));
        Ok(())
    })
    .unwrap();
    let error = e.start(CODE, END).unwrap_err();
    assert_eq!(error.to_string(), "soft fault");
}

#[test]
fn an_all_addresses_hook_fires_on_every_instruction() {
    let mut e = engine_with(&[NOP, NOP, BRK_0]);
    let hits = Rc::new(Cell::new(0));
    let counter = Rc::clone(&hits);
    // begin > end means "every address".
    let id = e
        .add_code_hook(1, 0, move |_engine, _pc, _size| {
            counter.set(counter.get() + 1);
            Ok(())
        })
        .unwrap();
    e.start(CODE, END).unwrap();
    assert_eq!(hits.get(), 3);
    e.remove_hook(id).unwrap();
    e.start(CODE, END).unwrap();
    assert_eq!(hits.get(), 3, "removed hooks no longer fire");
}
