//! A tiny guest that calls one shim slot per run.

use std::time::Duration;

use crate::infrastructure::apple_sap::emu::{EmuError, Engine, INSTRUCTION_SIZE, Register};

use super::super::{HEAP_BASE, HEAP_SIZE, ShimConfig, Shims};

pub(super) const CODE: u64 = 0x1_0000;
pub(super) const DATA: u64 = 0x2_0000;
pub(super) const DATA_SIZE: u64 = 0x4000;
pub(super) const STACK: u64 = 0x8_0000;
pub(super) const STACK_SIZE: u64 = 0x4000;
const CODE_SIZE: u64 = 0x1000;
const TIMEOUT: Duration = Duration::from_secs(5);
const MOVZ_X: u32 = 0xd280_0000;
const MOVK_X: u32 = 0xf280_0000;
const BLR_X16: u32 = 0xd63f_0200;
const SCRATCH_REGISTER: u32 = 16;
/// Where helper guest functions (callbacks) may be placed.
pub(super) const HELPER: u64 = CODE + 0x800;

pub(super) fn assemble(instructions: &[u32]) -> Vec<u8> {
    instructions
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

/// `movz/movk x16, #target` followed by `blr x16`.
fn call_program(target: u64) -> Vec<u32> {
    let mut program = Vec::new();
    for half in 0..4u32 {
        let immediate = ((target >> (16 * half)) & 0xffff) as u32;
        let base = if half == 0 { MOVZ_X } else { MOVK_X };
        program.push(base | (half << 21) | (immediate << 5) | SCRATCH_REGISTER);
    }
    program.push(BLR_X16);
    program
}

pub(super) struct Guest {
    pub(super) engine: Engine<'static>,
    pub(super) shims: Shims,
}

impl Guest {
    pub(super) fn new() -> Self {
        Self::with_config(ShimConfig::default())
    }

    pub(super) fn with_config(config: ShimConfig) -> Self {
        let mut engine = Engine::new().expect("engine");
        for (base, size) in [
            (CODE, CODE_SIZE),
            (DATA, DATA_SIZE),
            (STACK, STACK_SIZE),
            (HEAP_BASE, HEAP_SIZE),
        ] {
            engine.mem_map(base, size).expect("map");
        }
        let shims = Shims::install(&mut engine, config).expect("install");
        Self { engine, shims }
    }

    pub(super) fn address(&self, name: &str) -> u64 {
        self.shims
            .state()
            .borrow_mut()
            .resolve(name)
            .expect("resolve")
    }

    /// Calls `name` with integer `args` (beyond eight go on the stack) and
    /// returns `X0`.
    pub(super) fn call(&mut self, name: &str, args: &[u64]) -> Result<u64, EmuError> {
        let target = self.address(name);
        let program = call_program(target);
        self.engine.mem_write(CODE, &assemble(&program))?;
        let sp = STACK + STACK_SIZE / 2;
        for (index, &value) in args.iter().enumerate() {
            match u8::try_from(index).expect("index") {
                register @ 0..8 => self.engine.reg_write(Register::X(register), value)?,
                _ => self.engine.write_u64(sp + (index as u64 - 8) * 8, value)?,
            }
        }
        self.engine.reg_write(Register::Sp, sp)?;
        let end = CODE + program.len() as u64 * INSTRUCTION_SIZE;
        self.engine.run(CODE, end, TIMEOUT)?;
        self.engine.reg_read(Register::X(0))
    }

    pub(super) fn ok(&mut self, name: &str, args: &[u64]) -> u64 {
        self.call(name, args)
            .unwrap_or_else(|error| panic!("{name} failed: {error}"))
    }

    pub(super) fn put(&mut self, address: u64, data: &[u8]) {
        self.engine.mem_write(address, data).expect("write");
    }

    pub(super) fn put_str(&mut self, address: u64, text: &str) {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        self.put(address, &bytes);
    }

    pub(super) fn get(&self, address: u64, length: usize) -> Vec<u8> {
        self.engine.mem_read(address, length).expect("read")
    }

    pub(super) fn u32_at(&self, address: u64) -> u32 {
        self.engine.read_u32(address).expect("read")
    }

    pub(super) fn u64_at(&self, address: u64) -> u64 {
        self.engine.read_u64(address).expect("read")
    }
}
