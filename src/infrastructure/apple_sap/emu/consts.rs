//! Backend-neutral constants shared by the Unicorn and native engines.

/// Size in bytes of an ARM64 instruction and of a `ret` stub.
pub const INSTRUCTION_SIZE: u64 = 4;
/// Little-endian encoding of `ret` (`RET X30`), used for host-implemented stubs.
pub const RET_INSTRUCTION: [u8; 4] = [0xc0, 0x03, 0x5f, 0xd6];
