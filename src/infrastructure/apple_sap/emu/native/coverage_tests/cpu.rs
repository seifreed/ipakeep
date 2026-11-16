//! `NativeCpu::run`, guest `Memory` and page-hasher behavior not reached by
//! the instruction tests.

use std::hash::Hasher;

use super::super::{Memory, NativeCpu, NativeError, PAGE_SIZE, PageHasher, Step};
use super::CODE;

const NOP: u32 = 0xd503_201f;
const BRK_5: u32 = 0xd420_00a0; // brk #5
const B_PLUS_8: u32 = 0x1400_0002; // b #8

fn cpu_with(code: &[u32]) -> NativeCpu {
    let mut cpu = NativeCpu::new();
    cpu.mem.map(CODE, PAGE_SIZE);
    let bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
    cpu.mem.write(CODE, &bytes).unwrap();
    cpu.set_pc(CODE);
    cpu
}

#[test]
fn run_stops_at_brk_and_reports_its_immediate() {
    let mut cpu = cpu_with(&[NOP, BRK_5, NOP]);
    assert_eq!(cpu.run(u64::MAX, 10), Ok(Step::Break(5)));
    assert_eq!(cpu.pc(), CODE + 4, "PC stays on the brk");
}

#[test]
fn run_stops_when_a_branch_reaches_until() {
    let mut cpu = cpu_with(&[B_PLUS_8, BRK_5, NOP]);
    assert_eq!(cpu.run(CODE + 8, 10), Ok(Step::Next));
    assert_eq!(cpu.pc(), CODE + 8, "the brk was branched over");
}

#[test]
fn instruction_fetch_straddling_two_pages_takes_the_slow_path() {
    let mut mem = Memory::default();
    mem.map(0x1000, 2 * PAGE_SIZE);
    mem.write(0x1ffe, &[0x11, 0x22, 0x33, 0x44]).unwrap();
    assert_eq!(mem.read_u32(0x1ffe), Ok(0x4433_2211));
    // The second half lies on an unmapped page: the fault names its first byte.
    mem.write(0x2ffe, &[0xaa, 0xbb]).unwrap();
    assert_eq!(
        mem.read_u32(0x2ffe),
        Err(NativeError::Unmapped { address: 0x3000 })
    );
}

#[test]
fn is_mapped_tracks_map_and_unmap() {
    let mut mem = Memory::default();
    assert!(!mem.is_mapped(0x4000));
    mem.map(0x4000, 1);
    assert!(mem.is_mapped(0x4000));
    assert!(mem.is_mapped(0x4fff), "any byte of a mapped page");
    assert!(!mem.is_mapped(0x5000));
    mem.unmap(0x4000, PAGE_SIZE);
    assert!(!mem.is_mapped(0x4000));
}

#[test]
fn page_hasher_byte_path_is_deterministic_and_order_sensitive() {
    let hash = |bytes: &[u8]| {
        let mut h = PageHasher::default();
        h.write(bytes);
        h.finish()
    };
    assert_eq!(hash(&[]), 0);
    assert_eq!(hash(&[1, 2, 3]), hash(&[1, 2, 3]));
    assert_ne!(hash(&[1, 2, 3]), hash(&[3, 2, 1]));
    assert_ne!(hash(&[1]), 0);
}
