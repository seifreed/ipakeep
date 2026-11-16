//! Tests of [`Memory`]'s data software TLB and its fast/slow access paths.

use super::{Memory, NativeError, PAGE_SHIFT, PAGE_SIZE, TLB_ENTRIES};

/// Two pages this far apart share one direct-mapped TLB slot.
const ALIAS: u64 = TLB_ENTRIES as u64 * PAGE_SIZE;

/// The `(tag, frame)` held by the TLB slot that `address` maps to.
fn slot(mem: &Memory, address: u64) -> (u64, usize) {
    let vpn = address >> PAGE_SHIFT;
    mem.tlb[vpn as usize & (TLB_ENTRIES - 1)].get()
}

fn read_vec(mem: &Memory, address: u64, len: usize) -> Result<Vec<u8>, NativeError> {
    let mut buf = vec![0u8; len];
    mem.read(address, &mut buf).map(|()| buf)
}

#[test]
fn miss_fills_the_slot_and_hit_reuses_it() {
    let mut mem = Memory::default();
    mem.map(0x4000, PAGE_SIZE);
    assert_eq!(slot(&mem, 0x4000).0, u64::MAX, "cold TLB");
    mem.write(0x4010, &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    assert_eq!(slot(&mem, 0x4000), (0x4, 0), "the miss cached the page");
    assert_eq!(
        read_vec(&mem, 0x4010, 8).unwrap(),
        [1, 2, 3, 4, 5, 6, 7, 8],
        "the hit reads the same frame"
    );
    assert_eq!(slot(&mem, 0x4000), (0x4, 0));
}

#[test]
fn unmapped_pages_are_never_cached() {
    let mem = Memory::default();
    assert_eq!(
        read_vec(&mem, 0x7008, 8),
        Err(NativeError::Unmapped { address: 0x7008 })
    );
    assert_eq!(slot(&mem, 0x7000).0, u64::MAX, "no negative entry");
}

#[test]
fn conflicting_pages_evict_each_other_and_stay_correct() {
    let mut mem = Memory::default();
    let a = 0x10_0000;
    let b = a + ALIAS;
    mem.map(a, PAGE_SIZE);
    mem.map(b, PAGE_SIZE);
    mem.write(a, &[0xaa; 8]).unwrap();
    mem.write(b, &[0xbb; 8]).unwrap();
    assert_eq!(slot(&mem, a).0, b >> PAGE_SHIFT, "b evicted a");
    for _ in 0..3 {
        assert_eq!(read_vec(&mem, a, 8).unwrap(), [0xaa; 8]);
        assert_eq!(slot(&mem, a).0, a >> PAGE_SHIFT);
        assert_eq!(read_vec(&mem, b, 8).unwrap(), [0xbb; 8]);
        assert_eq!(slot(&mem, b).0, b >> PAGE_SHIFT);
    }
}

#[test]
fn unmap_flushes_moved_frames_and_remap_is_zeroed() {
    let mut mem = Memory::default();
    mem.map(0x1000, 3 * PAGE_SIZE);
    for (i, page) in [0x1000u64, 0x2000, 0x3000].into_iter().enumerate() {
        mem.write(page, &[i as u8 + 1; 8]).unwrap();
    }
    // Every page is cached; unmapping 0x1000 moves 0x3000's frame into slot 0.
    mem.unmap(0x1000, PAGE_SIZE);
    assert!(mem.tlb.iter().all(|s| s.get().0 == u64::MAX), "flushed");
    assert_eq!(mem.fetch_cache.get().0, u64::MAX, "fetch cache flushed");
    assert_eq!(
        read_vec(&mem, 0x1000, 8),
        Err(NativeError::Unmapped { address: 0x1000 })
    );
    assert_eq!(read_vec(&mem, 0x2000, 8).unwrap(), [2; 8]);
    assert_eq!(read_vec(&mem, 0x3000, 8).unwrap(), [3; 8]);
    assert_eq!(slot(&mem, 0x3000), (0x3, 0), "re-cached at its new frame");
    // Remapping yields a fresh zeroed page, not the stale cached frame.
    mem.map(0x1000, PAGE_SIZE);
    assert_eq!(read_vec(&mem, 0x1000, 8).unwrap(), [0; 8]);
    assert_eq!(read_vec(&mem, 0x3000, 8).unwrap(), [3; 8]);
}

#[test]
fn map_keeps_cached_translations_valid() {
    let mut mem = Memory::default();
    mem.map(0x1000, PAGE_SIZE);
    mem.write(0x1000, &[7; 4]).unwrap();
    mem.map(0x1000, 4 * PAGE_SIZE); // idempotent over the cached page
    assert_eq!(read_vec(&mem, 0x1000, 4).unwrap(), [7; 4]);
    assert_eq!(read_vec(&mem, 0x4000, 4).unwrap(), [0; 4]);
}

#[test]
fn every_access_size_round_trips_in_one_page() {
    let mut mem = Memory::default();
    mem.map(0x8000, PAGE_SIZE);
    for len in [1usize, 2, 3, 4, 8, 16, 32] {
        let data: Vec<u8> = (1..=len as u8).collect();
        let addr = 0x9000 - len as u64; // ends exactly at the page end
        mem.write(addr, &data).unwrap();
        assert_eq!(read_vec(&mem, addr, len).unwrap(), data, "len {len}");
    }
}

#[test]
fn cross_page_accesses_span_both_frames() {
    let mut mem = Memory::default();
    mem.map(0x1000, 2 * PAGE_SIZE);
    let data: Vec<u8> = (1..=16).collect();
    mem.write(0x1ff8, &data).unwrap();
    assert_eq!(read_vec(&mem, 0x1ff8, 16).unwrap(), data);
    assert_eq!(read_vec(&mem, 0x2000, 8).unwrap(), data[8..]);
    assert_eq!(read_vec(&mem, 0x1ff8, 8).unwrap(), data[..8]);
}

#[test]
fn faults_name_the_first_unmapped_byte_after_partial_copies() {
    let mut mem = Memory::default();
    mem.map(0x1000, PAGE_SIZE);
    // Straddling into an unmapped page: the mapped prefix is written.
    assert_eq!(
        mem.write(0x1ffc, &[9; 8]),
        Err(NativeError::Unmapped { address: 0x2000 })
    );
    assert_eq!(read_vec(&mem, 0x1ffc, 4).unwrap(), [9; 4]);
    let mut buf = [0u8; 8];
    assert_eq!(
        mem.read(0x1ffc, &mut buf),
        Err(NativeError::Unmapped { address: 0x2000 })
    );
    assert_eq!(
        buf,
        [9, 9, 9, 9, 0, 0, 0, 0],
        "prefix filled before the fault"
    );
    // Starting in an unmapped page faults at the start address.
    assert_eq!(
        mem.write(0xffc, &[1; 8]),
        Err(NativeError::Unmapped { address: 0xffc })
    );
    assert_eq!(
        read_vec(&mem, 0x1000, 4).unwrap(),
        [0; 4],
        "nothing written"
    );
}

#[test]
fn empty_accesses_succeed_even_when_unmapped() {
    let mut mem = Memory::default();
    assert_eq!(mem.read(0xdead_0000, &mut []), Ok(()));
    assert_eq!(mem.write(0xdead_0000, &[]), Ok(()));
}

#[test]
fn fast_path_stores_into_cached_code_are_recorded() {
    // Block-cache coherence: a TLB hit on an in-page store of every A64
    // access size must still clear the code flag and record the page.
    for len in [1usize, 2, 4, 8, 16] {
        let mut mem = Memory::default();
        mem.map(0x4000, PAGE_SIZE);
        mem.write(0x4100, &[0; 16]).unwrap(); // warm the TLB slot
        assert_eq!(slot(&mem, 0x4000).0, 0x4, "TLB hot");
        mem.mark_code(0x4000);
        assert!(!mem.code_written());
        mem.write(0x4100, &vec![0xab; len]).unwrap();
        assert!(mem.code_written(), "{len}-byte fast-path store recorded");
        assert_eq!(mem.take_code_writes(), [0x4000]);
        assert_eq!(read_vec(&mem, 0x4100, len).unwrap(), vec![0xab; len]);
        // The flag is cleared after the first recorded write.
        mem.write(0x4100, &vec![0xcd; len]).unwrap();
        assert!(!mem.code_written());
    }
}
