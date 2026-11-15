//! Heap, VM and `<string.h>` shims.

use super::super::{HEAP_BASE, PAGE_SIZE};
use super::harness::{DATA, Guest};

#[test]
fn malloc_free_and_realloc_track_the_heap() {
    let mut guest = Guest::new();
    let first = guest.ok("_malloc", &[24]);
    assert_eq!(first, HEAP_BASE);
    assert_eq!(guest.ok("_malloc_size", &[first]), 32);
    assert_eq!(guest.ok("_malloc_good_size", &[1]), 16);
    guest.put(first, b"payload!");

    assert_eq!(guest.ok("_realloc", &[first, 30]), first);
    let moved = guest.ok("_realloc", &[first, 100]);
    assert_ne!(moved, first);
    assert_eq!(guest.get(moved, 8), b"payload!");
    assert_eq!(guest.get(first, 8), [0; 8]);

    assert_eq!(guest.ok("_free", &[moved]), 0);
    assert_eq!(guest.ok("_free", &[0]), 0);
    assert!(guest.call("_free", &[moved]).is_err());
}

#[test]
fn calloc_clears_and_rejects_overflow() {
    let mut guest = Guest::new();
    let dirty = guest.ok("_malloc", &[16]);
    guest.put(dirty, &[0xff; 16]);
    guest.ok("_free", &[dirty]);
    let block = guest.ok("_calloc", &[2, 8]);
    assert_eq!(guest.get(block, 16), [0; 16]);
    assert!(guest.call("_calloc", &[u64::MAX, 2]).is_err());
}

#[test]
fn typed_and_aligned_kernel_allocations() {
    let mut guest = Guest::new();
    guest.put(DATA + 44, &0x0100_0030u32.to_le_bytes());
    let typed = guest.ok("_IOMallocTypeImpl", &[DATA]);
    assert_eq!(guest.ok("_malloc_size", &[typed]), 0x30);
    let aligned = guest.ok("_IOMallocAligned", &[10, 0x100]);
    assert_eq!(aligned % 0x100, 0);
    assert!(guest.call("_IOMallocAligned", &[10, 3]).is_err());
    let variable = guest.ok("_IOMallocTypeVarImpl", &[0, 40]);
    assert_eq!(guest.ok("_malloc_size", &[variable]), 48);
    assert_eq!(guest.ok("_IOFreeTypeImpl", &[0, variable]), 0);
    let lock = guest.ok("_IOLockAlloc", &[]);
    assert_eq!(guest.u64_at(lock), 0);
}

#[test]
fn mmap_and_vm_allocate_hand_out_cleared_pages() {
    let mut guest = Guest::new();
    let mapped = guest.ok("_mmap", &[0, 100]);
    assert_eq!(mapped % PAGE_SIZE, 0);
    assert_eq!(guest.ok("_munmap", &[mapped]), 0);
    assert_eq!(guest.ok("_munmap", &[mapped]), u64::MAX);
    assert_eq!(guest.ok("_mmap", &[0, u64::MAX]), u64::MAX);

    assert_eq!(guest.ok("_vm_allocate", &[0, DATA, 0x2000]), 0);
    let region = guest.u64_at(DATA);
    assert_eq!(region % PAGE_SIZE, 0);
    assert_eq!(guest.ok("_vm_deallocate", &[0, region]), 0);
    assert_eq!(guest.ok("_vm_deallocate", &[0, region]), 1);
    assert_eq!(guest.ok("_vm_allocate", &[0, DATA, u64::MAX]), 3);
}

#[test]
fn copies_fills_and_checked_variants() {
    let mut guest = Guest::new();
    guest.put(DATA, b"abcdef");
    assert_eq!(guest.ok("_memcpy", &[DATA + 0x100, DATA, 6]), DATA + 0x100);
    assert_eq!(guest.get(DATA + 0x100, 6), b"abcdef");
    guest.ok("_memset", &[DATA + 0x100, 0x1_7a, 3]);
    assert_eq!(guest.get(DATA + 0x100, 6), b"zzzdef");
    guest.ok("___bzero", &[DATA + 0x100, 2]);
    assert_eq!(guest.get(DATA + 0x100, 3), b"\0\0z");
    assert!(
        guest
            .call("___memcpy_chk", &[DATA + 0x100, DATA, 6, 5])
            .is_err()
    );
    guest.ok("___memset_chk", &[DATA + 0x100, 0x41, 2, 2]);
    assert_eq!(guest.get(DATA + 0x100, 2), b"AA");
    assert!(
        guest
            .call("_memmove", &[DATA, DATA, (64 << 20) + 1])
            .is_err()
    );
}

#[test]
fn comparisons_and_lengths_follow_libc() {
    let mut guest = Guest::new();
    guest.put_str(DATA, "apple");
    guest.put_str(DATA + 0x40, "apply");
    assert_eq!(guest.ok("_memcmp", &[DATA, DATA + 0x40, 4]), 0);
    assert_eq!(guest.ok("_memcmp", &[DATA, DATA + 0x40, 5]) as i64, -1);
    assert_eq!(guest.ok("_strcmp", &[DATA + 0x40, DATA]) as i64, 1);
    assert_eq!(guest.ok("_strncmp", &[DATA, DATA + 0x40, 4]), 0);
    assert_eq!(guest.ok("_strncmp", &[DATA, DATA + 0x40, 9]) as i64, -20);
    assert_eq!(guest.ok("_strncmp", &[DATA, DATA, 100]), 0);
    assert_eq!(guest.ok("_strlen", &[DATA]), 5);
    assert_eq!(guest.ok("_strnlen", &[DATA, 3]), 3);
    assert_eq!(guest.ok("_strnlen", &[DATA, 64]), 5);
}

#[test]
fn strnlen_crosses_pages() {
    let mut guest = Guest::new();
    let start = DATA + PAGE_SIZE - 2;
    guest.put(start, b"xyzw\0");
    assert_eq!(guest.ok("_strnlen", &[start, 100]), 4);
    assert_eq!(guest.ok("_strlen", &[start]), 4);
}
