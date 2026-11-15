//! First-fit guest heap bookkeeping (no guest memory access).

use std::collections::HashMap;

use super::error::ShimError;
use super::layout::{HEAP_BASE, HEAP_SIZE, MAX_GUEST_TRANSFER, align};

/// Granularity of ordinary allocations, matching Darwin's `malloc` quantum.
pub(super) const ALLOCATION_QUANTUM: u64 = 16;

/// A live allocation: the size the guest asked for and the bytes reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Allocation {
    pub(super) size: u64,
    pub(super) reserved: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreeBlock {
    address: u64,
    size: u64,
}

/// Bump allocator with a coalescing free list over `[HEAP_BASE, HEAP_BASE + HEAP_SIZE)`.
#[derive(Debug, Default)]
pub(super) struct Heap {
    cursor: u64,
    allocations: HashMap<u64, Allocation>,
    free_blocks: Vec<FreeBlock>,
}

impl Heap {
    /// Reserves `size` bytes with 16-byte granularity, reusing freed blocks first.
    pub(super) fn allocate(&mut self, size: u64) -> Result<u64, ShimError> {
        if size > MAX_GUEST_TRANSFER {
            return Err(ShimError::AllocationTooLarge { size });
        }
        let reserved = align(size.max(1), ALLOCATION_QUANTUM).ok_or(ShimError::SizeOverflow)?;
        let address = match self.take_free_block(reserved) {
            Some(address) => address,
            None => self.bump(self.cursor, reserved)?,
        };
        self.allocations
            .insert(address, Allocation { size, reserved });

        Ok(address)
    }

    /// Reserves `size` bytes at the next `alignment` boundary of the bump area.
    pub(super) fn allocate_aligned(&mut self, size: u64, alignment: u64) -> Result<u64, ShimError> {
        if size > MAX_GUEST_TRANSFER {
            return Err(ShimError::AllocationTooLarge { size });
        }
        let reserved = align(size.max(1), alignment).ok_or(ShimError::SizeOverflow)?;
        let start = align(self.cursor, alignment).ok_or(ShimError::HeapExhausted)?;
        let address = self.bump(start, reserved)?;
        self.allocations
            .insert(address, Allocation { size, reserved });

        Ok(address)
    }

    /// Returns the live allocation starting at `address`.
    pub(super) fn allocation(&self, address: u64) -> Option<Allocation> {
        self.allocations.get(&address).copied()
    }

    /// Records a new requested size for an allocation that still fits in place.
    pub(super) fn resize_in_place(&mut self, address: u64, size: u64) -> bool {
        match self.allocations.get_mut(&address) {
            Some(allocation) if size <= allocation.reserved => {
                allocation.size = size;
                true
            }
            _ => false,
        }
    }

    /// Returns the allocation's block to the free list.
    pub(super) fn release(&mut self, address: u64) -> Result<Allocation, ShimError> {
        let allocation = self
            .allocations
            .remove(&address)
            .ok_or(ShimError::UnknownPointer {
                operation: "free",
                address,
            })?;
        self.free_blocks.push(FreeBlock {
            address,
            size: allocation.reserved,
        });
        self.coalesce();

        Ok(allocation)
    }

    fn bump(&mut self, start: u64, reserved: u64) -> Result<u64, ShimError> {
        if start > HEAP_SIZE || reserved > HEAP_SIZE - start {
            return Err(ShimError::HeapExhausted);
        }
        self.cursor = start + reserved;

        Ok(HEAP_BASE + start)
    }

    fn take_free_block(&mut self, reserved: u64) -> Option<u64> {
        let index = self
            .free_blocks
            .iter()
            .position(|block| block.size >= reserved)?;
        let block = &mut self.free_blocks[index];
        let address = block.address;
        if block.size == reserved {
            self.free_blocks.remove(index);
        } else {
            block.address += reserved;
            block.size -= reserved;
        }

        Some(address)
    }

    fn coalesce(&mut self) {
        self.free_blocks.sort_by_key(|block| block.address);
        let mut merged: Vec<FreeBlock> = Vec::with_capacity(self.free_blocks.len());
        for block in self.free_blocks.drain(..) {
            match merged.last_mut() {
                Some(last) if last.address + last.size == block.address => last.size += block.size,
                _ => merged.push(block),
            }
        }
        self.free_blocks = merged;

        while let Some(last) = self.free_blocks.last() {
            if last.address + last.size != HEAP_BASE + self.cursor {
                break;
            }
            self.cursor -= last.size;
            self.free_blocks.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_quantum_aligned_and_reuse_freed_blocks() {
        let mut heap = Heap::default();
        let first = heap.allocate(1).expect("first");
        let second = heap.allocate(17).expect("second");
        let third = heap.allocate(0).expect("third");
        assert_eq!(first, HEAP_BASE);
        assert_eq!(second, HEAP_BASE + 16);
        assert_eq!(third, HEAP_BASE + 48);
        assert_eq!(
            heap.allocation(second),
            Some(Allocation {
                size: 17,
                reserved: 32
            })
        );

        heap.release(second).expect("release");
        assert_eq!(heap.allocate(8).expect("reuse"), second);
        assert_eq!(heap.allocate(8).expect("split"), second + 16);
    }

    #[test]
    fn releasing_the_tail_rewinds_the_cursor() {
        let mut heap = Heap::default();
        let first = heap.allocate(32).expect("first");
        let second = heap.allocate(32).expect("second");
        heap.release(first).expect("first");
        heap.release(second).expect("second");
        assert_eq!(heap.free_blocks, [] as [FreeBlock; 0]);
        assert_eq!(heap.cursor, 0);
        assert_eq!(heap.allocate(64).expect("again"), HEAP_BASE);
    }

    #[test]
    fn aligned_allocations_start_on_the_boundary() {
        let mut heap = Heap::default();
        heap.allocate(16).expect("small");
        let page = heap.allocate_aligned(10, PAGE).expect("page");
        assert_eq!(page, HEAP_BASE + PAGE);
        assert_eq!(heap.allocation(page).map(|a| a.reserved), Some(PAGE));
    }

    #[test]
    fn rejects_oversized_unknown_and_exhausting_requests() {
        let mut heap = Heap::default();
        assert!(matches!(
            heap.allocate(MAX_GUEST_TRANSFER + 1),
            Err(ShimError::AllocationTooLarge { .. })
        ));
        assert!(matches!(
            heap.release(HEAP_BASE),
            Err(ShimError::UnknownPointer { .. })
        ));
        heap.allocate(MAX_GUEST_TRANSFER).expect("whole heap");
        assert!(matches!(heap.allocate(1), Err(ShimError::HeapExhausted)));
    }

    #[test]
    fn resize_in_place_only_within_reservation() {
        let mut heap = Heap::default();
        let address = heap.allocate(20).expect("allocate");
        assert!(heap.resize_in_place(address, 32));
        assert!(!heap.resize_in_place(address, 33));
        assert_eq!(heap.allocation(address).map(|a| a.size), Some(32));
    }

    const PAGE: u64 = super::super::layout::PAGE_SIZE;
}
