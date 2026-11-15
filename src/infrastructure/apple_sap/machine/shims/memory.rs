//! Heap, `mmap` and Mach VM allocation shims.

use super::call::ShimCall;
use super::error::ShimError;
use super::heap::ALLOCATION_QUANTUM;
use super::layout::{PAGE_SIZE, align};

/// Byte offset of the size field in a kernel `kalloc_type_view`.
const TYPE_VIEW_SIZE_OFFSET: u64 = 44;
/// Mask selecting the element size from a type view's size field.
const TYPE_VIEW_SIZE_MASK: u32 = 0x00ff_ffff;
/// Size of an `IOLock`/`IORWLock` placeholder.
const LOCK_SIZE: u64 = 8;
/// Darwin `KERN_SUCCESS`.
pub(super) const KERN_SUCCESS: u64 = 0;
/// Darwin `KERN_INVALID_ADDRESS`.
const KERN_INVALID_ADDRESS: u64 = 1;
/// Darwin `KERN_NO_SPACE`.
const KERN_NO_SPACE: u64 = 3;
/// C `-1` / `MAP_FAILED` as a 64-bit register value.
pub(super) const MINUS_ONE: u64 = u64::MAX;

pub(super) fn malloc(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [size] = call.args()?;
    let address = call.allocate(size)?;

    call.set_result(address)
}

pub(super) fn malloc_aligned(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [size, alignment] = call.args()?;
    if !alignment.is_power_of_two() {
        return Err(ShimError::InvalidAlignment { alignment });
    }
    let address = call.allocate_aligned(size, alignment)?;

    call.set_result(address)
}

pub(super) fn malloc_typed(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [view] = call.args()?;
    let size = call.read_u32(view + TYPE_VIEW_SIZE_OFFSET)? & TYPE_VIEW_SIZE_MASK;
    let address = call.allocate(u64::from(size))?;

    call.set_result(address)
}

pub(super) fn malloc_typed_variable(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let size = call.arg(1)?;
    let address = call.allocate(size)?;

    call.set_result(address)
}

pub(super) fn malloc_lock(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let address = call.allocate(LOCK_SIZE)?;
    call.fill(address, 0, LOCK_SIZE)?;

    call.set_result(address)
}

pub(super) fn malloc_good_size(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [size] = call.args()?;
    let good = align(size.max(1), ALLOCATION_QUANTUM).ok_or(ShimError::SizeOverflow)?;

    call.set_result(good)
}

pub(super) fn malloc_size(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    let reserved = call
        .state()?
        .heap
        .allocation(address)
        .map_or(0, |allocation| allocation.reserved);

    call.set_result(reserved)
}

pub(super) fn calloc(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [count, size] = call.args()?;
    let total = count.checked_mul(size).ok_or(ShimError::SizeOverflow)?;
    let address = call.allocate(total)?;
    call.clear_new(address, total)?;

    call.set_result(address)
}

pub(super) fn realloc(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [old_address, new_size] = call.args()?;
    if old_address == 0 {
        let address = call.allocate(new_size)?;
        return call.set_result(address);
    }
    let old = call
        .state()?
        .heap
        .allocation(old_address)
        .ok_or(ShimError::UnknownPointer {
            operation: "reallocate",
            address: old_address,
        })?;
    if call.state()?.heap.resize_in_place(old_address, new_size) {
        return call.set_result(old_address);
    }

    let new_address = call.allocate(new_size)?;
    if let Err(error) = copy_allocation(call, old_address, new_address, old.size) {
        // The copy failure is reported; the new block is useless either way.
        let _ = call.release(new_address);
        return Err(error);
    }
    call.release(old_address)?;

    call.set_result(new_address)
}

fn copy_allocation(
    call: &mut ShimCall<'_, '_>,
    source: u64,
    destination: u64,
    size: u64,
) -> Result<(), ShimError> {
    let data = call.read_bytes(source, size)?;

    call.write_bytes(destination, &data)
}

pub(super) fn free(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    release_nonnull(call, address)
}

pub(super) fn free_typed(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let address = call.arg(1)?;
    release_nonnull(call, address)
}

fn release_nonnull(call: &mut ShimCall<'_, '_>, address: u64) -> Result<(), ShimError> {
    if address != 0 {
        call.release(address)?;
    }

    call.set_result(0)
}

pub(super) fn mmap(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let length = call.arg(1)?;
    let Ok(address) = call.allocate_aligned(length, PAGE_SIZE) else {
        return call.set_result(MINUS_ONE);
    };
    call.clear_new(address, length)?;

    call.set_result(address)
}

pub(super) fn munmap(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    let result = match call.release(address) {
        Ok(()) => 0,
        Err(_) => MINUS_ONE,
    };

    call.set_result(result)
}

pub(super) fn vm_allocate(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [_, field, size] = call.args()?;
    let Ok(address) = call.allocate_aligned(size, PAGE_SIZE) else {
        return call.set_result(KERN_NO_SPACE);
    };
    call.clear_new(address, size)?;
    if let Err(error) = call.write_u64(field, address) {
        // The output pointer is invalid; the fresh mapping cannot be handed out.
        let _ = call.release(address);
        return Err(error);
    }

    call.set_result(KERN_SUCCESS)
}

pub(super) fn vm_deallocate(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let address = call.arg(1)?;
    let result = match call.release(address) {
        Ok(()) => KERN_SUCCESS,
        Err(_) => KERN_INVALID_ADDRESS,
    };

    call.set_result(result)
}
