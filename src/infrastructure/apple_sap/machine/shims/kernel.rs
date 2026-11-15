//! Kernel-side `IOKit` shims for the `FairPlay` kext: `IOAESAccelerator` lookup,
//! `IOBufferMemoryDescriptor` objects with faked C++ vtables, and the
//! accelerator's `performAES` method.

use crate::infrastructure::apple_sap::emu::Register;

use super::call::{ShimCall, low_word};
use super::error::ShimError;
use super::ioaes::{AES_BLOCK_SIZE, KEY_DATA_SIZE, emulate_ioaes};
use super::layout::MAX_GUEST_TRANSFER;
use super::registry::{return_unchanged, return_zero};
use super::table::Handler;

/// Kernel service resolved to the faked accelerator.
const AES_SERVICE_NAME: &[u8] = b"IOAESAccelerator";
/// Bytes of the faked accelerator vtable.
const AES_VTABLE_SIZE: usize = 0x900;
/// Vtable slot of `retain`.
const AES_RETAIN_SLOT: usize = 0x20;
/// Vtable slots that dispatch to `performAES`.
const AES_PERFORM_SLOTS: [usize; 2] = [0x550, 0x890];
/// Size of the faked accelerator object (vtable pointer and padding).
const AES_SERVICE_SIZE: u64 = 16;
/// Bytes of the faked memory-descriptor vtable.
const BUFFER_VTABLE_SIZE: usize = 0x1000;
/// Descriptor vtable slots of `release`.
const RELEASE_SLOTS: [usize; 1] = [0x28];
/// Descriptor vtable slots of `readBytes`.
const READ_SLOTS: [usize; 1] = [0xc8];
/// Descriptor vtable slots of `writeBytes`.
const WRITE_SLOTS: [usize; 1] = [0xd0];
/// Descriptor vtable slots of `prepare` (memory-descriptor and buffer views).
const PREPARE_SLOTS: [usize; 2] = [0xd8, 0x218];
/// Descriptor vtable slots of `complete`.
const COMPLETE_SLOTS: [usize; 2] = [0xe0, 0x220];
/// Descriptor vtable slots of `getVirtualAddress`/`getBytesNoCopy`.
const ADDRESS_SLOTS: [usize; 2] = [0x148, 0x308];
/// Size of a faked descriptor: vtable, buffer address, capacity.
const DESCRIPTOR_SIZE: u64 = 24;
/// Offset of the buffer address in a faked descriptor.
const DESCRIPTOR_BUFFER_OFFSET: u64 = 8;
/// Offset of the capacity in a faked descriptor.
const DESCRIPTOR_CAPACITY_OFFSET: u64 = 16;
/// Alignment of buffers created by `inTaskWithOptions`.
const BUFFER_ALIGNMENT: u64 = 16;
/// `IOKit` `kIOReturnNoMemory`-style failure the kext treats as an error.
const IO_RETURN_ERROR: u64 = 3;
/// Size of a vtable entry.
const VTABLE_ENTRY_SIZE: usize = 8;

/// `IOService::waitForService`: returns the faked accelerator, else null.
pub(super) fn wait_for_kernel_service(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let name = call.read_c_string(call.arg(0)?)?;
    if name != AES_SERVICE_NAME {
        return call.set_result(0);
    }
    let existing = call.state()?.kernel.aes_service;
    if existing != 0 {
        return call.set_result(existing);
    }
    let vtable = build_vtable(
        call,
        AES_VTABLE_SIZE,
        ("$IOAESAccelerator.unhandled", return_zero),
        &[
            (
                "$IOAESAccelerator.retain",
                return_unchanged,
                &[AES_RETAIN_SLOT],
            ),
            (
                "$IOAESAccelerator.performAES",
                io_aes_perform,
                &AES_PERFORM_SLOTS,
            ),
        ],
    )?;
    let vtable = add_data(call, "kernel.ioaes.vtable", &vtable)?;
    let service = call.allocate(AES_SERVICE_SIZE)?;
    call.write_u64(service, vtable)?;
    call.state()?.kernel.aes_service = service;

    call.set_result(service)
}

/// A named vtable method and the slots it occupies.
type VtableMethod<'a> = (&'a str, Handler, &'a [usize]);

fn build_vtable(
    call: &mut ShimCall<'_, '_>,
    size: usize,
    fallback: (&str, Handler),
    methods: &[VtableMethod<'_>],
) -> Result<Vec<u8>, ShimError> {
    let mut state = call.state()?;
    let fallback = state.table.add_function(fallback.0, fallback.1)?;
    let mut vtable = fallback.to_le_bytes().repeat(size / VTABLE_ENTRY_SIZE);
    for (name, handler, slots) in methods {
        let address = state.table.add_function(name, *handler)?;
        for &slot in *slots {
            vtable[slot..slot + VTABLE_ENTRY_SIZE].copy_from_slice(&address.to_le_bytes());
        }
    }

    Ok(vtable)
}

fn add_data(call: &mut ShimCall<'_, '_>, name: &str, data: &[u8]) -> Result<u64, ShimError> {
    let mut state = call.state()?;

    state.table.add_data(call.engine(), name, data)
}

/// `IOBufferMemoryDescriptor::inTaskWithOptions(task, options, capacity, alignment)`.
pub(super) fn new_kernel_buffer_descriptor(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let capacity = call.arg(2)?;
    if capacity == 0 || capacity > MAX_GUEST_TRANSFER {
        return call.set_result(0);
    }
    let buffer = call.allocate_aligned(capacity, BUFFER_ALIGNMENT)?;
    call.fill(buffer, 0, capacity)?;

    create_kernel_buffer_descriptor(call, buffer, capacity)
}

/// `IOMemoryDescriptor::withAddressRange(address, length, options, task)`.
pub(super) fn new_kernel_buffer_descriptor_at(
    call: &mut ShimCall<'_, '_>,
) -> Result<(), ShimError> {
    let [buffer, capacity] = call.args()?;
    if buffer == 0 || capacity == 0 || capacity > MAX_GUEST_TRANSFER {
        return call.set_result(0);
    }

    create_kernel_buffer_descriptor(call, buffer, capacity)
}

fn create_kernel_buffer_descriptor(
    call: &mut ShimCall<'_, '_>,
    buffer: u64,
    capacity: u64,
) -> Result<(), ShimError> {
    let vtable = buffer_vtable(call)?;
    let descriptor = call.allocate(DESCRIPTOR_SIZE)?;
    call.write_u64(descriptor, vtable)?;
    call.write_u64(descriptor + DESCRIPTOR_BUFFER_OFFSET, buffer)?;
    call.write_u64(descriptor + DESCRIPTOR_CAPACITY_OFFSET, capacity)?;

    call.set_result(descriptor)
}

fn buffer_vtable(call: &mut ShimCall<'_, '_>) -> Result<u64, ShimError> {
    let existing = call.state()?.kernel.buffer_vtable;
    if existing != 0 {
        return Ok(existing);
    }
    let vtable = build_vtable(
        call,
        BUFFER_VTABLE_SIZE,
        (
            "$IOBufferMemoryDescriptor.unhandled",
            unsupported_kernel_buffer_method,
        ),
        &[
            (
                "$IOBufferMemoryDescriptor.prepare",
                kernel_buffer_prepare,
                &PREPARE_SLOTS,
            ),
            (
                "$IOBufferMemoryDescriptor.complete",
                return_zero,
                &COMPLETE_SLOTS,
            ),
            (
                "$IOBufferMemoryDescriptor.getVirtualAddress",
                kernel_buffer_address,
                &ADDRESS_SLOTS,
            ),
            (
                "$IOMemoryDescriptor.readBytes",
                kernel_buffer_read,
                &READ_SLOTS,
            ),
            (
                "$IOMemoryDescriptor.writeBytes",
                kernel_buffer_write,
                &WRITE_SLOTS,
            ),
            (
                "$IOBufferMemoryDescriptor.release",
                return_zero,
                &RELEASE_SLOTS,
            ),
        ],
    )?;
    let address = add_data(call, "kernel.iobuffer.vtable", &vtable)?;
    call.state()?.kernel.buffer_vtable = address;

    Ok(address)
}

fn unsupported_kernel_buffer_method(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let caller = call.engine().reg_read(Register::LR).unwrap_or_default();

    Err(ShimError::Unsupported {
        what: "IOMemoryDescriptor virtual method from",
        value: caller,
    })
}

/// The `(buffer, capacity)` a faked descriptor wraps.
fn descriptor_range(call: &ShimCall<'_, '_>, descriptor: u64) -> Result<(u64, u64), ShimError> {
    let buffer = call.read_u64(descriptor + DESCRIPTOR_BUFFER_OFFSET)?;
    let capacity = call.read_u64(descriptor + DESCRIPTOR_CAPACITY_OFFSET)?;

    Ok((buffer, capacity))
}

fn kernel_buffer_prepare(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let (buffer, capacity) = descriptor_range(call, call.arg(0)?)?;
    let valid = buffer != 0 && capacity != 0 && capacity <= MAX_GUEST_TRANSFER;

    call.set_result(if valid { 0 } else { IO_RETURN_ERROR })
}

fn kernel_buffer_address(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let (buffer, _) = descriptor_range(call, call.arg(0)?)?;

    call.set_result(buffer)
}

fn kernel_buffer_read(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    transfer_kernel_buffer(call, false)
}

fn kernel_buffer_write(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    transfer_kernel_buffer(call, true)
}

/// `readBytes`/`writeBytes(offset, bytes, length)`: returns bytes copied.
fn transfer_kernel_buffer(call: &mut ShimCall<'_, '_>, write: bool) -> Result<(), ShimError> {
    let [descriptor, offset, address, length] = call.args()?;
    let (buffer, capacity) = descriptor_range(call, descriptor)?;
    if offset > capacity || length > capacity - offset || length > MAX_GUEST_TRANSFER {
        return call.set_result(0);
    }
    let (source, destination) = if write {
        (address, buffer + offset)
    } else {
        (buffer + offset, address)
    };
    let data = call.read_bytes(source, length)?;
    call.write_bytes(destination, &data)?;

    call.set_result(length)
}

/// Arguments of `IOAESAccelerator::performAES`.
struct AesRequest {
    source_descriptor: u64,
    destination_descriptor: u64,
    length: u64,
    iv_address: u64,
    operation: u64,
    key_address: u64,
    source_offset: u64,
    destination_offset: u64,
}

fn read_aes_request(call: &ShimCall<'_, '_>) -> Result<AesRequest, ShimError> {
    let [
        _,
        source,
        destination,
        length,
        iv,
        operation,
        key,
        source_offset,
        destination_offset,
    ] = call.args()?;

    Ok(AesRequest {
        source_descriptor: source,
        destination_descriptor: destination,
        length,
        iv_address: iv,
        operation,
        key_address: key,
        source_offset,
        destination_offset,
    })
}

fn io_aes_perform(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let request = read_aes_request(call)?;
    let length = request.length;
    if length == 0 || length > MAX_GUEST_TRANSFER || length % AES_BLOCK_SIZE as u64 != 0 {
        return call.set_result(IO_RETURN_ERROR);
    }
    let (source_base, source_capacity) = descriptor_range(call, request.source_descriptor)?;
    let (destination_base, destination_capacity) =
        descriptor_range(call, request.destination_descriptor)?;
    if !fits(request.source_offset, length, source_capacity)
        || !fits(request.destination_offset, length, destination_capacity)
    {
        return call.set_result(IO_RETURN_ERROR);
    }
    let source = call.read_bytes(source_base + request.source_offset, length)?;
    let iv = call.read_bytes(request.iv_address, AES_BLOCK_SIZE as u64)?;
    let key = call.read_bytes(request.key_address, KEY_DATA_SIZE as u64)?;
    // The accelerator ABI passes the operation in the low word of the register.
    let output = emulate_ioaes(&source, &iv, low_word(request.operation), &key)?;
    call.write_bytes(destination_base + request.destination_offset, &output.data)?;
    call.write_bytes(request.iv_address, &output.next_iv)?;

    call.set_result(0)
}

fn fits(offset: u64, length: u64, capacity: u64) -> bool {
    offset <= capacity && length <= capacity - offset
}
