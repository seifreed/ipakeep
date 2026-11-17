//! Rejection paths and rarely taken branches of the shim families.

use std::rc::Rc;

use super::super::{FAKE_HANDLE, FairPlayReply, HEAP_BASE, SHIM_AREA_SIZE, ShimConfig};
use super::harness::{DATA, Guest};

/// Size of the guest pages the tests unmap.
const UNMAP_SIZE: u64 = 0x4000;

#[test]
fn corefoundation_handles_null_and_unknown_inputs() {
    let mut guest = Guest::new();
    assert_eq!(
        guest.ok("_CFStringCreateWithCStringNoCopy", &[0, DATA]),
        DATA
    );
    assert_eq!(guest.ok("_CFStringGetCString", &[DATA, 0, 16, 0]), 0);
    assert_eq!(
        guest.ok("_CFStringGetCString", &[DATA, DATA + 0x40, 0, 0]),
        0
    );
    guest.put(DATA + 0x40, b"xx");
    assert_eq!(
        guest.ok("_CFStringGetCString", &[FAKE_HANDLE, DATA + 0x40, 4, 0]),
        1
    );
    assert_eq!(guest.get(DATA + 0x40, 1), [0]);
    guest.put_str(DATA, "count");
    assert_eq!(guest.ok("_objc_msgSend", &[0, DATA]), 0);
    assert_eq!(guest.ok("_CFGetTypeID", &[]), 1);
    assert_eq!(guest.ok("_CFRunLoopRun", &[]), 0);
    assert_eq!(
        guest.ok("_CFMachPortCreateWithPort", &[0, 1, 0x4000, 0, 0]),
        FAKE_HANDLE
    );
    assert_eq!(guest.shims.state().borrow().mach.port_info, 0);
}

#[test]
fn notify_check_writes_the_changed_flag_when_requested() {
    let mut guest = Guest::new();
    guest.put(DATA, &7u32.to_le_bytes());
    assert_eq!(guest.ok("_notify_check", &[0, DATA]), 0);
    assert_eq!(guest.u32_at(DATA), 0);
    assert_eq!(guest.ok("_notify_check", &[0, 0]), 0);
}

#[test]
fn byte_shims_reject_oversized_and_unterminated_inputs() {
    let mut guest = Guest::new();
    guest.put(DATA, b"abc");
    assert_eq!(
        guest.ok("___memcpy_chk", &[DATA + 0x100, DATA, 3, 8]),
        DATA + 0x100
    );
    assert_eq!(guest.get(DATA + 0x100, 3), b"abc");
    assert!(guest.call("___memset_chk", &[DATA, 0, 3, 2]).is_err());
    assert!(
        guest
            .call("_strnlen", &[DATA, (64 << 20) + 1])
            .unwrap_err()
            .to_string()
            .contains("exceeds limit")
    );
    guest.put(DATA, &[b'a'; 5000]);
    assert!(
        guest
            .call("_strlen", &[DATA])
            .unwrap_err()
            .to_string()
            .contains("4096")
    );
}

#[test]
fn file_shims_reject_unknown_descriptors_and_paths() {
    let mut guest = Guest::new();
    assert_eq!(guest.ok("_fstat", &[42, DATA]), u64::MAX);
    assert_eq!(guest.ok("_ftruncate", &[42, 0]), u64::MAX);
    assert_eq!(guest.ok("_read", &[42, DATA, 4]), u64::MAX);
    guest.put_str(DATA, "/etc/hosts");
    assert_eq!(guest.ok("_unlink", &[DATA]), u64::MAX);
}

#[test]
fn iokit_rejects_null_outputs_and_invalid_buffers() {
    let mut guest = Guest::new();
    assert_eq!(guest.ok("_IORegistryEntryGetParentEntry", &[0, 0, DATA]), 0);
    assert_ne!(guest.u32_at(DATA), 0);
    assert!(
        guest
            .call("_IOServiceGetMatchingServices", &[0, 0, 0])
            .is_err()
    );
    assert!(
        guest
            .call(
                "_IOConnectCallStructMethod",
                &[7, 26, DATA, (1 << 20) + 1, 0, 0]
            )
            .is_err()
    );
    let mut empty = DATA.to_le_bytes().to_vec();
    empty.extend_from_slice(&0u64.to_le_bytes());
    guest.put(DATA, &empty);
    assert!(
        guest
            .call("_IOConnectCallStructMethod", &[7, 26, DATA, 16, 0, 0])
            .is_err()
    );
}

#[test]
fn iokit_direct_calls_skip_the_indirect_buffer() {
    let mut guest = Guest::new();
    guest.shims.state().borrow_mut().handlers.fair_play = Some(Rc::new(|request| {
        assert_eq!(request.indirect, [] as [u8; 0]);
        assert_eq!(request.output_size, 0);
        Ok(FairPlayReply::default())
    }));
    guest.put(DATA, &[1; 4]);
    assert_eq!(
        guest.ok(
            "_IOConnectCallStructMethod",
            &[7, 3, DATA, 4, DATA + 0x80, 0]
        ),
        0
    );
}

#[test]
fn kernel_shims_return_null_for_unknown_requests() {
    let mut guest = Guest::new();
    guest.put_str(DATA, "IOOtherService");
    assert_eq!(
        guest.ok(
            "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec",
            &[DATA, 0]
        ),
        0
    );
    let options = "__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm";
    assert_eq!(guest.ok(options, &[0, 0, 0, 0]), 0);

    guest.put_str(DATA, "IOAESAccelerator");
    let service = guest.ok(
        "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec",
        &[DATA, 0],
    );
    let source = guest.ok(options, &[0, 0, 32, 0]);
    let destination = guest.ok(options, &[0, 0, 32, 0]);
    let overflowing = [
        service,
        source,
        destination,
        32,
        DATA + 0x300,
        0,
        DATA + 0x200,
        16,
        0,
    ];
    assert_eq!(guest.ok("$IOAESAccelerator.performAES", &overflowing), 3);
}

#[test]
fn mach_shims_validate_message_sizes() {
    let mut guest = Guest::new();
    assert!(
        guest
            .call("_mach_msg_rpc_from_kernel_proper", &[DATA, 0, 8])
            .is_err()
    );
    guest.shims.state().borrow_mut().handlers.mach_rpc =
        Some(Rc::new(|_: &[u8], _| Ok(Vec::new())));
    assert!(
        guest
            .call("_mach_msg_rpc_from_kernel_proper", &[DATA, 4, 8])
            .is_err()
    );
    assert_eq!(guest.ok("_mach_msg", &[DATA, 1, 0]), 0);
}

#[test]
fn realloc_of_null_allocates() {
    let mut guest = Guest::new();
    let block = guest.ok("_realloc", &[0, 16]);
    assert_eq!(block, HEAP_BASE);
    assert_eq!(guest.ok("_malloc_size", &[block]), 16);
}

/// Allocates a filler block and unmaps the page the next allocation lands on.
fn unmap_next_allocation(guest: &mut Guest) {
    let filler = guest.ok("_malloc", &[UNMAP_SIZE]);
    let next = filler + guest.ok("_malloc_size", &[filler]);
    let page = next - next % UNMAP_SIZE;
    guest.engine.mem_unmap(page, UNMAP_SIZE).expect("unmap");
}

#[test]
fn realloc_reports_copy_failures() {
    let mut guest = Guest::new();
    let block = guest.ok("_malloc", &[16]);
    unmap_next_allocation(&mut guest);
    assert!(guest.call("_realloc", &[block, 0x100]).is_err());
}

#[test]
fn calloc_reports_unwritable_memory() {
    let mut guest = Guest::new();
    unmap_next_allocation(&mut guest);
    assert!(guest.call("_calloc", &[1, 16]).is_err());
}

#[test]
fn vm_allocate_reports_an_unwritable_output_pointer() {
    let mut guest = Guest::new();
    assert!(guest.call("_vm_allocate", &[0, 0x10, 0x1000]).is_err());
}

#[test]
fn system_shims_reject_invalid_arguments() {
    let mut guest = Guest::new();
    assert!(guest.call("_arc4random_uniform", &[1 << 33]).is_err());
    assert_eq!(guest.ok("_proc_pidpath", &[1, 0, 256]), u64::MAX);
    assert_eq!(guest.ok("_sysconf", &[57]), 1);
    assert_eq!(guest.ok("_sysconf", &[58]), 1);
    assert_eq!(guest.ok("_sysconf", &[1]), u64::MAX);
    for (name, value) in [
        ("hw.machine", &b"arm64\0"[..]),
        ("kern.osversion", b"16G29\0"),
    ] {
        guest.put_str(DATA, name);
        guest.put(DATA + 0x40, &64u64.to_le_bytes());
        assert_eq!(
            guest.ok("_sysctlbyname", &[DATA, DATA + 0x80, DATA + 0x40]),
            0
        );
        assert_eq!(guest.get(DATA + 0x80, value.len()), value);
    }
}

#[test]
fn default_host_uses_the_system_clock_and_random_source() {
    let mut guest = Guest::new();
    assert!(guest.ok("_time", &[0]) > 1_600_000_000);
    guest.ok("_read_random", &[DATA, 32]);
    assert_ne!(guest.get(DATA, 32), [0; 32]);
}

#[test]
fn state_allocations_and_data_symbols() {
    let mut guest = Guest::new();
    let state = guest.shims.state();
    assert_eq!(state.borrow_mut().allocate(16).ok(), Some(HEAP_BASE));
    let mut state = state.borrow_mut();
    let first = state
        .table
        .add_data(&mut guest.engine, "test.symbol", &[1; 8])
        .unwrap();
    let again = state
        .table
        .add_data(&mut guest.engine, "test.symbol", &[2; 8])
        .unwrap();
    assert_eq!(first, again);
    let oversized = vec![0; usize::try_from(SHIM_AREA_SIZE).unwrap()];
    assert!(
        state
            .table
            .add_data(&mut guest.engine, "test.huge", &oversized)
            .is_err()
    );
}

#[test]
fn xpc_objects_and_oversized_payloads() {
    let mut guest = Guest::new();
    let connection = guest.ok("_xpc_connection_create_mach_service", &[DATA, 0, 0]);
    let reply = guest.ok("_xpc_dictionary_create_reply", &[connection]);
    assert_ne!(connection, reply);
    assert!(
        guest
            .call("_xpc_dictionary_set_data", &[reply, 0, DATA, (1 << 20) + 1])
            .is_err()
    );
}

#[test]
fn uninstall_removes_the_dispatch_hook() {
    let Guest { mut engine, shims } = Guest::with_config(ShimConfig::default());
    assert!(shims.uninstall(&mut engine).is_ok());
}

#[test]
fn dispatch_rejects_reentry_while_the_state_is_borrowed() {
    let mut guest = Guest::new();
    let address = guest.address("_sysconf");
    let state = guest.shims.state();
    let _held = state.borrow_mut();

    let error = super::super::dispatch(&state, &mut guest.engine, address).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("guest service state is already in use"),
        "{error}"
    );
}

#[test]
fn dispatch_rejects_unregistered_service_addresses() {
    // Address zero lies outside the service area, so no shim is registered there.
    const UNREGISTERED: u64 = 0;
    let mut guest = Guest::new();
    let state = guest.shims.state();

    let error = super::super::dispatch(&state, &mut guest.engine, UNREGISTERED).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("guest entered unknown service address 0x0"),
        "{error}"
    );
}
