//! The ordered catalogue of emulated imports and data symbols.
//!
//! Registration order fixes slot addresses, so it follows upstream exactly:
//! memory services, platform services, profile aliases, then data symbols.

use crate::infrastructure::apple_sap::emu::Engine;

use super::call::ShimCall;
use super::callback::{CALLBACK_COMPLETE_SYMBOL, callback_complete, dispatch_once, pthread_once};
use super::error::ShimError;
use super::layout::FAKE_HANDLE;
use super::memory::MINUS_ONE;
use super::state::ShimState;
use super::table::Handler;
use super::xpc::XPC_DICTIONARY_TYPE_SYMBOL;
use super::{bytes, corefoundation as cf, files, iokit, kernel, mach, memory, system, xpc};

/// Names sharing one handler.
type Service = (&'static [&'static str], Handler);

pub(super) fn return_zero(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(0)
}

fn return_one(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(1)
}

fn return_two(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(2)
}

fn return_three(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(3)
}

/// Leaves `X0` untouched (identity functions such as `___chkstk_darwin`).
pub(super) fn return_unchanged(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [value] = call.args()?;
    call.set_result(value)
}

fn return_fake_handle(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(FAKE_HANDLE)
}

fn return_minus_one(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(MINUS_ONE)
}

const MEMORY_SERVICES: &[Service] = &[
    (&["_malloc", "_IOMalloc", "_IOMallocData"], memory::malloc),
    (&["_IOMallocAligned"], memory::malloc_aligned),
    (&["_IOMallocTypeImpl"], memory::malloc_typed),
    (
        &["_IOMallocTypeVarImpl", "_OSObject_typed_operator_new"],
        memory::malloc_typed_variable,
    ),
    (&["_IOLockAlloc", "_IORWLockAlloc"], memory::malloc_lock),
    (&["_malloc_good_size"], memory::malloc_good_size),
    (&["_malloc_size"], memory::malloc_size),
    (&["_calloc"], memory::calloc),
    (&["_realloc", "_reallocf"], memory::realloc),
    (
        &[
            "_free",
            "_IOFree",
            "_IOFreeAligned",
            "_IOFreeData",
            "_IOLockFree",
            "_IORWLockFree",
            "_OSObject_typed_operator_delete",
        ],
        memory::free,
    ),
    (
        &["_IOFreeTypeImpl", "_IOFreeTypeVarImpl"],
        memory::free_typed,
    ),
    (&["_mmap"], memory::mmap),
    (&["_munmap"], memory::munmap),
    (&["_vm_allocate"], memory::vm_allocate),
    (&["_vm_deallocate"], memory::vm_deallocate),
    (&["_memcpy", "_memmove"], bytes::memmove),
    (&["_memset"], bytes::memset),
    (&["___bzero"], bytes::bzero),
    (&["___memcpy_chk"], bytes::checked_memcpy),
    (&["___memset_chk"], bytes::checked_memset),
    (&["_memcmp"], bytes::memcmp),
    (&["_strcmp"], bytes::strcmp),
    (&["_strncmp"], bytes::strncmp),
    (&["_strlen"], bytes::strlen),
    (&["_strnlen"], bytes::strnlen),
];

const ZERO_RETURNING: &[&str] = &[
    "_CFBundleGetMainBundle",
    "_CFDataGetBytePtr",
    "_CFDataGetLength",
    "_CFStringGetLength",
    "_CFStringGetMaximumSizeForEncoding",
    "_CFUUIDCreateString",
    "_IORegistryEntryFromPath",
    "_IORegistryEntrySearchCFProperty",
    "_getenv",
    "_pthread_self",
];

const HANDLE_RETURNING: &[&str] = &[
    "_CFDictionaryGetValue",
    "_CFFileDescriptorCreate",
    "_CFFileDescriptorCreateRunLoopSource",
    "_CFMachPortCreateRunLoopSource",
    "_CFRunLoopGetCurrent",
    "_CFRunLoopGetMain",
    "_CFURLCreateFromFileSystemRepresentation",
    "_DADiskCopyDescription",
    "_DADiskCreateFromBSDName",
    "_DASessionCreate",
    "_IORegistryEntryCreateCFProperty",
    "_dispatch_get_global_queue",
    "_dispatch_queue_create",
    "_dispatch_queue_create_with_target",
    "_os_transaction_create",
    "_xpc_connection_create",
];

const NO_OPS: &[&str] = &[
    "_CFRelease",
    "_CFFileDescriptorEnableCallBacks",
    "_CFFileDescriptorInvalidate",
    "_CFFileSecuritySetMode",
    "_CFRunLoopAddSource",
    "_CFURLCopyResourcePropertyForKey",
    "_CFURLSetResourcePropertyForKey",
    "_CSBackupIsItemExcluded",
    "_CSBackupSetItemExcluded",
    "_IOObjectRelease",
    "_IOLockLock",
    "_IOLockUnlock",
    "_IOLockWakeup",
    "_IORWLockRead",
    "_IORWLockWrite",
    "_IORWLockUnlock",
    "_lck_mtx_lock",
    "_lck_mtx_unlock",
    "_lck_rw_lock_exclusive",
    "_lck_rw_unlock_exclusive",
    "_chmod",
    "_close",
    "_close$UNIX2003",
    "_fchmod",
    "_fcntl",
    "_fcntl$UNIX2003",
    "_kevent",
    "_lockf",
    "_mkdir",
    "_pthread_mutex_lock",
    "_pthread_mutex_unlock",
    "_pthread_rwlock_init",
    "_pthread_rwlock_init$UNIX2003",
    "_pthread_rwlock_destroy",
    "_pthread_rwlock_rdlock",
    "_pthread_rwlock_unlock",
    "_pthread_rwlock_unlock$UNIX2003",
    "_pthread_rwlock_wrlock",
    "_pthread_rwlock_wrlock$UNIX2003",
    "_pthread_set_qos_class_self_np",
    "_CFRunLoopStop",
    "_getpid",
    "_getuid",
    "_notify_post",
    "_ptrace",
    "_sched_yield",
    "_signal",
    "_umask",
    "_os_release",
    "_xpc_connection_activate",
    "_xpc_connection_cancel",
    "_xpc_connection_resume",
    "_xpc_connection_set_target_queue",
    "_xpc_dictionary_set_bool",
    "_xpc_dictionary_set_int64",
    "_xpc_dictionary_set_string",
    "_xpc_dictionary_set_uint64",
    "_xpc_dictionary_set_value",
    "_xpc_release",
    "_xpc_retain",
    "_xpc_transaction_begin",
    "_xpc_transaction_end",
];

const PLATFORM_SERVICES: &[Service] = &[
    (ZERO_RETURNING, return_zero),
    (HANDLE_RETURNING, return_fake_handle),
    (NO_OPS, return_zero),
    (&["_IOLog", "_IOLogv"], return_zero),
    (&["_notify_register_check"], cf::notify_register_check),
    (&["_notify_check"], cf::notify_check),
    (&["_notify_get_state"], cf::notify_get_state),
    (&["_notify_cancel"], return_zero),
    (&["_atexit"], return_zero),
    (&["_CFRunLoopRun"], cf::cf_run_loop_run),
    (
        &["_CFMachPortCreateWithPort"],
        cf::cf_mach_port_create_with_port,
    ),
    (&["_CFMachPortGetPort"], return_one),
    (
        &[
            "_SecTaskCreateWithAuditToken",
            "_SecTaskCopyValueForEntitlement",
        ],
        return_fake_handle,
    ),
    (&["_CFStringCreateWithCString"], cf::cf_string_create),
    (
        &["_CFStringCreateWithCStringNoCopy"],
        cf::cf_string_create_no_copy,
    ),
    (&["_CFStringGetCString"], cf::cf_string_get_c_string),
    (&["_CFGetTypeID", "_CFNumberGetTypeID"], return_one),
    (&["_CFStringGetTypeID"], return_two),
    (&["_CFDictionaryGetTypeID"], return_three),
    (&["_CFNumberGetValue"], cf::cf_number_get_value),
    (&["___chkstk_darwin", "____chkstk_darwin"], return_unchanged),
    (
        &["__ZN9IOService15serviceMatchingEPKcP12OSDictionary"],
        return_unchanged,
    ),
    (
        &["__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec"],
        kernel::wait_for_kernel_service,
    ),
    (
        &["__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm"],
        kernel::new_kernel_buffer_descriptor,
    ),
    (
        &["__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task"],
        kernel::new_kernel_buffer_descriptor_at,
    ),
    (&["_IOIteratorNext"], iokit::io_iterator_next),
    (
        &["_IOConnectCallStructMethod"],
        iokit::io_connect_call_struct_method,
    ),
    (
        &["_IORegistryEntryGetParentEntry"],
        iokit::io_registry_entry_get_parent_entry,
    ),
    (
        &["_IOServiceGetMatchingServices"],
        iokit::io_service_get_matching_services,
    ),
    (&["_IOServiceGetMatchingService"], return_one),
    (&["_IOServiceMatching"], return_fake_handle),
    (&["_IOMainPort"], iokit::io_main_port),
    (&["_IOServiceOpen"], iokit::io_service_open),
    (
        &["_OSAtomicCompareAndSwap32Barrier"],
        system::compare_and_swap_32,
    ),
    (&["___error"], system::error_pointer),
    (
        &["_abort", "___stack_chk_fail", "dyld_stub_binder"],
        system::abort,
    ),
    (&["_arc4random"], system::arc4random),
    (&["_random"], system::random),
    (&["_arc4random_uniform"], system::arc4random_uniform),
    (
        &["_read_random", "_kernel_read_random"],
        system::read_random,
    ),
    (&["_audit_token_to_au32"], system::audit_token_to_au32),
    (&["_audit_token_to_euid"], return_zero),
    (&["_basename"], system::basename),
    (&["_bootstrap_look_up"], mach::bootstrap_look_up),
    (&["_bootstrap_check_in"], mach::bootstrap_check_in),
    (
        &["_mach_msg_rpc_from_kernel_proper"],
        mach::mach_msg_rpc_from_kernel,
    ),
    (&["_mach_msg", "_mach_msg2_internal"], mach::mach_msg),
    (
        &[
            "_mach_msg_destroy",
            "_mach_msg_destroy_from_kernel_proper",
            "_mach_port_deallocate",
            "_mig_dealloc_reply_port",
            "_mig_deallocate",
            "_mig_put_reply_port",
        ],
        return_zero,
    ),
    (&["_mig_get_reply_port"], return_one),
    (&["_dispatch_once"], dispatch_once),
    (&["_dlopen"], cf::dlopen),
    (&["_dlsym"], cf::dlsym),
    (&["_statfs", "_statfs$INODE64"], return_minus_one),
    (&["_fstat"], files::fstat),
    (&["_ftruncate"], files::ftruncate),
    (&["_gettimeofday"], system::gettimeofday),
    (
        &["_clock_get_calendar_microtime"],
        system::clock_get_calendar_microtime,
    ),
    (&["_time"], system::time),
    (&["_gethostuuid"], system::gethostuuid),
    (&["_objc_msgSend"], cf::objc_msg_send),
    (&["_open", "_open$UNIX2003"], files::open),
    (
        &["_lstat", "_lstat$INODE64", "_stat", "_stat$INODE64"],
        files::lstat,
    ),
    (&["_pthread_once"], pthread_once),
    (&["_proc_pidpath"], system::proc_pid_path),
    (&["_read", "_read$UNIX2003"], files::read),
    (&["_write"], files::write),
    (&["_unlink"], files::unlink),
    (&["_sysctl"], return_minus_one),
    (&["_sysctlbyname"], system::sysctlbyname),
    (&["_sysconf"], system::sysconf),
    (&["_xpc_dictionary_get_data"], xpc::dictionary_get_data),
    (&["_xpc_dictionary_set_data"], xpc::dictionary_set_data),
    (
        &["_xpc_connection_create_mach_service"],
        xpc::connection_create_mach_service,
    ),
    (
        &["_xpc_connection_send_message_with_reply_sync"],
        xpc::connection_send_message_with_reply_sync,
    ),
    (
        &["_xpc_connection_set_event_handler"],
        xpc::connection_set_event_handler,
    ),
    (
        &["_xpc_dictionary_create_empty"],
        xpc::dictionary_create_empty,
    ),
    (
        &["_xpc_dictionary_create_reply"],
        xpc::dictionary_create_reply,
    ),
    (
        &["_xpc_dictionary_get_audit_token"],
        xpc::dictionary_get_audit_token,
    ),
    (&["_xpc_dictionary_send_reply"], xpc::dictionary_send_reply),
    (&["_xpc_get_type"], xpc::get_type),
    (&["_kqueue"], mach::kqueue),
    (&["_os_log_type_enabled"], return_one),
    (&["_os_log_impl", "__os_log_impl"], return_zero),
];

/// Symbol of the `errno` cell `___error` returns.
const ERRNO_SYMBOL: &str = "guest.errno";
/// Fixed stack-protector canary.
const STACK_GUARD: [u8; 8] = [0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10];
/// Data symbols initialised to zero.
const ZERO_DATA: &[&str] = &[
    "_NDR_record",
    "_kCFAllocatorDefault",
    "_kCFAllocatorNull",
    "_kDADiskDescriptionVolumeUUIDKey",
    "_kIOMasterPortDefault",
];
/// Faked XPC dictionary type tag.
const XPC_DICTIONARY_TYPE: u64 = 0xffff_1000_0000_0001;
/// Data symbols holding a fixed pointer-sized value.
const VALUE_DATA: &[(&str, u64)] = &[
    ("_kCFBooleanFalse", FAKE_HANDLE),
    ("_kCFBooleanTrue", FAKE_HANDLE),
    (XPC_DICTIONARY_TYPE_SYMBOL, XPC_DICTIONARY_TYPE),
    ("__xpc_type_error", XPC_DICTIONARY_TYPE + 1),
    ("__xpc_error_connection_invalid", XPC_DICTIONARY_TYPE + 2),
];

fn register_services(state: &mut ShimState, services: &[Service]) -> Result<(), ShimError> {
    for (names, handler) in services {
        for name in *names {
            state.table.add_function(name, *handler)?;
        }
    }

    Ok(())
}

fn register_data(state: &mut ShimState, engine: &mut Engine<'_>) -> Result<(), ShimError> {
    state.errno = state.table.add_data(engine, ERRNO_SYMBOL, &[0; 8])?;
    state
        .table
        .add_data(engine, "___stack_chk_guard", &STACK_GUARD)?;
    for name in ZERO_DATA {
        state.table.add_data(engine, name, &[0; 8])?;
    }
    for (name, value) in VALUE_DATA {
        state.table.add_data(engine, name, &value.to_le_bytes())?;
    }

    Ok(())
}

/// Registers every emulated import, the profile's zero-returning aliases and
/// the data symbols, in upstream order.
pub(super) fn register_all(
    state: &mut ShimState,
    engine: &mut Engine<'_>,
    zero_return_aliases: &[String],
) -> Result<(), ShimError> {
    register_services(state, MEMORY_SERVICES)?;
    register_services(state, PLATFORM_SERVICES)?;
    register_data(state, engine)?;
    state
        .table
        .add_function(CALLBACK_COMPLETE_SYMBOL, callback_complete)?;
    for alias in zero_return_aliases {
        state.table.add_function(alias, return_zero)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn no_import_is_registered_twice() {
        let mut seen = HashSet::new();
        for (names, _) in MEMORY_SERVICES.iter().chain(PLATFORM_SERVICES) {
            for name in *names {
                assert!(seen.insert(*name), "duplicate shim {name}");
            }
        }
        assert!(seen.len() > 200);
    }
}
