//! Platform shim families: system, files, `XPC`, Mach, `IOKit`, kernel, callbacks.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::infrastructure::apple_sap::emu::EmuError;

use super::super::{
    ADI_STATE_PATH, FAKE_HANDLE, FairPlayReply, FairPlayRequest, HostEnvironment, SHIM_BASE,
    ShimConfig,
};
use super::harness::{DATA, Guest, HELPER, assemble};

/// Fixed clock and a counting byte stream.
struct FixedHost {
    next: Cell<u8>,
}

impl HostEnvironment for FixedHost {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789)
    }

    fn fill_random(&self, buffer: &mut [u8]) {
        for byte in buffer {
            *byte = self.next.get();
            self.next.set(self.next.get().wrapping_add(1));
        }
    }
}

fn fixed_guest() -> Guest {
    Guest::with_config(ShimConfig {
        host: Rc::new(FixedHost {
            next: Cell::new(0xfc),
        }),
        ..ShimConfig::default()
    })
}

#[test]
fn unsupported_imports_fault_with_their_name() {
    let mut guest = Guest::new();
    let error = guest.call("_does_not_exist", &[]).expect_err("fault");
    assert_eq!(
        error.to_string(),
        "_does_not_exist: guest called unsupported import _does_not_exist"
    );
    assert!(
        guest
            .call("_abort", &[])
            .expect_err("abort")
            .to_string()
            .contains("guest aborted")
    );
}

#[test]
fn constant_and_profile_shims() {
    let mut guest = Guest::with_config(ShimConfig {
        zero_return_aliases: vec!["_pthread_mutex_init".into()],
        ..ShimConfig::default()
    });
    assert_eq!(guest.ok("_CFRunLoopGetMain", &[]), FAKE_HANDLE);
    assert_eq!(guest.ok("_CFStringGetTypeID", &[]), 2);
    assert_eq!(guest.ok("_CFDictionaryGetTypeID", &[]), 3);
    assert_eq!(guest.ok("___chkstk_darwin", &[0x1234]), 0x1234);
    assert_eq!(guest.ok("_pthread_mutex_init", &[9]), 0);
    assert_eq!(guest.ok("_statfs", &[]), u64::MAX);
    assert_eq!(guest.ok("_kqueue", &[]), 6);
    let errno = guest.ok("___error", &[]);
    assert!(errno >= SHIM_BASE);
    let guard = guest.address("___stack_chk_guard");
    assert_eq!(guest.u64_at(guard), 0x10ef_4286_d93c_71a5);
}

#[test]
fn time_and_randomness_come_from_the_host() {
    let mut guest = fixed_guest();
    assert_eq!(guest.ok("_time", &[DATA]), 1_700_000_000);
    assert_eq!(guest.u64_at(DATA), 1_700_000_000);
    guest.ok("_gettimeofday", &[DATA, DATA + 0x20]);
    assert_eq!(guest.u64_at(DATA), 1_700_000_000);
    assert_eq!(guest.u32_at(DATA + 8), 123_456);
    guest.ok("_clock_get_calendar_microtime", &[DATA, DATA + 4]);
    assert_eq!(guest.u32_at(DATA + 4), 123_456);

    assert_eq!(guest.ok("_arc4random", &[]), 0xfffe_fdfc);
    assert_eq!(guest.ok("_random", &[]), 0x0302_0100);
    assert_eq!(guest.ok("_arc4random_uniform", &[10]), 0x0706_0504 % 10);
    assert_eq!(guest.ok("_arc4random_uniform", &[1]), 0);
    guest.ok("_read_random", &[DATA, 3]);
    assert_eq!(guest.get(DATA, 3), [8, 9, 10]);
}

#[test]
fn sysctl_sysconf_and_identity_are_pinned() {
    let mut guest = Guest::new();
    guest.put_str(DATA, "hw.model");
    guest.put(DATA + 0x40, &64u64.to_le_bytes());
    assert_eq!(
        guest.ok("_sysctlbyname", &[DATA, DATA + 0x80, DATA + 0x40]),
        0
    );
    assert_eq!(guest.get(DATA + 0x80, 15), b"MacBookPro13,3\0");
    assert_eq!(guest.u64_at(DATA + 0x40), 15);
    guest.put(DATA + 0x40, &2u64.to_le_bytes());
    assert_eq!(
        guest.ok("_sysctlbyname", &[DATA, DATA + 0x80, DATA + 0x40]),
        u64::MAX
    );
    guest.put_str(DATA, "hw.unknown");
    assert_eq!(guest.ok("_sysctlbyname", &[DATA, 0, 0]), u64::MAX);
    assert_eq!(guest.ok("_sysconf", &[29]), 0x1000);
    assert_eq!(guest.ok("_sysconf", &[200]), 0x4000);

    assert!(guest.call("_gethostuuid", &[DATA]).is_err());
    guest.shims.state().borrow_mut().host_uuid = [7; 16];
    guest.ok("_gethostuuid", &[DATA]);
    assert_eq!(guest.get(DATA, 16), [7; 16]);

    assert_eq!(guest.ok("_proc_pidpath", &[1, DATA, 256]), 85);
    guest.put_str(DATA, "/a/b/name//");
    assert_eq!(guest.ok("_basename", &[DATA]), DATA + 5);
    guest.ok(
        "_audit_token_to_au32",
        &[0, 0, 0, 0, 0, 0, DATA + 0x100, 0, 0],
    );
    assert_eq!(guest.u32_at(DATA + 0x100), 123);
}

#[test]
fn stack_arguments_reach_shims() {
    let mut guest = Guest::new();
    guest.ok(
        "_audit_token_to_au32",
        &[0, 0, 0, 0, 0, 0, 0, DATA + 0x100, DATA + 0x200],
    );
    assert_eq!(guest.u32_at(DATA + 0x100), 100_000);
    assert_eq!(guest.u32_at(DATA + 0x200), 1);
}

#[test]
fn adi_state_file_round_trips() {
    let mut guest = Guest::new();
    guest.put_str(DATA, ADI_STATE_PATH);
    assert_eq!(guest.ok("_lstat", &[DATA, DATA + 0x100]), u64::MAX);
    assert_eq!(guest.ok("_open", &[DATA, 0]), u64::MAX);
    assert_eq!(guest.ok("_open", &[DATA, 0x200]), 5);
    guest.put(DATA + 0x80, b"state-bytes");
    assert_eq!(guest.ok("_write", &[5, DATA + 0x80, 11]), 11);
    assert_eq!(guest.ok("_fstat", &[5, DATA + 0x100]), 0);
    assert_eq!(guest.u64_at(DATA + 0x100 + 96), 11);
    assert_eq!(guest.ok("_ftruncate", &[5, 5]), 0);
    assert_eq!(guest.ok("_lstat", &[DATA, DATA + 0x100]), 0);
    assert_eq!(guest.get(DATA + 0x104, 2), [0x80, 0x81]);

    assert_eq!(guest.ok("_open", &[DATA, 0]), 5);
    assert_eq!(guest.ok("_read", &[5, DATA + 0x200, 64]), 5);
    assert_eq!(guest.get(DATA + 0x200, 5), b"state");
    assert_eq!(guest.ok("_read", &[5, DATA + 0x200, 64]), 0);
    let stored = guest
        .shims
        .state()
        .borrow()
        .files
        .adi
        .get(ADI_STATE_PATH)
        .cloned();
    assert_eq!(stored.as_deref(), Some(&b"state"[..]));
    assert_eq!(guest.ok("_unlink", &[DATA]), 0);
    assert!(guest.shims.state().borrow().files.adi.is_empty());
}

#[test]
fn icxs_and_directories_are_virtual() {
    let mut guest = Guest::with_config(ShimConfig {
        icxs: b"ICXS-blob".to_vec(),
        ..ShimConfig::default()
    });
    guest.put_str(DATA, "./../CoreFP.icxs");
    assert_eq!(guest.ok("_open", &[DATA, 0]), 3);
    assert_eq!(guest.ok("_read", &[3, DATA + 0x100, 4]), 4);
    assert_eq!(guest.ok("_read", &[3, DATA + 0x104, 64]), 5);
    assert_eq!(guest.get(DATA + 0x100, 9), b"ICXS-blob");
    assert_eq!(guest.ok("_write", &[3, DATA, 1]), u64::MAX);
    guest.put_str(DATA, "/var/db");
    assert_eq!(guest.ok("_open", &[DATA, 0]), 4);
    assert_eq!(guest.ok("_lstat", &[DATA, DATA + 0x100]), 0);
    assert_eq!(guest.get(DATA + 0x104, 2), [0xed, 0x41]);
    guest.put_str(DATA, "/etc/passwd");
    assert_eq!(guest.ok("_open", &[DATA, 0x200]), u64::MAX);
}

#[test]
fn corefoundation_and_dlfcn() {
    let mut guest = Guest::with_config(ShimConfig {
        core_exports: [("_cp2g1b9ro".to_owned(), 0xabc0)].into(),
        ..ShimConfig::default()
    });
    guest.put_str(DATA, "IOPlatformUUID");
    assert_eq!(
        guest.ok("_CFStringCreateWithCString", &[0, DATA, 0]),
        FAKE_HANDLE
    );
    guest.put_str(DATA + 0x40, "other");
    assert_eq!(
        guest.ok("_CFStringCreateWithCString", &[0, DATA + 0x40, 0]),
        0
    );
    assert_eq!(
        guest.ok("_CFStringGetCString", &[DATA + 0x40, DATA + 0x80, 16, 0]),
        1
    );
    assert_eq!(guest.get(DATA + 0x80, 6), b"other\0");
    assert_eq!(
        guest.ok("_CFStringGetCString", &[DATA + 0x40, DATA + 0x80, 3, 0]),
        0
    );
    assert_eq!(guest.ok("_CFNumberGetValue", &[0, 0, DATA + 0xc0]), 1);
    assert_eq!(guest.u32_at(DATA + 0xc0), 3_184_554_750);
    guest.put_str(DATA, "objectForKey:");
    assert_eq!(guest.ok("_objc_msgSend", &[0, DATA]), FAKE_HANDLE);

    guest.put_str(
        DATA,
        "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP",
    );
    assert_eq!(guest.ok("_dlopen", &[DATA, 0]), FAKE_HANDLE);
    guest.put_str(DATA, "cp2g1b9ro");
    assert_eq!(guest.ok("_dlsym", &[FAKE_HANDLE, DATA]), 0xabc0);
    guest.put_str(DATA, "missing");
    assert_eq!(guest.ok("_dlsym", &[FAKE_HANDLE, DATA]), 0);
}

#[test]
fn xpc_objects_carry_request_and_reply_payloads() {
    let mut guest = Guest::new();
    let message = guest.ok("_xpc_dictionary_create_empty", &[]);
    assert_eq!(message, 0xffff_0000_0000_0001);
    guest.put(DATA, b"request");
    guest.ok("_xpc_dictionary_set_data", &[message, 0, DATA, 7]);
    let state = guest.shims.state();
    assert_eq!(state.borrow().xpc.data, b"request");
    let dictionary_type = guest.address("__xpc_type_dictionary");
    assert_eq!(guest.ok("_xpc_get_type", &[message]), dictionary_type);
    assert_eq!(guest.ok("_xpc_get_type", &[42]), 0);

    let copy = guest.ok("_xpc_dictionary_get_data", &[message, 0, DATA + 0x40]);
    assert_eq!(guest.get(copy, 7), b"request");
    assert_eq!(guest.u64_at(DATA + 0x40), 7);
    assert_eq!(guest.ok("_xpc_dictionary_get_data", &[message, 0, 0]), copy);
    assert_eq!(
        guest.ok("_xpc_dictionary_get_data", &[42, 0, DATA + 0x40]),
        0
    );

    state.borrow_mut().xpc.sync_reply = Some(b"reply".to_vec());
    let reply = guest.ok(
        "_xpc_connection_send_message_with_reply_sync",
        &[0, message],
    );
    guest.ok("_xpc_dictionary_send_reply", &[reply]);
    assert!(state.borrow().xpc.replied);
    assert_eq!(state.borrow().xpc.reply, b"reply");
    guest.ok("_xpc_dictionary_get_audit_token", &[0, DATA + 0x100]);
    assert_eq!(guest.u32_at(DATA + 0x100 + 20), 123);

    guest.put(DATA + 0x200, &[0x5a; 64]);
    guest.ok("_xpc_connection_set_event_handler", &[0, DATA + 0x200]);
    let handler = state.borrow().xpc.event_handler;
    assert_eq!(guest.get(handler, 64), [0x5a; 64]);
}

#[test]
fn mach_messages_are_captured_and_routed() {
    let mut guest = Guest::new();
    guest.put(DATA, b"sent-message");
    guest.ok("_mach_msg", &[DATA, 1, 12]);
    let state = guest.shims.state();
    assert_eq!(state.borrow().mach.message_reply, b"sent-message");

    assert!(
        guest
            .call("_mach_msg_rpc_from_kernel_proper", &[DATA, 4, 8])
            .is_err()
    );
    state.borrow_mut().handlers.mach_rpc = Some(Rc::new(|request: &[u8], capacity| {
        assert_eq!(capacity, 8);
        Ok([request, b"-ok"].concat())
    }));
    guest.put(DATA, b"ping");
    assert_eq!(
        guest.ok("_mach_msg_rpc_from_kernel_proper", &[DATA, 4, 8]),
        0
    );
    assert_eq!(guest.get(DATA, 7), b"ping-ok");

    guest.put(DATA + 0x100, &[0; 8]);
    guest.put(DATA + 0x108, &0x77u64.to_le_bytes());
    assert_eq!(
        guest.ok(
            "_CFMachPortCreateWithPort",
            &[0, 1, 0x4000, DATA + 0x100, DATA + 0x180]
        ),
        FAKE_HANDLE
    );
    let port = {
        let mach = &state.borrow().mach;
        (mach.port_callback, mach.port_info)
    };
    assert_eq!(port, (0x4000, 0x77));
    assert_eq!(guest.ok("_bootstrap_look_up", &[0, 0, DATA]), 5);
    assert_eq!(guest.ok("_bootstrap_check_in", &[0, 0, DATA]), 0);
    assert_eq!(guest.u32_at(DATA), 1);
}

#[test]
fn fair_play_struct_calls_reach_the_handler() {
    let mut guest = Guest::new();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::clone(&seen);
    guest.shims.state().borrow_mut().handlers.fair_play =
        Some(Rc::new(move |request: FairPlayRequest| {
            log.borrow_mut().push(request.clone());
            Ok(FairPlayReply {
                output: vec![0; 16],
                indirect: b"REPLACED".to_vec(),
                status: -2,
            })
        }));
    guest.put(DATA + 0x100, b"original");
    let mut input = (DATA + 0x100).to_le_bytes().to_vec();
    input.extend_from_slice(&8u64.to_le_bytes());
    guest.put(DATA, &input);
    guest.put(DATA + 0x40, &32u64.to_le_bytes());
    let status = guest.ok(
        "_IOConnectCallStructMethod",
        &[7, 26, DATA, 16, DATA + 0x80, DATA + 0x40],
    );
    assert_eq!(status, 0xffff_fffe);
    assert_eq!(seen.borrow()[0].indirect, b"original");
    assert_eq!(seen.borrow()[0].output_size, 32);
    assert_eq!(guest.get(DATA + 0x100, 8), b"REPLACED");
    assert_eq!(guest.u64_at(DATA + 0x80), DATA + 0x100);
    assert_eq!(guest.u64_at(DATA + 0x40), 16);
}

#[test]
fn rejected_indirect_exchange_is_resealed() {
    let mut guest = Guest::new();
    guest.shims.state().borrow_mut().handlers.fair_play = Some(Rc::new(|_| {
        Ok(FairPlayReply {
            status: 5,
            ..FairPlayReply::default()
        })
    }));
    let message: Vec<u8> = (0..32).collect();
    guest.put(DATA + 0x100, &message);
    let mut input = (DATA + 0x100).to_le_bytes().to_vec();
    input.extend_from_slice(&32u64.to_le_bytes());
    guest.put(DATA, &input);
    guest.put(DATA + 0x40, &16u64.to_le_bytes());
    assert_eq!(
        guest.ok(
            "_IOConnectCallStructMethod",
            &[7, 26, DATA, 16, DATA + 0x80, DATA + 0x40]
        ),
        0
    );
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&message[..16]);
    assert_eq!(guest.get(DATA + 0x110, 16), digest[..16]);
}

#[test]
fn iokit_handles_and_iterators() {
    let mut guest = Guest::new();
    assert_eq!(guest.ok("_IOServiceGetMatchingServices", &[0, 0, DATA]), 0);
    assert_eq!(guest.u32_at(DATA), u32::MAX);
    assert_eq!(guest.ok("_IOIteratorNext", &[]), 1);
    assert_eq!(guest.ok("_IOIteratorNext", &[]), 0);
    assert!(
        guest
            .call("_IORegistryEntryGetParentEntry", &[0, 0, 0])
            .is_err()
    );
    guest.ok("_IOServiceOpen", &[0, 0, 0, DATA]);
    assert_eq!(guest.u32_at(DATA), 7);
    guest.ok("_IOMainPort", &[0, DATA]);
    assert_eq!(guest.u32_at(DATA), 1);
}

/// Calls the guest vtable method at `slot` of `object` through its slot address.
fn vtable_method(guest: &Guest, object: u64, slot: u64) -> u64 {
    guest.u64_at(guest.u64_at(object) + slot)
}

fn shim_name_at(guest: &Guest, address: u64) -> Option<String> {
    let state = guest.shims.state();
    let state = state.borrow();
    state
        .table
        .entry(address)
        .map(|entry| entry.name.to_string())
}

#[test]
fn kernel_aes_service_encrypts_through_descriptors() {
    let mut guest = Guest::new();
    guest.put_str(DATA, "IOAESAccelerator");
    let service = guest.ok(
        "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec",
        &[DATA, 0],
    );
    assert_eq!(
        guest.ok(
            "__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec",
            &[DATA, 0]
        ),
        service
    );
    let perform = vtable_method(&guest, service, 0x550);
    assert_eq!(
        shim_name_at(&guest, perform).as_deref(),
        Some("$IOAESAccelerator.performAES")
    );

    let options = "__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm";
    let source = guest.ok(options, &[0, 0, 32, 0]);
    let destination = guest.ok(options, &[0, 0, 32, 0]);
    let write = vtable_method(&guest, source, 0xd0);
    assert_eq!(
        shim_name_at(&guest, write).as_deref(),
        Some("$IOMemoryDescriptor.writeBytes")
    );
    guest.put(DATA + 0x100, &[0; 32]);
    assert_eq!(
        guest.ok(
            "$IOMemoryDescriptor.writeBytes",
            &[source, 0, DATA + 0x100, 32]
        ),
        32
    );
    assert_eq!(guest.ok("$IOBufferMemoryDescriptor.prepare", &[source]), 0);

    let mut key = vec![0; 40];
    key[36..].copy_from_slice(&0x89cu32.to_le_bytes());
    guest.put(DATA + 0x200, &key);
    guest.put(DATA + 0x300, &[0; 16]);
    let args = [
        service,
        source,
        destination,
        32,
        DATA + 0x300,
        0,
        DATA + 0x200,
        0,
        0,
    ];
    assert_eq!(guest.ok("$IOAESAccelerator.performAES", &args), 0);
    assert_eq!(
        guest.ok(
            "$IOMemoryDescriptor.readBytes",
            &[destination, 0, DATA + 0x400, 32]
        ),
        32
    );
    assert_eq!(
        hex::encode(guest.get(DATA + 0x400, 16)),
        "66e94bd4ef8a2c3b884cfa59ca342b2e"
    );
    assert_eq!(guest.get(DATA + 0x300, 16), guest.get(DATA + 0x410, 16));
    let bad = [
        service,
        source,
        destination,
        24,
        DATA + 0x300,
        0,
        DATA + 0x200,
        0,
        0,
    ];
    assert_eq!(guest.ok("$IOAESAccelerator.performAES", &bad), 3);
    let unhandled = vtable_method(&guest, source, 0x10);
    let error = guest
        .call("$IOBufferMemoryDescriptor.unhandled", &[])
        .expect_err("fault");
    assert_eq!(
        shim_name_at(&guest, unhandled).as_deref(),
        Some("$IOBufferMemoryDescriptor.unhandled")
    );
    assert!(error.to_string().contains("virtual method"));
}

#[test]
fn address_range_descriptors_wrap_existing_memory() {
    let mut guest = Guest::new();
    let range = "__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task";
    assert_eq!(guest.ok(range, &[0, 16, 0, 0]), 0);
    let descriptor = guest.ok(range, &[DATA, 16, 0, 0]);
    assert_eq!(
        guest.ok("$IOBufferMemoryDescriptor.getVirtualAddress", &[descriptor]),
        DATA
    );
    assert_eq!(
        guest.ok(
            "$IOMemoryDescriptor.readBytes",
            &[descriptor, 8, DATA + 0x100, 16]
        ),
        0
    );
}

/// `str x0, [x0, #24]; ret`: marks the block it was handed.
const MARK_BLOCK: [u32; 2] = [0xf900_0c00, 0xd65f_03c0];

#[test]
fn dispatch_once_runs_the_block_once_and_resumes() {
    let mut guest = Guest::new();
    guest.put(HELPER, &assemble(&MARK_BLOCK));
    let block = DATA + 0x100;
    guest.put(block + 16, &HELPER.to_le_bytes());
    guest.put(DATA, &[0; 8]);
    assert_eq!(guest.ok("_dispatch_once", &[DATA, block]), 0);
    assert_eq!(guest.u64_at(block + 24), block);
    assert_eq!(guest.u64_at(DATA), u64::MAX);
    guest.put(block + 24, &[0; 8]);
    assert_eq!(guest.ok("_dispatch_once", &[DATA, block]), 0);
    assert_eq!(guest.u64_at(block + 24), 0);
    assert!(guest.shims.state().borrow().callback_returns.is_empty());
}

#[test]
fn pthread_once_follows_upstream_predicate_rules() {
    let mut guest = Guest::new();
    guest.put(HELPER, &assemble(&MARK_BLOCK));
    guest.put(DATA, &1u64.to_le_bytes());
    assert_eq!(guest.ok("_pthread_once", &[DATA, HELPER]), 0);
    assert_eq!(guest.u64_at(DATA), 0x4f4e_4345);
    assert_eq!(guest.u64_at(DATA + 24), DATA);
    assert_eq!(guest.ok("_pthread_once", &[DATA, HELPER]), 0);
    guest.put(DATA + 0x40, &[0; 8]);
    assert_eq!(guest.ok("_pthread_once", &[DATA + 0x40, HELPER]), 0);
    assert_eq!(guest.u64_at(DATA + 0x40), 0);
}

#[test]
fn notify_and_misc_output_parameters() {
    let mut guest = Guest::new();
    guest.ok("_notify_register_check", &[0, DATA]);
    assert_eq!(guest.u32_at(DATA), 1);
    guest.ok("_notify_get_state", &[0, DATA]);
    assert_eq!(guest.u64_at(DATA), 0);
    guest.put(DATA, &5u32.to_le_bytes());
    assert_eq!(
        guest.ok("_OSAtomicCompareAndSwap32Barrier", &[5, 9, DATA]),
        1
    );
    assert_eq!(
        guest.ok("_OSAtomicCompareAndSwap32Barrier", &[5, 1, DATA]),
        0
    );
    assert_eq!(guest.u32_at(DATA), 9);
}

#[test]
fn run_loop_pauses_the_guest_when_configured() {
    let mut guest = Guest::with_config(ShimConfig {
        pause_run_loop: true,
        ..ShimConfig::default()
    });
    let result: Result<u64, EmuError> = guest.call("_CFRunLoopRun", &[0x55]);
    assert_eq!(result.ok(), Some(0x55));
    let slot = guest.address("_CFRunLoopRun");
    let pc = guest
        .engine
        .reg_read(crate::infrastructure::apple_sap::emu::Register::Pc)
        .ok();
    assert_eq!(pc, Some(slot));
}
