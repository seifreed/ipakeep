//! `CoreFoundation`, Objective-C, `notify`, run-loop and `dlfcn` shims.

use super::call::ShimCall;
use super::error::ShimError;
use super::layout::FAKE_HANDLE;

/// `IOKit` registry keys whose `CFString`s are represented by a fake handle.
const PLATFORM_KEYS: [&[u8]; 3] = [b"IOPlatformSerialNumber", b"IOPlatformUUID", b"board-id"];
/// The only Objective-C selector answered with a non-nil object.
const KEYED_SELECTOR: &[u8] = b"objectForKey:";
/// Value every `CFNumberGetValue` reports (the board identifier).
const CF_NUMBER_VALUE: u32 = 3_184_554_750;
/// Framework `dlopen` succeeds for.
const CORE_FP_PATH: &[u8] = b"/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP";
/// Offset of the `info` field inside a `CFMachPortContext`.
const MACH_PORT_CONTEXT_INFO_OFFSET: u64 = 8;

pub(super) fn cf_string_create(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let value = call.read_c_string(call.arg(1)?)?;
    let handle = if PLATFORM_KEYS.contains(&value.as_slice()) {
        FAKE_HANDLE
    } else {
        0
    };

    call.set_result(handle)
}

pub(super) fn cf_string_create_no_copy(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let address = call.arg(1)?;
    call.set_result(address)
}

pub(super) fn cf_string_get_c_string(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [value, buffer, capacity] = call.args()?;
    if buffer == 0 || capacity == 0 {
        return call.set_result(0);
    }
    let mut encoded = if value != 0 && value != FAKE_HANDLE {
        call.read_c_string(value).unwrap_or_default()
    } else {
        Vec::new()
    };
    encoded.push(0);
    if encoded.len() as u64 > capacity {
        return call.set_result(0);
    }
    call.write_bytes(buffer, &encoded)?;

    call.set_result(1)
}

pub(super) fn cf_number_get_value(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let address = call.arg(2)?;
    if address != 0 {
        call.write_u32(address, CF_NUMBER_VALUE)?;
    }

    call.set_result(1)
}

pub(super) fn objc_msg_send(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let selector = call.read_c_string(call.arg(1)?)?;
    let result = if selector == KEYED_SELECTOR {
        FAKE_HANDLE
    } else {
        0
    };

    call.set_result(result)
}

pub(super) fn notify_register_check(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let token = call.arg(1)?;
    if token != 0 {
        call.write_u32(token, 1)?;
    }

    call.set_result(0)
}

pub(super) fn notify_check(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let changed = call.arg(1)?;
    if changed != 0 {
        call.write_u32(changed, 0)?;
    }

    call.set_result(0)
}

pub(super) fn notify_get_state(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let state = call.arg(1)?;
    if state != 0 {
        call.write_u64(state, 0)?;
    }

    call.set_result(0)
}

/// Returns zero, or pauses the guest when the profile parks in its run loop.
pub(super) fn cf_run_loop_run(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    if !call.state()?.pause_run_loop {
        return call.set_result(0);
    }

    Ok(call.engine().stop()?)
}

pub(super) fn cf_mach_port_create_with_port(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [_, _, callback, context, should_free_info] = call.args()?;
    let info = if context == 0 {
        0
    } else {
        call.read_u64(context + MACH_PORT_CONTEXT_INFO_OFFSET)
            .unwrap_or_default()
    };
    {
        let mut state = call.state()?;
        state.mach.port_callback = callback;
        state.mach.port_context = context;
        if context != 0 {
            state.mach.port_info = info;
        }
    }
    if should_free_info != 0 {
        call.write_bytes(should_free_info, &[0])?;
    }

    call.set_result(FAKE_HANDLE)
}

pub(super) fn dlopen(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let path = call.read_c_string(call.arg(0)?)?;
    let handle = if path == CORE_FP_PATH { FAKE_HANDLE } else { 0 };

    call.set_result(handle)
}

pub(super) fn dlsym(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let name = call.read_c_string(call.arg(1)?)?;
    let symbol = format!("_{}", String::from_utf8_lossy(&name));
    let address = call
        .state()?
        .core_exports
        .get(&symbol)
        .copied()
        .unwrap_or(0);

    call.set_result(address)
}
