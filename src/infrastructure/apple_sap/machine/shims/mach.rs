//! Mach messaging and bootstrap shims.

use super::call::ShimCall;
use super::error::ShimError;

/// Largest Mach message the shims forward.
const MACH_MESSAGE_LIMIT: u64 = 1 << 20;
/// Darwin `KERN_FAILURE`.
const KERN_FAILURE: u64 = 5;
/// Port name handed out by `bootstrap_check_in`.
const CHECK_IN_PORT: u32 = 1;
/// Descriptor `kqueue` returns.
const KQUEUE_DESCRIPTOR: u64 = 6;

/// Forwards a kernel-originated RPC to the orchestration and writes the reply
/// over the request buffer.
pub(super) fn mach_msg_rpc_from_kernel(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [message, send_size, receive_size] = call.args()?;
    if send_size == 0 || send_size > MACH_MESSAGE_LIMIT || receive_size > MACH_MESSAGE_LIMIT {
        return Err(ShimError::Invalid("kernel Mach RPC size is invalid"));
    }
    let request = call.read_bytes(message, send_size)?;
    let handler = call
        .state()?
        .handlers
        .mach_rpc
        .clone()
        .ok_or(ShimError::MissingHandler {
            handler: "kernel Mach RPC",
        })?;
    let capacity = usize::try_from(receive_size).unwrap_or(usize::MAX);
    let reply = handler(&request, capacity)?;
    if reply.is_empty() || reply.len() > capacity {
        return Err(ShimError::Invalid("kernel Mach RPC reply is invalid"));
    }
    call.write_bytes(message, &reply)?;

    call.set_result(0)
}

/// Captures the message the guest sends (its reply to a forwarded request).
pub(super) fn mach_msg(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [message, _, send_size] = call.args()?;
    if send_size == 0 || send_size > MACH_MESSAGE_LIMIT {
        return call.set_result(0);
    }
    let sent = call.read_bytes(message, send_size)?;
    call.state()?.mach.message_reply = sent;

    call.set_result(0)
}

pub(super) fn kqueue(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    call.set_result(KQUEUE_DESCRIPTOR)
}

pub(super) fn bootstrap_look_up(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let service = call.arg(2)?;
    if service != 0 {
        call.write_u32(service, 0)?;
    }

    call.set_result(KERN_FAILURE)
}

pub(super) fn bootstrap_check_in(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let port = call.arg(2)?;
    if port != 0 {
        call.write_u32(port, CHECK_IN_PORT)?;
    }

    call.set_result(0)
}
