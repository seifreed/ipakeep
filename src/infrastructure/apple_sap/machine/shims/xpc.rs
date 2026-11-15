//! Faked XPC objects for the `com.apple.adid` request/reply exchange.

use super::call::ShimCall;
use super::error::ShimError;

/// Symbol whose address `xpc_get_type` reports for every known object.
pub(super) const XPC_DICTIONARY_TYPE_SYMBOL: &str = "__xpc_type_dictionary";
/// Bytes of a block literal copied by `xpc_connection_set_event_handler`.
const BLOCK_COPY_SIZE: u64 = 64;
/// Largest data payload a dictionary accepts.
const XPC_DATA_LIMIT: u64 = 1 << 20;
/// Size of a Darwin `audit_token_t`.
const AUDIT_TOKEN_SIZE: usize = 32;
/// `(byte offset, value)` pairs of the faked audit token (auid, pid, pidversion…).
const AUDIT_TOKEN_FIELDS: [(usize, u32); 4] = [(0, u32::MAX), (20, 123), (24, 100_000), (28, 1)];

fn new_object(call: &mut ShimCall<'_, '_>, data: Option<&[u8]>) -> Result<(), ShimError> {
    let object = call.state()?.xpc.new_object(data);

    call.set_result(object)
}

pub(super) fn connection_create_mach_service(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    new_object(call, None)
}

pub(super) fn dictionary_create_empty(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    new_object(call, None)
}

pub(super) fn dictionary_create_reply(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    new_object(call, None)
}

/// Answers with a dictionary carrying the machine-provided sync reply.
pub(super) fn connection_send_message_with_reply_sync(
    call: &mut ShimCall<'_, '_>,
) -> Result<(), ShimError> {
    let object = {
        let mut state = call.state()?;
        let reply = state.xpc.sync_reply.clone();
        state.xpc.new_object(reply.as_deref())
    };

    call.set_result(object)
}

/// Copies the handler block to the heap and records it.
pub(super) fn connection_set_event_handler(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let block = call.arg(1)?;
    let copy = call.allocate(BLOCK_COPY_SIZE)?;
    let literal = call.read_bytes(block, BLOCK_COPY_SIZE)?;
    call.write_bytes(copy, &literal)?;
    call.state()?.xpc.event_handler = copy;

    call.set_result(0)
}

pub(super) fn dictionary_get_audit_token(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let token = call.arg(1)?;
    if token != 0 {
        let mut value = [0; AUDIT_TOKEN_SIZE];
        for (offset, field) in AUDIT_TOKEN_FIELDS {
            value[offset..offset + 4].copy_from_slice(&field.to_le_bytes());
        }
        call.write_bytes(token, &value)?;
    }

    call.set_result(0)
}

pub(super) fn dictionary_send_reply(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [object] = call.args()?;
    {
        let mut state = call.state()?;
        let xpc = &mut state.xpc;
        if let Some(value) = xpc.objects.get(&object) {
            xpc.reply = value.data.clone().unwrap_or_default();
        }
        xpc.replied = true;
    }

    call.set_result(0)
}

pub(super) fn get_type(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [object] = call.args()?;
    let kind = {
        let state = call.state()?;
        if state.xpc.objects.contains_key(&object) {
            state.symbol(XPC_DICTIONARY_TYPE_SYMBOL).unwrap_or(0)
        } else {
            0
        }
    };

    call.set_result(kind)
}

pub(super) fn dictionary_set_data(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [object, _, address, length] = call.args()?;
    if length > XPC_DATA_LIMIT {
        return Err(ShimError::Invalid("XPC data exceeds guest limit"));
    }
    let data = call.read_bytes(address, length)?;
    {
        let mut state = call.state()?;
        if let Some(value) = state.xpc.objects.get_mut(&object) {
            value.data = Some(data.clone());
        }
        state.xpc.data = data;
    }

    call.set_result(0)
}

/// Returns a stable guest copy of the object's payload and its length.
pub(super) fn dictionary_get_data(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [object, _, length_address] = call.args()?;
    let (data, existing) = {
        let state = call.state()?;
        match state.xpc.objects.get(&object) {
            Some(value) => (value.data.clone(), value.data_address),
            None => (None, 0),
        }
    };
    let Some(data) = data else {
        if length_address != 0 {
            call.write_u64(length_address, 0)?;
        }
        return call.set_result(0);
    };
    let address = if existing == 0 {
        materialize(call, object, &data)?
    } else {
        existing
    };
    if length_address != 0 {
        call.write_u64(length_address, data.len() as u64)?;
    }

    call.set_result(address)
}

fn materialize(call: &mut ShimCall<'_, '_>, object: u64, data: &[u8]) -> Result<u64, ShimError> {
    let address = call.allocate(data.len().max(1) as u64)?;
    call.write_bytes(address, data)?;
    if let Some(value) = call.state()?.xpc.objects.get_mut(&object) {
        value.data_address = address;
    }

    Ok(address)
}
