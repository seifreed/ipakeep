//! User-space `IOKit` shims, including the `FairPlay` user client call.

use sha2::{Digest, Sha256};

use super::call::ShimCall;
use super::error::ShimError;
use super::state::{FairPlayReply, FairPlayRequest};

/// Port name `IOMainPort` hands out.
const MAIN_PORT: u32 = 1;
/// Connection handle `IOServiceOpen` hands out.
const CONNECTION_HANDLE: u32 = 7;
/// Registry entry / iterator handle written by the matching shims.
const REGISTRY_HANDLE: u32 = u32::MAX;
/// Largest structure buffer the `FairPlay` user client accepts.
const FAIRPLAY_BUFFER_LIMIT: u64 = 1 << 20;
/// Selector whose 16-byte input is `{pointer, length}` of a message buffer.
const INDIRECT_SELECTOR: u64 = 26;
/// Size of the `{pointer, length}` indirect descriptor.
const INDIRECT_DESCRIPTOR_SIZE: usize = 16;
/// Trailing digest bytes of an indirect `FairPlay` message.
const MESSAGE_DIGEST_SIZE: usize = 16;
/// Size of a little-endian pointer.
const POINTER_SIZE: usize = 8;

/// Alternates between a service handle and end-of-iteration.
pub(super) fn io_iterator_next(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let iterator = {
        let mut state = call.state()?;
        state.iterator = state.iterator.wrapping_add(1);
        state.iterator
    };

    call.set_result(u64::from(iterator % 2))
}

pub(super) fn io_main_port(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let port = call.arg(1)?;
    if port != 0 {
        call.write_u32(port, MAIN_PORT)?;
    }

    call.set_result(0)
}

pub(super) fn io_service_open(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let connection = call.arg(3)?;
    if connection != 0 {
        call.write_u32(connection, CONNECTION_HANDLE)?;
    }

    call.set_result(0)
}

pub(super) fn io_registry_entry_get_parent_entry(
    call: &mut ShimCall<'_, '_>,
) -> Result<(), ShimError> {
    let parent = call.arg(2)?;
    if parent == 0 {
        return Err(ShimError::Invalid("parent registry entry output is null"));
    }
    call.write_u32(parent, REGISTRY_HANDLE)?;

    call.set_result(0)
}

pub(super) fn io_service_get_matching_services(
    call: &mut ShimCall<'_, '_>,
) -> Result<(), ShimError> {
    let iterator = call.arg(2)?;
    if iterator == 0 {
        return Err(ShimError::Invalid(
            "matching services iterator output is null",
        ));
    }
    call.state()?.iterator = 0;
    call.write_u32(iterator, REGISTRY_HANDLE)?;

    call.set_result(0)
}

/// A decoded `IOConnectCallStructMethod` call.
struct StructCall {
    selector: u64,
    input: Vec<u8>,
    indirect: Vec<u8>,
    indirect_address: u64,
    output_address: u64,
    output_size_address: u64,
    output_size: u64,
}

/// Forwards the `FairPlay` user-client call to the orchestration handler.
pub(super) fn io_connect_call_struct_method(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let request = read_struct_call(call)?;
    let handler = call
        .state()?
        .handlers
        .fair_play
        .clone()
        .ok_or(ShimError::MissingHandler {
            handler: "emulated FairPlay IOKit",
        })?;
    let reply = handler(FairPlayRequest {
        input: request.input.clone(),
        indirect: request.indirect.clone(),
        output_size: usize::try_from(request.output_size).unwrap_or(usize::MAX),
    })?;
    let reply = accept_rejected_indirect(&request, reply);

    write_struct_reply(call, &request, reply)
}

fn read_struct_call(call: &mut ShimCall<'_, '_>) -> Result<StructCall, ShimError> {
    let [
        _,
        selector,
        input_address,
        input_size,
        output_address,
        output_size_address,
    ] = call.args()?;
    let output_size = if output_size_address == 0 {
        0
    } else {
        call.read_u64(output_size_address).unwrap_or_default()
    };
    if input_size > FAIRPLAY_BUFFER_LIMIT || output_size > FAIRPLAY_BUFFER_LIMIT {
        return Err(ShimError::Invalid(
            "FairPlay IOKit buffer exceeds guest limit",
        ));
    }
    let input = call.read_bytes(input_address, input_size)?;
    let (indirect_address, indirect) = read_indirect(call, selector, &input)?;

    Ok(StructCall {
        selector,
        input,
        indirect,
        indirect_address,
        output_address,
        output_size_address,
        output_size,
    })
}

fn read_indirect(
    call: &ShimCall<'_, '_>,
    selector: u64,
    input: &[u8],
) -> Result<(u64, Vec<u8>), ShimError> {
    if selector != INDIRECT_SELECTOR || input.len() != INDIRECT_DESCRIPTOR_SIZE {
        return Ok((0, Vec::new()));
    }
    let address = le_u64(&input[..POINTER_SIZE]);
    let size = le_u64(&input[POINTER_SIZE..]);
    if size == 0 || size > FAIRPLAY_BUFFER_LIMIT {
        return Err(ShimError::Invalid(
            "FairPlay IOKit indirect buffer is invalid",
        ));
    }

    Ok((address, call.read_bytes(address, size)?))
}

/// Mirrors upstream: a failed selector-26 exchange whose input echoes the
/// output size is answered by re-sealing the original message digest.
fn accept_rejected_indirect(request: &StructCall, reply: FairPlayReply) -> FairPlayReply {
    let echoes = request.input.len() as u64 == request.output_size;
    if reply.status == 0
        || request.selector != INDIRECT_SELECTOR
        || request.indirect.len() < MESSAGE_DIGEST_SIZE
        || !echoes
    {
        return reply;
    }
    let mut indirect = request.indirect.clone();
    let body = indirect.len() - MESSAGE_DIGEST_SIZE;
    let digest = Sha256::digest(&indirect[..body]);
    indirect[body..].copy_from_slice(&digest[..MESSAGE_DIGEST_SIZE]);

    FairPlayReply {
        output: request.input.clone(),
        indirect,
        status: 0,
    }
}

fn write_struct_reply(
    call: &mut ShimCall<'_, '_>,
    request: &StructCall,
    mut reply: FairPlayReply,
) -> Result<(), ShimError> {
    if !reply.indirect.is_empty() {
        call.write_bytes(request.indirect_address, &reply.indirect)?;
        if reply.output.len() >= POINTER_SIZE {
            reply.output[..POINTER_SIZE].copy_from_slice(&request.indirect_address.to_le_bytes());
        }
    }
    call.write_bytes(request.output_address, &reply.output)?;
    if request.output_size_address != 0 {
        call.write_u64(request.output_size_address, reply.output.len() as u64)?;
    }

    call.set_result(u64::from(reply.status.cast_unsigned()))
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut value = [0; POINTER_SIZE];
    value.copy_from_slice(bytes);

    u64::from_le_bytes(value)
}
