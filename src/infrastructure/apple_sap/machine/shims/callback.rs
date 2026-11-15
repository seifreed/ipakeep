//! One-time initialisers (`pthread_once`, `dispatch_once`) that call back into
//! guest code and resume the original caller through a completion slot.

use crate::infrastructure::apple_sap::emu::Register;

use super::call::ShimCall;
use super::error::ShimError;

/// Symbol of the slot guest callbacks return to.
pub(super) const CALLBACK_COMPLETE_SYMBOL: &str = "callback.complete";
/// Predicate value marking a completed `pthread_once`.
const PTHREAD_ONCE_DONE: u64 = 0x4f4e_4345;
/// Predicate value marking a completed `dispatch_once`.
const DISPATCH_ONCE_DONE: u64 = u64::MAX;
/// Offset of the invoke function pointer inside a block literal.
pub(super) const BLOCK_INVOKE_OFFSET: u64 = 16;

pub(super) fn pthread_once(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [control, initializer] = call.args()?;
    let value = call.read_u64(control)?;
    // Upstream treats a zero control word as already initialised.
    if value == 0 || value == PTHREAD_ONCE_DONE {
        return call.set_result(0);
    }
    call.write_u64(control, PTHREAD_ONCE_DONE)?;

    invoke_callback(call, initializer)
}

pub(super) fn dispatch_once(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [predicate, block] = call.args()?;
    if call.read_u64(predicate)? == DISPATCH_ONCE_DONE {
        return call.set_result(0);
    }
    call.write_u64(predicate, DISPATCH_ONCE_DONE)?;
    let initializer = call.read_u64(block + BLOCK_INVOKE_OFFSET)?;
    call.set_result(block)?;

    invoke_callback(call, initializer)
}

/// Redirects the guest into `initializer`, returning to the completion slot.
fn invoke_callback(call: &mut ShimCall<'_, '_>, initializer: u64) -> Result<(), ShimError> {
    let return_address = call.engine().reg_read(Register::LR)?;
    let completion = {
        let mut state = call.state()?;
        state.callback_returns.push(return_address);
        state
            .symbol(CALLBACK_COMPLETE_SYMBOL)
            .ok_or(ShimError::Invalid(
                "guest callback completion is not registered",
            ))?
    };
    call.engine().reg_write(Register::LR, completion)?;
    call.engine().reg_write(Register::Pc, initializer)?;

    Ok(())
}

pub(super) fn callback_complete(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let return_address = call
        .state()?
        .callback_returns
        .pop()
        .ok_or(ShimError::Invalid(
            "guest callback completion has no return address",
        ))?;
    call.engine().reg_write(Register::LR, return_address)?;

    call.set_result(0)
}
