//! `<string.h>` shims: copies, fills, comparisons and lengths.

use std::cmp::Ordering;

use super::call::{ShimCall, checked_size};
use super::error::ShimError;
use super::layout::{MAX_GUEST_TRANSFER, PAGE_SIZE};

/// Encodes a C comparison result (`-1`, `0`, `1`) as a register value.
fn ordering_result(ordering: Ordering) -> u64 {
    i64::from(ordering as i8).cast_unsigned()
}

pub(super) fn memmove(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [destination, source, length] = call.args()?;
    let data = call.read_bytes(source, length)?;
    call.write_bytes(destination, &data)?;

    call.set_result(destination)
}

pub(super) fn memset(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [destination, value, length] = call.args()?;
    call.fill(destination, value.to_le_bytes()[0], length)?;

    call.set_result(destination)
}

pub(super) fn bzero(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [destination, length] = call.args()?;
    call.fill(destination, 0, length)?;

    call.set_result(destination)
}

pub(super) fn checked_memcpy(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [_, _, length, capacity] = call.args()?;
    if length > capacity {
        return Err(ShimError::Invalid("checked copy exceeds destination"));
    }

    memmove(call)
}

pub(super) fn checked_memset(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [_, _, length, capacity] = call.args()?;
    if length > capacity {
        return Err(ShimError::Invalid("checked fill exceeds destination"));
    }

    memset(call)
}

pub(super) fn memcmp(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [left, right, length] = call.args()?;
    let left = call.read_bytes(left, length)?;
    let right = call.read_bytes(right, length)?;

    call.set_result(ordering_result(left.cmp(&right)))
}

pub(super) fn strcmp(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [left, right] = call.args()?;
    let left = call.read_c_string(left)?;
    let right = call.read_c_string(right)?;

    call.set_result(ordering_result(left.cmp(&right)))
}

pub(super) fn strncmp(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [left, right, length] = call.args()?;
    checked_size(length)?;
    let mut offset = 0;
    while offset < length {
        let (left_address, right_address) = offset_pair(left, right, offset)?;
        let chunk = (length - offset)
            .min(PAGE_SIZE - left_address % PAGE_SIZE)
            .min(PAGE_SIZE - right_address % PAGE_SIZE);
        let a = call.read_bytes(left_address, chunk)?;
        let b = call.read_bytes(right_address, chunk)?;
        if let Some(difference) = first_difference(&a, &b) {
            return call.set_result(difference);
        }
        offset += chunk;
    }

    call.set_result(0)
}

fn offset_pair(left: u64, right: u64, offset: u64) -> Result<(u64, u64), ShimError> {
    left.checked_add(offset)
        .zip(right.checked_add(offset))
        .ok_or(ShimError::Invalid("string comparison address overflows"))
}

/// Returns `a[i] - b[i]` at the first differing byte, `0` at a shared
/// terminator, or `None` when the chunks agree without terminating.
fn first_difference(a: &[u8], b: &[u8]) -> Option<u64> {
    for (&x, &y) in a.iter().zip(b) {
        if x != y {
            return Some((i64::from(x) - i64::from(y)).cast_unsigned());
        }
        if x == 0 {
            return Some(0);
        }
    }

    None
}

pub(super) fn strlen(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    let value = call.read_c_string(address)?;

    call.set_result(value.len() as u64)
}

pub(super) fn strnlen(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address, limit] = call.args()?;
    if limit > MAX_GUEST_TRANSFER {
        return Err(ShimError::TransferTooLarge { size: limit });
    }
    let mut offset = 0;
    while offset < limit {
        let cursor = address + offset;
        let chunk = (limit - offset).min(PAGE_SIZE - cursor % PAGE_SIZE);
        let data = call.read_bytes(cursor, chunk)?;
        if let Some(index) = data.iter().position(|&byte| byte == 0) {
            return call.set_result(offset + index as u64);
        }
        offset += chunk;
    }

    call.set_result(limit)
}
