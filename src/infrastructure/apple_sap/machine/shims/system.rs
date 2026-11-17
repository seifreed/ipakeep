//! libc/kernel system shims: errno, abort, atomics, randomness, time, host
//! identity, process information, `sysctlbyname` and `sysconf`.

use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use super::call::{ShimCall, checked_size, low_word};
use super::error::ShimError;
use super::layout::{HEAP_SIZE, PAGE_SIZE};
use super::memory::MINUS_ONE;
use super::state::HostEnvironment;

/// Values `audit_token_to_au32` writes to its eight output pointers.
const AUDIT_FIELDS: [u32; 8] = [0, 0, 0, 0, 0, 123, 100_000, 1];
/// Executable path reported by `proc_pidpath`, terminator included.
const PROCESS_PATH: &[u8] =
    b"/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce\0";
/// Mask that turns a 32-bit draw into `random()`'s 31-bit range.
const RANDOM_MASK: u32 = 0x7fff_ffff;
/// Size of `struct timeval` (`tv_sec` + `tv_usec` + padding).
const TIMEVAL_SIZE: usize = 16;
/// Offset of `tv_usec` in `struct timeval`.
const TIMEVAL_MICROSECONDS_OFFSET: usize = 8;
/// Size of `struct timezone`.
const TIMEZONE_SIZE: u64 = 8;
/// `_SC_PAGESIZE`.
const SC_PAGESIZE: u64 = 29;
/// `_SC_NPROCESSORS_CONF`.
const SC_NPROCESSORS_CONF: u64 = 57;
/// `_SC_NPROCESSORS_ONLN`.
const SC_NPROCESSORS_ONLN: u64 = 58;
/// `_SC_PHYS_PAGES`.
const SC_PHYS_PAGES: u64 = 200;
/// Value of every pinned integer sysctl.
const SYSCTL_ONE: u32 = 1;
/// Pinned `hw.memsize`.
const MEMORY_SIZE: u64 = 8 << 30;

fn host(call: &ShimCall<'_, '_>) -> Result<Rc<dyn HostEnvironment>, ShimError> {
    Ok(Rc::clone(&call.state()?.host))
}

fn random_u32(call: &ShimCall<'_, '_>) -> Result<u32, ShimError> {
    let mut bytes = [0; 4];
    host(call)?.fill_random(&mut bytes);

    Ok(u32::from_le_bytes(bytes))
}

fn since_epoch(call: &ShimCall<'_, '_>) -> Result<Duration, ShimError> {
    let now = host(call)?.now();

    Ok(now.duration_since(UNIX_EPOCH).unwrap_or_default())
}

pub(super) fn compare_and_swap_32(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [old_value, new_value, address] = call.args()?;
    // `OSAtomicCompareAndSwap32` takes 32-bit operands in W registers.
    if call.read_u32(address)? != low_word(old_value) {
        return call.set_result(0);
    }
    call.write_u32(address, low_word(new_value))?;

    call.set_result(1)
}

pub(super) fn error_pointer(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let errno = call.state()?.errno;
    call.set_result(errno)
}

pub(super) fn abort(_: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    Err(ShimError::Aborted)
}

pub(super) fn arc4random(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let value = random_u32(call)?;
    call.set_result(u64::from(value))
}

pub(super) fn random(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let value = random_u32(call)? & RANDOM_MASK;
    call.set_result(u64::from(value))
}

/// Uniform draw in `[0, upper)` by rejection sampling, as upstream.
pub(super) fn arc4random_uniform(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [upper] = call.args()?;
    if upper < 2 {
        return call.set_result(0);
    }
    let range = u64::from(u32::MAX) + 1;
    if upper > range {
        return Err(ShimError::Unsupported {
            what: "arc4random_uniform bound",
            value: upper,
        });
    }
    let limit = range - range % upper;
    loop {
        let value = u64::from(random_u32(call)?);
        if value < limit {
            return call.set_result(value % upper);
        }
    }
}

pub(super) fn read_random(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address, length] = call.args()?;
    let mut data = vec![0; checked_size(length)?];
    host(call)?.fill_random(&mut data);
    call.write_bytes(address, &data)?;

    call.set_result(0)
}

pub(super) fn audit_token_to_au32(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    for (index, value) in AUDIT_FIELDS.into_iter().enumerate() {
        let address = call.arg(index + 1)?;
        if address != 0 {
            call.write_u32(address, value)?;
        }
    }

    call.set_result(0)
}

/// Returns a pointer to the last path component inside the guest string.
pub(super) fn basename(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    let value = call.read_c_string(address)?;
    let trimmed_length = value
        .iter()
        .rposition(|&byte| byte != b'/')
        .map_or(0, |i| i + 1);
    let component = value[..trimmed_length]
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |index| index as u64 + 1);

    call.set_result(address + component)
}

pub(super) fn time(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [address] = call.args()?;
    let seconds = since_epoch(call)?.as_secs();
    if address != 0 {
        call.write_u64(address, seconds)?;
    }

    call.set_result(seconds)
}

pub(super) fn clock_get_calendar_microtime(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [seconds_address, microseconds_address] = call.args()?;
    let now = since_epoch(call)?;
    // The kernel ABI stores `clock_sec_t` and `clock_usec_t` as 32-bit fields.
    call.write_u32(seconds_address, low_word(now.as_secs()))?;
    call.write_u32(microseconds_address, now.subsec_micros())?;

    call.set_result(0)
}

pub(super) fn gettimeofday(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [time_address, zone_address] = call.args()?;
    let now = since_epoch(call)?;
    if time_address != 0 {
        let mut value = [0; TIMEVAL_SIZE];
        value[..TIMEVAL_MICROSECONDS_OFFSET].copy_from_slice(&now.as_secs().to_le_bytes());
        value[TIMEVAL_MICROSECONDS_OFFSET..TIMEVAL_MICROSECONDS_OFFSET + 4]
            .copy_from_slice(&now.subsec_micros().to_le_bytes());
        call.write_bytes(time_address, &value)?;
    }
    if zone_address != 0 {
        call.fill(zone_address, 0, TIMEZONE_SIZE)?;
    }

    call.set_result(0)
}

pub(super) fn gethostuuid(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let uuid = call.state()?.host_uuid;
    if uuid == [0; 16] {
        return Err(ShimError::Invalid("guest host UUID is unavailable"));
    }
    let address = call.arg(0)?;
    if address != 0 {
        call.write_bytes(address, &uuid)?;
    }

    call.set_result(0)
}

pub(super) fn proc_pid_path(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [_, buffer, size] = call.args()?;
    if buffer == 0 || size < PROCESS_PATH.len() as u64 {
        return call.set_result(MINUS_ONE);
    }
    call.write_bytes(buffer, PROCESS_PATH)?;

    call.set_result(PROCESS_PATH.len() as u64 - 1)
}

/// Pinned value of a supported `sysctlbyname` name.
fn sysctl_value(name: &[u8]) -> Option<Vec<u8>> {
    match name {
        b"kern.monotonicclock"
        | b"hw.ncpu"
        | b"hw.logicalcpu"
        | b"hw.physicalcpu"
        | b"hw.optional.arm64" => Some(SYSCTL_ONE.to_le_bytes().to_vec()),
        b"hw.memsize" => Some(MEMORY_SIZE.to_le_bytes().to_vec()),
        b"hw.machine" => Some(b"arm64\0".to_vec()),
        b"hw.model" => Some(b"MacBookPro13,3\0".to_vec()),
        b"kern.osversion" => Some(b"16G29\0".to_vec()),
        _ => None,
    }
}

pub(super) fn sysctlbyname(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [name, output, length_address] = call.args()?;
    let Some(value) = sysctl_value(&call.read_c_string(name)?) else {
        return call.set_result(MINUS_ONE);
    };
    if length_address != 0 {
        let requested = call.read_u64(length_address)?;
        if output != 0 && requested < value.len() as u64 {
            return call.set_result(MINUS_ONE);
        }
        if output != 0 {
            call.write_bytes(output, &value)?;
        }
        call.write_u64(length_address, value.len() as u64)?;
    }

    call.set_result(0)
}

pub(super) fn sysconf(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [name] = call.args()?;
    let value = match name {
        SC_PAGESIZE => PAGE_SIZE,
        SC_NPROCESSORS_CONF | SC_NPROCESSORS_ONLN => 1,
        SC_PHYS_PAGES => HEAP_SIZE / PAGE_SIZE,
        _ => MINUS_ONE,
    };

    call.set_result(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_single_cpu_sysctl_reports_one() {
        for name in [
            b"kern.monotonicclock".as_slice(),
            b"hw.ncpu",
            b"hw.logicalcpu",
            b"hw.physicalcpu",
            b"hw.optional.arm64",
        ] {
            assert_eq!(
                sysctl_value(name),
                Some(SYSCTL_ONE.to_le_bytes().to_vec()),
                "{}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn pinned_sysctl_values_are_reported() {
        assert_eq!(
            sysctl_value(b"hw.memsize"),
            Some(MEMORY_SIZE.to_le_bytes().to_vec())
        );
        assert_eq!(sysctl_value(b"hw.machine"), Some(b"arm64\0".to_vec()));
        assert_eq!(sysctl_value(b"kern.osversion"), Some(b"16G29\0".to_vec()));
        assert_eq!(sysctl_value(b"hw.unknown"), None);
    }
}
