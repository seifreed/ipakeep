//! `AOSKit.framework` FFI wrapper (macOS only).
//!
//! Loads `/System/Library/PrivateFrameworks/AOSKit.framework` at runtime and
//! safely exposes `+[AOSUtilities retrieveOTPHeadersForDSID:]`. All `unsafe` code is
//! confined to this module.

#![allow(unsafe_code, unexpected_cfgs, unsafe_op_in_unsafe_fn)]

use libc::{RTLD_LAZY, c_char, dlopen};
use objc::runtime::{Class, Object};
use std::collections::HashMap;
use std::ffi::{CStr, CString};

/// Error type internal to this module.
#[derive(Debug)]
enum AosKitError {
    FrameworkNotFound,
    ClassNotFound,
    MethodFailed,
}

/// Safe wrapper around `AOSUtilities`. Returns `None` if the framework is unavailable
/// or the call fails.
pub fn retrieve_otp_headers(dsid: &str) -> Option<HashMap<String, String>> {
    unsafe { try_retrieve_otp_headers(dsid).ok() }
}

/// Returns the machine hardware UUID (for `X-Mme-Device-Id`).
/// Uses `ioreg` instead of `AOSUtilities` FFI to avoid uncatchable Objective-C exceptions.
pub fn machine_udid() -> Option<String> {
    let output = std::process::Command::new("ioreg")
        .args(["-c", "IOPlatformExpertDevice", "-d", "2"])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    // Format: "IOPlatformUUID" = "CD4BA2D3-B68F-5F4C-A716-E5DFD2F14FC5"
    text.lines()
        .find(|l| l.contains("IOPlatformUUID"))
        .and_then(|l| l.rsplit_once('"'))
        .and_then(|(before, _)| before.rsplit_once('"'))
        .map(|(_, uuid)| uuid.to_string())
}

/// Returns the machine serial number (for `X-Apple-I-SRL-NO`).
/// Uses `system_profiler` instead of `AOSUtilities` FFI.
pub fn machine_serial_number() -> Option<String> {
    let output = std::process::Command::new("system_profiler")
        .args(["SPHardwareDataType", "-xml"])
        .output()
        .ok()?;
    let plist = String::from_utf8(output.stdout).ok()?;
    plist
        .lines()
        .find(|l| l.contains("serial_number"))
        .and_then(|l| l.split_once('>'))
        .and_then(|(_, rest)| rest.split_once('<'))
        .map(|(sn, _)| sn.trim().to_string())
}

/// Core unsafe logic: dlopen the framework, call the Objective-C method, and
/// convert the resulting `NSDictionary` into a Rust `HashMap`.
unsafe fn try_retrieve_otp_headers(dsid: &str) -> Result<HashMap<String, String>, AosKitError> {
    let path = CString::new("/System/Library/PrivateFrameworks/AOSKit.framework/AOSKit")
        .map_err(|_| AosKitError::FrameworkNotFound)?;

    let handle = unsafe { dlopen(path.as_ptr(), RTLD_LAZY) };
    if handle.is_null() {
        return Err(AosKitError::FrameworkNotFound);
    }

    let cls = Class::get("AOSUtilities").ok_or(AosKitError::ClassNotFound)?;

    let dsid_c = CString::new(dsid).map_err(|_| AosKitError::MethodFailed)?;
    let nsstring_cls = Class::get("NSString").ok_or(AosKitError::ClassNotFound)?;
    let dsid_obj: *mut Object = msg_send![nsstring_cls, stringWithUTF8String: dsid_c.as_ptr()];

    if dsid_obj.is_null() {
        return Err(AosKitError::MethodFailed);
    }

    let dict: *mut Object = msg_send![cls, retrieveOTPHeadersForDSID: dsid_obj];
    if dict.is_null() {
        return Err(AosKitError::MethodFailed);
    }

    let mut map = HashMap::new();
    let keys: *mut Object = msg_send![dict, allKeys];
    if keys.is_null() {
        return Ok(map);
    }

    let count: usize = msg_send![keys, count];

    for i in 0..count {
        let key: *mut Object = msg_send![keys, objectAtIndex: i];
        let val: *mut Object = msg_send![dict, objectForKey: key];

        let key_rust = unsafe { nsstring_to_rust(key) }.ok_or(AosKitError::MethodFailed)?;
        let val_rust = unsafe { nsstring_to_rust(val) }.ok_or(AosKitError::MethodFailed)?;
        map.insert(key_rust, val_rust);
    }

    Ok(map)
}

/// Convert an `NSString*` to a Rust `String`.
unsafe fn nsstring_to_rust(obj: *mut Object) -> Option<String> {
    if obj.is_null() {
        return None;
    }

    let utf8: *const c_char = msg_send![obj, UTF8String];
    if utf8.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(utf8) }
        .to_str()
        .ok()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieve_otp_headers_does_not_panic() {
        // AOSKit may or may not be available on the host; we only assert that
        // the FFI call does not panic and returns a well-formed Option.
        let _result = retrieve_otp_headers("-2");
    }

    #[test]
    fn machine_udid_returns_uuid() {
        let uuid = machine_udid();
        assert!(uuid.is_some(), "ioreg should return IOPlatformUUID");
        let uuid = uuid.unwrap();
        // Basic UUID validation: contains hyphens and is reasonably long
        assert!(uuid.contains('-'));
        assert!(uuid.len() >= 36);
    }

    #[test]
    fn machine_serial_returns_value() {
        let serial = machine_serial_number();
        assert!(
            serial.is_some(),
            "system_profiler should return serial number"
        );
    }
}
