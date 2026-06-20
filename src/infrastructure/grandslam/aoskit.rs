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
/// Uses `ioreg` instead of `AOSUtilities` FFI, matching [`machine_udid`]: its
/// `"key" = "value"` output keeps the serial on the same line, unlike
/// `system_profiler -xml` (whose `<key>`/`<string>` split made a naive parser
/// return the literal key name).
pub fn machine_serial_number() -> Option<String> {
    let output = std::process::Command::new("ioreg")
        .args(["-c", "IOPlatformExpertDevice", "-d", "2"])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    // Format: "IOPlatformSerialNumber" = "L2D6M931F1"
    text.lines()
        .find(|l| l.contains("IOPlatformSerialNumber"))
        .and_then(|l| l.rsplit_once('"'))
        .and_then(|(before, _)| before.rsplit_once('"'))
        .map(|(_, serial)| serial.to_string())
        .filter(|serial| !serial.is_empty())
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
        assert!(uuid.contains('-'));
        assert!(uuid.len() >= 36);
    }

    #[test]
    fn machine_serial_returns_real_value_not_key_name() {
        let serial = machine_serial_number().expect("ioreg should return serial number");
        // Regression: the previous system_profiler -xml parser returned the
        // literal key name "serial_number" instead of the actual serial, which
        // was then sent as X-Apple-I-SRL-NO and triggered Apple error 433.
        assert_ne!(serial, "serial_number");
        assert!(!serial.is_empty());
        assert!(
            !serial.contains('<'),
            "serial must not contain plist markup"
        );
    }
}
