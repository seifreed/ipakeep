//! Native macOS App Store request signing and device proofs.

#![allow(unsafe_code)]

use crate::domain::error::AppStoreError;
use base64::Engine;
use libc::{c_char, c_uchar, c_void, free};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;

static SIGNING_LOCK: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn ipakeep_native_auth_headers(
        endpoint: *const c_char,
        body: *const c_uchar,
        body_length: usize,
        signature: *mut *mut c_uchar,
        signature_length: *mut usize,
        amd: *mut *mut c_char,
        amd_machine: *mut *mut c_char,
        error: *mut *mut c_char,
    ) -> i32;
}

/// Create fresh headers for a serialized native App Store authentication request.
pub(super) async fn request_headers(
    endpoint: &str,
    body: &[u8],
) -> Result<HashMap<String, String>, AppStoreError> {
    let endpoint = endpoint.to_owned();
    let body = body.to_vec();

    tokio::task::spawn_blocking(move || native_headers(&endpoint, &body))
        .await
        .map_err(|error| {
            AppStoreError::NetworkError(format!("native Store authentication task failed: {error}"))
        })?
}

fn native_headers(endpoint: &str, body: &[u8]) -> Result<HashMap<String, String>, AppStoreError> {
    let _guard = SIGNING_LOCK.lock().map_err(|_| {
        AppStoreError::NetworkError("native Store authentication lock was poisoned".into())
    })?;
    let endpoint = CString::new(endpoint).map_err(|_| {
        AppStoreError::NetworkError("native Store authentication URL is invalid".into())
    })?;
    let mut signature = ptr::null_mut();
    let mut signature_length = 0;
    let mut amd = ptr::null_mut();
    let mut amd_machine = ptr::null_mut();
    let mut error = ptr::null_mut();

    let status = unsafe {
        ipakeep_native_auth_headers(
            endpoint.as_ptr(),
            body.as_ptr(),
            body.len(),
            &raw mut signature,
            &raw mut signature_length,
            &raw mut amd,
            &raw mut amd_machine,
            &raw mut error,
        )
    };
    let result = read_headers(status, signature, signature_length, amd, amd_machine, error);
    free_outputs(
        signature.cast(),
        amd.cast(),
        amd_machine.cast(),
        error.cast(),
    );
    result
}

fn read_headers(
    status: i32,
    signature: *mut c_uchar,
    signature_length: usize,
    amd: *mut c_char,
    amd_machine: *mut c_char,
    error: *mut c_char,
) -> Result<HashMap<String, String>, AppStoreError> {
    if status != 0 {
        let message = if error.is_null() {
            "macOS native Store authentication failed".to_owned()
        } else {
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        };
        return Err(AppStoreError::NetworkError(message));
    }
    if signature.is_null() || signature_length == 0 || signature_length > 16 * 1024 {
        return Err(AppStoreError::NetworkError(
            "macOS returned an invalid SAP signature".into(),
        ));
    }

    let signature = unsafe { std::slice::from_raw_parts(signature, signature_length) };
    let amd = read_header(amd)?;
    let amd_machine = read_header(amd_machine)?;
    Ok(HashMap::from([
        (
            "X-Apple-ActionSignature".into(),
            base64::engine::general_purpose::STANDARD.encode(signature),
        ),
        ("X-Apple-AMD".into(), amd),
        ("X-Apple-AMD-M".into(), amd_machine),
    ]))
}

fn read_header(value: *mut c_char) -> Result<String, AppStoreError> {
    if value.is_null() {
        return Err(AppStoreError::NetworkError(
            "macOS returned an incomplete Store device proof".into(),
        ));
    }
    let value = unsafe { CStr::from_ptr(value) }.to_str().map_err(|_| {
        AppStoreError::NetworkError("macOS returned an invalid Store device proof".into())
    })?;
    if value.is_empty() || value.len() > 8192 || value.contains(['\r', '\n']) {
        return Err(AppStoreError::NetworkError(
            "macOS returned an invalid Store device proof".into(),
        ));
    }
    Ok(value.to_owned())
}

fn free_outputs(
    signature: *mut c_void,
    amd: *mut c_void,
    amd_machine: *mut c_void,
    error: *mut c_void,
) {
    for output in [signature, amd, amd_machine, error] {
        if !output.is_null() {
            unsafe { free(output) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allocate(bytes: &[u8], null_terminate: bool) -> *mut c_void {
        let length = bytes.len() + usize::from(null_terminate);
        let output = unsafe { libc::malloc(length) }.cast::<u8>();
        assert!(!output.is_null());
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
            if null_terminate {
                output.add(bytes.len()).write(0);
            }
        }
        output.cast()
    }

    fn read_response(
        status: i32,
        signature: Option<&[u8]>,
        signature_length: usize,
        amd: Option<&[u8]>,
        amd_machine: Option<&[u8]>,
        error: Option<&[u8]>,
    ) -> Result<HashMap<String, String>, AppStoreError> {
        let signature = signature.map(|bytes| allocate(bytes, false));
        let amd = amd.map(|bytes| allocate(bytes, true));
        let amd_machine = amd_machine.map(|bytes| allocate(bytes, true));
        let error = error.map(|bytes| allocate(bytes, true));
        let result = read_headers(
            status,
            signature.unwrap_or(ptr::null_mut()).cast(),
            signature_length,
            amd.unwrap_or(ptr::null_mut()).cast(),
            amd_machine.unwrap_or(ptr::null_mut()).cast(),
            error.unwrap_or(ptr::null_mut()).cast(),
        );
        free_outputs(
            signature.unwrap_or(ptr::null_mut()),
            amd.unwrap_or(ptr::null_mut()),
            amd_machine.unwrap_or(ptr::null_mut()),
            error.unwrap_or(ptr::null_mut()),
        );
        result
    }

    #[test]
    fn native_status_and_signature_failures_are_reported() {
        assert!(matches!(
            read_response(1, None, 0, None, None, None),
            Err(AppStoreError::NetworkError(_))
        ));
        assert!(
            read_response(1, None, 0, None, None, Some(b"denied"))
                .unwrap_err()
                .to_string()
                .contains("denied")
        );
        assert!(read_response(0, None, 1, None, None, None).is_err());
        assert!(read_response(0, Some(&[1]), 0, None, None, None).is_err());
        assert!(read_response(0, Some(&[1]), 16 * 1024 + 1, None, None, None).is_err());
    }

    #[test]
    fn native_device_proofs_reject_missing_invalid_and_unsafe_headers() {
        assert!(read_response(0, Some(&[1]), 1, None, Some(b"machine"), None).is_err());
        assert!(read_response(0, Some(&[1]), 1, Some(&[0xff]), Some(b"machine"), None).is_err());
        assert!(read_response(0, Some(&[1]), 1, Some(b""), Some(b"machine"), None).is_err());
        assert!(
            read_response(
                0,
                Some(&[1]),
                1,
                Some(b"line\nbreak"),
                Some(b"machine"),
                None,
            )
            .is_err()
        );
        assert!(
            read_response(
                0,
                Some(&[1]),
                1,
                Some(&vec![b'a'; 8193]),
                Some(b"machine"),
                None,
            )
            .is_err()
        );
        assert!(read_response(0, Some(&[1]), 1, Some(b"amd"), None, None).is_err());
    }

    #[test]
    fn native_headers_encode_signature_and_preserve_valid_proofs() {
        let headers = read_response(
            0,
            Some(&[1, 2, 3]),
            3,
            Some(b"amd-proof"),
            Some(b"machine-proof"),
            None,
        )
        .unwrap();

        assert_eq!(headers["X-Apple-ActionSignature"], "AQID");
        assert_eq!(headers["X-Apple-AMD"], "amd-proof");
        assert_eq!(headers["X-Apple-AMD-M"], "machine-proof");
    }

    #[tokio::test]
    async fn native_request_rejects_nul_endpoint_before_calling_ffi() {
        assert!(matches!(
            request_headers("invalid\0endpoint", b"").await,
            Err(AppStoreError::NetworkError(_))
        ));
    }
}
