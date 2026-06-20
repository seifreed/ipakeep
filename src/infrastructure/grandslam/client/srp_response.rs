//! `GrandSlam` SRP response handling.

use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::{
    client::{SrpCompleteResult, SrpInitResponse},
    srp::decrypt_spd,
    srp_handshake::{compute_a_pub, verify_server_proof},
};
use crate::infrastructure::http::plist_codec::decode_plist;
use serde_json::Value as JsonValue;

use super::account::parse_spd_account;
use super::response::extract_base64;

/// Parse the SRP parameters returned by the init step.
///
/// `a` is the locally generated private ephemeral, threaded through so the
/// complete step can reuse it.
pub(super) fn parse_srp_init_response(
    inner: &JsonValue,
    a: Vec<u8>,
) -> Result<SrpInitResponse, AppStoreError> {
    let sp = inner
        .get("sp")
        .and_then(|v| v.as_str())
        .unwrap_or("s2k")
        .to_string();

    let salt = extract_base64(inner, "s").map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("missing salt in SRP init: {e}"))
    })?;

    let iterations = u32::try_from(
        inner
            .get("i")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(10_000),
    )
    .unwrap_or(10_000);

    let b_pub = extract_base64(inner, "B").map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("missing server ephemeral in SRP init: {e}"))
    })?;

    tracing::debug!(
        sp = %sp,
        iterations,
        salt_len = salt.len(),
        b_pub_len = b_pub.len(),
        "received SRP init parameters"
    );

    let c = inner
        .get("c")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if c.is_empty() {
        return Err(AppStoreError::AuthenticationFailed(
            "missing continuation handle in SRP init".into(),
        ));
    }

    Ok(SrpInitResponse {
        sp,
        salt,
        iterations,
        b_pub,
        c,
        a,
    })
}

/// Build the 2FA challenge result from the `-21669` complete response.
///
/// The trusted-device / SMS flow needs the account's `adsid` and IDMS token to
/// form the `X-Apple-Identity-Token`. Apple returns those inside the encrypted
/// `spd` payload.
pub(super) fn two_factor_required_result(
    inner: &JsonValue,
    session_key: &[u8],
) -> Result<SrpCompleteResult, AppStoreError> {
    let spd = extract_base64(inner, "spd")
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("missing spd: {e}")))?;
    let decrypted_spd = decrypt_spd(session_key, &spd)
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("failed to decrypt spd: {e}")))?;
    let spd_value = decode_plist(&decrypted_spd)
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("failed to parse spd: {e}")))?;

    let account = parse_spd_account(&spd_value);
    let dsid = account
        .adsid
        .filter(|s| !s.is_empty())
        .unwrap_or(account.directory_services_id);
    let idms_token = account.idms_token.unwrap_or_default();

    if dsid.is_empty() || idms_token.is_empty() {
        return Err(AppStoreError::AuthenticationFailed(
            "2FA challenge response missing identity fields".into(),
        ));
    }

    Ok(SrpCompleteResult::TwoFactorRequired { dsid, idms_token })
}

/// Verify the server proof and decrypt the SPD account payload.
pub(super) fn finalize_srp_complete(
    inner: &JsonValue,
    init: &SrpInitResponse,
    m1: &[u8],
    session_key: &[u8],
) -> Result<SrpCompleteResult, AppStoreError> {
    let m2 = extract_base64(inner, "M2")
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("missing server proof: {e}")))?;

    verify_server_proof(&compute_a_pub(&init.a), m1, session_key, &m2).map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("server proof verification failed: {e}"))
    })?;

    let spd = extract_base64(inner, "spd")
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("missing spd: {e}")))?;

    let decrypted_spd = decrypt_spd(session_key, &spd)
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("failed to decrypt spd: {e}")))?;

    let spd_value = decode_plist(&decrypted_spd)
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("failed to parse spd: {e}")))?;

    Ok(SrpCompleteResult::Success(Box::new(parse_spd_account(
        &spd_value,
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use serde_json::json;

    #[test]
    fn parse_srp_init_response_reads_values_and_defaults() {
        let response = parse_srp_init_response(
            &json!({
                "s": BASE64.encode([1_u8, 2, 3]),
                "B": BASE64.encode([4_u8, 5, 6]),
                "c": "continuation"
            }),
            vec![9],
        )
        .unwrap();

        assert_eq!(response.sp, "s2k");
        assert_eq!(response.salt, vec![1, 2, 3]);
        assert_eq!(response.iterations, 10_000);
        assert_eq!(response.b_pub, vec![4, 5, 6]);
        assert_eq!(response.c, "continuation");
        assert_eq!(response.a, vec![9]);
    }

    #[test]
    fn parse_srp_init_response_uses_supplied_algorithm_and_safe_iteration_default() {
        let response = parse_srp_init_response(
            &json!({
                "sp": "s2k_fo",
                "s": BASE64.encode([1_u8]),
                "i": u64::from(u32::MAX) + 1,
                "B": BASE64.encode([2_u8]),
                "c": "continuation"
            }),
            Vec::new(),
        )
        .unwrap();

        assert_eq!(response.sp, "s2k_fo");
        assert_eq!(response.iterations, 10_000);
    }

    #[test]
    fn parse_srp_init_response_reports_missing_required_fields() {
        assert!(
            parse_srp_init_response(&json!({"B": BASE64.encode([1_u8]), "c": "c"}), Vec::new())
                .unwrap_err()
                .to_string()
                .contains("salt")
        );
        assert!(
            parse_srp_init_response(&json!({"s": BASE64.encode([1_u8]), "c": "c"}), Vec::new())
                .unwrap_err()
                .to_string()
                .contains("server ephemeral")
        );
        assert!(
            parse_srp_init_response(
                &json!({"s": BASE64.encode([1_u8]), "B": BASE64.encode([2_u8])}),
                Vec::new()
            )
            .unwrap_err()
            .to_string()
            .contains("continuation")
        );
    }
}
