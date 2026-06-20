use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::{
    anisette::resolve_anisette,
    srp::derive_srp_password,
    srp_handshake::{compute_a_pub, compute_client_proof, generate_a},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::response::{check_grandslam_status, extract_response};
use super::srp_response::{
    finalize_srp_complete, parse_srp_init_response, two_factor_required_result,
};
use super::{GRANDSLAM_URL, http};

pub(super) async fn init(
    client: &reqwest::Client,
    email: &str,
) -> Result<SrpInitResponse, AppStoreError> {
    let a = generate_a();
    let a_pub = compute_a_pub(&a);
    let anisette = resolve_anisette(client).await?;

    let body = serde_json::json!({
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": anisette.cpd,
            "A2k": { "__binary": BASE64.encode(&a_pub) },
            "ps": ["s2k", "s2k_fo"],
            "u": email,
            "o": "init",
        },
    });

    let response = http::post_plist(client, GRANDSLAM_URL, &body, Some(&anisette.headers)).await?;
    let inner = extract_response(&response)?;
    let ec = check_grandslam_status(inner, "SRP init")?;
    if ec != 0 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "SRP init failed with error code {ec}"
        )));
    }

    parse_srp_init_response(inner, a)
}

pub(super) async fn complete(
    client: &reqwest::Client,
    email: &str,
    password: &str,
    init: &SrpInitResponse,
) -> Result<SrpCompleteResult, AppStoreError> {
    let derived = derive_srp_password(password, &init.salt, init.iterations, &init.sp);
    let (m1, session_key) = compute_client_proof(
        &init.a,
        &compute_a_pub(&init.a),
        &init.b_pub,
        email,
        &init.salt,
        &derived,
    )
    .map_err(|e| AppStoreError::AuthenticationFailed(format!("SRP proof failed: {e}")))?;

    let anisette = resolve_anisette(client).await?;
    let body = serde_json::json!({
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": anisette.cpd,
            "c": init.c,
            "M1": { "__binary": BASE64.encode(&m1) },
            "u": email,
            "o": "complete",
        },
    });

    let response = http::post_plist(client, GRANDSLAM_URL, &body, Some(&anisette.headers)).await?;
    let inner = extract_response(&response)?;
    let ec = check_grandslam_status(inner, "SRP complete")?;

    if ec == -21669 {
        return two_factor_required_result(inner, &session_key);
    }
    if ec != 0 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "SRP complete failed with error code {ec}"
        )));
    }

    finalize_srp_complete(inner, init, &m1, &session_key)
}

/// Response from the SRP init step.
#[derive(Debug, Clone)]
pub struct SrpInitResponse {
    /// Protocol string (`"s2k"` or `"s2k_fo"`).
    pub sp: String,
    /// Salt bytes.
    pub salt: Vec<u8>,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// Server public ephemeral.
    pub b_pub: Vec<u8>,
    /// Continuation handle.
    pub c: String,
    /// Private ephemeral (kept for the complete step).
    pub(crate) a: Vec<u8>,
}

/// Result of the SRP complete step.
#[derive(Debug, Clone)]
pub enum SrpCompleteResult {
    /// Authentication succeeded.
    Success(Box<Account>),
    /// Two-factor authentication is required.
    TwoFactorRequired {
        /// Directory Services ID.
        dsid: String,
        /// IDMS token.
        idms_token: String,
    },
}
