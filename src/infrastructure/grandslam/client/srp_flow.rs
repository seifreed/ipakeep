use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::{
    anisette::{AnisetteData, resolve_anisette},
    srp::derive_srp_password,
    srp_handshake::{compute_a_pub, compute_client_proof, generate_a},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::response::{check_grandslam_status, extract_response, read_status};
use super::srp_response::{
    finalize_srp_complete, parse_srp_init_response, two_factor_required_result,
    verify_server_proof_response,
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
            "cpd": anisette.cpd.clone(),
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
        return Err(srp_init_error(ec));
    }

    parse_srp_init_response(inner, a, anisette)
}

fn srp_init_error(ec: i64) -> AppStoreError {
    if ec == -80045 {
        return AppStoreError::AuthenticationFailed(format!(
            "SRP init failed with error code {ec}: Apple rejected the Anisette identity before validating credentials; check IPAKEEP_ANISETTE_URL"
        ));
    }
    AppStoreError::AuthenticationFailed(format!("SRP init failed with error code {ec}"))
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

    let inner = send_complete_request(client, email, init, &m1).await?;
    if let Some(server_proof_required) = second_factor_server_proof_required(read_status(&inner)) {
        if server_proof_required {
            verify_server_proof_response(&inner, init, &m1, &session_key)?;
        }
        return two_factor_required_result(&inner, &session_key);
    }
    let ec = check_grandslam_status(&inner, "SRP complete")?;

    if ec != 0 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "SRP complete failed with error code {ec}"
        )));
    }

    finalize_srp_complete(&inner, init, &m1, &session_key)
}

async fn send_complete_request(
    client: &reqwest::Client,
    email: &str,
    init: &SrpInitResponse,
    m1: &[u8],
) -> Result<serde_json::Value, AppStoreError> {
    let body = serde_json::json!({
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "cpd": init.anisette.cpd.clone(),
            "c": init.c,
            "M1": { "__binary": BASE64.encode(m1) },
            "u": email,
            "o": "complete",
        },
    });

    let response =
        http::post_plist(client, GRANDSLAM_URL, &body, Some(&init.anisette.headers)).await?;
    extract_response(&response).cloned()
}

fn second_factor_server_proof_required(status: (u64, i64)) -> Option<bool> {
    if status.0 == 409 {
        Some(true)
    } else if status.1 == -21669 {
        Some(false)
    } else {
        None
    }
}

/// Response from the SRP init step.
#[derive(Clone)]
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
    /// Anisette identity must remain stable across both SRP requests.
    pub(crate) anisette: AnisetteData,
}

impl std::fmt::Debug for SrpInitResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpInitResponse")
            .field("sp", &self.sp)
            .field("salt_len", &self.salt.len())
            .field("iterations", &self.iterations)
            .field("b_pub_len", &self.b_pub.len())
            .field("continuation_present", &!self.c.is_empty())
            .finish_non_exhaustive()
    }
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

#[cfg(test)]
mod tests {
    use super::{second_factor_server_proof_required, srp_init_error};

    #[test]
    fn identifies_grandslam_two_factor_statuses() {
        assert_eq!(second_factor_server_proof_required((409, 0)), Some(true));
        assert_eq!(
            second_factor_server_proof_required((200, -21669)),
            Some(false)
        );
        assert_eq!(second_factor_server_proof_required((200, 0)), None);
    }

    #[test]
    fn anisette_rejection_does_not_look_like_a_password_error() {
        let message = srp_init_error(-80045).to_string();
        assert!(message.contains("before validating credentials"));
        assert!(message.contains("IPAKEEP_ANISETTE_URL"));
    }

    #[test]
    fn other_init_errors_keep_their_code() {
        assert!(srp_init_error(-20970).to_string().contains("-20970"));
    }
}
