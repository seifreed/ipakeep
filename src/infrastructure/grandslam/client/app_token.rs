//! `GrandSlam` app-token request state and AES-GCM token decryption.

use super::response::{extract_base64, extract_response, read_status};
use super::{GRANDSLAM_URL, http};
use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::anisette::resolve_anisette;
use crate::infrastructure::http::plist_codec::decode_plist;
use aes::Aes256;
use aes_gcm::{
    AesGcm, Key, KeyInit as AesKeyInit, Nonce,
    aead::{AeadInPlace, consts::U16},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use serde_json::Value as JsonValue;
use sha2::Sha256;

pub(super) const APP_TOKEN_OPERATION: &str = "apptokens";
const APP_TOKEN_PREFIX: &str = "com.apple.gs.";
const APP_TOKEN_HEADER_LEN: usize = 3;
const APP_TOKEN_IV_LEN: usize = 16;
const APP_TOKEN_MIN_LEN: usize = APP_TOKEN_HEADER_LEN + APP_TOKEN_IV_LEN + 16;
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// The credentials needed to request a service-specific app token.
#[derive(Debug)]
pub(super) struct AppTokenState {
    pub(super) identity_id: String,
    pub(super) auth_token: String,
    pub(super) session_key: Vec<u8>,
    pub(super) continuation: String,
}

impl AppTokenState {
    pub(super) fn from_account(account: &Account) -> Result<Self, AppStoreError> {
        let identity_id = account
            .adsid
            .as_deref()
            .or(account.dsid.as_deref())
            .or(Some(account.directory_services_id.as_str()))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppStoreError::AuthenticationFailed(
                    "missing GrandSlam identity id for app token".into(),
                )
            })?
            .to_string();

        let auth_token = account
            .idms_token
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppStoreError::AuthenticationFailed(
                    "missing GrandSlam IDMS token for app token".into(),
                )
            })?
            .to_string();

        let session_key = decode_account_state_b64(
            account.grandslam_session_key.as_deref(),
            "GrandSlam session key",
        )?;
        let continuation = account
            .grandslam_continuation
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppStoreError::AuthenticationFailed(
                    "missing GrandSlam continuation for app token".into(),
                )
            })?
            .to_string();

        Ok(Self {
            identity_id,
            auth_token,
            session_key,
            continuation,
        })
    }
}

fn decode_account_state_b64(value: Option<&str>, label: &str) -> Result<Vec<u8>, AppStoreError> {
    let encoded = value
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppStoreError::AuthenticationFailed(format!("missing {label}")))?;
    BASE64
        .decode(encoded)
        .map_err(|e| AppStoreError::AuthenticationFailed(format!("invalid {label} encoding: {e}")))
}

pub(super) fn grandslam_app_identifier(app: &str) -> String {
    if app.starts_with(APP_TOKEN_PREFIX) {
        app.to_string()
    } else {
        format!("{APP_TOKEN_PREFIX}{app}")
    }
}

pub(super) fn app_token_checksum(
    session_key: &[u8],
    identity_id: &str,
    app: &str,
) -> Result<Vec<u8>, AppStoreError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("failed to build app token checksum: {e}"))
    })?;
    mac.update(APP_TOKEN_OPERATION.as_bytes());
    mac.update(identity_id.as_bytes());
    mac.update(app.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn decrypt_app_token(
    session_key: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, AppStoreError> {
    if encrypted.len() < APP_TOKEN_MIN_LEN {
        return Err(AppStoreError::AuthenticationFailed(
            "encrypted app token is too short".into(),
        ));
    }
    if session_key.len() != 32 {
        return Err(AppStoreError::AuthenticationFailed(
            "GrandSlam session key has invalid length".into(),
        ));
    }

    let header = &encrypted[..APP_TOKEN_HEADER_LEN];
    if header != b"XYZ" {
        return Err(AppStoreError::AuthenticationFailed(
            "encrypted app token has invalid header".into(),
        ));
    }

    let iv_end = APP_TOKEN_HEADER_LEN + APP_TOKEN_IV_LEN;
    let iv = &encrypted[APP_TOKEN_HEADER_LEN..iv_end];
    let mut ciphertext_and_tag = encrypted[iv_end..].to_vec();

    let key = Key::<Aes256Gcm16>::from_slice(session_key);
    let cipher = Aes256Gcm16::new(key);
    let nonce = Nonce::<U16>::from_slice(iv);
    cipher
        .decrypt_in_place(nonce, header, &mut ciphertext_and_tag)
        .map_err(|_| AppStoreError::AuthenticationFailed("failed to decrypt app token".into()))?;

    Ok(ciphertext_and_tag)
}

pub(super) fn extract_app_token(
    token_value: &JsonValue,
    app: &str,
) -> Result<String, AppStoreError> {
    let status = token_value
        .get("status-code")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(200);
    if status != 200 {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "app token request failed with status code {status}"
        )));
    }

    token_value
        .get("t")
        .and_then(|v| v.get(app))
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
        .ok_or_else(|| AppStoreError::AuthenticationFailed("missing app token".into()))
}

pub(super) async fn request_app_token(
    client: &reqwest::Client,
    account: &Account,
    app: &str,
) -> Result<String, AppStoreError> {
    let app = grandslam_app_identifier(app);
    let state = AppTokenState::from_account(account)?;
    let checksum = app_token_checksum(&state.session_key, &state.identity_id, &app)?;
    let anisette = resolve_anisette(client).await?;

    let body = serde_json::json!({
        "Header": {
            "Version": "1.0.1",
        },
        "Request": {
            "app": [app.clone()],
            "c": { "__binary": state.continuation },
            "checksum": { "__binary": BASE64.encode(checksum) },
            "cpd": anisette.cpd,
            "o": APP_TOKEN_OPERATION,
            "u": state.identity_id,
            "t": state.auth_token,
        },
    });

    let response = http::post_plist(client, GRANDSLAM_URL, &body, Some(&anisette.headers)).await?;
    let inner = extract_response(&response)?;
    ensure_app_token_status(inner)?;

    let encrypted_token = extract_base64(inner, "et").map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("missing encrypted app token: {e}"))
    })?;
    let decrypted_token = decrypt_app_token(&state.session_key, &encrypted_token)?;
    let token_value = decode_plist(&decrypted_token).map_err(|e| {
        AppStoreError::AuthenticationFailed(format!("failed to parse app token: {e}"))
    })?;

    extract_app_token(&token_value, &app)
}

fn ensure_app_token_status(inner: &JsonValue) -> Result<(), AppStoreError> {
    let (hsc, ec) = read_status(inner);
    if hsc == 200 && ec == 0 {
        return Ok(());
    }
    let msg = inner
        .get("Status")
        .and_then(|s| s.get("em"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown error");
    Err(AppStoreError::AuthenticationFailed(format!(
        "app token request failed: HTTP {hsc} (error code {ec}): {msg}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn account_fixture() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "token".into(),
            directory_services_id: "dir-123".into(),
            store_front: "143441-2,26".into(),
            pod: "1".into(),
            idms_token: Some("idms-token".into()),
            dsid: Some("dsid-123".into()),
            adsid: Some("adsid-123".into()),
            grandslam_session_key: Some(BASE64.encode([1_u8; 32])),
            grandslam_continuation: Some(BASE64.encode([2_u8; 16])),
            cookies: Vec::new(),
        }
    }

    #[test]
    fn app_token_checksum_matches_expected_vector() {
        let checksum = app_token_checksum(
            &[1_u8; 32],
            "000123-45-identity",
            "com.apple.gs.itunes.mu.invite",
        )
        .expect("checksum");

        assert_eq!(
            hex::encode(checksum),
            "ea03a33b7969df74b13c9af9bcd2e0c87226ff5c6518bada126148e3be07126a"
        );
    }

    #[test]
    fn grandslam_app_identifier_adds_prefix() {
        assert_eq!(
            grandslam_app_identifier("itunes.mu.invite"),
            "com.apple.gs.itunes.mu.invite"
        );
        assert_eq!(
            grandslam_app_identifier("com.apple.gs.xcode.auth"),
            "com.apple.gs.xcode.auth"
        );
    }

    #[test]
    fn app_token_state_reads_required_account_fields() {
        let state = AppTokenState::from_account(&account_fixture()).unwrap();

        assert_eq!(state.identity_id, "adsid-123");
        assert_eq!(state.auth_token, "idms-token");
        assert_eq!(state.session_key, vec![1_u8; 32]);
        assert_eq!(state.continuation, BASE64.encode([2_u8; 16]));
    }

    #[test]
    fn app_token_state_reports_missing_or_invalid_fields() {
        let mut account = account_fixture();
        account.adsid = None;
        account.dsid = None;
        account.directory_services_id.clear();
        assert!(
            AppTokenState::from_account(&account)
                .unwrap_err()
                .to_string()
                .contains("identity id")
        );

        let mut account = account_fixture();
        account.idms_token = None;
        assert!(
            AppTokenState::from_account(&account)
                .unwrap_err()
                .to_string()
                .contains("IDMS token")
        );

        let mut account = account_fixture();
        account.grandslam_session_key = Some("not-base64".into());
        assert!(
            AppTokenState::from_account(&account)
                .unwrap_err()
                .to_string()
                .contains("invalid")
        );

        let mut account = account_fixture();
        account.grandslam_continuation = None;
        assert!(
            AppTokenState::from_account(&account)
                .unwrap_err()
                .to_string()
                .contains("continuation")
        );
    }

    #[test]
    fn decrypt_app_token_validates_shape_and_decrypts() {
        assert!(
            decrypt_app_token(&[1_u8; 32], b"short")
                .unwrap_err()
                .to_string()
                .contains("too short")
        );
        assert!(
            decrypt_app_token(&[1_u8; 31], &[0_u8; APP_TOKEN_MIN_LEN])
                .unwrap_err()
                .to_string()
                .contains("invalid length")
        );

        let mut invalid_header = vec![0_u8; APP_TOKEN_MIN_LEN];
        invalid_header[..APP_TOKEN_HEADER_LEN].copy_from_slice(b"BAD");
        assert!(
            decrypt_app_token(&[1_u8; 32], &invalid_header)
                .unwrap_err()
                .to_string()
                .contains("invalid header")
        );

        let encrypted = encrypt_fixture(&[1_u8; 32], b"token-plist");
        assert_eq!(
            decrypt_app_token(&[1_u8; 32], &encrypted).unwrap(),
            b"token-plist"
        );

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(
            decrypt_app_token(&[1_u8; 32], &tampered)
                .unwrap_err()
                .to_string()
                .contains("decrypt")
        );
    }

    #[test]
    fn extract_app_token_reads_success_and_errors() {
        let app = "com.apple.gs.itunes.mu.invite";
        let value = json!({"t": {app: {"token": "app-token"}}});
        assert_eq!(extract_app_token(&value, app).unwrap(), "app-token");

        let failed = json!({"status-code": 403});
        assert!(
            extract_app_token(&failed, app)
                .unwrap_err()
                .to_string()
                .contains("403")
        );

        assert!(
            extract_app_token(&json!({"t": {}}), app)
                .unwrap_err()
                .to_string()
                .contains("missing app token")
        );
    }

    #[test]
    fn ensure_app_token_status_reports_grandslam_error() {
        assert!(ensure_app_token_status(&json!({"Status": {"hsc": 200, "ec": 0}})).is_ok());

        let error = ensure_app_token_status(&json!({
            "Status": {"hsc": 500, "ec": 123, "em": "nope"}
        }))
        .unwrap_err()
        .to_string();

        assert!(error.contains("HTTP 500"));
        assert!(error.contains("nope"));
    }

    fn encrypt_fixture(session_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let header = b"XYZ";
        let iv = [7_u8; APP_TOKEN_IV_LEN];
        let key = Key::<Aes256Gcm16>::from_slice(session_key);
        let cipher = Aes256Gcm16::new(key);
        let nonce = Nonce::<U16>::from_slice(&iv);
        let mut ciphertext = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, header, &mut ciphertext)
            .unwrap();

        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(header);
        encrypted.extend_from_slice(&iv);
        encrypted.extend(ciphertext);
        encrypted
    }
}
