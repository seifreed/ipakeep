//! `GrandSlam` HTTP client for Apple SRP authentication.
//!
//! Communicates with `gsa.apple.com` to perform SRP login and
//! two-factor authentication flows.

use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::grandslam::{
    anisette::generate_anisette,
    srp::{decrypt_spd, derive_srp_password},
    srp_handshake::{compute_a_pub, compute_client_proof, generate_a, verify_server_proof},
};
use crate::infrastructure::http::plist_codec::{decode_plist, encode_plist};
use aes::Aes256;
use aes_gcm::{
    AesGcm, Key, KeyInit as AesKeyInit, Nonce,
    aead::{AeadInPlace, consts::U16},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac};
use serde_json::Value as JsonValue;
use sha2::Sha256;
use std::collections::HashMap;

const GRANDSLAM_URL: &str = "https://gsa.apple.com/grandslam/GsService2";
const TRUSTED_DEVICE_URL: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
const PHONE_URL: &str = "https://gsa.apple.com/auth/verify/phone";
const PHONE_SECURITY_CODE_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";
const VALIDATE_URL: &str = "https://gsa.apple.com/grandslam/GsService2/validate";
const APP_TOKEN_OPERATION: &str = "apptokens";
const APP_TOKEN_PREFIX: &str = "com.apple.gs.";
const APP_TOKEN_HEADER_LEN: usize = 3;
const APP_TOKEN_IV_LEN: usize = 16;
const APP_TOKEN_MIN_LEN: usize = APP_TOKEN_HEADER_LEN + APP_TOKEN_IV_LEN + 16;
const RESPONSE_SNIPPET_LEN: usize = 240;
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// Client for Apple `GrandSlam` authentication endpoints.
#[derive(Debug, Clone)]
pub struct GrandSlamClient {
    client: reqwest::Client,
}

impl GrandSlamClient {
    /// Create a new `GrandSlam` client from an existing HTTP client.
    ///
    /// Sharing the `reqwest::Client` ensures cookies are persisted
    /// across legacy and `GrandSlam` requests.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Perform the first step of SRP authentication (init).
    ///
    /// Generates a client ephemeral, embeds it with Anisette CPD, and
    /// POSTs to Apple's `GrandSlam` endpoint.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    /// Returns `AppStoreError::AuthenticationFailed` if Apple rejects the init.
    pub async fn srp_init(&self, email: &str) -> Result<SrpInitResponse, AppStoreError> {
        let a = generate_a();
        let a_pub = compute_a_pub(&a);

        let anisette = generate_anisette();

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

        let response = self
            .post_plist(GRANDSLAM_URL, &body, Some(&anisette.headers))
            .await?;

        let inner = extract_response(&response)?;

        let (hsc, ec) = read_status(inner);

        if hsc != 200 {
            let msg = inner
                .get("Status")
                .and_then(|s| s.get("em"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(AppStoreError::AuthenticationFailed(format!(
                "SRP init failed: HTTP {hsc} (error code {ec}): {msg}"
            )));
        }
        if ec != 0 {
            return Err(AppStoreError::AuthenticationFailed(format!(
                "SRP init failed with error code {ec}"
            )));
        }

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
            AppStoreError::AuthenticationFailed(format!(
                "missing server ephemeral in SRP init: {e}"
            ))
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
            a, // store private ephemeral for complete step
        })
    }

    /// Perform the second step of SRP authentication (complete).
    ///
    /// Derives the SRP password, computes the client proof `M1`, and
    /// completes the exchange with Apple.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if credentials are invalid.
    /// Returns `AppStoreError::AuthCodeRequired` if 2FA is required.
    pub async fn srp_complete(
        &self,
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

        let anisette = generate_anisette();

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

        let response = self
            .post_plist(GRANDSLAM_URL, &body, Some(&anisette.headers))
            .await?;
        let inner = extract_response(&response)?;
        let (hsc, ec) = read_status(inner);

        if hsc != 200 {
            let msg = inner
                .get("Status")
                .and_then(|s| s.get("em"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(AppStoreError::AuthenticationFailed(format!(
                "SRP complete failed: HTTP {hsc} (error code {ec}): {msg}"
            )));
        }

        // Check for 2FA requirement
        if ec == -21669 {
            let dsid = inner
                .get("dsid")
                .or_else(|| inner.get("DirectoryServicesID"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let idms_token = inner
                .get("idms-token")
                .or_else(|| inner.get("IDMSToken"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            return Ok(SrpCompleteResult::TwoFactorRequired { dsid, idms_token });
        }

        if ec != 0 {
            return Err(AppStoreError::AuthenticationFailed(format!(
                "SRP complete failed with error code {ec}"
            )));
        }

        // Verify server proof M2
        let m2 = extract_base64(inner, "M2").map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("missing server proof: {e}"))
        })?;

        verify_server_proof(&compute_a_pub(&init.a), &m1, &session_key, &m2).map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("server proof verification failed: {e}"))
        })?;

        // Decrypt spd
        let spd = extract_base64(inner, "spd")
            .map_err(|e| AppStoreError::AuthenticationFailed(format!("missing spd: {e}")))?;

        let decrypted_spd = decrypt_spd(&session_key, &spd).map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("failed to decrypt spd: {e}"))
        })?;

        let spd_value = decode_plist(&decrypted_spd).map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("failed to parse spd: {e}"))
        })?;

        let account = parse_spd_account(&spd_value);

        Ok(SrpCompleteResult::Success(Box::new(account)))
    }

    /// Request a service-specific `GrandSlam` app token for an account.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the stored
    /// `GrandSlam` account state is incomplete or Apple rejects the request.
    pub async fn request_app_token(
        &self,
        account: &Account,
        app: &str,
    ) -> Result<String, AppStoreError> {
        let app = grandslam_app_identifier(app);
        let state = AppTokenState::from_account(account)?;
        let checksum = app_token_checksum(&state.session_key, &state.identity_id, &app)?;
        let anisette = generate_anisette();

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

        let response = self
            .post_plist(GRANDSLAM_URL, &body, Some(&anisette.headers))
            .await?;
        let inner = extract_response(&response)?;
        let (hsc, ec) = read_status(inner);

        if hsc != 200 || ec != 0 {
            let msg = inner
                .get("Status")
                .and_then(|s| s.get("em"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(AppStoreError::AuthenticationFailed(format!(
                "app token request failed: HTTP {hsc} (error code {ec}): {msg}"
            )));
        }

        let encrypted_token = extract_base64(inner, "et").map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("missing encrypted app token: {e}"))
        })?;
        let decrypted_token = decrypt_app_token(&state.session_key, &encrypted_token)?;
        let token_value = decode_plist(&decrypted_token).map_err(|e| {
            AppStoreError::AuthenticationFailed(format!("failed to parse app token: {e}"))
        })?;

        extract_app_token(&token_value, &app)
    }

    /// Send a trusted-device notification to trigger the Apple ID 2FA
    /// approval prompt on all trusted devices.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn request_trusted_device_notification(
        &self,
        dsid: &str,
        idms_token: &str,
    ) -> Result<(), AppStoreError> {
        let token = format!("{dsid}:{idms_token}");
        let identity_token = BASE64.encode(token.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Apple-Identity-Token".into(), identity_token);
        headers.insert("Content-Type".into(), "text/x-xml-plist".into());

        let response = self
            .client
            .get(TRUSTED_DEVICE_URL)
            .headers(Self::build_header_map(&headers)?)
            .send()
            .await
            .map_err(|e| {
                AppStoreError::NetworkError(format!("trusted device request failed: {e}"))
            })?;
        ensure_success_status(response, "trusted device request").await?;

        Ok(())
    }

    /// Validate a trusted-device 2FA code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    pub async fn validate_trusted_device_code(
        &self,
        dsid: &str,
        idms_token: &str,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let token = format!("{dsid}:{idms_token}");
        let identity_token = BASE64.encode(token.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Apple-Identity-Token".into(), identity_token);
        headers.insert("Content-Type".into(), "text/x-xml-plist".into());
        headers.insert("security-code".into(), code.into());

        self.client
            .get(VALIDATE_URL)
            .headers(Self::build_header_map(&headers)?)
            .send()
            .await
            .map_err(|e| AppStoreError::NetworkError(format!("validate code request failed: {e}")))?
            .error_for_status()
            .map_err(|e| AppStoreError::AuthenticationFailed(format!("invalid 2FA code: {e}")))?;

        Ok(())
    }

    /// Request an SMS code to be sent to a trusted phone number.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the request fails.
    pub async fn request_sms(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
    ) -> Result<(), AppStoreError> {
        let token = format!("{dsid}:{idms_token}");
        let identity_token = BASE64.encode(token.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Apple-Identity-Token".into(), identity_token);
        headers.insert("Content-Type".into(), "application/json".into());

        let body = serde_json::json!({
            "phoneNumber": { "id": phone_id },
            "mode": "sms",
        });

        let response = self
            .client
            .put(PHONE_URL)
            .headers(Self::build_header_map(&headers)?)
            .json(&body)
            .send()
            .await
            .map_err(|e| AppStoreError::NetworkError(format!("SMS request failed: {e}")))?;
        ensure_success_status(response, "SMS request").await?;

        Ok(())
    }

    /// Validate an SMS 2FA code.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::AuthenticationFailed` if the code is invalid.
    pub async fn validate_sms_code(
        &self,
        dsid: &str,
        idms_token: &str,
        phone_id: i64,
        code: &str,
    ) -> Result<(), AppStoreError> {
        let token = format!("{dsid}:{idms_token}");
        let identity_token = BASE64.encode(token.as_bytes());

        let mut headers = HashMap::new();
        headers.insert("X-Apple-Identity-Token".into(), identity_token);
        headers.insert("Content-Type".into(), "application/json".into());

        let body = serde_json::json!({
            "phoneNumber": { "id": phone_id },
            "securityCode": { "code": code },
            "mode": "sms",
        });

        self.client
            .post(PHONE_SECURITY_CODE_URL)
            .headers(Self::build_header_map(&headers)?)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                AppStoreError::NetworkError(format!("SMS validation request failed: {e}"))
            })?
            .error_for_status()
            .map_err(|e| AppStoreError::AuthenticationFailed(format!("invalid SMS code: {e}")))?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// POST a plist XML body and decode the plist response.
    async fn post_plist(
        &self,
        url: &str,
        body: &JsonValue,
        extra_headers: Option<&HashMap<String, String>>,
    ) -> Result<JsonValue, AppStoreError> {
        let plist_xml = encode_plist(body)
            .map_err(|e| AppStoreError::NetworkError(format!("plist encode failed: {e}")))?;

        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/x-apple-plist")
            .header("Accept", "*/*")
            .body(plist_xml);

        if let Some(h) = extra_headers {
            for (k, v) in h {
                request = request.header(k.as_str(), v.as_str());
            }
        }

        let response = request
            .send()
            .await
            .map_err(|e| AppStoreError::NetworkError(format!("HTTP POST failed: {e}")))?;

        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| AppStoreError::NetworkError(format!("failed to read response: {e}")))?;

        if !status.is_success() {
            return Err(AppStoreError::NetworkError(format!(
                "GrandSlam request failed with HTTP {status}: {}",
                response_snippet(&bytes)
            )));
        }

        decode_plist(&bytes)
            .map_err(|e| AppStoreError::NetworkError(format!("plist decode failed: {e}")))
    }

    /// Build a `reqwest::header::HeaderMap` from a `HashMap<String, String>`.
    fn build_header_map(
        headers: &HashMap<String, String>,
    ) -> Result<reqwest::header::HeaderMap, AppStoreError> {
        let mut map = reqwest::header::HeaderMap::new();
        for (k, v) in headers {
            let name = reqwest::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| AppStoreError::NetworkError(format!("invalid header name: {e}")))?;
            let value = reqwest::header::HeaderValue::from_str(v)
                .map_err(|e| AppStoreError::NetworkError(format!("invalid header value: {e}")))?;
            map.insert(name, value);
        }
        Ok(map)
    }
}

/// Extract the inner `Response` dictionary from a `GrandSlam` plist response.
fn extract_response(response: &JsonValue) -> Result<&JsonValue, AppStoreError> {
    response.get("Response").ok_or_else(|| {
        AppStoreError::AuthenticationFailed("missing Response wrapper in GrandSlam response".into())
    })
}

/// Read the `Status` value from a `GrandSlam` response.
///
/// Returns `(hsc, ec)`:
/// - `hsc` defaults to `200` if the `Status` dict or `hsc` key is missing.
/// - `ec`  defaults to `0` if the `Status` dict or `ec` key is missing.
/// - Also handles legacy string `Status` values (e.g. `"-21669"`).
fn read_status(response: &JsonValue) -> (u64, i64) {
    let Some(status) = response.get("Status") else {
        return (200, 0);
    };

    // Handle dict {hsc, ec}
    if let Some(hsc) = status.get("hsc").and_then(serde_json::Value::as_u64) {
        let ec = status
            .get("ec")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        return (hsc, ec);
    }

    // Handle string status (legacy / error codes like "-21669")
    if let Some(s) = status.as_str() {
        if s == "-21669" {
            return (200, -21669);
        }
        if let Ok(code) = s.parse::<i64>() {
            return (200, code);
        }
    }

    (200, 0)
}

async fn ensure_success_status(
    response: reqwest::Response,
    operation: &str,
) -> Result<(), AppStoreError> {
    let status = response.status();
    let body = response.bytes().await.map_err(|e| {
        AppStoreError::NetworkError(format!("{operation} response read failed: {e}"))
    })?;

    if !status.is_success() {
        return Err(two_factor_status_error(operation, status, &body));
    }

    Ok(())
}

fn two_factor_status_error(
    operation: &str,
    status: reqwest::StatusCode,
    body: &[u8],
) -> AppStoreError {
    AppStoreError::AuthenticationFailed(format!(
        "{operation} failed with HTTP {status}: {}",
        response_snippet(body)
    ))
}

fn response_snippet(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars()
        .take(RESPONSE_SNIPPET_LEN)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
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

/// Extract a base64-encoded field from a JSON value.
fn extract_base64(value: &JsonValue, key: &str) -> Result<Vec<u8>, String> {
    let s = value
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing field: {key}"))?;
    BASE64
        .decode(s)
        .map_err(|e| format!("base64 decode failed for {key}: {e}"))
}

#[derive(Debug)]
struct AppTokenState {
    identity_id: String,
    auth_token: String,
    session_key: Vec<u8>,
    continuation: String,
}

impl AppTokenState {
    fn from_account(account: &Account) -> Result<Self, AppStoreError> {
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

fn grandslam_app_identifier(app: &str) -> String {
    if app.starts_with(APP_TOKEN_PREFIX) {
        app.to_string()
    } else {
        format!("{APP_TOKEN_PREFIX}{app}")
    }
}

fn app_token_checksum(
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

fn decrypt_app_token(session_key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, AppStoreError> {
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

fn extract_app_token(token_value: &JsonValue, app: &str) -> Result<String, AppStoreError> {
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

/// Parse an Account from decrypted SPD plist data.
fn parse_spd_account(spd: &JsonValue) -> Account {
    let dsid = string_from_keys(spd, &["dsid", "DsPrsId", "DirectoryServicesID", "adsid"]);

    let idms_token = optional_string_from_keys(spd, &["idms-token", "IDMSToken", "GsIdmsToken"]);

    let adsid = optional_string_from_keys(spd, &["adsid"]);

    let grandslam_session_key = optional_string_from_keys(spd, &["sk"]);

    let grandslam_continuation = optional_string_from_keys(spd, &["c"]);

    let email = string_from_keys(spd, &["accountName", "acname", "primaryEmail"]);

    let first_name = string_from_keys(spd, &["firstName", "fn"]);

    let last_name = string_from_keys(spd, &["lastName", "ln"]);

    let name = format!("{first_name} {last_name}").trim().to_string();

    // GrandSlam does not return password_token, store_front, or pod in the
    // same way as legacy auth. We populate them from spd if available, or
    // leave them empty for later filling.
    let password_token = optional_string_from_keys(spd, &["token", "passwordToken"])
        .or_else(|| service_token(spd, "com.apple.gs.itunes.mu.invite"))
        .or_else(|| service_token(spd, "com.apple.gs.appleid.auth"))
        .unwrap_or_default();

    let store_front = string_from_keys(spd, &["storeFront", "store-front"]);

    let pod = string_from_keys(spd, &["pod"]);

    let dsid_opt = if dsid.is_empty() {
        None
    } else {
        Some(dsid.clone())
    };

    Account {
        email,
        name,
        password_token,
        directory_services_id: dsid,
        store_front,
        pod,
        idms_token,
        dsid: dsid_opt,
        adsid,
        grandslam_session_key,
        grandslam_continuation,
        cookies: Vec::new(),
    }
}

fn string_from_keys(value: &JsonValue, keys: &[&str]) -> String {
    optional_string_from_keys(value, keys).unwrap_or_default()
}

fn optional_string_from_keys(value: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(std::string::ToString::to_string)
    })
}

fn service_token(value: &JsonValue, service: &str) -> Option<String> {
    value
        .get("t")
        .and_then(|v| v.get(service))
        .and_then(|v| v.get("token"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn extract_base64_success() {
        let encoded = BASE64.encode(b"hello");
        let value = serde_json::json!({ "data": encoded });
        assert_eq!(extract_base64(&value, "data").unwrap(), b"hello");
    }

    #[test]
    fn extract_base64_missing_key() {
        let value = serde_json::json!({});
        assert!(extract_base64(&value, "data").is_err());
    }

    #[test]
    fn parse_spd_account_extracts_fields() {
        let spd = serde_json::json!({
            "dsid": "12345",
            "idms-token": "tok-abc",
            "adsid": "adsid-abc",
            "accountName": "test@example.com",
            "firstName": "Test",
            "lastName": "User",
            "token": "ptok",
            "storeFront": "143441-2,26",
            "pod": "3",
            "sk": BASE64.encode([1_u8; 32]),
            "c": BASE64.encode([2_u8; 16]),
        });

        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "test@example.com");
        assert_eq!(account.name, "Test User");
        assert_eq!(account.directory_services_id, "12345");
        assert_eq!(account.password_token, "ptok");
        assert_eq!(account.store_front, "143441-2,26");
        assert_eq!(account.pod, "3");
        assert_eq!(account.idms_token, Some("tok-abc".into()));
        assert_eq!(account.dsid, Some("12345".into()));
        assert_eq!(account.adsid, Some("adsid-abc".into()));
        assert!(account.grandslam_session_key.is_some());
        assert!(account.grandslam_continuation.is_some());
    }

    #[test]
    fn parse_spd_account_extracts_grandslam_fields() {
        let spd = serde_json::json!({
            "DsPrsId": "67890",
            "GsIdmsToken": "idms-token",
            "adsid": "adsid-def",
            "sk": BASE64.encode([3_u8; 32]),
            "c": BASE64.encode([4_u8; 16]),
            "acname": "test@example.com",
            "fn": "Test",
            "ln": "User",
            "t": {
                "com.apple.gs.itunes.mu.invite": {
                    "token": "gs-token"
                }
            }
        });

        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "test@example.com");
        assert_eq!(account.name, "Test User");
        assert_eq!(account.directory_services_id, "67890");
        assert_eq!(account.password_token, "gs-token");
        assert_eq!(account.idms_token, Some("idms-token".into()));
        assert_eq!(account.dsid, Some("67890".into()));
        assert_eq!(account.adsid, Some("adsid-def".into()));
        assert!(account.grandslam_session_key.is_some());
        assert!(account.grandslam_continuation.is_some());
    }

    #[test]
    fn parse_spd_account_empty_defaults() {
        let spd = serde_json::json!({});
        let account = parse_spd_account(&spd);
        assert_eq!(account.email, "");
        assert_eq!(account.name, "");
        assert_eq!(account.directory_services_id, "");
        assert!(account.idms_token.is_none());
        assert!(account.dsid.is_none());
        assert!(account.adsid.is_none());
        assert!(account.grandslam_session_key.is_none());
        assert!(account.grandslam_continuation.is_none());
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
    fn two_factor_status_error_includes_http_status_and_body() {
        let error = two_factor_status_error(
            "trusted device request",
            reqwest::StatusCode::UNAUTHORIZED,
            b"not authorized",
        );

        let AppStoreError::AuthenticationFailed(message) = error else {
            panic!("expected authentication failure");
        };
        assert!(message.contains("HTTP 401"));
        assert!(message.contains("not authorized"));
    }

    #[tokio::test]
    async fn post_plist_returns_status_error_before_decoding_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/grandslam"))
            .respond_with(ResponseTemplate::new(500).set_body_raw(
                encode_plist(&serde_json::json!({ "Response": { "ok": true } })).expect("plist"),
                "application/x-apple-plist",
            ))
            .mount(&server)
            .await;

        let client = GrandSlamClient::new(reqwest::Client::new());
        let result = client
            .post_plist(
                &format!("{}/grandslam", server.uri()),
                &serde_json::json!({}),
                None,
            )
            .await;

        let Err(AppStoreError::NetworkError(message)) = result else {
            panic!("expected network error");
        };
        assert!(message.contains("HTTP 500"));
        assert!(message.contains("Response"));
    }
}
