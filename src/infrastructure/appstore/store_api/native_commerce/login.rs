//! Store (`MZFinance`) sign-in with a SAP-signed plist body.
//!
//! Ported from ipatool `pkg/appstore/appstore_native_login.go`,
//! `appstore_login.go` and `appstore_login_storefront.go`, sending the
//! request directly instead of through the emulated `AppleMediaServices`.

use super::bag::{
    AMS_SESSION_HEADERS, STORE_USER_AGENT, decode_store_plist, encode_request_plist,
    validate_authentication_endpoint,
};
use super::owned_apps::ActionSign;
use super::telemetry::{apple_code, endpoint};
use crate::domain::entity::Account;
use crate::domain::error::{AppStoreError, TwoFactorMethod};
use crate::infrastructure::http::telemetry::{read_response_bytes, send_with_observability};
use base64::Engine;
use reqwest::header::{HeaderMap, LOCATION, RETRY_AFTER, SET_COOKIE};
use reqwest::{StatusCode, Url};
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

const MAX_REQUEST_ATTEMPTS: u32 = 3;
const MAX_REDIRECTS: u32 = 4;
const RETRY_DELAY: Duration = Duration::from_secs(10);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
const MIN_RETRY_AFTER: Duration = Duration::from_secs(1);
const AUTH_CODE_DIGITS: usize = 6;
const PASTE_START: &str = "\x1b[200~";
const PASTE_END: &str = "\x1b[201~";
const FAILURE_INVALID_CREDENTIALS: &str = "-5000";
const MESSAGE_BAD_LOGIN: &str = "MZFinance.BadLogin.Configurator_message";
const MESSAGE_ACCOUNT_DISABLED: &str = "Your account is disabled.";
const HEADER_STORE_FRONT: &str = "X-Set-Apple-Store-Front";
const HEADER_REQUEST_STORE_FRONT: &str = "X-Apple-Request-Store-Front";
const HEADER_POD: &str = "pod";
const HEADER_AMD_ACTION: &str = "X-Apple-AMD-Action";
const HEADER_AMD_DATA: &str = "X-Apple-AMD-Data";
const MACHINE_ID_HEADER: &str = "X-Apple-I-MD";
const MACHINE_ID_M_HEADER: &str = "X-Apple-I-MD-M";
const MACHINE_ID_RINFO_HEADER: &str = "X-Apple-I-MD-RINFO";
const ACTION_RESET_PROVISIONING: &str = "RP";
const ACTION_STORE_PROVISIONING: &str = "SP";
const DSID_COOKIE_PREFIXES: [&str; 2] = ["mz_at0-", "mz_at_ssl-"];
const HTTPS_PORT: u16 = 443;
const CREDENTIAL_SOURCE_PASSWORD: i64 = 0;
const NULL_STORE_FRONT: &str = "<null>";

/// Apple ID credentials for one sign-in.
#[derive(Debug, Clone, Copy)]
pub struct Credentials<'a> {
    /// Apple ID (email or phone number).
    pub email: &'a str,
    /// Account password.
    pub password: &'a str,
    /// Six-digit 2FA code, if Apple asked for one.
    pub auth_code: Option<&'a str>,
}

/// Request inputs besides the credentials.
pub struct LoginContext<'a> {
    /// Store client (see [`super::bag::store_client`]); its cookie jar must
    /// persist between the code-less attempt and the 2FA attempt.
    pub client: &'a reqwest::Client,
    /// `StoreBag::authenticate_account`.
    pub endpoint: &'a str,
    /// Uppercase hex machine GUID.
    pub guid: &'a str,
    /// SAP signer for `X-Apple-ActionSignature`.
    pub sign: ActionSign<'a>,
    /// Anisette or Store AMD headers (`X-Apple-I-MD`, `X-Apple-I-MD-M`, ...).
    pub machine_headers: HashMap<String, String>,
    /// `X-Apple-Store-Front` routing hint for phone-number Apple IDs.
    pub storefront_hint: Option<String>,
    /// Validates redirect targets; production uses [`validate_authentication_endpoint`].
    pub validate_redirect: fn(&str) -> Result<Url, AppStoreError>,
}

impl LoginContext<'_> {
    /// Production redirect policy.
    pub const DEFAULT_REDIRECT_POLICY: fn(&str) -> Result<Url, AppStoreError> =
        validate_authentication_endpoint;
}

/// Sign in, handling Apple's machine actions like upstream `nativeLogin`:
/// `RP` drops the `X-Apple-I-MD*` headers and retries; `SP` calls
/// `provision_store` with `X-Apple-AMD-Data` (Store provisioning, kbsync and
/// the fresh Store AMD proof live behind that seam) and retries with the
/// headers it returns.
///
/// # Errors
///
/// [`AppStoreError::AuthCodeRequired`] when Apple wants a 2FA code,
/// [`AppStoreError::AccountDisabled`], [`AppStoreError::InvalidCredentials`],
/// and authentication/network failures.
pub async fn login<P, Fut>(
    context: &mut LoginContext<'_>,
    credentials: Credentials<'_>,
    provision_store: P,
) -> Result<Account, AppStoreError>
where
    P: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<HashMap<String, String>, AppStoreError>>,
{
    let mut provision = Some(provision_store);
    let mut reset_done = false;
    loop {
        match sign_in(context, credentials).await {
            Err(LoginFailure::MachineAction { action, data }) => {
                log_machine_action(&action);
                let store_provisioning = action == ACTION_STORE_PROVISIONING;
                if action == ACTION_RESET_PROVISIONING && !reset_done {
                    reset_done = true;
                    strip_machine_identity(&mut context.machine_headers);
                } else if let Some(provision) = provision.take_if(|_| store_provisioning) {
                    context.machine_headers = provision(data).await?;
                } else {
                    return Err(machine_action_error(&action));
                }
            }
            Err(LoginFailure::Store(error)) => return Err(error),
            Ok(account) => return Ok(account),
        }
    }
}

// ponytail: upstream only handles RP then SP after a fresh anisette
// provisioning and returns any action when a stored Store AMD proof is used;
// here each action is honoured once in whatever order Apple sends it.
fn machine_action_error(action: &str) -> AppStoreError {
    AppStoreError::AuthenticationFailed(format!(
        "apple requested an authentication machine action: {action}"
    ))
}

fn strip_machine_identity(headers: &mut HashMap<String, String>) {
    headers.retain(|key, _| {
        ![
            MACHINE_ID_HEADER,
            MACHINE_ID_M_HEADER,
            MACHINE_ID_RINFO_HEADER,
        ]
        .iter()
        .any(|name| key.eq_ignore_ascii_case(name))
    });
}

enum LoginFailure {
    MachineAction { action: String, data: String },
    Store(AppStoreError),
}

impl From<AppStoreError> for LoginFailure {
    fn from(error: AppStoreError) -> Self {
        Self::Store(error)
    }
}

/// Upstream `login`: attempt 1, a second attempt after `-5000`, and up to
/// four pod redirects that replay the same body at the new URL.
async fn sign_in(
    context: &mut LoginContext<'_>,
    credentials: Credentials<'_>,
) -> Result<Account, LoginFailure> {
    let auth_code = normalize_auth_code(credentials.auth_code.unwrap_or_default())?;
    let mut url = context.endpoint.to_string();
    let mut attempt = 1;
    let mut redirects = 0;
    let mut cookies = Vec::new();
    loop {
        let body = login_body(credentials, &auth_code, context.guid, attempt)?;
        let response = send_with_retries(context, &url, &body, redirects > 0).await?;
        log_auth_response(&url, &response, attempt);
        cookies.extend(set_cookies(&response.headers));
        match next_step(context, &response, attempt, !auth_code.is_empty(), &url)? {
            Step::Done => return Ok(account_from(&response, credentials.email, cookies)?),
            Step::Retry => attempt += 1,
            Step::Redirect(target) if redirects < MAX_REDIRECTS => {
                redirects += 1;
                log_redirect(&target, redirects);
                url = target;
            }
            Step::Redirect(target) => {
                return Err(redirect_error(
                    "too many authentication redirects",
                    response.status,
                    &target,
                )
                .into());
            }
        }
    }
}

enum Step {
    Done,
    Retry,
    Redirect(String),
}

/// Upstream `parseLoginResponse`, in its precedence order.
fn next_step(
    context: &LoginContext<'_>,
    response: &AuthResponse,
    attempt: u32,
    has_code: bool,
    url: &str,
) -> Result<Step, LoginFailure> {
    if let Some(action) = header(&response.headers, HEADER_AMD_ACTION) {
        let data = header(&response.headers, HEADER_AMD_DATA).unwrap_or_default();
        return Err(LoginFailure::MachineAction { action, data });
    }
    if let Some(message) = dialog_error(&response.body) {
        return Err(AppStoreError::AuthenticationFailed(message).into());
    }
    if response.status.is_redirection() {
        return Ok(Step::Redirect(redirect_target(context, response, url)?));
    }
    let failure = text(&response.body, "failureType");
    let message = text(&response.body, "customerMessage");
    if attempt == 1 && failure == FAILURE_INVALID_CREDENTIALS {
        return Ok(Step::Retry);
    }
    if failure.is_empty() {
        check_customer_message(&message, has_code)?;
    } else {
        return Err(failure_error(&failure, &message).into());
    }
    if response.status != StatusCode::OK || text(&response.body, "passwordToken").is_empty() {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "apple returned no usable authentication response (HTTP {}): missing account credentials or unexpected status; try again later or from another network",
            response.status.as_u16()
        ))
        .into());
    }
    Ok(Step::Done)
}

fn check_customer_message(message: &str, has_code: bool) -> Result<(), AppStoreError> {
    match message {
        MESSAGE_BAD_LOGIN if has_code => Err(AppStoreError::AuthenticationFailed(
            "apple did not complete verification; try a fresh 2FA code".into(),
        )),
        MESSAGE_BAD_LOGIN => Err(AppStoreError::AuthCodeRequired {
            dsid: String::new(),
            idms_token: String::new(),
            method: TwoFactorMethod::TrustedDevice,
        }),
        MESSAGE_ACCOUNT_DISABLED => Err(AppStoreError::AccountDisabled),
        _ => Ok(()),
    }
}

fn failure_error(failure: &str, message: &str) -> AppStoreError {
    if failure == FAILURE_INVALID_CREDENTIALS {
        return AppStoreError::InvalidCredentials;
    }
    let detail = if message.is_empty() {
        "something went wrong"
    } else {
        message
    };
    AppStoreError::AuthenticationFailed(detail.to_string())
}

fn redirect_target(
    context: &LoginContext<'_>,
    response: &AuthResponse,
    url: &str,
) -> Result<String, AppStoreError> {
    let location = header(&response.headers, LOCATION.as_str()).unwrap_or_default();
    let status = response.status;
    if location.is_empty() {
        return Err(redirect_error(
            "failed to retrieve redirect location",
            status,
            "",
        ));
    }
    if !is_authentication_redirect(status) {
        return Err(redirect_error(
            "unsupported authentication redirect status",
            status,
            &location,
        ));
    }
    let target = Url::parse(url)
        .and_then(|base| base.join(&location))
        .map_err(|_| {
            redirect_error(
                "invalid authentication redirect location",
                status,
                &location,
            )
        })?;
    (context.validate_redirect)(target.as_str())
        .map(|valid| valid.to_string())
        .map_err(|error| {
            redirect_error(
                &format!("invalid authentication redirect: {error}"),
                status,
                &location,
            )
        })
}

fn is_authentication_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 307 | 308)
}

/// Keep routing diagnostics without query, credentials or fragment.
fn redirect_error(reason: &str, status: StatusCode, location: &str) -> AppStoreError {
    let destination = Url::parse(location).map_or_else(
        |_| "invalid URL".to_string(),
        |url| {
            format!(
                "{}://{}{}",
                url.scheme(),
                url.host_str().unwrap_or_default(),
                url.path()
            )
        },
    );
    AppStoreError::AuthenticationFailed(format!(
        "{reason} (HTTP {}) [destination: {destination}]",
        status.as_u16()
    ))
}

/// `message[: explanation][ (Label: https://...apple.com/...)]` from a server dialog.
fn dialog_error(body: &plist::Dictionary) -> Option<String> {
    let dialog = body.get("dialog").and_then(plist::Value::as_dictionary)?;
    let field = |key: &str| text(dialog, key).trim().to_string();
    let action = dialog
        .get("okButtonAction")
        .and_then(plist::Value::as_dictionary);
    let action_field = |key: &str| {
        action
            .map(|a| text(a, key).trim().to_string())
            .unwrap_or_default()
    };
    let any = [
        "message",
        "explanation",
        "okButtonString",
        "cancelButtonString",
    ]
    .iter()
    .any(|key| !field(key).is_empty())
        || !action_field("kind").is_empty()
        || !action_field("url").is_empty();
    if !any {
        return None;
    }
    let mut message = field("message");
    if message.is_empty() {
        message = text(body, "customerMessage").trim().to_string();
    }
    let explanation = field("explanation");
    let url = trusted_dialog_url(&action_field("kind"), &action_field("url"));
    format_dialog(&message, &explanation, url, &field("okButtonString"))
}

fn format_dialog(
    message: &str,
    explanation: &str,
    url: Option<String>,
    label: &str,
) -> Option<String> {
    if message.is_empty() && explanation.is_empty() && url.is_none() {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    if !message.is_empty() {
        parts.push(message);
    }
    if !explanation.is_empty() && explanation != message {
        parts.push(explanation);
    }
    let mut detail = parts.join(": ");
    if detail.is_empty() {
        detail = "Apple requires action before sign-in can continue".into();
    }
    if let Some(url) = url {
        let label = if label.is_empty() { "Continue" } else { label };
        detail = format!("{detail} ({label}: {url})");
    }
    Some(detail)
}

fn trusted_dialog_url(kind: &str, value: &str) -> Option<String> {
    if !kind.eq_ignore_ascii_case("OpenURL") {
        return None;
    }
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    let trusted = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.port().is_none_or(|port| port == HTTPS_PORT)
        && (host == "apple.com" || host.ends_with(".apple.com"));
    trusted.then(|| url.to_string())
}

fn account_from(
    response: &AuthResponse,
    email: &str,
    cookies: Vec<String>,
) -> Result<Account, AppStoreError> {
    let headers = &response.headers;
    let store_front = header(headers, HEADER_STORE_FRONT)
        .or_else(|| header(headers, HEADER_REQUEST_STORE_FRONT))
        .filter(|value| value != NULL_STORE_FRONT)
        .ok_or_else(|| {
            AppStoreError::AuthenticationFailed("failed to get storefront header".into())
        })?;
    let dsid = Some(text(&response.body, "dsPersonId"))
        .filter(|dsid| !dsid.is_empty())
        .or_else(|| response_dsid(headers))
        .ok_or_else(|| {
            AppStoreError::AuthenticationFailed(
                "apple returned no directory services identifier".into(),
            )
        })?;
    let (account_email, name) = account_identity(&response.body);
    Ok(Account {
        email: account_email.unwrap_or_else(|| email.to_string()),
        name,
        password_token: text(&response.body, "passwordToken"),
        dsid: Some(dsid.clone()),
        directory_services_id: dsid,
        store_front,
        pod: header(headers, HEADER_POD).unwrap_or_default(),
        idms_token: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies,
    })
}

/// `accountInfo.appleId` (when present) and upstream's `"first last"` name.
fn account_identity(body: &plist::Dictionary) -> (Option<String>, String) {
    let info = body
        .get("accountInfo")
        .and_then(plist::Value::as_dictionary);
    let address = info
        .and_then(|info| info.get("address"))
        .and_then(plist::Value::as_dictionary);
    let part = |dict: Option<&plist::Dictionary>, key: &str| {
        dict.map(|dict| text(dict, key)).unwrap_or_default()
    };
    let email = Some(part(info, "appleId")).filter(|value| !value.is_empty());
    let name = format!(
        "{} {}",
        part(address, "firstName"),
        part(address, "lastName")
    );
    (email, name)
}

/// `X-Dsid`, else the digits of an `mz_at0-<dsid>=` / `mz_at_ssl-<dsid>=` cookie.
fn response_dsid(headers: &HeaderMap) -> Option<String> {
    if let Some(dsid) = header(headers, "X-Dsid") {
        return Some(dsid);
    }
    set_cookies(headers)
        .iter()
        .find_map(|cookie| cookie_dsid(cookie))
}

fn cookie_dsid(cookie: &str) -> Option<String> {
    let candidates = std::iter::once(cookie).chain(
        cookie
            .match_indices([' ', ','])
            .map(|(index, _)| &cookie[index + 1..]),
    );
    candidates.into_iter().find_map(|tail| {
        let rest = DSID_COOKIE_PREFIXES
            .iter()
            .find_map(|prefix| tail.strip_prefix(prefix))?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty() && rest[digits.len()..].starts_with('=')).then_some(digits)
    })
}

fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn text(dict: &plist::Dictionary, key: &str) -> String {
    match dict.get(key) {
        Some(plist::Value::String(value)) => value.clone(),
        Some(plist::Value::Integer(value)) => value.to_string(),
        _ => String::new(),
    }
}

/// The authenticate plist body as the Store session sends it: upstream's
/// fields plus the ones `AppleMediaServices` adds, keys in Core Foundation's
/// sorted order.
///
/// # Errors
///
/// Never fails today; the `Result` keeps the encoding seam stable.
pub fn login_body(
    credentials: Credentials<'_>,
    auth_code: &str,
    guid: &str,
    attempt: u32,
) -> Result<Vec<u8>, AppStoreError> {
    let text = |value: &str| plist::Value::String(value.to_string());
    let password = format!("{}{}", credentials.password, auth_code.replace(' ', ""));
    let mut dict = plist::Dictionary::new();
    dict.insert("appleId".into(), text(credentials.email));
    dict.insert("attempt".into(), text(&attempt.to_string()));
    dict.insert("createSession".into(), plist::Value::Boolean(true));
    dict.insert(
        "credentialSource".into(),
        plist::Value::Integer(CREDENTIAL_SOURCE_PASSWORD.into()),
    );
    dict.insert("deviceOffersCheck".into(), text("true"));
    dict.insert("guid".into(), text(guid));
    dict.insert(
        "isSilentAuthentication".into(),
        plist::Value::Boolean(false),
    );
    dict.insert("password".into(), text(&password));
    dict.insert("passwordSettings".into(), password_settings());
    dict.insert("rmp".into(), text("0"));
    dict.insert("why".into(), text("signIn"));
    Ok(encode_request_plist(&dict))
}

/// Always ask for the password on free and paid purchases.
fn password_settings() -> plist::Value {
    let mut settings = plist::Dictionary::new();
    for kind in ["free", "paid"] {
        settings.insert(kind.into(), plist::Value::String("always".into()));
    }
    plist::Value::Dictionary(settings)
}

/// Strip whitespace and a matched bracketed-paste pair; require six ASCII digits.
///
/// # Errors
///
/// Returns [`AppStoreError::AuthenticationFailed`] for anything else non-empty.
pub fn normalize_auth_code(code: &str) -> Result<String, AppStoreError> {
    if code.is_empty() {
        return Ok(String::new());
    }
    let trimmed = code.trim();
    let unwrapped = trimmed
        .strip_prefix(PASTE_START)
        .and_then(|inner| inner.strip_suffix(PASTE_END))
        .unwrap_or(trimmed);
    let digits: String = unwrapped.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() == AUTH_CODE_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()) {
        Ok(digits)
    } else {
        Err(AppStoreError::AuthenticationFailed(
            "2FA code must contain exactly six digits".into(),
        ))
    }
}

/// `CN` or `IN` when the Apple ID is a mainland-China or India phone number
/// (the storefront routing hint upstream adds), otherwise `None`.
#[must_use]
pub fn phone_number_country_code(apple_id: &str) -> Option<&'static str> {
    let compact: String = apple_id
        .trim()
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .collect();
    let (international, number) = if let Some(rest) = compact.strip_prefix('+') {
        (true, rest)
    } else if let Some(rest) = compact.strip_prefix("00") {
        (true, rest)
    } else {
        (false, compact.as_str())
    };
    if !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let national = if number.len() == 13 && number.starts_with("861") {
        return Some("CN");
    } else if number.len() == 12 && number.starts_with("91") {
        &number[2..]
    } else if international {
        return None;
    } else {
        number
    };
    national_country(national, international)
}

fn national_country(number: &str, international: bool) -> Option<&'static str> {
    if number.len() == 11 && number.starts_with('1') {
        return Some("CN");
    }
    let number = if !international && number.len() == 11 && number.starts_with('0') {
        &number[1..]
    } else {
        number
    };
    let first = number.bytes().next().unwrap_or_default();
    (number.len() == 10 && (b'6'..=b'9').contains(&first)).then_some("IN")
}

/// One authentication response as upstream's XML client hands it over.
struct AuthResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: plist::Dictionary,
}

/// A failure upstream retries (`UnexpectedResponseError` or a transient transport error).
struct Transient {
    status: Option<StatusCode>,
    retry_after: Option<String>,
    error: AppStoreError,
}

/// Upstream `sendAuthenticationRequest`: three attempts for transient
/// failures (204/403/404/429/5xx non-plist answers, timeouts, resets) with
/// 10 s/20 s backoff capped at 30 s, honouring `Retry-After`.
async fn send_with_retries(
    context: &mut LoginContext<'_>,
    url: &str,
    body: &[u8],
    at_pod: bool,
) -> Result<AuthResponse, AppStoreError> {
    let mut outcomes = Vec::new();
    let mut attempt = 1;
    loop {
        let failure = match send_once(context, url, body).await? {
            Ok(response) => return Ok(response),
            Err(failure) => failure,
        };
        let retryable = failure.status.is_none_or(is_retryable_status);
        if !retryable {
            return Err(failure.error);
        }
        outcomes.push(
            failure
                .status
                .map_or("transport error".into(), |s| format!("HTTP {}", s.as_u16())),
        );
        if attempt == MAX_REQUEST_ATTEMPTS {
            return Err(exhausted(&outcomes, &failure.error, at_pod));
        }
        let delay = retry_delay(attempt, failure.retry_after.as_deref())?;
        log_retry(attempt, failure.status, delay);
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

fn exhausted(outcomes: &[String], error: &AppStoreError, at_pod: bool) -> AppStoreError {
    let stage = if at_pod {
        "sign-in at Store pod"
    } else {
        "sign-in"
    };
    AppStoreError::AuthenticationFailed(format!(
        "{stage}: authentication request failed after {MAX_REQUEST_ATTEMPTS} attempts ({}): {error}",
        outcomes.join(", ")
    ))
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 204 | 403 | 404 | 429) || status.is_server_error()
}

fn retry_delay(attempt: u32, retry_after: Option<&str>) -> Result<Duration, AppStoreError> {
    let backoff = RETRY_DELAY
        .saturating_mul(1 << (attempt - 1))
        .min(MAX_RETRY_DELAY);
    // ponytail: only delta-seconds Retry-After is parsed; HTTP-date values
    // (which upstream also accepts) fall back to the backoff.
    let Some(seconds) = retry_after.and_then(|value| value.trim().parse::<u64>().ok()) else {
        return Ok(backoff);
    };
    let requested = Duration::from_secs(seconds);
    if requested > MAX_RETRY_DELAY {
        return Err(AppStoreError::AuthenticationFailed(format!(
            "apple requested a wait longer than {}s; try again later",
            MAX_RETRY_DELAY.as_secs()
        )));
    }
    Ok(requested.max(MIN_RETRY_AFTER))
}

/// Outer `Err` is final; inner `Err` is a transient candidate.
async fn send_once(
    context: &mut LoginContext<'_>,
    url: &str,
    body: &[u8],
) -> Result<Result<AuthResponse, Transient>, AppStoreError> {
    let signature = (context.sign)(body)?;
    let mut request = context
        .client
        .post(url)
        .header("Content-Type", "application/x-apple-plist")
        .header("User-Agent", STORE_USER_AGENT);
    for (key, value) in AMS_SESSION_HEADERS {
        request = request.header(key, value);
    }
    for (key, value) in request_machine_headers(&context.machine_headers) {
        request = request.header(key, value);
    }
    if let Some(storefront) = &context.storefront_hint {
        request = request.header("X-Apple-Store-Front", storefront);
    }
    let request = request
        .header(
            "X-Apple-ActionSignature",
            base64::engine::general_purpose::STANDARD.encode(signature),
        )
        .body(body.to_vec());
    match send_with_observability(context.client, request).await {
        Ok(response) => read_response(response).await,
        Err(error) => transport_failure(&error),
    }
}

/// Upstream renames `X-Apple-I-MD`/`-M` to `X-Apple-AMD`/`-M` on the Store
/// request; every other anisette header goes out unchanged.
fn request_machine_headers(headers: &HashMap<String, String>) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(key, value)| {
            let renamed = if key.eq_ignore_ascii_case(MACHINE_ID_HEADER) {
                "X-Apple-AMD".to_string()
            } else if key.eq_ignore_ascii_case(MACHINE_ID_M_HEADER) {
                "X-Apple-AMD-M".to_string()
            } else {
                key.clone()
            };
            (renamed, value.clone())
        })
        .collect()
}

fn transport_failure(
    error: &reqwest::Error,
) -> Result<Result<AuthResponse, Transient>, AppStoreError> {
    let wrapped = AppStoreError::NetworkError(format!("authentication request failed: {error}"));
    if is_transient_transport(error) {
        Ok(Err(Transient {
            status: None,
            retry_after: None,
            error: wrapped,
        }))
    } else {
        Err(wrapped)
    }
}

fn is_transient_transport(error: &reqwest::Error) -> bool {
    if error.is_timeout() {
        return true;
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::{BrokenPipe, ConnectionReset, TimedOut, UnexpectedEof};
            if matches!(
                io.kind(),
                BrokenPipe | ConnectionReset | TimedOut | UnexpectedEof
            ) {
                return true;
            }
        }
        source = cause.source();
    }
    false
}

async fn read_response(
    response: reqwest::Response,
) -> Result<Result<AuthResponse, Transient>, AppStoreError> {
    let status = response.status();
    let headers = response.headers().clone();
    let retry_after = header(&headers, RETRY_AFTER.as_str());
    let body = match read_response_bytes(response).await {
        Ok(body) => body,
        Err(error) => return transport_failure(&error),
    };
    if is_authentication_redirect(status) && header(&headers, LOCATION.as_str()).is_none() {
        return Err(unexpected(
            status,
            "authentication redirect is missing Location",
            body.len(),
        ));
    }
    if status.is_redirection() {
        return Ok(Ok(AuthResponse {
            status,
            headers,
            body: plist::Dictionary::new(),
        }));
    }
    let reason = if status == StatusCode::TOO_MANY_REQUESTS {
        "rate limited by Apple"
    } else {
        "empty or non-plist authentication response"
    };
    match decode_store_plist(&body) {
        Ok(body) => Ok(Ok(AuthResponse {
            status,
            headers,
            body,
        })),
        Err(_) => Ok(Err(Transient {
            status: Some(status),
            retry_after,
            error: unexpected(status, reason, body.len()),
        })),
    }
}

fn log_auth_response(url: &str, response: &AuthResponse, attempt: u32) {
    let status = response.status.as_u16();
    let failure_type = apple_code(&text(&response.body, "failureType"));
    let customer_message = apple_code(&text(&response.body, "customerMessage"));
    tracing::debug!(service = "ipakeep", component = "appstore", operation = "login", event_name = "appstore.login.response", endpoint = %endpoint(url), status, attempt, failure_type = %failure_type, customer_message = %customer_message, "Store sign-in response received");
}

/// Only the action code: `X-Apple-AMD-Data` is a provisioning challenge.
fn log_machine_action(action: &str) {
    tracing::info!(service = "ipakeep", component = "appstore", operation = "login", event_name = "appstore.login.machine_action", action = %apple_code(action), "Apple requested an authentication machine action");
}

fn log_redirect(target: &str, redirects: u32) {
    tracing::debug!(service = "ipakeep", component = "appstore", operation = "login", event_name = "appstore.login.redirect", endpoint = %endpoint(target), redirects, "Store sign-in redirected");
}

fn log_retry(attempt: u32, status: Option<StatusCode>, delay: Duration) {
    let status = status.map_or(0, |status| status.as_u16());
    let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    tracing::warn!(
        service = "ipakeep",
        component = "appstore",
        operation = "login",
        event_name = "appstore.login.retry",
        attempt,
        status,
        delay_ms,
        outcome = "retry",
        "Store sign-in request failed transiently; retrying"
    );
}

/// Never echo bodies: authentication responses can carry credentials.
fn unexpected(status: StatusCode, reason: &str, length: usize) -> AppStoreError {
    let advice = if status == StatusCode::TOO_MANY_REQUESTS {
        "apple rate limited authentication; try again later"
    } else {
        "apple returned no usable authentication response; try again later or from another network"
    };
    AppStoreError::AuthenticationFailed(format!(
        "{advice}: unexpected response from Apple (HTTP {}): {reason} (body length={length})",
        status.as_u16()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const GUID: &str = "AABBCCDDEEFF";
    const AUTH_PATH: &str = "/WebObjects/MZFinance.woa/wa/authenticate/";
    const EMAIL: &str = "user@example.com";
    const PASSWORD: &str = "secret";

    fn plist_body(entries: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>{entries}</dict></plist>"
        )
    }

    fn success_body() -> String {
        plist_body(
            "<key>passwordToken</key><string>pt</string>\
             <key>dsPersonId</key><string>8765</string>\
             <key>accountInfo</key><dict><key>appleId</key><string>real@example.com</string>\
             <key>address</key><dict><key>firstName</key><string>Jane</string><key>lastName</key><string>Doe</string></dict></dict>",
        )
    }

    fn success() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header(HEADER_STORE_FRONT, "143441-1,29")
            .insert_header(HEADER_POD, "48")
            .append_header("Set-Cookie", "mz_at_ssl-8765=abc; Path=/")
            .set_body_string(success_body())
    }

    fn message(text: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_string(plist_body(&format!(
            "<key>customerMessage</key><string>{text}</string>"
        )))
    }

    fn permissive(value: &str) -> Result<Url, AppStoreError> {
        Url::parse(value).map_err(|_| AppStoreError::AuthenticationFailed("bad".into()))
    }

    struct Harness {
        server: MockServer,
        signed: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Harness {
        async fn new() -> Self {
            Self {
                server: MockServer::start().await,
                signed: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn respond(&self, route: &str, response: ResponseTemplate, times: u64) {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(response)
                .up_to_n_times(times)
                .with_priority(1)
                .mount(&self.server)
                .await;
        }

        async fn login(
            &self,
            code: Option<&str>,
            headers: HashMap<String, String>,
        ) -> Result<Account, AppStoreError> {
            self.login_with(code, headers, |_| async {
                Err(AppStoreError::Unexpected("no SP".into()))
            })
            .await
        }

        async fn login_with<P, Fut>(
            &self,
            code: Option<&str>,
            headers: HashMap<String, String>,
            provision: P,
        ) -> Result<Account, AppStoreError>
        where
            P: FnOnce(String) -> Fut,
            Fut: Future<Output = Result<HashMap<String, String>, AppStoreError>>,
        {
            let client = crate::infrastructure::http::client_builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client");
            let recorder = Arc::clone(&self.signed);
            let mut sign = move |body: &[u8]| {
                recorder.lock().expect("lock").push(body.to_vec());
                Ok(b"signature".to_vec())
            };
            let endpoint = format!("{}{AUTH_PATH}", self.server.uri());
            let mut context = LoginContext {
                client: &client,
                endpoint: &endpoint,
                guid: GUID,
                sign: &mut sign,
                machine_headers: headers,
                storefront_hint: None,
                validate_redirect: permissive,
            };
            let credentials = Credentials {
                email: EMAIL,
                password: PASSWORD,
                auth_code: code,
            };
            login(&mut context, credentials, provision).await
        }

        async fn requests(&self) -> Vec<Request> {
            self.server.received_requests().await.expect("recorded")
        }
    }

    fn sent(request: &Request) -> plist::Dictionary {
        decode_store_plist(&request.body).expect("plist body")
    }

    fn field(dict: &plist::Dictionary, key: &str) -> String {
        text(dict, key)
    }

    fn header_of(request: &Request, name: &str) -> Option<String> {
        request
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    #[tokio::test]
    async fn signs_exact_body_and_parses_account() {
        let harness = Harness::new().await;
        harness.respond(AUTH_PATH, success(), 1).await;
        let headers = HashMap::from([
            (MACHINE_ID_HEADER.to_string(), "md".to_string()),
            (MACHINE_ID_M_HEADER.to_string(), "mdm".to_string()),
            ("X-Apple-I-MD-RINFO".to_string(), "17106176".to_string()),
        ]);
        let account = harness.login(None, headers).await.expect("account");
        assert_eq!(account.password_token, "pt");
        assert_eq!(account.directory_services_id, "8765");
        assert_eq!(account.dsid.as_deref(), Some("8765"));
        assert_eq!(account.email, "real@example.com");
        assert_eq!(account.name, "Jane Doe");
        assert_eq!(account.store_front, "143441-1,29");
        assert_eq!(account.pod, "48");
        assert_eq!(account.cookies, ["mz_at_ssl-8765=abc; Path=/"]);
        let requests = harness.requests().await;
        assert_eq!(harness.signed.lock().expect("lock")[0], requests[0].body);
        assert_signed_request(&requests[0]);
    }

    fn assert_signed_request(request: &Request) {
        let credentials = Credentials {
            email: EMAIL,
            password: PASSWORD,
            auth_code: None,
        };
        assert_eq!(
            request.body,
            login_body(credentials, "", GUID, 1).expect("body")
        );
        for (name, value) in [
            ("X-Apple-ActionSignature", "c2lnbmF0dXJl"),
            ("Content-Type", "application/x-apple-plist"),
            ("User-Agent", STORE_USER_AGENT),
            ("X-Apple-AMD", "md"),
            ("X-Apple-AMD-M", "mdm"),
            ("X-Apple-I-MD-RINFO", "17106176"),
            ("Accept-Language", "en"),
            ("X-Apple-Client-Application", "me.majd.ipatool"),
            ("X-Apple-TZ", "0"),
        ] {
            assert_eq!(header_of(request, name).as_deref(), Some(value), "{name}");
        }
        assert_eq!(header_of(request, MACHINE_ID_HEADER), None);
        let body = sent(request);
        let keys: Vec<&str> = body.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "appleId",
                "attempt",
                "createSession",
                "credentialSource",
                "deviceOffersCheck",
                "guid",
                "isSilentAuthentication",
                "password",
                "passwordSettings",
                "rmp",
                "why"
            ]
        );
        assert_eq!(
            body.get("createSession"),
            Some(&plist::Value::Boolean(true))
        );
        assert_eq!(field(&body, "credentialSource"), "0");
        assert_eq!(field(&body, "deviceOffersCheck"), "true");
        assert_eq!(
            body.get("isSilentAuthentication"),
            Some(&plist::Value::Boolean(false))
        );
        let settings = body
            .get("passwordSettings")
            .and_then(plist::Value::as_dictionary)
            .expect("password settings");
        assert_eq!(field(settings, "free"), "always");
        assert_eq!(field(settings, "paid"), "always");
        assert!(
            request
                .body
                .starts_with(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist")
        );
        assert_eq!(field(&body, "why"), "signIn");
        assert_eq!(field(&body, "rmp"), "0");
        assert_eq!(field(&body, "guid"), GUID);
    }

    #[tokio::test]
    async fn reports_2fa_and_appends_the_code_to_the_password() {
        let harness = Harness::new().await;
        harness
            .respond(AUTH_PATH, message(MESSAGE_BAD_LOGIN), 2)
            .await;
        let error = harness.login(None, HashMap::new()).await.expect_err("2fa");
        assert!(matches!(error, AppStoreError::AuthCodeRequired { .. }));
        let error = harness
            .login(Some(" 123 456 "), HashMap::new())
            .await
            .expect_err("stale");
        assert!(error.to_string().contains("try a fresh 2FA code"));
        let requests = harness.requests().await;
        assert_eq!(field(&sent(&requests[1]), "password"), "secret123456");
    }

    #[tokio::test]
    async fn follows_pod_redirect_with_the_same_body() {
        let harness = Harness::new().await;
        let pod = format!("{}/pod42/authenticate", harness.server.uri());
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(302).insert_header("Location", pod.as_str()),
                1,
            )
            .await;
        harness.respond("/pod42/authenticate", success(), 1).await;
        assert!(harness.login(None, HashMap::new()).await.is_ok());
        let requests = harness.requests().await;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].url.path(), "/pod42/authenticate");
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(field(&sent(&requests[1]), "attempt"), "1");
    }

    #[tokio::test]
    async fn rejects_redirects_outside_apple_pods() {
        let harness = Harness::new().await;
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(302).insert_header("Location", "https://example.com/steal"),
                1,
            )
            .await;
        let client = super::super::bag::store_client(Arc::new(reqwest::cookie::Jar::default()))
            .expect("client");
        let mut sign = |_: &[u8]| Ok(Vec::new());
        let endpoint = format!("{}{AUTH_PATH}", harness.server.uri());
        let mut context = LoginContext {
            client: &client,
            endpoint: &endpoint,
            guid: GUID,
            sign: &mut sign,
            machine_headers: HashMap::new(),
            storefront_hint: Some("143465".into()),
            validate_redirect: LoginContext::DEFAULT_REDIRECT_POLICY,
        };
        let credentials = Credentials {
            email: EMAIL,
            password: PASSWORD,
            auth_code: None,
        };
        let error = login(&mut context, credentials, |_| async { Ok(HashMap::new()) })
            .await
            .expect_err("redirect");
        assert!(
            error
                .to_string()
                .contains("invalid authentication redirect")
        );
        assert_eq!(
            header_of(&harness.requests().await[0], "X-Apple-Store-Front").as_deref(),
            Some("143465")
        );
    }

    #[tokio::test]
    async fn retries_invalid_credentials_once_with_attempt_two() {
        let harness = Harness::new().await;
        let invalid = ResponseTemplate::new(200)
            .set_body_string(plist_body("<key>failureType</key><string>-5000</string>"));
        harness.respond(AUTH_PATH, invalid, 2).await;
        let error = harness
            .login(None, HashMap::new())
            .await
            .expect_err("invalid");
        assert!(matches!(error, AppStoreError::InvalidCredentials));
        let requests = harness.requests().await;
        assert_eq!(field(&sent(&requests[1]), "attempt"), "2");
    }

    #[tokio::test]
    async fn handles_reset_then_store_provisioning_actions() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let harness = Harness::new().await;
        let action = |name: &str| {
            ResponseTemplate::new(200)
                .insert_header(HEADER_AMD_ACTION, name)
                .insert_header(HEADER_AMD_DATA, "spdata")
                .set_body_string(plist_body(""))
        };
        harness.respond(AUTH_PATH, action("RP"), 1).await;
        harness.respond(AUTH_PATH, action("SP"), 1).await;
        harness.respond(AUTH_PATH, success(), 1).await;
        let headers = HashMap::from([
            (MACHINE_ID_HEADER.to_string(), "md".to_string()),
            ("X-Mme-Device-Id".to_string(), "dev".to_string()),
        ]);
        let seen = Arc::new(Mutex::new(String::new()));
        let recorder = Arc::clone(&seen);
        let account = harness
            .login_with(None, headers, move |data| async move {
                *recorder.lock().expect("lock") = data;
                Ok(HashMap::from([(
                    MACHINE_ID_HEADER.to_string(),
                    "store-amd".to_string(),
                )]))
            })
            .await;
        assert!(account.is_ok());
        assert_eq!(*seen.lock().expect("lock"), "spdata");
        let requests = harness.requests().await;
        let amd = |index: usize| header_of(&requests[index], "X-Apple-AMD");
        assert_eq!(amd(0).as_deref(), Some("md"));
        assert_eq!(amd(1), None);
        assert_eq!(amd(2).as_deref(), Some("store-amd"));
        assert_eq!(
            header_of(&requests[1], "X-Mme-Device-Id").as_deref(),
            Some("dev")
        );
        assert_eq!(header_of(&requests[2], "X-Mme-Device-Id"), None);
        let logs = capture.contents();
        assert!(logs.contains("appstore.login.machine_action"));
        assert!(logs.contains("action=RP") && logs.contains("action=SP"));
        for secret in ["spdata", "store-amd"] {
            assert!(!logs.contains(secret), "{secret} leaked");
        }
    }

    fn action(name: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header(HEADER_AMD_ACTION, name)
            .set_body_string(plist_body(""))
    }

    async fn failure_message(harness: &Harness) -> String {
        harness
            .login(None, HashMap::new())
            .await
            .expect_err("sign-in failure")
            .to_string()
    }

    #[tokio::test]
    async fn rejects_repeated_or_unknown_machine_actions() {
        let harness = Harness::new().await;
        harness.respond(AUTH_PATH, action("RP"), 2).await;
        assert!(
            failure_message(&harness)
                .await
                .contains("apple requested an authentication machine action: RP")
        );
        let harness = Harness::new().await;
        harness.respond(AUTH_PATH, action("SP"), 2).await;
        let error = harness
            .login_with(None, HashMap::new(), |_| async { Ok(HashMap::new()) })
            .await
            .expect_err("second SP");
        assert!(error.to_string().contains("machine action: SP"));
    }

    #[tokio::test]
    async fn gives_up_after_too_many_redirects() {
        let harness = Harness::new().await;
        let back = format!("{}{AUTH_PATH}", harness.server.uri());
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(302).insert_header("Location", back.as_str()),
                u64::MAX,
            )
            .await;
        assert!(
            failure_message(&harness)
                .await
                .contains("too many authentication redirects (HTTP 302)")
        );
        assert_eq!(harness.requests().await.len(), 5);
    }

    #[tokio::test]
    async fn rejects_unusable_redirects() {
        for (response, expected) in [
            (
                ResponseTemplate::new(303),
                "failed to retrieve redirect location (HTTP 303) [destination: invalid URL]",
            ),
            (
                ResponseTemplate::new(303).insert_header("Location", "/pod"),
                "unsupported authentication redirect status (HTTP 303)",
            ),
            (
                ResponseTemplate::new(302).insert_header("Location", "http://[::1"),
                "invalid authentication redirect location (HTTP 302) [destination: invalid URL]",
            ),
            (
                ResponseTemplate::new(302),
                "authentication redirect is missing Location",
            ),
        ] {
            let harness = Harness::new().await;
            harness.respond(AUTH_PATH, response, 1).await;
            let message = failure_message(&harness).await;
            assert!(message.contains(expected), "{message}");
        }
    }

    #[tokio::test]
    async fn surfaces_dialogs_and_unusable_success_responses() {
        for (body, expected) in [
            (
                "<key>dialog</key><dict><key>message</key><string>Locked.</string></dict>",
                "Locked.",
            ),
            (
                "<key>status</key><integer>0</integer>",
                "apple returned no usable authentication response (HTTP 200)",
            ),
            (
                "<key>failureType</key><string>9999</string>",
                "something went wrong",
            ),
            (
                "<key>failureType</key><string>9999</string>\
                 <key>customerMessage</key><string>Custom failure</string>",
                "Custom failure",
            ),
        ] {
            let harness = Harness::new().await;
            harness
                .respond(
                    AUTH_PATH,
                    ResponseTemplate::new(200).set_body_string(plist_body(body)),
                    1,
                )
                .await;
            let message = failure_message(&harness).await;
            assert!(message.contains(expected), "{message}");
        }
    }

    fn dialog(entries: &str, extra: &str) -> Option<String> {
        let body = plist_body(&format!("<key>dialog</key><dict>{entries}</dict>{extra}"));
        dialog_error(&decode_store_plist(body.as_bytes()).expect("dialog"))
    }

    #[test]
    fn formats_partial_dialogs() {
        assert_eq!(dialog("", ""), None);
        assert_eq!(
            dialog("<key>okButtonString</key><string>OK</string>", ""),
            None
        );
        assert_eq!(
            dialog(
                "<key>okButtonString</key><string>OK</string>",
                "<key>customerMessage</key><string>Fallback</string>"
            )
            .as_deref(),
            Some("Fallback")
        );
        assert_eq!(
            dialog(
                "<key>okButtonAction</key><dict><key>kind</key><string>OpenURL</string>\
                 <key>url</key><string>https://support.apple.com/x</string></dict>",
                ""
            )
            .as_deref(),
            Some(
                "Apple requires action before sign-in can continue (Continue: https://support.apple.com/x)"
            )
        );
        assert_eq!(
            dialog(
                "<key>okButtonAction</key><dict><key>url</key><string>https://support.apple.com/x</string></dict>",
                ""
            ),
            None
        );
    }

    fn response_with(headers: &[(&'static str, &'static str)]) -> AuthResponse {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.append(*name, value.parse().expect("header value"));
        }
        AuthResponse {
            status: StatusCode::OK,
            headers: map,
            body: plist::Dictionary::new(),
        }
    }

    #[test]
    fn falls_back_to_header_and_cookie_dsids() {
        let dsid = |headers: &[(&'static str, &'static str)]| {
            account_from(&response_with(headers), EMAIL, Vec::new())
                .map(|account| account.directory_services_id)
        };
        assert_eq!(
            dsid(&[(HEADER_STORE_FRONT, "143441-1,29"), ("X-Dsid", "11")]).ok(),
            Some("11".into())
        );
        assert_eq!(
            dsid(&[
                (HEADER_REQUEST_STORE_FRONT, "143441-1,29"),
                ("Set-Cookie", "other=1"),
                ("Set-Cookie", "mz_at0-22=x; Path=/"),
            ])
            .ok(),
            Some("22".into())
        );
        assert!(matches!(
            dsid(&[(HEADER_STORE_FRONT, "143441-1,29")]),
            Err(AppStoreError::AuthenticationFailed(m)) if m.contains("directory services identifier")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn reports_exhausted_retries_at_the_pod_and_rate_limits() {
        let harness = Harness::new().await;
        let pod = format!("{}/pod42/authenticate", harness.server.uri());
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(302).insert_header("Location", pod.as_str()),
                1,
            )
            .await;
        harness
            .respond(
                "/pod42/authenticate",
                ResponseTemplate::new(429).insert_header("Retry-After", "1"),
                3,
            )
            .await;
        let message = failure_message(&harness).await;
        assert!(message.contains("sign-in at Store pod: authentication request failed after 3 attempts (HTTP 429, HTTP 429, HTTP 429)"), "{message}");
        assert!(message.contains("apple rate limited authentication"));
        assert!(message.contains("rate limited by Apple"));
    }

    async fn login_at(client: &reqwest::Client, endpoint: &str) -> Result<Account, AppStoreError> {
        let mut sign = |_: &[u8]| Ok(Vec::new());
        let mut context = LoginContext {
            client,
            endpoint,
            guid: GUID,
            sign: &mut sign,
            machine_headers: HashMap::new(),
            storefront_hint: None,
            validate_redirect: permissive,
        };
        let credentials = Credentials {
            email: EMAIL,
            password: PASSWORD,
            auth_code: None,
        };
        login(&mut context, credentials, |_| async { Ok(HashMap::new()) }).await
    }

    /// Answers every connection with `reply`, then closes it (with a TCP
    /// reset when `reset` is set).
    async fn raw_server(reply: &'static [u8], reset: bool) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = vec![0; 64 * 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(reply).await;
                if reset {
                    let _ = stream.set_zero_linger();
                }
            }
        });
        format!("http://{address}{AUTH_PATH}")
    }

    fn plain_client() -> reqwest::Client {
        crate::infrastructure::http::client_builder()
            .build()
            .expect("client")
    }

    #[tokio::test]
    async fn refused_connections_fail_without_retrying() {
        let error = login_at(&plain_client(), "http://127.0.0.1:1/authenticate")
            .await
            .expect_err("refused");
        assert!(
            matches!(error, AppStoreError::NetworkError(m) if m.starts_with("authentication request failed"))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_connection_resets() {
        let endpoint = raw_server(b"", true).await;
        let error = login_at(&plain_client(), &endpoint)
            .await
            .expect_err("reset");
        assert!(
            error
                .to_string()
                .contains("after 3 attempts (transport error, transport error, transport error)"),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_truncated_bodies() {
        let endpoint =
            raw_server(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc", false).await;
        let error = login_at(&plain_client(), &endpoint)
            .await
            .expect_err("truncated");
        assert!(
            error.to_string().contains("authentication request failed"),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_timeouts() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
            .mount(&server)
            .await;
        let client = crate::infrastructure::http::client_builder()
            .timeout(Duration::from_millis(50))
            .build()
            .expect("client");
        let error = login_at(&client, &format!("{}{AUTH_PATH}", server.uri()))
            .await
            .expect_err("timeout");
        assert!(
            error
                .to_string()
                .contains("after 3 attempts (transport error"),
            "{error}"
        );
    }

    #[test]
    fn ignores_null_request_store_front() {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER_REQUEST_STORE_FRONT, "<null>".parse().expect("value"));
        let response = AuthResponse {
            status: StatusCode::OK,
            headers,
            body: plist::Dictionary::new(),
        };
        assert!(account_from(&response, EMAIL, Vec::new()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn retries_transient_statuses_then_succeeds() {
        let harness = Harness::new().await;
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(503).set_body_string("<html>busy</html>"),
                1,
            )
            .await;
        harness
            .respond(AUTH_PATH, ResponseTemplate::new(204), 1)
            .await;
        harness.respond(AUTH_PATH, success(), 1).await;
        assert!(harness.login(None, HashMap::new()).await.is_ok());
        assert_eq!(harness.requests().await.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_after_three_transient_failures_and_never_retries_401() {
        let harness = Harness::new().await;
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(403).set_body_string("<html>no</html>"),
                3,
            )
            .await;
        let error = harness
            .login(None, HashMap::new())
            .await
            .expect_err("exhausted");
        assert!(
            error
                .to_string()
                .contains("after 3 attempts (HTTP 403, HTTP 403, HTTP 403)")
        );
        let harness = Harness::new().await;
        harness
            .respond(
                AUTH_PATH,
                ResponseTemplate::new(401).set_body_string("<html>no</html>"),
                3,
            )
            .await;
        assert!(harness.login(None, HashMap::new()).await.is_err());
        assert_eq!(harness.requests().await.len(), 1);
    }

    #[tokio::test]
    async fn surfaces_disabled_accounts_and_trusted_dialogs() {
        let harness = Harness::new().await;
        harness
            .respond(AUTH_PATH, message(MESSAGE_ACCOUNT_DISABLED), 1)
            .await;
        assert!(matches!(
            harness.login(None, HashMap::new()).await,
            Err(AppStoreError::AccountDisabled)
        ));
        let dialog = plist_body(
            "<key>dialog</key><dict><key>message</key><string>Locked.</string>\
             <key>explanation</key><string>Reset your password.</string>\
             <key>okButtonString</key><string>Reset</string>\
             <key>okButtonAction</key><dict><key>kind</key><string>OpenURL</string>\
             <key>url</key><string>https://iforgot.apple.com/cgi-bin/iforgot.cgi</string></dict></dict>",
        );
        let parsed = decode_store_plist(dialog.as_bytes()).expect("dialog");
        assert_eq!(
            dialog_error(&parsed).as_deref(),
            Some(
                "Locked.: Reset your password. (Reset: https://iforgot.apple.com/cgi-bin/iforgot.cgi)"
            )
        );
        assert_eq!(
            trusted_dialog_url("OpenURL", "https://evil.example/x"),
            None
        );
        assert_eq!(
            trusted_dialog_url("OpenURL", "http://iforgot.apple.com/"),
            None
        );
        assert_eq!(
            trusted_dialog_url("Buy", "https://iforgot.apple.com/"),
            None
        );
    }

    #[test]
    fn reads_dsid_from_headers_and_cookies() {
        assert_eq!(
            cookie_dsid("mz_at0-12345=token; Path=/").as_deref(),
            Some("12345")
        );
        assert_eq!(cookie_dsid("a=b, mz_at_ssl-777=x").as_deref(), Some("777"));
        assert_eq!(cookie_dsid("xmz_at0-1=x"), None);
        assert_eq!(cookie_dsid("mz_at0-=x"), None);
    }

    #[test]
    fn normalizes_auth_codes() {
        assert_eq!(normalize_auth_code("").expect("empty"), "");
        assert_eq!(normalize_auth_code(" 123 456\n").expect("spaces"), "123456");
        assert_eq!(
            normalize_auth_code("\x1b[200~123456\x1b[201~").expect("paste"),
            "123456"
        );
        for bad in [
            " \t",
            "12345",
            "1234567",
            "12345a",
            "１２３４５６",
            "\x1b[31m123456",
            "\x1b[200~123456",
            "\x1b[200~\x1b[201~",
            "123\x1b[200~456\x1b[201~",
        ] {
            assert!(normalize_auth_code(bad).is_err(), "{bad:?}");
        }
    }

    const CN_NUMBERS: &[&str] = &[
        "13912345678",
        "+8613912345678",
        "008613912345678",
        "8613912345678",
        " +86 139-1234-5678 ",
    ];
    const IN_NUMBERS: &[&str] = &[
        "9123456789",
        "8612345678",
        "6123456789",
        "09123456789",
        "+919123456789",
        "00919123456789",
        "919123456789",
        "+91 91234-56789",
    ];
    const NON_HINT_IDS: &[&str] = &[
        "person@example.test",
        "13912345678@example.test",
        "",
        " -- ",
        "+",
        "00",
        "139x12345678",
        "+８６１３９１２３４５６７８",
        "139+12345678",
        "++8613912345678",
        "+008613912345678",
        "+13912345678",
        "0013912345678",
        "+8612345678",
        "+9123456789",
        "+861391234567",
        "+86139123456789",
        "8609123456789",
        "+8623912345678",
        "+91912345678",
        "+9191234567890",
        "+915123456789",
        "+9109123456789",
    ];

    #[test]
    fn detects_phone_number_storefront_hints() {
        for (ids, expected) in [
            (CN_NUMBERS, Some("CN")),
            (IN_NUMBERS, Some("IN")),
            (NON_HINT_IDS, None),
        ] {
            for id in ids {
                assert_eq!(phone_number_country_code(id), expected, "{id:?}");
            }
        }
    }

    #[test]
    fn computes_backoff_and_retry_after() {
        assert_eq!(retry_delay(1, None).ok(), Some(Duration::from_secs(10)));
        assert_eq!(retry_delay(2, None).ok(), Some(Duration::from_secs(20)));
        assert_eq!(retry_delay(3, None).ok(), Some(Duration::from_secs(30)));
        assert_eq!(retry_delay(1, Some("0")).ok(), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(1, Some("5")).ok(), Some(Duration::from_secs(5)));
        assert!(retry_delay(1, Some("31")).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn logs_retries_redirects_and_codes_without_credentials() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let harness = Harness::new().await;
        let pod = format!(
            "{}/pod42/authenticate?ticket=query-secret",
            harness.server.uri()
        );
        let busy = ResponseTemplate::new(503).set_body_string("busy-body-secret");
        harness.respond(AUTH_PATH, busy, 1).await;
        let redirect = ResponseTemplate::new(302).insert_header("Location", pod.as_str());
        harness.respond(AUTH_PATH, redirect, 1).await;
        harness.respond("/pod42/authenticate", success(), 1).await;
        let headers = HashMap::from([(MACHINE_ID_HEADER.to_string(), "otp-secret".to_string())]);

        harness
            .login(Some("123456"), headers)
            .await
            .expect("account");

        let logs = capture.contents();
        for event in [
            "appstore.login.retry",
            "appstore.login.redirect",
            "appstore.login.response",
            "http.response.headers_received",
        ] {
            assert!(logs.contains(event), "missing {event}");
        }
        assert!(logs.contains("/pod42/authenticate") && logs.contains("status=503"));
        for secret in [
            PASSWORD,
            "123456",
            EMAIL,
            "real@example.com",
            GUID,
            "query-secret",
            "busy-body-secret",
            "otp-secret",
            "c2lnbmF0dXJl",
            "mz_at_ssl",
            "8765",
        ] {
            assert!(!logs.contains(secret), "{secret} leaked");
        }
    }

    #[tokio::test]
    async fn logs_apple_codes_but_redacts_free_text_messages() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let harness = Harness::new().await;
        let failure = plist_body(
            "<key>failureType</key><string>2034</string>\
             <key>customerMessage</key><string>The Apple ID user@example.com is locked</string>",
        );
        let response = ResponseTemplate::new(200).set_body_string(failure);
        harness.respond(AUTH_PATH, response, 1).await;

        assert!(harness.login(None, HashMap::new()).await.is_err());

        let logs = capture.contents();
        assert!(logs.contains("failure_type=2034"));
        assert!(logs.contains("customer_message=redacted"));
        assert!(!logs.contains(EMAIL) && !logs.contains("locked"));
    }
}
