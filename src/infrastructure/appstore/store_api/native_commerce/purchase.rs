//! Free-app license acquisition (`MZFinance` `buyProduct`).
//!
//! Ported from ipatool `pkg/appstore/appstore_purchase.go` plus the 2034
//! handling of the former `tools/modern-anisette/store.go` helper.

use super::bag::{AMS_SESSION_HEADERS, STORE_USER_AGENT, decode_store_plist, encode_request_plist};
use super::telemetry::{apple_code, error_type};
use crate::domain::entity::Account;
use crate::domain::error::AppStoreError;
use crate::infrastructure::http::telemetry::{read_response_bytes, send_with_observability};
use std::future::Future;

const BUY_HOST: &str = "buy.itunes.apple.com";
const PURCHASE_PATH: &str = "/WebObjects/MZFinance.woa/wa/buyProduct";
const PRICING_APP_STORE: &str = "STDQ";
const PRICING_ARCADE: &str = "GAME";
const FAILURE_TEMPORARILY_UNAVAILABLE: &str = "2059";
const FAILURE_PASSWORD_TOKEN_EXPIRED: &str = "2034";
const FAILURE_SIGN_IN_REQUIRED: &str = "2042";
const FAILURE_DEVICE_VERIFICATION: &str = "1008";
const FAILURE_LICENSE_EXISTS: &str = "5002";
const MESSAGE_SUBSCRIPTION_REQUIRED: &str = "Subscription Required";
const MESSAGE_PASSWORD_CHANGED: &str = "Your password has changed.";
const PURCHASE_SUCCESS: &str = "purchaseSuccess";
const UUID_LEN: usize = 16;
const UUID_VERSION_BYTE: usize = 6;
const UUID_VARIANT_BYTE: usize = 8;
const UUID_GROUPS: [usize; 5] = [4, 2, 2, 2, 6];
const UUID_LOW_NIBBLE: u8 = 0x0f;
const UUID_VERSION_4: u8 = 0x40;
const UUID_VARIANT_MASK: u8 = 0x3f;
const UUID_VARIANT_RFC4122: u8 = 0x80;

/// `https://p{pod}-buy.itunes.apple.com/.../buyProduct` (no prefix without a pod).
#[must_use]
pub fn purchase_url(pod: &str) -> String {
    let prefix = if pod.is_empty() {
        String::new()
    } else {
        format!("p{pod}-")
    };
    format!("https://{prefix}{BUY_HOST}{PURCHASE_PATH}")
}

/// Request inputs besides the account and app.
pub struct PurchaseContext<'a> {
    /// Store client (see [`super::bag::store_client`]).
    pub client: &'a reqwest::Client,
    /// Usually [`purchase_url`] of the account's pod.
    pub url: &'a str,
    /// Uppercase hex machine GUID.
    pub guid: &'a str,
}

/// Outcome of one `buyProduct` attempt that is not a plain failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attempt {
    Purchased,
    AlreadyOwned,
    TemporarilyUnavailable,
    TokenExpired,
}

/// Acquire the free license for `app_id`: `STDQ`, then `GAME` when Apple
/// answers 2059. A license that already exists is success. When Apple asks
/// for a fresh sign-in (2034/2042/1008, "password has changed"), which it does
/// even for apps the account owns, `owns_license` decides: `Ok` (typically a
/// successful list-versions) means owned and is success.
///
/// # Errors
///
/// Transport and decoding failures, Apple failures, and an expired token
/// when `owns_license` fails.
pub async fn purchase<F, Fut>(
    context: &PurchaseContext<'_>,
    account: &Account,
    app_id: i64,
    owns_license: F,
) -> Result<(), AppStoreError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), AppStoreError>>,
{
    let mut outcome = attempt(context, account, app_id, PRICING_APP_STORE).await?;
    if outcome == Attempt::TemporarilyUnavailable {
        outcome = attempt(context, account, app_id, PRICING_ARCADE).await?;
    }
    match outcome {
        Attempt::Purchased | Attempt::AlreadyOwned => Ok(()),
        Attempt::TokenExpired => {
            let owned = owns_license().await;
            owned.map_err(|error| unconfirmed_license(&error))
        }
        Attempt::TemporarilyUnavailable => Err(unavailable_error()),
    }
}

fn unavailable_error() -> AppStoreError {
    AppStoreError::PurchaseFailed(format!(
        "failed to purchase item with param '{PRICING_ARCADE}': item is temporarily unavailable"
    ))
}

/// Apple asked for a fresh sign-in and no license could be confirmed.
fn unconfirmed_license(error: &AppStoreError) -> AppStoreError {
    tracing::warn!(
        service = "ipakeep",
        component = "appstore",
        operation = "purchase",
        event_name = "appstore.purchase.license_unconfirmed",
        outcome = "failure",
        error_type = error_type(error),
        "Apple asked for a fresh sign-in and the license could not be confirmed"
    );
    expired_token_error()
}

fn expired_token_error() -> AppStoreError {
    AppStoreError::AuthenticationFailed(
        "Apple requires a recent sign-in to acquire this license: password token is expired; run auth login again".into(),
    )
}

async fn attempt(
    context: &PurchaseContext<'_>,
    account: &Account,
    app_id: i64,
    pricing: &str,
) -> Result<Attempt, AppStoreError> {
    let body = purchase_body(context.guid, app_id, pricing, &correlation_key());
    let mut request = context
        .client
        .post(context.url)
        .header("Content-Type", "application/x-apple-plist")
        .header("User-Agent", STORE_USER_AGENT)
        .header("iCloud-DSID", &account.directory_services_id)
        .header("X-Dsid", &account.directory_services_id)
        .header("X-Apple-Store-Front", &account.store_front)
        .header("X-Token", &account.password_token);
    for (name, value) in AMS_SESSION_HEADERS {
        request = request.header(name, value);
    }
    let response = send_with_observability(context.client, request.body(body))
        .await
        .map_err(|error| {
            AppStoreError::NetworkError(format!("purchase request failed: {error}"))
        })?;
    let status = response.status().as_u16();
    let data = read_response_bytes(response)
        .await
        .map_err(|error| AppStoreError::NetworkError(format!("read purchase response: {error}")))?;
    let result = decode_store_plist(&data)?;
    let outcome = classify(status, &result, pricing);
    log_attempt(pricing, status, &result, &outcome);
    outcome
}

fn log_attempt(
    pricing: &str,
    status: u16,
    result: &plist::Dictionary,
    outcome: &Result<Attempt, AppStoreError>,
) {
    let text = |key: &str| {
        apple_code(
            result
                .get(key)
                .and_then(plist::Value::as_string)
                .unwrap_or_default(),
        )
    };
    let (failure_type, customer_message) = (text("failureType"), text("customerMessage"));
    let outcome = match outcome {
        Ok(Attempt::Purchased) => "purchased",
        Ok(Attempt::AlreadyOwned) => "already_owned",
        Ok(Attempt::TemporarilyUnavailable) => "temporarily_unavailable",
        Ok(Attempt::TokenExpired) => "token_expired",
        Err(_) => "failure",
    };
    tracing::debug!(service = "ipakeep", component = "appstore", operation = "purchase", event_name = "appstore.purchase.response", pricing, status, failure_type = %failure_type, customer_message = %customer_message, outcome, "Store purchase response classified");
}

/// The `buyProduct` plist as the Store session sends it: upstream's fields
/// plus `clientCorrelationKey` and `hasBeenAuthedForBuy` from `AMSPurchase`,
/// keys in Core Foundation's sorted order.
#[must_use]
pub fn purchase_body(guid: &str, app_id: i64, pricing: &str, correlation_key: &str) -> Vec<u8> {
    let text = |value: &str| plist::Value::String(value.to_string());
    let mut dict = plist::Dictionary::new();
    dict.insert("appExtVrsId".into(), text("0"));
    dict.insert("buyWithoutAuthorization".into(), text("true"));
    dict.insert("clientCorrelationKey".into(), text(correlation_key));
    dict.insert("guid".into(), text(guid));
    dict.insert("hasAskedToFulfillPreorder".into(), text("true"));
    dict.insert("hasBeenAuthedForBuy".into(), plist::Value::Boolean(true));
    dict.insert("hasDoneAgeCheck".into(), text("true"));
    dict.insert("needDiv".into(), text("0"));
    dict.insert("origPage".into(), text(&format!("Software-{app_id}")));
    dict.insert("origPageLocation".into(), text("Buy"));
    dict.insert("price".into(), text("0"));
    dict.insert("pricingParameters".into(), text(pricing));
    dict.insert("productType".into(), text("C"));
    dict.insert("salableAdamId".into(), plist::Value::Integer(app_id.into()));
    encode_request_plist(&dict)
}

/// A random version 4 UUID in uppercase, like `NSUUID().UUIDString`.
fn correlation_key() -> String {
    let mut bytes = [0u8; UUID_LEN];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes[UUID_VERSION_BYTE] = (bytes[UUID_VERSION_BYTE] & UUID_LOW_NIBBLE) | UUID_VERSION_4;
    bytes[UUID_VARIANT_BYTE] =
        (bytes[UUID_VARIANT_BYTE] & UUID_VARIANT_MASK) | UUID_VARIANT_RFC4122;
    let mut groups = Vec::with_capacity(UUID_GROUPS.len());
    let mut offset = 0;
    for size in UUID_GROUPS {
        groups.push(hex::encode_upper(&bytes[offset..offset + size]));
        offset += size;
    }
    groups.join("-")
}

fn classify(
    status: u16,
    result: &plist::Dictionary,
    pricing: &str,
) -> Result<Attempt, AppStoreError> {
    let text = |key: &str| {
        result
            .get(key)
            .and_then(plist::Value::as_string)
            .unwrap_or_default()
    };
    let failure = text("failureType");
    let message = text("customerMessage");
    let failed = |detail: &str| {
        AppStoreError::PurchaseFailed(format!(
            "failed to purchase item with param '{pricing}': {detail}"
        ))
    };
    if failure == FAILURE_TEMPORARILY_UNAVAILABLE {
        return Ok(Attempt::TemporarilyUnavailable);
    }
    if message == MESSAGE_SUBSCRIPTION_REQUIRED {
        return Err(failed("subscription required"));
    }
    if is_token_expired(failure, message) {
        return Ok(Attempt::TokenExpired);
    }
    if failure == FAILURE_LICENSE_EXISTS {
        return Ok(Attempt::AlreadyOwned);
    }
    if !failure.is_empty() {
        return Err(failed(if message.is_empty() {
            "something went wrong"
        } else {
            message
        }));
    }
    if status == INTERNAL_SERVER_ERROR {
        return Ok(Attempt::AlreadyOwned);
    }
    if text("jingleDocType") != PURCHASE_SUCCESS || purchase_status(result) != 0 {
        return Err(failed("failed to purchase app"));
    }
    Ok(Attempt::Purchased)
}

const INTERNAL_SERVER_ERROR: u16 = 500;

fn is_token_expired(failure: &str, message: &str) -> bool {
    [
        FAILURE_PASSWORD_TOKEN_EXPIRED,
        FAILURE_SIGN_IN_REQUIRED,
        FAILURE_DEVICE_VERIFICATION,
    ]
    .contains(&failure)
        || message == MESSAGE_PASSWORD_CHANGED
}

fn purchase_status(result: &plist::Dictionary) -> i64 {
    match result.get("status") {
        Some(plist::Value::Integer(value)) => value.as_signed().unwrap_or(-1),
        Some(plist::Value::String(value)) => value.parse().unwrap_or(-1),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use std::sync::atomic::{AtomicBool, Ordering};
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    #[tokio::test]
    async fn logs_classified_attempts_without_account_secrets() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let owned = MockServer::start().await;
        let license = failure(
            FAILURE_LICENSE_EXISTS,
            &format!("You already own it, {EMAIL}"),
        );
        mount(&owned, PRICING_APP_STORE, 200, license).await;
        let rejected = MockServer::start().await;
        let subscription = failure("", MESSAGE_SUBSCRIPTION_REQUIRED);
        mount(&rejected, PRICING_APP_STORE, 200, subscription).await;

        assert!(run(&owned, Ok(())).await.0.is_ok());
        assert!(run(&rejected, Ok(())).await.0.is_err());

        let logs = capture.contents();
        assert!(logs.contains("outcome=\"already_owned\"") && logs.contains("failure_type=5002"));
        assert!(logs.contains("outcome=\"failure\"") && logs.contains("customer_message=redacted"));
        for secret in [EMAIL, TOKEN, DSID, GUID] {
            assert!(!logs.contains(secret), "{secret} leaked");
        }
    }

    const GUID: &str = "AABBCCDDEEFF";
    // Distinctive fake secrets: they cannot appear in logs by coincidence.
    const EMAIL: &str = "fake-user-QZ7XM3T6@example.com";
    const TOKEN: &str = "fake-token-QZ7XK4M9";
    const DSID: &str = "9073814265031";
    const APP: i64 = 1_234_567_890;

    fn account() -> Account {
        Account {
            email: EMAIL.into(),
            name: "User".into(),
            password_token: TOKEN.into(),
            directory_services_id: DSID.into(),
            store_front: "143441-1,29".into(),
            pod: "48".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    fn plist_body(entries: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>{entries}</dict></plist>"
        )
    }

    fn success() -> String {
        plist_body(
            "<key>jingleDocType</key><string>purchaseSuccess</string><key>status</key><integer>0</integer>",
        )
    }

    fn failure(code: &str, message: &str) -> String {
        plist_body(&format!(
            "<key>failureType</key><string>{code}</string><key>customerMessage</key><string>{message}</string>"
        ))
    }

    async fn mount(server: &MockServer, pricing: &str, status: u16, body: String) {
        Mock::given(method("POST"))
            .and(path(PURCHASE_PATH))
            .and(body_string_contains(format!("<string>{pricing}</string>")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn run(
        server: &MockServer,
        owned: Result<(), AppStoreError>,
    ) -> (Result<(), AppStoreError>, bool) {
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let url = format!("{}{PURCHASE_PATH}", server.uri());
        let context = PurchaseContext {
            client: &client,
            url: &url,
            guid: GUID,
        };
        let asked = AtomicBool::new(false);
        let result = purchase(&context, &account(), APP, || async {
            asked.store(true, Ordering::SeqCst);
            owned
        })
        .await;
        (result, asked.load(Ordering::SeqCst))
    }

    #[test]
    fn builds_pod_specific_url() {
        assert_eq!(
            purchase_url("48"),
            "https://p48-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
        );
        assert_eq!(
            purchase_url(""),
            "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct"
        );
    }

    #[tokio::test]
    async fn sends_upstream_request_and_accepts_success() {
        let server = MockServer::start().await;
        mount(&server, PRICING_APP_STORE, 200, success()).await;
        let (result, asked) = run(&server, Ok(())).await;
        assert!(result.is_ok());
        assert!(!asked);
        let requests = server.received_requests().await.expect("recorded");
        assert_request(&requests[0]);
    }

    fn assert_request(request: &Request) {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        assert_eq!(
            header("Content-Type").as_deref(),
            Some("application/x-apple-plist")
        );
        assert_eq!(header("User-Agent").as_deref(), Some(STORE_USER_AGENT));
        assert_eq!(header("iCloud-DSID").as_deref(), Some(DSID));
        assert_eq!(header("X-Dsid").as_deref(), Some(DSID));
        assert_eq!(
            header("X-Apple-Store-Front").as_deref(),
            Some("143441-1,29")
        );
        assert_eq!(header("X-Token").as_deref(), Some(TOKEN));
        assert_eq!(header("Accept-Language").as_deref(), Some("en"));
        assert_eq!(
            header("X-Apple-Client-Application").as_deref(),
            Some("me.majd.ipatool")
        );
        assert_eq!(header("X-Apple-TZ").as_deref(), Some("0"));
        assert_eq!(header("X-Apple-ActionSignature"), None);
        let sent = decode_store_plist(&request.body).expect("plist");
        let key = sent
            .get("clientCorrelationKey")
            .and_then(plist::Value::as_string)
            .expect("correlation key");
        assert_eq!(
            request.body,
            purchase_body(GUID, APP, PRICING_APP_STORE, key)
        );
        assert_eq!(
            sent.get("salableAdamId")
                .and_then(plist::Value::as_signed_integer),
            Some(APP)
        );
        assert_eq!(
            sent.get("origPage").and_then(plist::Value::as_string),
            Some("Software-1234567890")
        );
        assert_eq!(
            sent.get("guid").and_then(plist::Value::as_string),
            Some(GUID)
        );
        assert_eq!(
            sent.get("hasBeenAuthedForBuy"),
            Some(&plist::Value::Boolean(true))
        );
        assert_eq!(sent.len(), 14);
    }

    #[test]
    fn correlation_keys_are_uppercase_v4_uuids() {
        let key = correlation_key();
        let groups: Vec<usize> = key.split('-').map(str::len).collect();
        assert_eq!(groups, [8, 4, 4, 4, 12]);
        assert_eq!(key.as_bytes()[14], b'4');
        assert!(matches!(key.as_bytes()[19], b'8' | b'9' | b'A' | b'B'));
        assert_eq!(key, key.to_ascii_uppercase());
        assert_ne!(key, correlation_key());
    }

    #[tokio::test]
    async fn retries_with_arcade_pricing_on_2059() {
        let server = MockServer::start().await;
        mount(
            &server,
            PRICING_APP_STORE,
            200,
            failure("2059", "unavailable"),
        )
        .await;
        mount(&server, PRICING_ARCADE, 200, success()).await;
        assert!(run(&server, Ok(())).await.0.is_ok());
    }

    #[tokio::test]
    async fn treats_2034_as_owned_when_the_seam_confirms_the_license() {
        let server = MockServer::start().await;
        mount(&server, PRICING_APP_STORE, 200, failure("2034", "Sign In")).await;
        let (result, asked) = run(&server, Ok(())).await;
        assert!(result.is_ok());
        assert!(asked);
    }

    #[tokio::test]
    async fn reports_expired_token_when_the_license_is_missing() {
        let server = MockServer::start().await;
        mount(&server, PRICING_APP_STORE, 200, failure("2042", "Sign In")).await;
        let (result, _) = run(&server, Err(AppStoreError::NoLicense(APP))).await;
        assert!(
            matches!(result, Err(AppStoreError::AuthenticationFailed(m)) if m.contains("recent sign-in"))
        );
    }

    #[tokio::test]
    async fn reports_items_unavailable_under_both_pricings() {
        let server = MockServer::start().await;
        mount(&server, PRICING_APP_STORE, 200, failure("2059", "x")).await;
        mount(&server, PRICING_ARCADE, 200, failure("2059", "x")).await;
        let (result, _) = run(&server, Ok(())).await;
        assert!(
            matches!(result, Err(AppStoreError::PurchaseFailed(m)) if m.contains("temporarily unavailable"))
        );
    }

    #[tokio::test]
    async fn reports_unreachable_purchase_endpoint() {
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let context = PurchaseContext {
            client: &client,
            url: "http://127.0.0.1:1/buyProduct",
            guid: GUID,
        };
        let result = purchase(&context, &account(), APP, || async { Ok(()) }).await;
        assert!(
            matches!(result, Err(AppStoreError::NetworkError(m)) if m.starts_with("purchase request failed"))
        );
    }

    #[test]
    fn reads_integer_and_string_statuses() {
        let status = |value: plist::Value| {
            let mut result = plist::Dictionary::new();
            result.insert("status".into(), value);
            purchase_status(&result)
        };
        assert_eq!(status(plist::Value::Integer(3.into())), 3);
        assert_eq!(status(plist::Value::Integer(u64::MAX.into())), -1);
        assert_eq!(status(plist::Value::String("7".into())), 7);
        assert_eq!(status(plist::Value::String("seven".into())), -1);
        assert_eq!(status(plist::Value::Boolean(true)), 0);
    }

    #[test]
    fn classifies_upstream_failures() {
        let parse = |body: String| decode_store_plist(body.as_bytes()).expect("plist");
        let classify = |status, body| classify(status, &parse(body), PRICING_APP_STORE);
        assert_eq!(
            classify(200, failure("5002", "x")).ok(),
            Some(Attempt::AlreadyOwned)
        );
        assert_eq!(
            classify(500, plist_body("")).ok(),
            Some(Attempt::AlreadyOwned)
        );
        assert_eq!(
            classify(200, failure("1008", "x")).ok(),
            Some(Attempt::TokenExpired)
        );
        assert_eq!(
            classify(200, failure("", MESSAGE_PASSWORD_CHANGED)).ok(),
            Some(Attempt::TokenExpired)
        );
        let message =
            |result: Result<Attempt, AppStoreError>| result.expect_err("failure").to_string();
        assert!(
            message(classify(200, failure("", MESSAGE_SUBSCRIPTION_REQUIRED)))
                .contains("subscription required")
        );
        assert!(message(classify(200, failure("9999", "Custom"))).contains("Custom"));
        assert!(message(classify(200, failure("9999", ""))).contains("something went wrong"));
        assert!(message(classify(200, plist_body(""))).contains("failed to purchase app"));
    }
}
