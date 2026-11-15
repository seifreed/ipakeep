//! Purchase history through `MZPurchaseDaap` (`pd.itunes.apple.com`).
//!
//! Ported from ipatool `pkg/appstore/appstore_owned_apps.go`: per storefront
//! (`,34` Configurator then `,13` Mac App Store) a DAAP `login` opens a
//! session, `update` returns the revision and `databases/{rev}/items` lists
//! the purchases. `update` and `items` carry `X-Apple-ActionSignature`.

use super::bag::STORE_USER_AGENT;
use super::daap::{self, DmapError};
use crate::domain::entity::{Account, OwnedApp};
use crate::domain::error::AppStoreError;
use base64::Engine;
use std::collections::HashMap;

/// Production `MZPurchaseDaap` base URL.
pub const PURCHASE_DAAP_BASE_URL: &str =
    "https://pd.itunes.apple.com/WebObjects/MZPurchaseDaap.woa/purchase";

/// Listing size used when the caller passes 0.
pub const DEFAULT_OWNED_APPS_LIMIT: u32 = 10;
/// Largest listing size upstream accepts.
pub const MAX_OWNED_APPS_LIMIT: u32 = 100;

const MOBILE_MEDIA_KIND: u64 = 131_072;
const ARCADE_MEDIA_KIND: u64 = 262_144;
const MAC_MEDIA_KIND: u64 = 67_108_864;
const STOREFRONT_KINDS: [&str; 2] = ["34", "13"];
const ITEMS_KIND: u8 = 2;
const HTTP_OK: u64 = 200;
const HTTP_UNAUTHORIZED: u64 = 401;
const HTTP_FORBIDDEN: u64 = 403;
const PRODUCT_PLATFORMS: [(u64, &str); 4] =
    [(1, "iphone"), (2, "ipad"), (16, "visionos"), (8, "macos")];
const UNKNOWN_PLATFORM: &str = "unknown";
const MAC_PLATFORM: &str = "macos";

/// Wall clock values the DAAP headers and items body carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaapClock {
    /// Seconds since the Unix epoch.
    pub unix_seconds: u64,
    /// Local offset from UTC in minutes (`X-Apple-TZ`).
    pub utc_offset_minutes: i32,
    /// `X-Apple-I-TimeZone` value.
    pub time_zone: String,
}

impl DaapClock {
    /// The current time with a UTC offset of 0.
    // ponytail: the wire carries the literal "Local" (Go's `time.Local.String()`)
    // and the host offset in minutes (two digits in the capture, e.g. "60");
    // reading the host offset needs `time`'s `local-offset` feature, so callers
    // that know it set `utc_offset_minutes` themselves.
    #[must_use]
    pub fn now_utc() -> Self {
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        Self {
            unix_seconds,
            utc_offset_minutes: 0,
            time_zone: "Local".into(),
        }
    }
}

/// Signs a request body with the SAP session (`X-Apple-ActionSignature`).
pub type ActionSign<'a> = &'a mut (dyn FnMut(&[u8]) -> Result<Vec<u8>, AppStoreError> + Send);

/// Everything an owned-apps listing needs besides the account.
pub struct OwnedAppsContext<'a> {
    /// Store client (see [`super::bag::store_client`]).
    pub client: &'a reqwest::Client,
    /// Usually [`PURCHASE_DAAP_BASE_URL`].
    pub base_url: &'a str,
    /// Uppercase hex machine GUID.
    pub guid: &'a str,
    /// SAP body signer.
    pub sign: ActionSign<'a>,
    /// Time source for headers and the items body.
    pub clock: DaapClock,
}

/// List up to `limit` owned apps (0 means 10, capped at 100), newest purchase
/// first, merged across the Configurator and Mac App Store storefronts.
///
/// # Errors
///
/// Transport failures, non-200 HTTP/DAAP statuses (401/403 mean the password
/// token expired) and malformed DMAP.
pub async fn owned_apps(
    context: &mut OwnedAppsContext<'_>,
    account: &Account,
    limit: u32,
) -> Result<Vec<OwnedApp>, AppStoreError> {
    let storefront = account.store_front.split(',').next().unwrap_or_default();
    let mut records = Vec::new();
    for kind in STOREFRONT_KINDS {
        let mut scoped = account.clone();
        scoped.store_front = format!("{storefront},{kind}");
        records.extend(fetch_storefront(context, &scoped).await?);
    }
    let mut records = merge(records);
    sort_by_purchase_date(&mut records);
    let limit = normalized_limit(limit);
    Ok(records
        .into_iter()
        .take(limit)
        .map(PurchaseRecord::into_owned_app)
        .collect())
}

fn normalized_limit(limit: u32) -> usize {
    let limit = match limit {
        0 => DEFAULT_OWNED_APPS_LIMIT,
        value => value.min(MAX_OWNED_APPS_LIMIT),
    };
    usize::try_from(limit).unwrap_or(usize::MAX)
}

/// The DAAP query upstream sends for mobile, Arcade and Mac software.
#[must_use]
pub fn purchase_query() -> String {
    format!(
        "('com.apple.itunes.extended\\-media\\-kind:{MOBILE_MEDIA_KIND}','com.apple.itunes.extended\\-media\\-kind:{ARCADE_MEDIA_KIND}','com.apple.itunes.extended\\-media\\-kind:{MAC_MEDIA_KIND}')"
    )
}

async fn fetch_storefront(
    context: &mut OwnedAppsContext<'_>,
    account: &Account,
) -> Result<Vec<PurchaseRecord>, AppStoreError> {
    let login = send(context, account, DaapStep::Login).await?;
    let session = required_u32(&login, "mlid", "purchase history login", "session ID")?;
    let query = purchase_query();
    let update = send(
        context,
        account,
        DaapStep::Update {
            session,
            query: &query,
        },
    )
    .await?;
    let revision = required_u32(&update, "musr", "purchase history update", "revision")?;
    let step = DaapStep::Items {
        session,
        revision,
        query: &query,
    };
    let items = send(context, account, step).await?;
    parse_purchases(&items).map_err(|error| {
        AppStoreError::Unexpected(format!(
            "failed to parse purchase history items response: {error}"
        ))
    })
}

fn required_u32(data: &[u8], tag: &str, label: &str, what: &str) -> Result<u32, AppStoreError> {
    let value = daap::first_uint(data, tag).map_err(|error| {
        AppStoreError::Unexpected(format!("failed to parse {label} response: {error}"))
    })?;
    value
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            AppStoreError::Unexpected(format!("{label} response did not contain a valid {what}"))
        })
}

enum DaapStep<'q> {
    Login,
    Update {
        session: u32,
        query: &'q str,
    },
    Items {
        session: u32,
        revision: u32,
        query: &'q str,
    },
}

impl DaapStep<'_> {
    fn label(&self) -> &'static str {
        match self {
            Self::Login => "purchase history login",
            Self::Update { .. } => "purchase history update",
            Self::Items { .. } => "purchase history items",
        }
    }

    fn path(&self) -> String {
        match self {
            Self::Login => "/login".into(),
            Self::Update { .. } => "/update".into(),
            Self::Items { revision, .. } => format!("/databases/{revision}/items"),
        }
    }

    fn content_type(&self) -> Option<&'static str> {
        match self {
            Self::Login => None,
            Self::Update { .. } => Some("application/x-www-form-urlencoded"),
            Self::Items { .. } => Some("application/x-dmap-tagged"),
        }
    }

    fn body(&self, unix_seconds: u64) -> Option<Vec<u8>> {
        match self {
            Self::Login => None,
            Self::Update { session, query } => Some(
                format!("session-id={session}&revision-number=(null)&query={query}").into_bytes(),
            ),
            Self::Items {
                session,
                revision,
                query,
            } => Some(items_body(*session, *revision, query, unix_seconds)),
        }
    }
}

/// The `adsr` DMAP request body for `databases/{rev}/items`.
#[must_use]
pub fn items_body(session: u32, revision: u32, query: &str, unix_seconds: u64) -> Vec<u8> {
    // Upstream truncates the timestamp to 32 bits (`uint32(now.Unix())`).
    let timestamp = u32::try_from(unix_seconds & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    let payload = [
        daap::uint32(b"mstc", timestamp),
        daap::uint32(b"mlid", session),
        daap::uint8(b"mikd", ITEMS_KIND),
        daap::uint32(b"musr", revision),
        daap::uint32(b"mder", 0),
        daap::string(b"mque", query),
        daap::tag(b"aetl", &[]),
    ]
    .concat();
    daap::tag(b"adsr", &payload)
}

async fn send(
    context: &mut OwnedAppsContext<'_>,
    account: &Account,
    step: DaapStep<'_>,
) -> Result<Vec<u8>, AppStoreError> {
    let url = format!("{}{}", context.base_url, step.path());
    let mut request = context.client.post(url);
    for (key, value) in daap_headers(account, context.guid, &context.clock) {
        request = request.header(key, value);
    }
    if let Some(content_type) = step.content_type() {
        request = request.header("Content-Type", content_type);
    }
    if let Some(body) = step.body(context.clock.unix_seconds) {
        let signature = (context.sign)(&body)?;
        request = request
            .header(
                "X-Apple-ActionSignature",
                base64::engine::general_purpose::STANDARD.encode(signature),
            )
            .body(body);
    } else {
        // Apple answers a body-less POST without Content-Length with HTTP 411.
        request = request.header(reqwest::header::CONTENT_LENGTH, "0");
    }
    let label = step.label();
    let response = request
        .send()
        .await
        .map_err(|error| AppStoreError::NetworkError(format!("{label} request failed: {error}")))?;
    let status = u64::from(response.status().as_u16());
    let data = response
        .bytes()
        .await
        .map_err(|error| AppStoreError::NetworkError(format!("read {label} response: {error}")))?;
    check_status(label, status, "request returned HTTP")?;
    let daap_status = daap::first_uint(&data, "mstt").map_err(|error| {
        AppStoreError::Unexpected(format!("failed to parse {label} response: {error}"))
    })?;
    if let Some(status) = daap_status {
        check_status(label, status, "response returned DAAP status")?;
    }
    Ok(data.to_vec())
}

fn check_status(label: &str, status: u64, what: &str) -> Result<(), AppStoreError> {
    match status {
        HTTP_OK => Ok(()),
        HTTP_UNAUTHORIZED | HTTP_FORBIDDEN => Err(AppStoreError::AuthenticationFailed(format!(
            "password token is expired: {label} {what} {status}; run auth login again"
        ))),
        _ => Err(AppStoreError::Unexpected(format!(
            "{label} {what} {status}"
        ))),
    }
}

/// Headers every DAAP request carries on the wire: upstream's
/// `ownedAppsHeaders` minus `Date`, which the Store session does not send.
#[must_use]
pub fn daap_headers(
    account: &Account,
    guid: &str,
    clock: &DaapClock,
) -> Vec<(&'static str, String)> {
    vec![
        ("Accept", "*/*".into()),
        ("Accept-Language", "en-us".into()),
        ("Client-Cloud-DAAP-Request-Reason", "5".into()),
        (
            "Client-Cloud-Purchase-Daap-Version",
            "1.1/Configurator-2.0".into(),
        ),
        ("Client-DAAP-Version", "3.12".into()),
        ("User-Agent", STORE_USER_AGENT.into()),
        ("iCloud-DSID", account.directory_services_id.clone()),
        ("X-Apple-I-Client-Time", rfc3339(clock.unix_seconds)),
        ("X-Apple-I-Locale", "en_US".into()),
        ("X-Apple-I-TimeZone", clock.time_zone.clone()),
        ("X-Apple-Store-Front", account.store_front.clone()),
        ("X-Apple-TZ", (clock.utc_offset_minutes).to_string()),
        ("X-Dsid", account.directory_services_id.clone()),
        ("X-Guid", guid.to_string()),
        ("X-Token", account.password_token.clone()),
    ]
}

/// One purchase-history row before conversion to [`OwnedApp`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PurchaseRecord {
    id: i64,
    bundle_id: String,
    name: String,
    version: String,
    platforms: Vec<&'static str>,
    purchased: Option<u32>,
}

impl PurchaseRecord {
    fn into_owned_app(self) -> OwnedApp {
        OwnedApp {
            id: self.id,
            bundle_id: self.bundle_id,
            name: self.name,
            version: self.version,
            platforms: self.platforms.into_iter().map(str::to_string).collect(),
            purchase_date: self.purchased.map(|seconds| rfc3339(u64::from(seconds))),
        }
    }
}

fn parse_purchases(data: &[u8]) -> Result<Vec<PurchaseRecord>, DmapError> {
    let mut records = Vec::new();
    daap::walk(data, &mut |name, payload| {
        if name == "mlit" {
            let record = parse_purchase(payload)?;
            if record.id != 0 {
                records.push(record);
            }
        }
        Ok(())
    })?;
    Ok(merge(records))
}

#[derive(Default)]
struct PurchaseFields {
    media_kind: u64,
    products: u64,
}

fn parse_purchase(data: &[u8]) -> Result<PurchaseRecord, DmapError> {
    let mut record = PurchaseRecord::default();
    let mut fields = PurchaseFields::default();
    let walked = daap::walk(data, &mut |name, payload| {
        read_purchase_field(&mut record, &mut fields, name, payload)
    });
    record.platforms = platforms(fields.media_kind, fields.products);
    walked.map(|()| record)
}

fn read_purchase_field(
    record: &mut PurchaseRecord,
    fields: &mut PurchaseFields,
    name: &str,
    payload: &[u8],
) -> Result<(), DmapError> {
    let text = || String::from_utf8_lossy(payload).into_owned();
    match name {
        "aeMk" => fields.media_kind = flexible_uint(name, payload)?,
        "aeSS" => fields.products = flexible_uint(name, payload)?,
        "aeSI" => record.id = app_id(payload)?,
        "aeBI" => record.bundle_id = text(),
        "aeLN" => record.name = text(),
        "minm" if record.name.is_empty() => record.name = text(),
        "aePd" => record.version = text(),
        "asdp" => record.purchased = Some(purchase_date(payload)?),
        _ => {}
    }
    Ok(())
}

fn flexible_uint(name: &str, payload: &[u8]) -> Result<u64, DmapError> {
    daap::be_uint(payload).ok_or_else(|| {
        DmapError::Invalid(format!(
            "owned app {name} has invalid integer length {}",
            payload.len()
        ))
    })
}

fn app_id(payload: &[u8]) -> Result<i64, DmapError> {
    let invalid = || {
        DmapError::Invalid(format!(
            "failed to parse owned app ID: invalid integer length {}",
            payload.len()
        ))
    };
    if !matches!(payload.len(), 4 | 8) {
        return Err(invalid());
    }
    let value = daap::be_uint(payload).ok_or_else(invalid)?;
    i64::try_from(value).map_err(|_| {
        DmapError::Invalid("failed to parse owned app ID: integer exceeds int64".into())
    })
}

fn purchase_date(payload: &[u8]) -> Result<u32, DmapError> {
    let bytes: [u8; 4] = payload.try_into().map_err(|_| {
        DmapError::Invalid(format!(
            "owned app purchase date has invalid length {}",
            payload.len()
        ))
    })?;
    Ok(u32::from_be_bytes(bytes))
}

/// Mac software has its own media kind; for mobile and Arcade the
/// supported-products mask uses 1 iPhone, 2 iPad, 16 visionOS, 8 Mac.
fn platforms(media_kind: u64, products: u64) -> Vec<&'static str> {
    let found: Vec<&'static str> = match media_kind {
        MAC_MEDIA_KIND => vec![MAC_PLATFORM],
        MOBILE_MEDIA_KIND | ARCADE_MEDIA_KIND => PRODUCT_PLATFORMS
            .iter()
            .filter(|(mask, _)| products & mask != 0)
            .map(|(_, platform)| *platform)
            .collect(),
        _ => Vec::new(),
    };
    if found.is_empty() {
        vec![UNKNOWN_PLATFORM]
    } else {
        found
    }
}

/// Collapse duplicate IDs: union of platforms (dropping `unknown` once known)
/// and the latest purchase date, keeping first-seen order.
fn merge(records: Vec<PurchaseRecord>) -> Vec<PurchaseRecord> {
    let mut merged: Vec<PurchaseRecord> = Vec::with_capacity(records.len());
    let mut seen: HashMap<i64, usize> = HashMap::new();
    for record in records {
        if let Some(&index) = seen.get(&record.id) {
            absorb(&mut merged[index], record);
        } else {
            seen.insert(record.id, merged.len());
            merged.push(record);
        }
    }
    for record in &mut merged {
        if record.platforms.len() > 1 {
            record
                .platforms
                .retain(|platform| *platform != UNKNOWN_PLATFORM);
        }
    }
    merged
}

fn absorb(target: &mut PurchaseRecord, record: PurchaseRecord) {
    for platform in record.platforms {
        if !target.platforms.contains(&platform) {
            target.platforms.push(platform);
        }
    }
    if record.purchased > target.purchased {
        target.purchased = record.purchased;
    }
}

/// Newest first; records without a date last; stable for ties.
fn sort_by_purchase_date(records: &mut [PurchaseRecord]) {
    records.sort_by(newest_first);
}

fn newest_first(left: &PurchaseRecord, right: &PurchaseRecord) -> std::cmp::Ordering {
    match (left.purchased, right.purchased) {
        (Some(left), Some(right)) => right.cmp(&left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const MINUTE: u64 = 60;

struct UtcTime {
    year: i64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

/// Howard Hinnant's days-to-civil conversion for UTC timestamps.
fn utc_time(unix_seconds: u64) -> UtcTime {
    let days = unix_seconds / SECONDS_PER_DAY;
    let rem = unix_seconds % SECONDS_PER_DAY;
    let z = i64::try_from(days).unwrap_or(i64::MAX) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u64::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or_default();
    let month = u64::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or_default();
    let year = yoe + era * 400 + i64::from(month <= 2);
    UtcTime {
        year,
        month,
        day,
        hour: rem / SECONDS_PER_HOUR,
        minute: rem % SECONDS_PER_HOUR / MINUTE,
        second: rem % MINUTE,
    }
}

/// `2006-01-02T15:04:05Z`.
fn rfc3339(unix_seconds: u64) -> String {
    let t = utc_time(unix_seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use wiremock::matchers::{body_bytes, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const GUID: &str = "AABBCCDDEEFF";
    const NOW: u64 = 1_700_000_000;
    const SESSION: u32 = 42;
    const REVISION: u32 = 99;

    fn account() -> Account {
        Account {
            email: String::new(),
            name: String::new(),
            password_token: "token".into(),
            directory_services_id: "1234".into(),
            store_front: "143441-1,29".into(),
            pod: String::new(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    fn clock() -> DaapClock {
        DaapClock {
            unix_seconds: NOW,
            utc_offset_minutes: 60,
            time_zone: "Local".into(),
        }
    }

    fn item(id: u32, kind: u32, products: u32, date: u32) -> Vec<u8> {
        let fields = [
            daap::uint32(b"aeSI", id),
            daap::uint32(b"aeMk", kind),
            daap::uint32(b"aeSS", products),
            daap::uint32(b"asdp", date),
        ];
        daap::tag(b"mlit", &fields.concat())
    }

    fn listing(items: &[Vec<u8>]) -> Vec<u8> {
        daap::tag(b"adbs", &daap::tag(b"mlcl", &items.concat()))
    }

    async fn mount_storefront(server: &MockServer, storefront: &str, items: Vec<u8>) {
        let expected = storefront.to_string();
        let mount = |route: String, body: Vec<u8>| {
            let expected = expected.clone();
            Mock::given(method("POST"))
                .and(path(route))
                .and(move |request: &Request| {
                    request
                        .headers
                        .get("X-Apple-Store-Front")
                        .is_some_and(|value| value.as_bytes() == expected.as_bytes())
                })
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .expect(1)
        };
        mount(
            "/login".into(),
            daap::tag(b"mlog", &daap::uint32(b"mlid", SESSION)),
        )
        .mount(server)
        .await;
        mount(
            "/update".into(),
            daap::tag(b"mupd", &daap::uint32(b"musr", REVISION)),
        )
        .mount(server)
        .await;
        mount(format!("/databases/{REVISION}/items"), items)
            .mount(server)
            .await;
    }

    async fn run(
        server: &MockServer,
        signed: &Arc<Mutex<Vec<Vec<u8>>>>,
        limit: u32,
    ) -> Result<Vec<OwnedApp>, AppStoreError> {
        let client = crate::infrastructure::http::client_builder()
            .build()
            .expect("HTTP client");
        let recorder = Arc::clone(signed);
        let mut sign = move |body: &[u8]| {
            recorder.lock().expect("lock").push(body.to_vec());
            Ok(b"sig".to_vec())
        };
        let mut context = OwnedAppsContext {
            client: &client,
            base_url: &server.uri(),
            guid: GUID,
            sign: &mut sign,
            clock: clock(),
        };
        owned_apps(&mut context, &account(), limit).await
    }

    #[tokio::test]
    async fn lists_merged_purchases_newest_first_with_exact_requests() {
        let server = MockServer::start().await;
        let mobile = listing(&[
            item(1, 131_072, 1, 300),
            item(2, 131_072, 19, 200),
            item(3, 131_072, 0, 100),
        ]);
        let mac = listing(&[item(2, 67_108_864, 0, 200), item(4, 67_108_864, 0, 400)]);
        mount_storefront(&server, "143441-1,34", mobile).await;
        mount_storefront(&server, "143441-1,13", mac).await;
        let signed = Arc::new(Mutex::new(Vec::new()));

        let apps = run(&server, &signed, 0).await.expect("owned apps");

        let ids: Vec<i64> = apps.iter().map(|app| app.id).collect();
        assert_eq!(ids, [4, 1, 2, 3]);
        assert_eq!(apps[2].platforms, ["iphone", "ipad", "visionos", "macos"]);
        assert_eq!(apps[3].platforms, ["unknown"]);
        assert_eq!(
            apps[0].purchase_date.as_deref(),
            Some("1970-01-01T00:06:40Z")
        );
        let query = purchase_query();
        let update = format!("session-id={SESSION}&revision-number=(null)&query={query}");
        let signed = signed.lock().expect("lock").clone();
        assert_eq!(signed.len(), 4);
        assert_eq!(signed[0], update.as_bytes());
        assert_eq!(signed[1], items_body(SESSION, REVISION, &query, NOW));
        assert_requests(
            &server.received_requests().await.expect("recorded"),
            &update,
        );
    }

    fn header(request: &Request, name: &str) -> Option<String> {
        request
            .headers
            .get(name)
            .map(|value| value.to_str().expect("ascii").to_string())
    }

    fn assert_requests(requests: &[Request], update: &str) {
        assert_eq!(requests.len(), 6);
        assert!(
            requests
                .iter()
                .all(|request| header(request, "Date").is_none())
        );
        let common = [
            ("X-Dsid", "1234"),
            ("iCloud-DSID", "1234"),
            ("X-Token", "token"),
            ("X-Guid", GUID),
            ("Client-DAAP-Version", "3.12"),
            ("Client-Cloud-Purchase-Daap-Version", "1.1/Configurator-2.0"),
            ("User-Agent", STORE_USER_AGENT),
            ("X-Apple-I-Client-Time", "2023-11-14T22:13:20Z"),
            ("X-Apple-TZ", "60"),
        ];
        for request in requests {
            for (name, value) in common {
                assert_eq!(header(request, name).as_deref(), Some(value), "{name}");
            }
        }
        assert_eq!(requests[0].body, [] as [u8; 0]);
        assert_eq!(header(&requests[0], "X-Apple-ActionSignature"), None);
        assert_eq!(requests[1].body, update.as_bytes());
        let expect = |index: usize, name: &str, value: &str| {
            assert_eq!(header(&requests[index], name).as_deref(), Some(value));
        };
        expect(1, "Content-Type", "application/x-www-form-urlencoded");
        expect(1, "X-Apple-ActionSignature", "c2ln");
        expect(2, "Content-Type", "application/x-dmap-tagged");
    }

    #[tokio::test]
    async fn applies_limit_after_sorting() {
        let server = MockServer::start().await;
        mount_storefront(&server, "143441-1,34", listing(&[item(1, 131_072, 1, 300)])).await;
        mount_storefront(
            &server,
            "143441-1,13",
            listing(&[item(4, 67_108_864, 0, 400)]),
        )
        .await;
        let apps = run(&server, &Arc::new(Mutex::new(Vec::new())), 1)
            .await
            .expect("apps");
        assert_eq!(apps.iter().map(|app| app.id).collect::<Vec<_>>(), [4]);
    }

    #[tokio::test]
    async fn daap_forbidden_status_means_expired_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .and(wiremock::matchers::header("content-length", "0"))
            .and(body_bytes(Vec::<u8>::new()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(daap::tag(b"mlog", &daap::uint32(b"mstt", 403))),
            )
            .mount(&server)
            .await;
        let error = run(&server, &Arc::new(Mutex::new(Vec::new())), 0)
            .await
            .expect_err("403");
        assert!(
            matches!(error, AppStoreError::AuthenticationFailed(message) if message.contains("DAAP status 403"))
        );
    }

    #[tokio::test]
    async fn http_unauthorized_means_expired_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let error = run(&server, &Arc::new(Mutex::new(Vec::new())), 0)
            .await
            .expect_err("401");
        assert!(
            matches!(error, AppStoreError::AuthenticationFailed(message) if message.contains("HTTP 401"))
        );
    }

    async fn mount_bodies(server: &MockServer, update: Vec<u8>, items: Vec<u8>) {
        let routes = [
            (
                "/login".to_string(),
                daap::tag(b"mlog", &daap::uint32(b"mlid", SESSION)),
            ),
            ("/update".to_string(), update),
            (format!("/databases/{REVISION}/items"), items),
        ];
        for (route, body) in routes {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(server)
                .await;
        }
    }

    async fn unexpected_message(update: Vec<u8>, items: Vec<u8>) -> String {
        let server = MockServer::start().await;
        mount_bodies(&server, update, items).await;
        match run(&server, &Arc::new(Mutex::new(Vec::new())), 0).await {
            Err(AppStoreError::Unexpected(message)) => message,
            other => panic!("expected an unexpected-response error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reports_malformed_daap_responses() {
        let update = daap::tag(b"mupd", &daap::uint32(b"musr", REVISION));
        let truncated = b"mupd\0\0\0\x10".to_vec();
        assert!(
            unexpected_message(truncated.clone(), Vec::new())
                .await
                .starts_with("failed to parse purchase history update response")
        );
        assert!(
            unexpected_message(daap::tag(b"mupd", &[]), Vec::new())
                .await
                .contains("did not contain a valid revision")
        );
        assert!(
            unexpected_message(daap::tag(b"mupd", &daap::tag(b"musr", &[0, 1])), Vec::new())
                .await
                .starts_with("failed to parse purchase history update response")
        );
        let bad_item = daap::tag(b"mlit", &daap::tag(b"asdp", &[1, 2, 3]));
        assert!(
            unexpected_message(update.clone(), listing(&[bad_item]))
                .await
                .starts_with("failed to parse purchase history items response")
        );
        assert!(
            unexpected_message(update, truncated)
                .await
                .starts_with("failed to parse purchase history items response")
        );
    }

    #[tokio::test]
    async fn reports_unexpected_http_statuses() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let error = run(&server, &Arc::new(Mutex::new(Vec::new())), 0)
            .await
            .expect_err("500");
        assert!(
            matches!(error, AppStoreError::Unexpected(message) if message.ends_with("request returned HTTP 500"))
        );
    }

    #[test]
    fn clock_reports_the_current_utc_time() {
        let clock = DaapClock::now_utc();
        assert!(clock.unix_seconds > NOW);
        assert_eq!(clock.utc_offset_minutes, 0);
        assert_eq!(clock.time_zone, "Local");
    }

    #[test]
    fn falls_back_to_the_item_name_and_validates_app_ids() {
        let item = [
            daap::uint32(b"aeSI", 7),
            daap::string(b"minm", "Fallback"),
            daap::string(b"minm", "Ignored"),
        ]
        .concat();
        assert_eq!(parse_purchase(&item).expect("parse").name, "Fallback");
        let length = parse_purchase(&daap::tag(b"aeSI", &[0, 1])).expect_err("length");
        assert!(length.to_string().contains("invalid integer length 2"));
        let wide = parse_purchase(&daap::tag(b"aeSI", &u64::MAX.to_be_bytes())).expect_err("wide");
        assert!(wide.to_string().contains("integer exceeds int64"));
    }

    #[test]
    fn sorts_undated_records_after_dated_ones() {
        let record = |id, purchased| PurchaseRecord {
            id,
            purchased,
            ..PurchaseRecord::default()
        };
        let mut records = vec![record(1, None), record(2, Some(10))];
        sort_by_purchase_date(&mut records);
        assert_eq!(records.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1]);
        assert_eq!(
            newest_first(&record(1, None), &record(2, Some(10))),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            newest_first(&record(2, Some(10)), &record(1, None)),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn parses_fields_ignores_unknown_and_deduplicates() {
        let fields = [
            daap::string(b"zzzz", "unknown"),
            daap::tag(b"aeSI", &123_u64.to_be_bytes()),
            daap::string(b"aeBI", "com.example.app"),
            daap::string(b"aeLN", "Example"),
            daap::string(b"aePd", "1.2.3"),
            daap::uint32(b"asdp", 1_700_000_000),
        ]
        .concat();
        let one = daap::tag(b"mlit", &fields);
        let records = parse_purchases(&listing(&[one.clone(), one])).expect("parse");
        assert_eq!(
            records,
            [PurchaseRecord {
                id: 123,
                bundle_id: "com.example.app".into(),
                name: "Example".into(),
                version: "1.2.3".into(),
                platforms: vec!["unknown"],
                purchased: Some(1_700_000_000),
            }]
        );
    }

    #[test]
    fn decodes_supported_platforms() {
        let cases: [(u64, &[u8], &[&str]); 12] = [
            (131_072, &[0, 1], &["iphone"]),
            (131_072, &[0, 2], &["ipad"]),
            (131_072, &[0, 8], &["macos"]),
            (131_072, &[0, 16], &["visionos"]),
            (262_144, &[0, 3], &["iphone", "ipad"]),
            (131_072, &[0, 27], &["iphone", "ipad", "visionos", "macos"]),
            (67_108_864, &[0, 7], &["macos"]),
            (131_072, &[0, 4], &["unknown"]),
            (131_072, &[0, 32], &["unknown"]),
            (999, &[0, 31], &["unknown"]),
            (131_072, &[3], &["iphone", "ipad"]),
            (131_072, &[0, 0, 0, 0, 0, 0, 0, 3], &["iphone", "ipad"]),
        ];
        for (kind, products, expected) in cases {
            let kind = u32::try_from(kind).expect("kind");
            let data = [daap::uint32(b"aeMk", kind), daap::tag(b"aeSS", products)].concat();
            assert_eq!(
                parse_purchase(&data).expect("parse").platforms,
                expected,
                "{kind} {products:?}"
            );
        }
    }

    #[test]
    fn merges_platforms_and_keeps_latest_date() {
        let mobile = [
            daap::uint32(b"aeSI", 123),
            daap::uint32(b"aeSS", 3),
            daap::uint32(b"aeMk", 131_072),
            daap::uint32(b"asdp", 100),
        ]
        .concat();
        let mac = [
            daap::uint32(b"aeSI", 123),
            daap::uint32(b"aeMk", 67_108_864),
            daap::uint32(b"asdp", 300),
        ]
        .concat();
        let other = [daap::uint32(b"aeSI", 456), daap::uint32(b"asdp", 200)].concat();
        let items: Vec<Vec<u8>> = [&mobile, &other, &mac, &mobile]
            .iter()
            .map(|item| daap::tag(b"mlit", item))
            .collect();
        let mut records = parse_purchases(&listing(&items)).expect("parse");
        sort_by_purchase_date(&mut records);
        assert_eq!(records[0].id, 123);
        assert_eq!(records[0].platforms, ["iphone", "ipad", "macos"]);
        assert_eq!(records[0].purchased, Some(300));
        let unknown_first = merge(vec![
            PurchaseRecord {
                id: 1,
                platforms: vec!["unknown"],
                ..PurchaseRecord::default()
            },
            PurchaseRecord {
                id: 1,
                platforms: vec!["macos"],
                ..PurchaseRecord::default()
            },
        ]);
        assert_eq!(unknown_first[0].platforms, ["macos"]);
    }

    #[test]
    fn rejects_malformed_fields() {
        for name in [b"aeMk", b"aeSS"] {
            let error = parse_purchase(&daap::tag(name, &[1, 2, 3])).expect_err("length");
            assert!(error.to_string().contains("invalid integer length 3"));
        }
        let item = [daap::uint32(b"aeSI", 123), daap::tag(b"asdp", &[1, 2, 3])].concat();
        let error = parse_purchases(&listing(&[daap::tag(b"mlit", &item)])).expect_err("date");
        assert!(
            error
                .to_string()
                .contains("purchase date has invalid length 3")
        );
    }

    #[test]
    fn sorts_missing_dates_last_and_keeps_ties_stable() {
        let record = |id, purchased| PurchaseRecord {
            id,
            purchased,
            ..PurchaseRecord::default()
        };
        let mut records = vec![
            record(1, None),
            record(2, Some(10)),
            record(3, Some(20)),
            record(4, Some(10)),
            record(5, None),
        ];
        sort_by_purchase_date(&mut records);
        assert_eq!(
            records.iter().map(|r| r.id).collect::<Vec<_>>(),
            [3, 2, 4, 1, 5]
        );
    }

    #[test]
    fn builds_items_body() {
        let body = items_body(42, 99, "q", NOW);
        assert_eq!(daap::first_uint(&body, "mstc"), Ok(Some(NOW)));
        assert_eq!(daap::first_uint(&body, "mlid"), Ok(Some(42)));
        assert_eq!(daap::first_uint(&body, "musr"), Ok(Some(99)));
        assert_eq!(&body[..4], b"adsr");
        assert_eq!(body.len(), 8 + 12 + 12 + 9 + 12 + 12 + 9 + 8);
    }

    #[test]
    fn formats_dates() {
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(normalized_limit(0), 10);
        assert_eq!(normalized_limit(500), 100);
    }
}
