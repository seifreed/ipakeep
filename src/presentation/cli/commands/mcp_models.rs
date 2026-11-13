use crate::domain::entity::{
    Account, App, AppVersion, DownloadMetadata, OwnedApp, metadata_string,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) fn parse_args<T: for<'de> Deserialize<'de>>(arguments: Value) -> Result<T, String> {
    serde_json::from_value(arguments).map_err(|error| format!("invalid arguments: {error}"))
}

pub(super) fn to_value<T: Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to serialize result: {error}"))
}

pub(super) fn ipa_filename(metadata: &DownloadMetadata, app_id: i64, index: usize) -> String {
    let bundle = metadata_string(metadata, "softwareVersionBundleId")
        .or_else(|| metadata_string(metadata, "bundleId"))
        .unwrap_or_else(|| format!("app_{app_id}"));
    let bundle = sanitize_segment(&bundle);
    let version = metadata_string(metadata, "bundleShortVersionString")
        .map(|version| sanitize_segment(&version))
        .unwrap_or_default();
    if version.is_empty() {
        format!("{bundle}_{index}.ipa")
    } else {
        format!("{bundle}_{version}_{index}.ipa")
    }
}

fn sanitize_segment(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "_".to_string()
    } else {
        safe
    }
}

fn default_country() -> String {
    "us".to_string()
}

const fn default_limit() -> u32 {
    5
}

#[derive(Debug, Deserialize)]
pub(super) struct SearchArgs {
    pub(super) term: String,
    #[serde(default = "default_country")]
    pub(super) country: String,
    #[serde(default = "default_limit")]
    pub(super) limit: u32,
}

#[derive(Debug, Deserialize)]
pub(super) struct AppArgs {
    pub(super) app: String,
    #[serde(default = "default_country")]
    pub(super) country: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct DownloadArgs {
    pub(super) app: String,
    #[serde(default = "default_country")]
    pub(super) country: String,
    #[serde(default)]
    pub(super) external_version_id: Option<String>,
    #[serde(default)]
    pub(super) output: Option<String>,
    #[serde(default)]
    pub(super) no_purchase: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct PurchasesArgs {
    #[serde(default)]
    pub(super) page: Option<u32>,
    #[serde(default)]
    pub(super) max_results: Option<u32>,
    #[serde(default)]
    pub(super) platform: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct SearchOutput {
    pub(super) count: usize,
    pub(super) apps: Vec<App>,
}

#[derive(Debug, Serialize)]
pub(super) struct PurchasesOutput {
    pub(super) count: usize,
    pub(super) apps: Vec<OwnedApp>,
}

#[derive(Debug, Serialize)]
pub(super) struct VersionsOutput {
    pub(super) app_id: i64,
    pub(super) count: usize,
    pub(super) versions: Vec<AppVersion>,
}

#[derive(Debug, Serialize)]
pub(super) struct DownloadOutput {
    pub(super) app_id: i64,
    pub(super) count: usize,
    pub(super) files: Vec<SavedFile>,
}

#[derive(Debug, Serialize)]
pub(super) struct SavedFile {
    pub(super) path: String,
    pub(super) size: usize,
}

/// Account details safe for API output, without credentials or session data.
#[derive(Debug, Serialize)]
pub(super) struct AuthInfoOutput {
    email: String,
    name: String,
    store_front: String,
    pod: String,
    has_password_token: bool,
    has_cookies: bool,
}

impl From<&Account> for AuthInfoOutput {
    fn from(account: &Account) -> Self {
        Self {
            email: account.email.clone(),
            name: account.name.clone(),
            store_front: account.store_front.clone(),
            pod: account.pod.clone(),
            has_password_token: !account.password_token.is_empty(),
            has_cookies: !account.cookies.is_empty(),
        }
    }
}
