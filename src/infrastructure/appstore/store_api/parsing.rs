//! Pure parsers for App Store API payloads.

use crate::domain::entity::{App, DownloadItem, Sinf};
use crate::domain::error::AppStoreError;
use base64::Engine;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Parse an [`App`] from an iTunes Search/Lookup result entry.
///
/// Requires the identity fields (`trackId`, `bundleId`); the display name,
/// version, and price default when absent so that otherwise-valid results are
/// never silently dropped.
pub(super) fn parse_app(item: &serde_json::Value) -> Option<App> {
    Some(App {
        id: item.get("trackId").and_then(serde_json::Value::as_i64)?,
        bundle_id: item.get("bundleId").and_then(|v| v.as_str())?.to_string(),
        name: item
            .get("trackName")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        version: item
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        price: item
            .get("price")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0),
    })
}

pub(super) fn parse_download_item(
    item: &serde_json::Value,
) -> Result<Option<DownloadItem>, AppStoreError> {
    let Some(url) = item
        .get("URL")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
        return Ok(None);
    };

    let md5 = item
        .get("md5")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let sinfs = parse_download_sinfs(item.get("sinfs"))?;

    let metadata = item
        .get("metadata")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    Ok(Some(DownloadItem {
        url,
        md5,
        sinfs,
        metadata,
    }))
}

pub(super) fn external_version_ids(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(ids) => ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect(),
        serde_json::Value::Array(ids) => ids
            .iter()
            .filter_map(external_version_id)
            .collect::<Vec<_>>(),
        other => external_version_id(other).into_iter().collect(),
    }
}

fn external_version_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(id) => {
            let id = id.trim();
            if id.is_empty() {
                None
            } else {
                Some(id.to_string())
            }
        }
        serde_json::Value::Number(id) => Some(id.to_string()),
        _ => None,
    }
}

fn parse_download_sinfs(value: Option<&serde_json::Value>) -> Result<Vec<Sinf>, AppStoreError> {
    let Some(arr) = value.and_then(serde_json::Value::as_array) else {
        return Ok(Vec::new());
    };

    let mut sinfs = Vec::new();
    for sinf in arr {
        let Some(id) = sinf.get("id").and_then(serde_json::Value::as_i64) else {
            continue;
        };
        let data = match sinf.get("sinf").and_then(serde_json::Value::as_str) {
            Some(encoded) if !encoded.is_empty() => BASE64.decode(encoded).map_err(|e| {
                AppStoreError::Unexpected(format!("invalid sinf base64 for id {id}: {e}"))
            })?,
            _ => Vec::new(),
        };
        sinfs.push(Sinf { id, data });
    }

    Ok(sinfs)
}
