//! CLI command handlers — adapter layer between CLI input and use cases.

pub mod auth;
pub mod decrypt;
pub mod device;
pub mod download;
pub mod list_versions;
pub mod mcp;
mod mcp_tools;
pub mod purchase;
pub mod purchases;
pub mod search;
pub mod simulator;

use crate::domain::entity::DownloadItem;
use crate::domain::repository::AppStoreRepository;
use crate::domain::usecase::ResolveApp;
use crate::infrastructure::ipa::prepare_download;
use std::path::Path;
use std::time::Instant;

/// Get the device GUID (MAC address) for Apple API requests.
pub fn get_guid() -> String {
    mac_address::get_mac_address().ok().flatten().map_or_else(
        || "000000000000".to_string(),
        |addr| addr.to_string().replace(':', "").to_uppercase(),
    )
}

fn save_artifact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let started = Instant::now();
    if let Err(error) = std::fs::write(path, bytes) {
        tracing::error!(
            service = "ipakeep",
            component = "download",
            operation = "save_ipa",
            event_name = "download.artifact.save_failed",
            outcome = "failure",
            error_type = ?error.kind(),
            duration_ms = elapsed_ms(started),
            "failed to save downloaded IPA"
        );
        return Err(format!("failed to write file: {error}"));
    }
    tracing::info!(
        service = "ipakeep",
        component = "download",
        operation = "save_ipa",
        event_name = "download.artifact.saved",
        outcome = "success",
        size_bytes = bytes.len(),
        duration_ms = elapsed_ms(started),
        "downloaded IPA saved"
    );
    Ok(())
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn download_item_to_path<R: AppStoreRepository>(
    app_store: &R,
    item: &DownloadItem,
    path: &Path,
) -> Result<usize, String> {
    let bytes = app_store
        .download_bytes(&item.url)
        .await
        .map_err(|error| format!("download failed: {error}"))?;
    let prepared = prepare_download(item, &bytes)?;
    let size = prepared.len();
    save_artifact(path, &prepared)?;
    Ok(size)
}

/// Resolve a user-supplied app reference into a numeric App Store id.
///
/// Accepts a numeric App Store id, a bundle identifier, or an app name, in that
/// resolution order: a pure-digit string is taken as the id directly; otherwise
/// it is tried as a bundle identifier via lookup, then as a search term, using
/// the first matching result.
///
/// # Errors
///
/// Returns an error string if the lookup/search request fails or nothing matches.
pub async fn resolve_app_id<R>(app_store: &R, app: &str, country: &str) -> Result<i64, String>
where
    R: AppStoreRepository,
{
    let result = ResolveApp::new(app_store).execute(app, country).await;
    tracing::debug!(
        service = "ipakeep",
        component = "cli",
        operation = "resolve_app_id",
        event_name = "app.reference.resolved",
        outcome = if result.is_ok() {
            "success"
        } else {
            "not_found_or_error"
        },
        "app reference resolved"
    );
    result.map_err(|error| match error {
        crate::domain::error::AppStoreError::AppNotFound(_) => {
            format!("no app found matching '{app}'")
        }
        error => error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_app_id;
    use crate::domain::entity::App;
    use crate::domain::repository::FakeAppStoreRepository;
    use crate::infrastructure::observability::log_capture::LogCapture;

    fn app(id: i64) -> App {
        App {
            id,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            price: 0.0,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_app_id_logs_resolution_without_app_ref_value() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let repo = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![app(99)]));

        assert_eq!(
            resolve_app_id(&repo, "secret-app-name", "es")
                .await
                .unwrap(),
            99
        );

        let logs = capture.contents();
        assert!(logs.contains("app.reference.resolved"));
        assert!(!logs.contains("secret-app-name"));
    }
}
