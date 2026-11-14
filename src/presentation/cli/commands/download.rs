//! Download command handler.

mod output;

use self::output::{OutputDestination, derive_ipa_filename, prepare_output_destination};
use crate::domain::entity::DownloadItem;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::Download;
use crate::infrastructure::simulator::{SimulatorTarget, install_ipa};
use crate::presentation::cli::commands::{get_guid, resolve_app_id};
use crate::presentation::cli::output::OutputFormat;
use serde::Serialize;
use std::path::Path;

/// CLI request parameters for the download command.
pub struct DownloadRequest<'a> {
    /// App reference: numeric App Store id, bundle identifier, or app name.
    pub app: &'a str,
    /// ISO 3166-1 alpha-2 country code used to resolve the app reference.
    pub country: &'a str,
    /// Specific external version id to download, or `None` for the latest.
    pub external_version_id: Option<String>,
    /// Output file or directory path, or `None` for the current directory.
    pub output: Option<&'a str>,
    /// Acquire the app license automatically if it is not yet owned.
    pub auto_purchase: bool,
    /// Install the saved IPA in the first booted Simulator.
    pub simulator_run: bool,
    /// Launch the app after installing it in Simulator.
    pub simulator_launch: bool,
}

/// Handle the download command.
///
/// # Errors
///
/// Returns an error string if the download fails or the user is not logged in.
pub async fn handle_download<R, C>(
    request: DownloadRequest<'_>,
    app_store: R,
    credentials: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository + Clone,
    C: CredentialRepository,
{
    let guid = get_guid();

    let resolved_app_id = resolve_app_id(&app_store, request.app, request.country).await?;
    let output = request.output;
    let simulator_run = request.simulator_run;
    let simulator_launch = request.simulator_launch;
    let items =
        fetch_download_items(&app_store, credentials, request, resolved_app_id, &guid).await?;
    validate_download_items(&items, simulator_run)?;

    let output_destination = OutputDestination::resolve(output, items.len())?;
    prepare_output_destination(&output_destination)?;
    let results = download_items(
        &app_store,
        &items,
        resolved_app_id,
        &output_destination,
        format,
    )
    .await?;
    install_downloaded_ipa(&results, simulator_run, simulator_launch)?;
    print_download_results(&results, format)?;

    Ok(())
}

async fn fetch_download_items<R, C>(
    app_store: &R,
    credentials: C,
    request: DownloadRequest<'_>,
    app_id: i64,
    guid: &str,
) -> Result<Vec<DownloadItem>, String>
where
    R: AppStoreRepository + Clone,
    C: CredentialRepository,
{
    Download::new(app_store.clone(), credentials)
        .execute(
            app_id,
            guid,
            request.external_version_id,
            request.auto_purchase,
        )
        .await
        .map_err(|error| format!("download failed: {error}"))
}

fn validate_download_items(items: &[DownloadItem], simulator_run: bool) -> Result<(), String> {
    if items.is_empty() {
        return Err("no download items returned".into());
    }
    if simulator_run && items.len() > 1 {
        return Err("simulator install only supports single-item downloads".into());
    }
    Ok(())
}

async fn download_items<R>(
    app_store: &R,
    items: &[DownloadItem],
    app_id: i64,
    destination: &OutputDestination,
    format: &OutputFormat,
) -> Result<Vec<DownloadResult>, String>
where
    R: AppStoreRepository,
{
    let mut results = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        results.push(
            download_and_save_item(app_store, item, index, app_id, destination, format).await?,
        );
    }
    Ok(results)
}

fn install_downloaded_ipa(
    results: &[DownloadResult],
    simulator_run: bool,
    simulator_launch: bool,
) -> Result<(), String> {
    if simulator_run {
        install_ipa(
            Path::new(&results[0].path),
            simulator_launch,
            false,
            &SimulatorTarget::default(),
            None,
        )
        .map_err(|error| format!("simulator install failed: {error}"))?;
    }
    Ok(())
}

fn print_download_results(results: &[DownloadResult], format: &OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(results)
                    .map_err(|e| format!("failed to serialize output: {e}"))?
            );
        }
        OutputFormat::Text => {
            // Progress already printed above.
        }
    }
    Ok(())
}

/// Download one item, verify it, patch it, and write it to its destination.
async fn download_and_save_item<R>(
    app_store: &R,
    item: &DownloadItem,
    index: usize,
    app_id: i64,
    destination: &OutputDestination,
    format: &OutputFormat,
) -> Result<DownloadResult, String>
where
    R: AppStoreRepository,
{
    let md5 = if item.md5.is_empty() {
        "N/A"
    } else {
        &item.md5
    };
    print_download_progress(
        format,
        &format!("Downloading item {} (MD5: {md5})", index + 1),
    );

    let file_name = derive_ipa_filename(&item.metadata, app_id, index);
    let full_path = destination.path_for_item(&file_name);
    let saved_size = super::download_item_to_path(app_store, item, &full_path).await?;
    print_download_progress(format, &format!("Saved to: {}", full_path.display()));

    Ok(DownloadResult {
        path: full_path.to_string_lossy().to_string(),
        size: saved_size,
    })
}

fn print_download_progress(format: &OutputFormat, message: &str) {
    match format {
        OutputFormat::Json => eprintln!("{message}"),
        OutputFormat::Text => println!("{message}"),
    }
}

/// Result of a single downloaded item for JSON output.
#[derive(Debug, Serialize)]
struct DownloadResult {
    path: String,
    size: usize,
}

#[cfg(test)]
mod observability_tests {
    use super::DownloadResult;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use tempfile::TempDir;

    #[test]
    fn artifact_saved_event_reports_size_without_full_path() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let directory = TempDir::new().expect("temporary output directory");
        let path = directory.path().join("private-app.ipa");
        super::super::save_artifact(&path, b"ipa-content").expect("save artifact");

        let logs = capture.contents();
        assert!(logs.contains("download.artifact.saved"));
        assert!(logs.contains("size_bytes=11"));
        assert!(!logs.contains(path.to_string_lossy().as_ref()));
    }

    #[test]
    fn download_json_result_does_not_include_signed_source_url() {
        let result = DownloadResult {
            path: "app.ipa".into(),
            size: 11,
        };
        let json = serde_json::to_string(&result).expect("download result JSON");
        assert!(!json.contains("url"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{DownloadMetadata, Sinf, test_support::test_account};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use std::path::PathBuf;

    fn request<'a>(output: Option<&'a str>) -> DownloadRequest<'a> {
        DownloadRequest {
            app: "42",
            country: "us",
            external_version_id: None,
            output,
            auto_purchase: false,
            simulator_run: false,
            simulator_launch: false,
        }
    }

    fn item(md5: &str) -> DownloadItem {
        DownloadItem {
            url: "https://example.invalid/app.ipa".into(),
            md5: md5.into(),
            sinfs: Vec::<Sinf>::new(),
            metadata: DownloadMetadata::from_iter([(
                "bundleId".into(),
                serde_json::json!("com.example.app"),
            )]),
        }
    }

    #[test]
    fn validation_rejects_empty_and_multi_item_simulator_results() {
        assert!(validate_download_items(&[], false).is_err());
        assert!(validate_download_items(&[item(""), item("")], true).is_err());
        assert!(validate_download_items(&[item(""), item("")], false).is_ok());
        assert!(validate_download_items(&[item("")], true).is_ok());
    }

    #[test]
    fn install_is_skipped_when_simulator_run_is_disabled() {
        assert!(install_downloaded_ipa(&[], false, false).is_ok());
    }

    #[test]
    fn result_and_progress_printers_support_both_formats() {
        let results = [DownloadResult {
            path: "App.ipa".into(),
            size: 123,
        }];
        assert!(print_download_results(&results, &OutputFormat::Text).is_ok());
        assert!(print_download_results(&results, &OutputFormat::Json).is_ok());
        print_download_progress(&OutputFormat::Text, "text progress");
        print_download_progress(&OutputFormat::Json, "json progress");
    }

    #[tokio::test]
    async fn download_reports_missing_login_and_empty_repository_results() {
        let error = handle_download(
            request(None),
            FakeAppStoreRepository::new(),
            InMemoryCredentialRepository::new(),
            &OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(error.contains("not logged in"));

        let app_store = FakeAppStoreRepository::new().with_download_result(Ok(Vec::new()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());
        let error = handle_download(request(None), app_store, credentials, &OutputFormat::Text)
            .await
            .unwrap_err();
        assert!(error.contains("no download items"));
    }

    #[tokio::test]
    async fn download_item_progresses_then_returns_repository_download_error() {
        let app_store = FakeAppStoreRepository::new()
            .with_download_bytes_result(Err(AppStoreError::NetworkError("offline".into())));
        let download_item = item("");
        let destination = OutputDestination::File(PathBuf::from("App.ipa"));
        let error = download_and_save_item(
            &app_store,
            &download_item,
            0,
            42,
            &destination,
            &OutputFormat::Text,
        )
        .await
        .unwrap_err();
        assert!(error.contains("offline"));

        let download_item = item("expected-md5");
        let error = download_and_save_item(
            &app_store,
            &download_item,
            1,
            42,
            &destination,
            &OutputFormat::Json,
        )
        .await
        .unwrap_err();
        assert!(error.contains("offline"));
    }
}
