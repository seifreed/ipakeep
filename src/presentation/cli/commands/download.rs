//! Download command handler.

mod output;

use self::output::{OutputDestination, derive_ipa_filename, prepare_output_destination};
use crate::domain::entity::DownloadItem;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::Download;
use crate::infrastructure::ipa::{patch_ipa, verify_md5};
use crate::infrastructure::simulator::{SimulatorTarget, install_ipa};
use crate::presentation::cli::commands::{get_guid, resolve_app_id};
use crate::presentation::cli::output::OutputFormat;
use serde::Serialize;
use std::io::Cursor;
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

    let use_case = Download::new(app_store.clone(), credentials);
    let items = use_case
        .execute(
            resolved_app_id,
            &guid,
            request.external_version_id,
            request.auto_purchase,
        )
        .await
        .map_err(|e| format!("download failed: {e}"))?;

    if items.is_empty() {
        return Err("no download items returned".into());
    }
    if request.simulator_run && items.len() > 1 {
        return Err("simulator install only supports single-item downloads".into());
    }

    let output_destination = OutputDestination::resolve(request.output, items.len())?;
    prepare_output_destination(&output_destination)?;

    let mut results = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let result = download_and_save_item(
            &app_store,
            item,
            index,
            resolved_app_id,
            &output_destination,
            format,
        )
        .await?;
        results.push(result);
    }

    if request.simulator_run {
        let path = Path::new(&results[0].path);
        install_ipa(
            path,
            request.simulator_launch,
            false,
            &SimulatorTarget::default(),
            None,
        )
        .map_err(|e| format!("simulator install failed: {e}"))?;
    }

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&results)
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
        &format!("Downloading item {}: {} (MD5: {md5})", index + 1, item.url),
    );

    let bytes = app_store
        .download_bytes(&item.url)
        .await
        .map_err(|e| format!("download failed: {e}"))?;

    verify_md5(&bytes, &item.md5).map_err(|e| format!("MD5 verification failed: {e}"))?;

    if zip::ZipArchive::new(Cursor::new(&bytes)).is_err() {
        return Err("downloaded file is not a valid ZIP archive".into());
    }

    let patched = patch_ipa(&bytes, &item.sinfs, &item.metadata)
        .map_err(|e| format!("IPA patching failed: {e}"))?;
    let saved_size = patched.len();

    let file_name = derive_ipa_filename(&item.metadata, app_id, index);
    let full_path = destination.path_for_item(&file_name);

    std::fs::write(&full_path, &patched).map_err(|e| format!("failed to write file: {e}"))?;
    print_download_progress(format, &format!("Saved to: {}", full_path.display()));

    Ok(DownloadResult {
        url: item.url.clone(),
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
    url: String,
    path: String,
    size: usize,
}
