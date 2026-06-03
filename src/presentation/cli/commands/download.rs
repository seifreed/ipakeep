//! Download command handler.

use crate::domain::entity::DownloadMetadata;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::Download;
use crate::presentation::cli::commands::get_guid;
use crate::presentation::cli::output::OutputFormat;
use serde::Serialize;
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

/// Handle the download command.
///
/// # Errors
///
/// Returns an error string if the download fails or the user is not logged in.
#[allow(clippy::too_many_arguments)]
pub async fn handle_download<R, C>(
    app_id: Option<i64>,
    bundle_identifier: Option<&str>,
    external_version_id: Option<String>,
    output: Option<&str>,
    auto_purchase: bool,
    app_store: R,
    credentials: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository + Clone,
    C: CredentialRepository,
{
    let guid = get_guid();

    let resolved_app_id = match bundle_identifier {
        Some(bundle_id) => {
            let app = app_store
                .lookup(bundle_id, "us")
                .await
                .map_err(|e| format!("lookup failed: {e}"))?
                .ok_or_else(|| format!("app not found for bundle identifier: {bundle_id}"))?;
            app.id
        }
        None => app_id
            .ok_or_else(|| "either --app-id or --bundle-identifier is required".to_string())?,
    };

    let use_case = Download::new(app_store.clone(), credentials);
    let items = use_case
        .execute(resolved_app_id, &guid, external_version_id, auto_purchase)
        .await
        .map_err(|e| format!("download failed: {e}"))?;

    if items.is_empty() {
        return Err("no download items returned".into());
    }

    let output_destination = resolve_output_destination(output, items.len())?;
    prepare_output_destination(&output_destination)?;
    let mut results = Vec::new();

    for (i, item) in items.iter().enumerate() {
        print_download_progress(
            format,
            &format!(
                "Downloading item {}: {} (MD5: {})",
                i + 1,
                item.url,
                if item.md5.is_empty() {
                    "N/A"
                } else {
                    &item.md5
                }
            ),
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

        let file_name = derive_ipa_filename(&item.metadata, resolved_app_id, i);
        let full_path = output_destination.path_for_item(&file_name);

        std::fs::write(&full_path, &patched).map_err(|e| format!("failed to write file: {e}"))?;

        print_download_progress(format, &format!("Saved to: {}", full_path.display()));

        results.push(DownloadResult {
            url: item.url.clone(),
            path: full_path.to_string_lossy().to_string(),
            size: saved_size,
        });
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

#[derive(Debug)]
enum OutputDestination {
    Directory(PathBuf),
    File(PathBuf),
}

impl OutputDestination {
    fn path_for_item(&self, file_name: &str) -> PathBuf {
        match self {
            Self::Directory(path) => path.join(file_name),
            Self::File(path) => path.clone(),
        }
    }
}

fn resolve_output_destination(
    output: Option<&str>,
    item_count: usize,
) -> Result<OutputDestination, String> {
    let Some(raw_output) = output else {
        return Ok(OutputDestination::Directory(PathBuf::from(".")));
    };

    let path = PathBuf::from(raw_output);
    if output_designates_directory(raw_output, &path) {
        return Ok(OutputDestination::Directory(path));
    }

    if item_count > 1 {
        return Err("--output must be a directory when downloading multiple items".into());
    }

    Ok(OutputDestination::File(path))
}

fn output_designates_directory(raw_output: &str, path: &Path) -> bool {
    path.is_dir() || raw_output.ends_with('/') || raw_output.ends_with('\\')
}

fn prepare_output_destination(destination: &OutputDestination) -> Result<(), String> {
    match destination {
        OutputDestination::Directory(path) => {
            std::fs::create_dir_all(path).map_err(|e| format!("failed to create output dir: {e}"))
        }
        OutputDestination::File(path) => {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("failed to create output dir: {e}"))?;
            }
            Ok(())
        }
    }
}

/// Verify the MD5 checksum of downloaded bytes.
fn verify_md5(bytes: &[u8], expected: &str) -> Result<(), String> {
    if expected.is_empty() {
        return Ok(());
    }
    let computed = format!("{:x}", md5::compute(bytes));
    if computed != expected {
        return Err(format!("MD5 mismatch: expected {expected}, got {computed}"));
    }
    Ok(())
}

/// Patch an IPA with sinf data and iTunesMetadata.plist.
fn patch_ipa(
    ipa_bytes: &[u8],
    sinfs: &[crate::domain::entity::Sinf],
    metadata: &DownloadMetadata,
) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(ipa_bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| e.to_string())?;

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut written = std::collections::HashSet::new();

    let sinf_targets = sinf_target_paths(&mut archive, sinfs)?;
    let sinf_target_names: HashSet<String> =
        sinf_targets.iter().map(|(name, _)| name.clone()).collect();

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().to_string();

        if sinf_target_names.contains(&name) {
            continue;
        }
        if name == "iTunesMetadata.plist" && !metadata.is_empty() {
            continue;
        }
        if !written.insert(name.clone()) {
            continue;
        }

        copy_zip_entry(&mut writer, file).map_err(|e| e.to_string())?;
    }

    // Inject iTunesMetadata.plist
    if !metadata.is_empty() {
        let plist_data = build_itunes_metadata_plist(metadata).map_err(|e| e.to_string())?;
        if written.insert("iTunesMetadata.plist".to_string()) {
            writer
                .start_file("iTunesMetadata.plist", inserted_file_options())
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut writer, &plist_data).map_err(|e| e.to_string())?;
        }
    }

    // Inject sinf files into the app bundle's SC_Info directory.
    for (sinf_name, data) in sinf_targets {
        if written.insert(sinf_name.clone()) {
            writer
                .start_file(&sinf_name, inserted_file_options())
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(&mut writer, &data).map_err(|e| e.to_string())?;
        }
    }

    let cursor = writer.finish().map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn copy_zip_entry<W: std::io::Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    mut file: zip::read::ZipFile<'_>,
) -> zip::result::ZipResult<()> {
    let name = file.name().to_string();

    if file.is_dir() {
        let options = entry_options(&file, 0o755);
        return writer.add_directory(name, options);
    }

    if file.is_symlink() {
        let options = entry_options(&file, 0o777);
        let mut target = String::new();
        file.read_to_string(&mut target)?;
        return writer.add_symlink(name, target, options);
    }

    writer.raw_copy_file(file)
}

fn entry_options(
    file: &zip::read::ZipFile<'_>,
    default_permissions: u32,
) -> zip::write::SimpleFileOptions {
    let modified = file
        .last_modified()
        .filter(zip::DateTime::is_valid)
        .unwrap_or_else(zip::DateTime::default_for_write);

    zip::write::SimpleFileOptions::default()
        .large_file(file.compressed_size().max(file.size()) > u32::MAX.into())
        .compression_method(file.compression())
        .unix_permissions(file.unix_mode().unwrap_or(default_permissions))
        .last_modified_time(modified)
}

fn inserted_file_options() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644)
}

fn sinf_target_paths<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    sinfs: &[crate::domain::entity::Sinf],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if sinfs.is_empty() {
        return Ok(Vec::new());
    }

    let bundle_prefix = find_app_bundle_prefix(archive)?;
    if let Some(manifest) = read_manifest_sinf_paths(archive, &bundle_prefix)? {
        if manifest.primary_paths.len() != sinfs.len() {
            return Err(format!(
                "sinf count mismatch: manifest has {}, response has {}",
                manifest.primary_paths.len(),
                sinfs.len()
            ));
        }

        let mut targets: Vec<(String, Vec<u8>)> = manifest
            .primary_paths
            .into_iter()
            .zip(sinfs.iter())
            .map(|(path, sinf)| {
                (
                    bundle_relative_path(&bundle_prefix, &path),
                    sinf.data.clone(),
                )
            })
            .collect();

        if !manifest.replication_paths.is_empty() {
            if sinfs.len() == 1 {
                targets.extend(manifest.replication_paths.into_iter().map(|path| {
                    (
                        bundle_relative_path(&bundle_prefix, &path),
                        sinfs[0].data.clone(),
                    )
                }));
            } else if manifest.replication_paths.len() == sinfs.len() {
                targets.extend(
                    manifest
                        .replication_paths
                        .into_iter()
                        .zip(sinfs.iter())
                        .map(|(path, sinf)| {
                            (
                                bundle_relative_path(&bundle_prefix, &path),
                                sinf.data.clone(),
                            )
                        }),
                );
            } else {
                return Err(format!(
                    "cannot map {} sinf replication paths to {} sinfs",
                    manifest.replication_paths.len(),
                    sinfs.len()
                ));
            }
        }

        let mut seen = HashSet::new();
        targets.retain(|(path, _)| seen.insert(path.clone()));
        return Ok(targets);
    }

    if sinfs.len() != 1 {
        return Err("multiple sinfs returned but SC_Info/Manifest.plist is missing".into());
    }

    let executable = read_bundle_executable(archive, &bundle_prefix)?;
    Ok(vec![(
        format!("{bundle_prefix}SC_Info/{executable}.sinf"),
        sinfs[0].data.clone(),
    )])
}

fn find_app_bundle_prefix<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<String, String> {
    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            return Ok(name.trim_end_matches("Info.plist").to_string());
        }
    }

    Err("missing Payload/*.app/Info.plist".into())
}

struct SinfManifest {
    primary_paths: Vec<String>,
    replication_paths: Vec<String>,
}

fn read_manifest_sinf_paths<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    bundle_prefix: &str,
) -> Result<Option<SinfManifest>, String> {
    let Some(data) = read_zip_entry(archive, &format!("{bundle_prefix}SC_Info/Manifest.plist"))?
    else {
        return Ok(None);
    };

    let plist = plist::Value::from_reader(Cursor::new(data)).map_err(|e| e.to_string())?;
    let Some(dict) = plist.as_dictionary() else {
        return Ok(None);
    };

    let primary_paths = manifest_string_array(dict.get("SinfPaths"), "SinfPaths")?;
    let replication_paths =
        manifest_string_array(dict.get("SinfReplicationPaths"), "SinfReplicationPaths")?;

    if primary_paths.is_empty() && replication_paths.is_empty() {
        return Ok(None);
    }

    Ok(Some(SinfManifest {
        primary_paths,
        replication_paths,
    }))
}

fn manifest_string_array(value: Option<&plist::Value>, key: &str) -> Result<Vec<String>, String> {
    let Some(paths) = value.and_then(plist::Value::as_array) else {
        return Ok(Vec::new());
    };

    paths
        .iter()
        .map(|path| {
            path.as_string()
                .map(str::to_string)
                .ok_or_else(|| format!("manifest {key} contains a non-string value"))
        })
        .collect::<Result<Vec<_>, String>>()
}

fn read_bundle_executable<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    bundle_prefix: &str,
) -> Result<String, String> {
    let data = read_zip_entry(archive, &format!("{bundle_prefix}Info.plist"))?
        .ok_or_else(|| "missing app Info.plist".to_string())?;
    let plist = plist::Value::from_reader(Cursor::new(data)).map_err(|e| e.to_string())?;
    plist
        .as_dictionary()
        .and_then(|dict| dict.get("CFBundleExecutable"))
        .and_then(plist::Value::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "missing CFBundleExecutable in app Info.plist".into())
}

fn read_zip_entry<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    path: &str,
) -> Result<Option<Vec<u8>>, String> {
    match archive.by_name(path) {
        Ok(mut file) => {
            let mut data = Vec::new();
            file.read_to_end(&mut data).map_err(|e| e.to_string())?;
            Ok(Some(data))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn bundle_relative_path(bundle_prefix: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
    if path.starts_with("Payload/") {
        path.to_string()
    } else {
        format!("{bundle_prefix}{path}")
    }
}

/// Build an iTunesMetadata.plist XML blob from metadata.
fn build_itunes_metadata_plist(metadata: &DownloadMetadata) -> Result<Vec<u8>, plist::Error> {
    let mut dict = plist::Dictionary::new();
    for (key, value) in metadata {
        dict.insert(key.clone(), json_to_plist(value));
    }

    let plist_value = plist::Value::Dictionary(dict);

    let mut buf = Vec::new();
    plist_value.to_writer_xml(&mut buf)?;
    Ok(buf)
}

fn json_to_plist(value: &serde_json::Value) -> plist::Value {
    match value {
        serde_json::Value::Null => plist::Value::String(String::new()),
        serde_json::Value::Bool(value) => plist::Value::Boolean(*value),
        serde_json::Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                plist::Value::Integer(plist::Integer::from(integer))
            } else if let Some(float) = value.as_f64() {
                plist::Value::Real(float)
            } else {
                plist::Value::String(value.to_string())
            }
        }
        serde_json::Value::String(value) => plist::Value::String(value.clone()),
        serde_json::Value::Array(values) => {
            plist::Value::Array(values.iter().map(json_to_plist).collect())
        }
        serde_json::Value::Object(values) => {
            let dict = values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_plist(value)))
                .collect();
            plist::Value::Dictionary(dict)
        }
    }
}

/// Derive an IPA filename from metadata.
fn derive_ipa_filename(metadata: &DownloadMetadata, app_id: i64, index: usize) -> String {
    let bundle_id = metadata_string(metadata, "softwareVersionBundleId")
        .or_else(|| metadata_string(metadata, "bundleId"))
        .unwrap_or_else(|| format!("app_{app_id}"));
    let version = metadata_string(metadata, "bundleShortVersionString").unwrap_or_default();
    if version.is_empty() {
        format!("{bundle_id}_{index}.ipa")
    } else {
        format!("{bundle_id}_{version}_{index}.ipa")
    }
}

fn metadata_string(metadata: &DownloadMetadata, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Sinf;
    use std::io::{Read, Write};

    fn test_ipa_bytes() -> Vec<u8> {
        test_ipa_bytes_with_manifest(None)
    }

    fn test_ipa_bytes_with_manifest(manifest: Option<plist::Dictionary>) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();

        writer
            .start_file("Payload/Test.app/Info.plist", options)
            .expect("start Info.plist");
        let mut info = plist::Dictionary::new();
        info.insert(
            "CFBundleExecutable".into(),
            plist::Value::String("TestExec".into()),
        );
        let mut info_bytes = Vec::new();
        plist::Value::Dictionary(info)
            .to_writer_xml(&mut info_bytes)
            .expect("write info");
        writer.write_all(&info_bytes).expect("write Info.plist");

        writer
            .start_file("Payload/Test.app/TestExec", options.unix_permissions(0o755))
            .expect("start executable");
        writer.write_all(b"binary").expect("write executable");

        writer
            .add_symlink("Payload/Test.app/Frameworks/Current", "Versions/A", options)
            .expect("add symlink");

        if let Some(manifest) = manifest {
            writer
                .start_file("Payload/Test.app/SC_Info/Manifest.plist", options)
                .expect("start manifest");
            let mut manifest_bytes = Vec::new();
            plist::Value::Dictionary(manifest)
                .to_writer_xml(&mut manifest_bytes)
                .expect("write manifest");
            writer
                .write_all(&manifest_bytes)
                .expect("write manifest bytes");
        }

        writer.finish().expect("finish zip").into_inner()
    }

    fn zip_entry(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("zip");
        let mut file = archive.by_name(name).ok()?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).expect("read entry");
        Some(data)
    }

    #[test]
    fn patch_ipa_writes_sinf_inside_app_sc_info() {
        let patched = patch_ipa(
            &test_ipa_bytes(),
            &[Sinf {
                id: 0,
                data: b"decoded-sinf".to_vec(),
            }],
            &DownloadMetadata::new(),
        )
        .expect("patch ipa");

        assert!(zip_entry(&patched, "SC_Info/0.sinf").is_none());
        assert_eq!(
            zip_entry(&patched, "Payload/Test.app/SC_Info/TestExec.sinf").expect("app sinf"),
            b"decoded-sinf"
        );
    }

    #[test]
    fn patch_ipa_preserves_zip_permissions() {
        let patched = patch_ipa(&test_ipa_bytes(), &[], &DownloadMetadata::new()).expect("patch");
        let mut archive = zip::ZipArchive::new(Cursor::new(patched)).expect("zip");

        {
            let executable = archive
                .by_name("Payload/Test.app/TestExec")
                .expect("executable");
            assert_eq!(executable.unix_mode(), Some(0o100755));
        }

        {
            let symlink = archive
                .by_name("Payload/Test.app/Frameworks/Current")
                .expect("symlink");
            assert!(symlink.is_symlink());
            assert_eq!(symlink.unix_mode(), Some(0o120777));
        }
    }

    #[test]
    fn patch_ipa_replicates_manifest_sinf_paths() {
        let mut manifest = plist::Dictionary::new();
        manifest.insert(
            "SinfPaths".into(),
            plist::Value::Array(vec![plist::Value::String("SC_Info/TestExec.sinf".into())]),
        );
        manifest.insert(
            "SinfReplicationPaths".into(),
            plist::Value::Array(vec![plist::Value::String(
                "Frameworks/TestSDK.framework/SC_Info/TestSDK.sinf".into(),
            )]),
        );

        let patched = patch_ipa(
            &test_ipa_bytes_with_manifest(Some(manifest)),
            &[Sinf {
                id: 0,
                data: b"decoded-sinf".to_vec(),
            }],
            &DownloadMetadata::new(),
        )
        .expect("patch ipa");

        assert_eq!(
            zip_entry(&patched, "Payload/Test.app/SC_Info/TestExec.sinf").expect("app sinf"),
            b"decoded-sinf"
        );
        assert_eq!(
            zip_entry(
                &patched,
                "Payload/Test.app/Frameworks/TestSDK.framework/SC_Info/TestSDK.sinf"
            )
            .expect("replicated sinf"),
            b"decoded-sinf"
        );
    }

    #[test]
    fn metadata_plist_preserves_non_string_values() {
        let metadata = serde_json::json!({
            "bundleShortVersionString": "1.0",
            "softwareVersionExternalIdentifiers": [100, "200"],
            "hasOrEverHasHadIAP": true
        });
        let metadata = metadata.as_object().expect("object");

        let plist_bytes = build_itunes_metadata_plist(metadata).expect("metadata plist");
        let plist = plist::Value::from_reader(Cursor::new(plist_bytes)).expect("plist");
        let dict = plist.as_dictionary().expect("dict");

        assert!(matches!(
            dict.get("softwareVersionExternalIdentifiers"),
            Some(plist::Value::Array(_))
        ));
        assert_eq!(
            dict.get("hasOrEverHasHadIAP"),
            Some(&plist::Value::Boolean(true))
        );
    }

    #[test]
    fn resolve_output_uses_exact_file_for_single_item() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("custom.ipa");
        let destination =
            resolve_output_destination(output.to_str(), 1).expect("output destination");

        assert_eq!(destination.path_for_item("derived.ipa"), output);
    }

    #[test]
    fn resolve_output_uses_directory_when_path_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let destination =
            resolve_output_destination(dir.path().to_str(), 1).expect("output destination");

        assert_eq!(
            destination.path_for_item("derived.ipa"),
            dir.path().join("derived.ipa")
        );
    }

    #[test]
    fn resolve_output_rejects_file_path_for_multiple_items() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("custom.ipa");

        let error = resolve_output_destination(output.to_str(), 2).unwrap_err();

        assert!(error.contains("directory"));
    }

    #[test]
    fn prepare_output_creates_parent_directory_for_file_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("nested").join("custom.ipa");
        let destination =
            resolve_output_destination(output.to_str(), 1).expect("output destination");

        prepare_output_destination(&destination).expect("prepare output");

        assert!(dir.path().join("nested").is_dir());
    }
}
