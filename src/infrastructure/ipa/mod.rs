//! IPA packaging — integrity verification and DRM/metadata patching.
//!
//! This is pure byte/format manipulation over the downloaded archive: it
//! verifies the download checksum, injects `iTunesMetadata.plist`, and
//! replicates the `sinf` DRM blobs into the app bundle's `SC_Info` directory.
//! It depends only on the domain entities and the `zip`/`plist` codecs.

mod metadata;
mod sinf;

use crate::domain::entity::{DownloadMetadata, Sinf};
use metadata::build_itunes_metadata_plist;
use sinf::sinf_target_paths;
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek, Write};

/// Verify the MD5 checksum of downloaded bytes.
///
/// An empty `expected` checksum is treated as "no checksum available" and
/// passes verification.
///
/// # Errors
///
/// Returns an error when the computed checksum does not match `expected`.
pub fn verify_md5(bytes: &[u8], expected: &str) -> Result<(), String> {
    if expected.is_empty() {
        return Ok(());
    }
    let computed = format!("{:x}", md5::compute(bytes));
    if computed != expected {
        return Err(format!("MD5 mismatch: expected {expected}, got {computed}"));
    }
    Ok(())
}

/// Patch an IPA with sinf DRM data and an `iTunesMetadata.plist`.
///
/// # Errors
///
/// Returns an error if the archive cannot be read, the sinf manifest is
/// inconsistent with the response, or re-writing the archive fails.
pub fn patch_ipa(
    ipa_bytes: &[u8],
    sinfs: &[Sinf],
    metadata: &DownloadMetadata,
) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(ipa_bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| e.to_string())?;

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let mut written = HashSet::new();

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

    inject_metadata(&mut writer, &mut written, metadata)?;
    inject_sinfs(&mut writer, &mut written, sinf_targets)?;

    let cursor = writer.finish().map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn inject_metadata<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    written: &mut HashSet<String>,
    metadata: &DownloadMetadata,
) -> Result<(), String> {
    if metadata.is_empty() || !written.insert("iTunesMetadata.plist".to_string()) {
        return Ok(());
    }
    let plist_data = build_itunes_metadata_plist(metadata).map_err(|e| e.to_string())?;
    writer
        .start_file("iTunesMetadata.plist", inserted_file_options())
        .map_err(|e| e.to_string())?;
    writer.write_all(&plist_data).map_err(|e| e.to_string())
}

fn inject_sinfs<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    written: &mut HashSet<String>,
    sinf_targets: Vec<(String, Vec<u8>)>,
) -> Result<(), String> {
    for (sinf_name, data) in sinf_targets {
        if !written.insert(sinf_name.clone()) {
            continue;
        }
        writer
            .start_file(&sinf_name, inserted_file_options())
            .map_err(|e| e.to_string())?;
        writer.write_all(&data).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn copy_zip_entry<W: Write + Seek, R: Read>(
    writer: &mut zip::ZipWriter<W>,
    mut file: zip::read::ZipFile<'_, R>,
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

fn entry_options<R: Read + ?Sized>(
    file: &zip::read::ZipFile<'_, R>,
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

#[cfg(test)]
mod tests;
