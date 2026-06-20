//! `sinf` target path resolution for patched IPA archives.

use crate::domain::entity::Sinf;
use std::collections::HashSet;
use std::io::{Cursor, Read, Seek};

pub(super) fn sinf_target_paths<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    sinfs: &[Sinf],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if sinfs.is_empty() {
        return Ok(Vec::new());
    }

    let bundle_prefix = find_app_bundle_prefix(archive)?;
    if let Some(manifest) = read_manifest_sinf_paths(archive, &bundle_prefix)? {
        return manifest_sinf_targets(&bundle_prefix, manifest, sinfs);
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

fn manifest_sinf_targets(
    bundle_prefix: &str,
    manifest: SinfManifest,
    sinfs: &[Sinf],
) -> Result<Vec<(String, Vec<u8>)>, String> {
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
            bundle_relative_path(bundle_prefix, &path).map(|path| (path, sinf.data.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;

    extend_replication_targets(
        &mut targets,
        bundle_prefix,
        manifest.replication_paths,
        sinfs,
    )?;

    let mut seen = HashSet::new();
    targets.retain(|(path, _)| seen.insert(path.clone()));
    Ok(targets)
}

fn extend_replication_targets(
    targets: &mut Vec<(String, Vec<u8>)>,
    bundle_prefix: &str,
    replication_paths: Vec<String>,
    sinfs: &[Sinf],
) -> Result<(), String> {
    if replication_paths.is_empty() {
        return Ok(());
    }

    if sinfs.len() == 1 {
        let replicas = replication_paths
            .into_iter()
            .map(|path| {
                bundle_relative_path(bundle_prefix, &path).map(|path| (path, sinfs[0].data.clone()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        targets.extend(replicas);
        return Ok(());
    }

    if replication_paths.len() != sinfs.len() {
        return Err(format!(
            "cannot map {} sinf replication paths to {} sinfs",
            replication_paths.len(),
            sinfs.len()
        ));
    }

    let replicas = replication_paths
        .into_iter()
        .zip(sinfs.iter())
        .map(|(path, sinf)| {
            bundle_relative_path(bundle_prefix, &path).map(|path| (path, sinf.data.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    targets.extend(replicas);
    Ok(())
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

fn bundle_relative_path(bundle_prefix: &str, path: &str) -> Result<String, String> {
    if path.starts_with('/') || path.contains('\\') {
        return Err(format!("unsafe sinf manifest path: {path}"));
    }
    if path
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("unsafe sinf manifest path: {path}"));
    }

    if path.starts_with("Payload/") {
        if path.starts_with(bundle_prefix) {
            Ok(path.to_string())
        } else {
            Err(format!("sinf manifest path outside app bundle: {path}"))
        }
    } else {
        Ok(format!("{bundle_prefix}{path}"))
    }
}
