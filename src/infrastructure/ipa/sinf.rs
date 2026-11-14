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
        let name = file.name().map_err(|error| error.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plist_bytes(value: plist::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        value.to_writer_xml(&mut bytes).unwrap();
        bytes
    }

    fn info() -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert(
            "CFBundleExecutable".into(),
            plist::Value::String("Game".into()),
        );
        plist_bytes(plist::Value::Dictionary(dict))
    }

    fn manifest(primary: &[&str], replicas: &[&str]) -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        for (key, paths) in [("SinfPaths", primary), ("SinfReplicationPaths", replicas)] {
            dict.insert(
                key.into(),
                plist::Value::Array(
                    paths
                        .iter()
                        .map(|path| plist::Value::String((*path).into()))
                        .collect(),
                ),
            );
        }
        plist_bytes(plist::Value::Dictionary(dict))
    }

    fn ipa(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut writer, data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn sinfs(count: usize) -> Vec<Sinf> {
        (0..count)
            .map(|id| Sinf {
                id: id as i64,
                data: vec![id as u8],
            })
            .collect()
    }

    fn targets(bytes: &[u8], sinfs: &[Sinf]) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        sinf_target_paths(&mut archive, sinfs)
    }

    #[test]
    fn empty_sinf_response_needs_no_app_archive() {
        assert!(targets(&ipa(&[]), &sinfs(0)).unwrap().is_empty());
    }

    #[test]
    fn missing_manifest_uses_executable_for_one_sinf_and_rejects_many() {
        let bytes = ipa(&[("Payload/Game.app/Info.plist", &info())]);
        assert_eq!(
            targets(&bytes, &sinfs(1)).unwrap(),
            [("Payload/Game.app/SC_Info/Game.sinf".into(), vec![0])]
        );
        assert!(
            targets(&bytes, &sinfs(2))
                .unwrap_err()
                .contains("Manifest.plist is missing")
        );

        let no_info = ipa(&[("Payload/Other.txt", b"data")]);
        assert!(
            targets(&no_info, &sinfs(1))
                .unwrap_err()
                .contains("missing Payload/*.app/Info.plist")
        );
    }

    #[test]
    fn manifest_maps_multiple_sinfs_and_deduplicates_replication_paths() {
        let valid_manifest = manifest(
            &["SC_Info/A.sinf", "SC_Info/B.sinf"],
            &["SC_Info/A.sinf", "SC_Info/B-copy.sinf"],
        );
        let bytes = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            ("Payload/Game.app/SC_Info/Manifest.plist", &valid_manifest),
        ]);
        assert_eq!(
            targets(&bytes, &sinfs(2)).unwrap(),
            [
                ("Payload/Game.app/SC_Info/A.sinf".into(), vec![0]),
                ("Payload/Game.app/SC_Info/B.sinf".into(), vec![1]),
                ("Payload/Game.app/SC_Info/B-copy.sinf".into(), vec![1]),
            ]
        );

        let mismatched_manifest = manifest(
            &["SC_Info/A.sinf", "SC_Info/B.sinf"],
            &["SC_Info/A-copy.sinf"],
        );
        let mismatched = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            (
                "Payload/Game.app/SC_Info/Manifest.plist",
                &mismatched_manifest,
            ),
        ]);
        assert!(
            targets(&mismatched, &sinfs(2))
                .unwrap_err()
                .contains("cannot map 1 sinf replication paths to 2 sinfs")
        );
    }

    #[test]
    fn manifest_rejects_count_mismatches_and_unsafe_or_external_paths() {
        let bytes = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            (
                "Payload/Game.app/SC_Info/Manifest.plist",
                &manifest(&["SC_Info/A.sinf", "SC_Info/B.sinf"], &[]),
            ),
        ]);
        assert!(
            targets(&bytes, &sinfs(1))
                .unwrap_err()
                .contains("sinf count mismatch")
        );

        let valid = [
            "../escape",
            "/absolute",
            r"SC_Info\bad",
            "./dot",
            "SC_Info//bad",
        ];
        for path in valid {
            assert!(bundle_relative_path("Payload/Game.app/", path).is_err());
        }
        assert!(
            bundle_relative_path("Payload/Game.app/", "Payload/Elsewhere/a.sinf")
                .unwrap_err()
                .contains("outside app bundle")
        );
        assert_eq!(
            bundle_relative_path("Payload/Game.app/", "Payload/Game.app/SC_Info/Game.sinf")
                .unwrap(),
            "Payload/Game.app/SC_Info/Game.sinf"
        );
    }

    #[test]
    fn malformed_or_empty_manifest_values_fall_back_or_fail_cleanly() {
        let malformed = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            ("Payload/Game.app/SC_Info/Manifest.plist", b"broken"),
        ]);
        assert!(targets(&malformed, &sinfs(1)).is_err());

        let root_array = plist_bytes(plist::Value::Array(Vec::new()));
        let fallback = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            ("Payload/Game.app/SC_Info/Manifest.plist", &root_array),
        ]);
        assert_eq!(
            targets(&fallback, &sinfs(1)).unwrap()[0].0,
            "Payload/Game.app/SC_Info/Game.sinf"
        );

        let empty_manifest = plist_bytes(plist::Value::Dictionary(plist::Dictionary::new()));
        let empty = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            ("Payload/Game.app/SC_Info/Manifest.plist", &empty_manifest),
        ]);
        assert_eq!(
            targets(&empty, &sinfs(1)).unwrap()[0].0,
            "Payload/Game.app/SC_Info/Game.sinf"
        );

        let mut wrong_type = plist::Dictionary::new();
        wrong_type.insert(
            "SinfPaths".into(),
            plist::Value::Array(vec![plist::Value::Integer(1.into())]),
        );
        let invalid = plist_bytes(plist::Value::Dictionary(wrong_type));
        let invalid = ipa(&[
            ("Payload/Game.app/Info.plist", &info()),
            ("Payload/Game.app/SC_Info/Manifest.plist", &invalid),
        ]);
        assert!(
            targets(&invalid, &sinfs(1))
                .unwrap_err()
                .contains("non-string value")
        );
    }

    #[test]
    fn manifest_helpers_cover_optional_arrays_single_sinf_replicas_and_mismatches() {
        assert!(manifest_string_array(None, "SinfPaths").unwrap().is_empty());
        assert!(
            manifest_string_array(Some(&plist::Value::String("x".into())), "SinfPaths")
                .unwrap()
                .is_empty()
        );

        let mut archive = zip::ZipArchive::new(Cursor::new(ipa(&[]))).unwrap();
        assert!(
            read_manifest_sinf_paths(&mut archive, "Payload/Game.app/")
                .unwrap()
                .is_none()
        );

        let single = SinfManifest {
            primary_paths: vec!["Payload/Game.app/SC_Info/Game.sinf".into()],
            replication_paths: vec!["Frameworks/A.sinf".into(), "Frameworks/B.sinf".into()],
        };
        assert_eq!(
            manifest_sinf_targets("Payload/Game.app/", single, &sinfs(1))
                .unwrap()
                .len(),
            3
        );

        let primary_only = SinfManifest {
            primary_paths: vec!["SC_Info/Game.sinf".into()],
            replication_paths: Vec::new(),
        };
        assert_eq!(
            manifest_sinf_targets("Payload/Game.app/", primary_only, &sinfs(1))
                .unwrap()
                .len(),
            1
        );

        let mut targets = Vec::new();
        assert!(
            extend_replication_targets(
                &mut targets,
                "Payload/Game.app/",
                vec!["Frameworks/A.sinf".into()],
                &sinfs(2),
            )
            .unwrap_err()
            .contains("cannot map 1 sinf replication paths to 2 sinfs")
        );
    }

    #[test]
    fn bundle_info_plist_failures_are_reported() {
        let empty = ipa(&[]);
        let mut archive = zip::ZipArchive::new(Cursor::new(empty)).unwrap();
        assert!(
            read_bundle_executable(&mut archive, "Payload/Game.app/")
                .unwrap_err()
                .contains("missing app Info.plist")
        );

        let invalid_info = plist_bytes(plist::Value::Dictionary(plist::Dictionary::new()));
        let mut archive =
            zip::ZipArchive::new(Cursor::new(ipa(&[("Info.plist", &invalid_info)]))).unwrap();
        assert!(
            read_bundle_executable(&mut archive, "")
                .unwrap_err()
                .contains("missing CFBundleExecutable")
        );
    }
}
