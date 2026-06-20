use crate::domain::entity::{DownloadMetadata, metadata_string};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) enum OutputDestination {
    Directory(PathBuf),
    File(PathBuf),
}

impl OutputDestination {
    pub(super) fn resolve(output: Option<&str>, item_count: usize) -> Result<Self, String> {
        let Some(raw_output) = output else {
            return Ok(Self::Directory(PathBuf::from(".")));
        };

        let path = PathBuf::from(raw_output);
        if output_designates_directory(raw_output, &path) {
            return Ok(Self::Directory(path));
        }

        if item_count > 1 {
            return Err("--output must be a directory when downloading multiple items".into());
        }

        Ok(Self::File(path))
    }

    pub(super) fn path_for_item(&self, file_name: &str) -> PathBuf {
        match self {
            Self::Directory(path) => path.join(file_name),
            Self::File(path) => path.clone(),
        }
    }
}

pub(super) fn prepare_output_destination(destination: &OutputDestination) -> Result<(), String> {
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

/// Derive an IPA filename from metadata.
pub(super) fn derive_ipa_filename(
    metadata: &DownloadMetadata,
    app_id: i64,
    index: usize,
) -> String {
    let bundle_id = metadata_string(metadata, "softwareVersionBundleId")
        .or_else(|| metadata_string(metadata, "bundleId"))
        .unwrap_or_else(|| format!("app_{app_id}"));
    let bundle_id = safe_filename_segment(&bundle_id);
    let version = metadata_string(metadata, "bundleShortVersionString")
        .map(|version| safe_filename_segment(&version))
        .unwrap_or_default();
    if version.is_empty() {
        format!("{bundle_id}_{index}.ipa")
    } else {
        format!("{bundle_id}_{version}_{index}.ipa")
    }
}

fn safe_filename_segment(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() { "_".into() } else { safe }
}

fn output_designates_directory(raw_output: &str, path: &Path) -> bool {
    path.is_dir() || raw_output.ends_with('/') || raw_output.ends_with('\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_output_uses_exact_file_for_single_item() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("custom.ipa");
        let destination = OutputDestination::resolve(output.to_str(), 1).expect("output");

        assert_eq!(destination.path_for_item("derived.ipa"), output);
    }

    #[test]
    fn resolve_output_uses_directory_when_path_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let destination = OutputDestination::resolve(dir.path().to_str(), 1).expect("output");

        assert_eq!(
            destination.path_for_item("derived.ipa"),
            dir.path().join("derived.ipa")
        );
    }

    #[test]
    fn resolve_output_rejects_file_path_for_multiple_items() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("custom.ipa");

        let error = OutputDestination::resolve(output.to_str(), 2).unwrap_err();

        assert!(error.contains("directory"));
    }

    #[test]
    fn prepare_output_creates_parent_directory_for_file_output() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = dir.path().join("nested").join("custom.ipa");
        let destination = OutputDestination::resolve(output.to_str(), 1).expect("output");

        prepare_output_destination(&destination).expect("prepare output");

        assert!(dir.path().join("nested").is_dir());
    }

    #[test]
    fn derive_ipa_filename_sanitizes_remote_metadata_segments() {
        let metadata = serde_json::json!({
            "softwareVersionBundleId": "../bad\\bundle",
            "bundleShortVersionString": "1/2:3"
        });
        let metadata = metadata.as_object().unwrap();

        assert_eq!(
            derive_ipa_filename(metadata, 123, 0),
            ".._bad_bundle_1_2_3_0.ipa"
        );
    }
}
