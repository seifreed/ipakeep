//! IPA extraction, signing, and installation for iOS Simulator.

use super::macho::{encrypted_macho_files, is_macho_file};
use super::{
    SimulatorTarget, codesign_command, install_app, prepare_path, run_app, run_checked,
    temp_workdir,
};
use crate::infrastructure::ipa::{bundle_identifier, extract_ipa, find_app_bundle};
use crate::infrastructure::signing::collect_sign_targets;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn install_ipa(
    ipa: &Path,
    run_after_install: bool,
    console: bool,
    target: &SimulatorTarget,
    entitlements: Option<&Path>,
) -> Result<PathBuf, String> {
    let workdir = temp_workdir();
    fs::create_dir_all(&workdir).map_err(|e| format!("{}: {e}", workdir.display()))?;
    extract_ipa(ipa, &workdir)?;
    let app = find_app_bundle(&workdir)?;
    reject_encrypted_app(&app)?;

    prepare_path(&app)?;
    sign_app_bundle(&app, "-", entitlements)?;
    install_app(&app, target)?;

    if run_after_install {
        run_app(
            &bundle_identifier(&app)?,
            &[],
            console,
            target,
            entitlements,
        )?;
    }
    Ok(app)
}

fn reject_encrypted_app(app: &Path) -> Result<(), String> {
    let encrypted = encrypted_macho_files(app)?;
    if encrypted.is_empty() {
        return Ok(());
    }
    let first = encrypted[0].display();
    Err(format!(
        "IPA contains FairPlay-encrypted Mach-O files, starting with {first}. \
         Xcode Simulator cannot run protected App Store IPAs; use a decrypted IPA."
    ))
}

pub(super) fn sign_app_bundle(
    app: &Path,
    identity: &str,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    let mut targets = Vec::new();
    collect_sign_targets(app, &mut targets, &is_macho_file)?;
    targets.sort_by_key(|path| path.components().count());
    for target in targets.iter().rev() {
        run_checked(codesign_command(target, identity, entitlements))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn codesign_command_adds_entitlements_before_target() {
        let command = codesign_command(
            Path::new("/tmp/App.app"),
            "-",
            Some(Path::new("/tmp/entitlements.plist")),
        );

        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            args,
            vec![
                "-f",
                "-s",
                "-",
                "--entitlements",
                "/tmp/entitlements.plist",
                "/tmp/App.app",
            ]
        );
    }

    #[test]
    fn encrypted_app_is_rejected_and_plain_app_is_allowed() {
        let directory = tempfile::tempdir().expect("app directory");
        assert!(reject_encrypted_app(directory.path()).is_ok());

        let executable = directory.path().join("App");
        write_encrypted_arm64_macho(&executable);
        let error = reject_encrypted_app(directory.path()).unwrap_err();
        assert!(error.contains("FairPlay-encrypted"));
        assert!(error.contains("App"));
    }

    #[test]
    fn signing_empty_bundle_is_a_noop_and_missing_bundle_fails() {
        let directory = tempfile::tempdir().expect("app directory");
        assert!(sign_app_bundle(directory.path(), "-", None).is_ok());
        assert!(sign_app_bundle(&directory.path().join("missing"), "-", None).is_err());
    }

    fn write_encrypted_arm64_macho(path: &Path) {
        let mut bytes = Vec::new();
        for value in [
            super::super::macho::MH_MAGIC_64,
            0x0100_000c_u32,
            0,
            0,
            1,
            24,
            0,
            0,
            0x2c,
            24,
            0,
            4096,
            1,
            0,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        fs::write(path, bytes).expect("write encrypted Mach-O fixture");
    }
}
