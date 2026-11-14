//! IPA extraction, signing, and installation for iOS Simulator.

use super::macho::{encrypted_macho_files, is_macho_file};
use super::{
    SimulatorTarget, codesign_command, install_app, prepare_path, run_app, run_checked,
    temp_workdir,
};
use crate::infrastructure::ipa::{extract_ipa, find_app_bundle};
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
        run_app(&bundle_id(&app)?, &[], console, target, entitlements)?;
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

fn bundle_id(app: &Path) -> Result<String, String> {
    let info = app.join("Info.plist");
    let plist = plist::Value::from_file(&info).map_err(|e| format!("{}: {e}", info.display()))?;
    plist
        .as_dictionary()
        .and_then(|dict| dict.get("CFBundleIdentifier"))
        .and_then(plist::Value::as_string)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{} missing CFBundleIdentifier", info.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
