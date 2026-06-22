//! IPA extraction, signing, and installation for iOS Simulator.

use super::macho::{encrypted_macho_files, is_macho_file};
use super::{
    SimulatorTarget, codesign_command, install_app, prepare_path, run_app, run_checked,
    temp_workdir,
};
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
    let app = find_extracted_app(&workdir)?;
    reject_encrypted_app(&app)?;

    prepare_path(&app)?;
    sign_app_bundle(&app, "-", entitlements)?;
    install_app(&app, target)?;

    if run_after_install {
        run_app(&bundle_id(&app)?, &[], console, target, entitlements)?;
    }
    Ok(app)
}

fn extract_ipa(ipa: &Path, destination: &Path) -> Result<(), String> {
    let file = fs::File::open(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("invalid IPA ZIP: {e}"))?;
    archive
        .extract(destination)
        .map_err(|e| format!("failed to extract IPA: {e}"))
}

fn find_extracted_app(workdir: &Path) -> Result<PathBuf, String> {
    let payload = workdir.join("Payload");
    for entry in fs::read_dir(&payload).map_err(|e| format!("{}: {e}", payload.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if metadata.is_dir() && path.extension().is_some_and(|extension| extension == "app") {
            return Ok(path);
        }
    }
    Err("IPA did not contain Payload/*.app".into())
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
    collect_sign_targets(app, &mut targets)?;
    targets.sort_by_key(|path| path.components().count());
    for target in targets.iter().rev() {
        run_checked(codesign_command(target, identity, entitlements))?;
    }
    Ok(())
}

fn collect_sign_targets(path: &Path, targets: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if path.extension().is_some_and(|ext| ext == "dylib") && is_macho_file(path)? {
            targets.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let is_code_bundle = path.extension().is_some_and(|ext| {
        matches!(
            ext.to_string_lossy().as_ref(),
            "framework" | "appex" | "app"
        )
    });
    if is_code_bundle {
        targets.push(path.to_path_buf());
    }

    for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
        collect_sign_targets(&entry.map_err(|e| e.to_string())?.path(), targets)?;
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

    #[cfg(unix)]
    #[test]
    fn collect_sign_targets_skips_symlinked_bundles() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = dir.path().join("Outside.framework");
        let link = dir
            .path()
            .join("App.app")
            .join("Frameworks")
            .join("Linked.framework");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let mut targets = Vec::new();
        collect_sign_targets(dir.path(), &mut targets).unwrap();

        assert!(!targets.iter().any(|target| target == &link));
    }
}
