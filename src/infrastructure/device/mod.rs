//! Installation of a verified, re-signed IPA on a connected iOS device.

use crate::infrastructure::decrypt::ensure_decrypted;
use crate::infrastructure::exec::{require_program, run_inherit, temp_dir};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Inputs for installing a decrypted IPA on a physical device.
pub struct InstallRequest<'a> {
    /// IPA whose Mach-O slices must already be decrypted.
    pub ipa: &'a Path,
    /// Connected device identifier accepted by `devicectl`.
    pub device: &'a str,
    /// Signing identity installed in the local keychain.
    pub identity: &'a str,
    /// Development provisioning profile for the app/team.
    pub provisioning_profile: &'a Path,
    /// Main-app entitlements. When omitted, they are read from the profile.
    pub entitlements: Option<&'a Path>,
    /// Launch the app after installation.
    pub launch: bool,
}

/// Re-sign and install a decrypted IPA with Apple's native `devicectl`.
///
/// Nested bundles retain their own entitlement sets. A profile or entitlement
/// mismatch is returned by `codesign` instead of being hidden by a deep sign.
///
/// # Errors
///
/// Returns an error when the IPA is encrypted, signing fails, or the device
/// tools reject the installation.
pub fn install_ipa(request: &InstallRequest<'_>) -> Result<(), String> {
    require_program("xcrun")?;
    let ipa_bytes =
        fs::read(request.ipa).map_err(|error| format!("{}: {error}", request.ipa.display()))?;
    ensure_decrypted(ipa_bytes)?;

    let workdir = temp_dir("device-install")?;
    let result = install_in_workdir(request, &workdir);
    let _ = fs::remove_dir_all(&workdir);
    result
}

fn install_in_workdir(request: &InstallRequest<'_>, workdir: &Path) -> Result<(), String> {
    extract_ipa(request.ipa, workdir)?;
    let app = find_app(workdir)?;
    embed_profiles(&app, request.provisioning_profile)?;
    let generated = request
        .entitlements
        .is_none()
        .then(|| profile_entitlements(request.provisioning_profile, workdir))
        .transpose()?;
    sign_bundle(
        &app,
        request.identity,
        request.entitlements.or(generated.as_deref()),
    )?;
    install_app(&app, request.device)?;
    if request.launch {
        launch_app(&app, request.device)?;
    }
    Ok(())
}

fn extract_ipa(ipa: &Path, destination: &Path) -> Result<(), String> {
    let file = fs::File::open(ipa).map_err(|error| format!("{}: {error}", ipa.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|error| format!("invalid IPA ZIP: {error}"))?;
    archive
        .extract(destination)
        .map_err(|error| format!("failed to extract IPA: {error}"))
}

fn find_app(workdir: &Path) -> Result<PathBuf, String> {
    let payload = workdir.join("Payload");
    for entry in
        fs::read_dir(&payload).map_err(|error| format!("{}: {error}", payload.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() && path.extension().is_some_and(|ext| ext == "app") {
            return Ok(path);
        }
    }
    Err("IPA did not contain Payload/*.app".into())
}

fn embed_profiles(path: &Path, profile: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir()
        && path
            .extension()
            .is_some_and(|ext| ext == "app" || ext == "appex")
    {
        fs::copy(profile, path.join("embedded.mobileprovision"))
            .map_err(|error| format!("embedding profile in {}: {error}", path.display()))?;
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
            embed_profiles(&entry.map_err(|error| error.to_string())?.path(), profile)?;
        }
    }
    Ok(())
}

fn sign_bundle(app: &Path, identity: &str, main_entitlements: Option<&Path>) -> Result<(), String> {
    let mut targets = Vec::new();
    collect_sign_targets(app, &mut targets)?;
    targets.sort_by_key(|path| path.components().count());
    for target in targets.iter().rev() {
        let mut command = Command::new("/usr/bin/codesign");
        command.args(["--force", "--sign", identity]);
        if target == app {
            if let Some(entitlements) = main_entitlements {
                command.args(["--entitlements", &entitlements.to_string_lossy()]);
            }
        } else {
            command.arg("--preserve-metadata=identifier,requirements,flags,entitlements");
        }
        command.arg(target);
        run_inherit(command)?;
    }
    Ok(())
}

fn collect_sign_targets(path: &Path, targets: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if path.extension().is_some_and(|ext| ext == "dylib") {
            targets.push(path.to_path_buf());
        }
        return Ok(());
    }
    if path
        .extension()
        .is_some_and(|ext| ext == "framework" || ext == "appex" || ext == "app")
    {
        targets.push(path.to_path_buf());
    }
    for entry in fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        collect_sign_targets(&entry.map_err(|error| error.to_string())?.path(), targets)?;
    }
    Ok(())
}

fn profile_entitlements(profile: &Path, workdir: &Path) -> Result<PathBuf, String> {
    let output = Command::new("/usr/bin/security")
        .args(["cms", "-D", "-i"])
        .arg(profile)
        .output()
        .map_err(|error| format!("failed to decode provisioning profile: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let value = plist::Value::from_reader(Cursor::new(output.stdout))
        .map_err(|error| format!("invalid provisioning profile: {error}"))?;
    let entitlements = value
        .as_dictionary()
        .and_then(|dict| dict.get("Entitlements"))
        .ok_or("provisioning profile has no Entitlements dictionary")?;
    let path = workdir.join("profile-entitlements.plist");
    let mut file =
        fs::File::create(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    entitlements
        .to_writer_xml(&mut file)
        .map_err(|error| format!("writing {}: {error}", path.display()))?;
    Ok(path)
}

fn install_app(app: &Path, device: &str) -> Result<(), String> {
    let mut command = Command::new("/usr/bin/xcrun");
    command.args(["devicectl", "device", "install", "app", "--device", device]);
    command.arg(app);
    run_inherit(command)
}

fn launch_app(app: &Path, device: &str) -> Result<(), String> {
    let bundle_id = bundle_identifier(app)?;
    let mut command = Command::new("/usr/bin/xcrun");
    command.args([
        "devicectl",
        "device",
        "process",
        "launch",
        "--device",
        device,
    ]);
    command.arg(bundle_id);
    run_inherit(command)
}

fn bundle_identifier(app: &Path) -> Result<String, String> {
    let info = plist::Value::from_file(app.join("Info.plist"))
        .map_err(|error| format!("{}: {error}", app.join("Info.plist").display()))?;
    info.as_dictionary()
        .and_then(|dict| dict.get("CFBundleIdentifier"))
        .and_then(plist::Value::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{} missing CFBundleIdentifier", app.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_sign_targets_places_nested_code_before_app() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("App.app");
        let framework = app.join("Frameworks").join("Kit.framework");
        let dylib = framework.join("Kit.dylib");
        fs::create_dir_all(&framework).unwrap();
        fs::write(&dylib, []).unwrap();

        let mut targets = Vec::new();
        collect_sign_targets(&app, &mut targets).unwrap();
        targets.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        assert_eq!(targets[0], dylib);
        assert_eq!(targets[1], framework);
        assert_eq!(targets[2], app);
    }

    #[test]
    fn bundle_identifier_reads_info_plist() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("App.app");
        fs::create_dir_all(&app).unwrap();
        let mut info = Vec::new();
        plist::Value::Dictionary(plist::Dictionary::from_iter([(
            String::from("CFBundleIdentifier"),
            plist::Value::String("com.example.app".into()),
        )]))
        .to_writer_xml(&mut info)
        .unwrap();
        fs::write(app.join("Info.plist"), info).unwrap();
        assert_eq!(bundle_identifier(&app).unwrap(), "com.example.app");
    }
}
