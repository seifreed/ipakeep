//! Installation of a verified, re-signed IPA on a connected iOS device.

use crate::infrastructure::decrypt::ensure_decrypted;
use crate::infrastructure::exec::{require_program, run_inherit, temp_dir};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod signing;

/// Inputs for installing a decrypted IPA on a physical device.
pub struct InstallRequest<'a> {
    /// IPA whose Mach-O slices must already be decrypted.
    pub ipa: &'a Path,
    /// Device identifier; a USB UDID is required for legacy devices.
    pub device: &'a str,
    /// Signing identity installed in the local keychain.
    pub identity: &'a str,
    /// Development profiles matched to the app and nested bundle identifiers.
    pub provisioning_profiles: &'a [PathBuf],
    /// Main-app entitlements override. Otherwise preserve the original capabilities.
    pub entitlements: Option<&'a Path>,
    /// Launch the app after installation.
    pub launch: bool,
    /// Use libimobiledevice for devices not supported by `devicectl` (iOS 16).
    pub legacy_device: bool,
}

/// Re-sign and install a decrypted IPA through the selected device tools.
///
/// Each app/extension uses a matching profile and its own entitlements.
/// Profile-incompatible capabilities are rejected before installation.
///
/// # Errors
///
/// Returns an error when the IPA is encrypted, signing fails, or the device
/// tools reject the installation.
pub fn install_ipa(request: &InstallRequest<'_>) -> Result<(), String> {
    require_program(if request.legacy_device {
        "ideviceinstaller"
    } else {
        "xcrun"
    })?;
    if request.legacy_device && request.launch {
        require_program("idevicedebug")?;
    }
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
    signing::sign_bundle(&app, request, workdir)?;
    run_inherit(install_command(&app, request.device, request.legacy_device))?;
    if request.launch {
        run_inherit(launch_command(
            &bundle_identifier(&app)?,
            request.device,
            request.legacy_device,
        ))?;
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

fn install_command(app: &Path, device: &str, legacy: bool) -> Command {
    let mut command = if legacy {
        let mut command = Command::new("ideviceinstaller");
        command.args(["--udid", device, "install"]);
        command
    } else {
        let mut command = Command::new("/usr/bin/xcrun");
        command.args(["devicectl", "device", "install", "app", "--device", device]);
        command
    };
    command.arg(app);
    command
}

fn launch_command(bundle_id: &str, device: &str, legacy: bool) -> Command {
    let mut command = if legacy {
        let mut command = Command::new("idevicedebug");
        command.args(["--udid", device, "--detach", "run"]);
        command
    } else {
        let mut command = Command::new("/usr/bin/xcrun");
        command.args([
            "devicectl",
            "device",
            "process",
            "launch",
            "--device",
            device,
        ]);
        command
    };
    command.arg(bundle_id);
    command
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
    fn rejects_invalid_profile_before_embedding_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let app = dir.path().join("App.app");
        fs::create_dir(&app).unwrap();
        let profile = dir.path().join("invalid.mobileprovision");
        fs::write(&profile, b"not a provisioning profile").unwrap();
        assert!(signing::Profile::read(&profile).is_err());
        assert!(!app.join("embedded.mobileprovision").exists());
    }

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

    #[test]
    fn install_commands_preserve_device_and_bundle_paths() {
        let app = Path::new("/tmp/My App.app");
        let legacy = install_command(app, "USB-UDID", true);
        assert_eq!(legacy.get_program(), "ideviceinstaller");
        assert_eq!(
            legacy.get_args().collect::<Vec<_>>(),
            ["--udid", "USB-UDID", "install", "/tmp/My App.app"]
        );
        let native = install_command(app, "iPhone Name", false);
        assert_eq!(native.get_program(), "/usr/bin/xcrun");
        assert_eq!(
            native.get_args().collect::<Vec<_>>(),
            [
                "devicectl",
                "device",
                "install",
                "app",
                "--device",
                "iPhone Name",
                "/tmp/My App.app"
            ]
        );
    }

    #[test]
    fn legacy_launch_detaches_while_native_launch_uses_devicectl() {
        let legacy = launch_command("com.example.test", "USB-UDID", true);
        assert_eq!(legacy.get_program(), "idevicedebug");
        assert_eq!(
            legacy.get_args().collect::<Vec<_>>(),
            ["--udid", "USB-UDID", "--detach", "run", "com.example.test"]
        );
        let native = launch_command("com.example.test", "iPhone Name", false);
        assert_eq!(native.get_program(), "/usr/bin/xcrun");
        assert_eq!(
            native.get_args().collect::<Vec<_>>(),
            [
                "devicectl",
                "device",
                "process",
                "launch",
                "--device",
                "iPhone Name",
                "com.example.test"
            ]
        );
    }
}
