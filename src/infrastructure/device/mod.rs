//! Installation of a verified, re-signed IPA on a connected iOS device.

use crate::infrastructure::decrypt::ensure_decrypted;
use crate::infrastructure::exec::{require_program, run_inherit, temp_dir};
use crate::infrastructure::ipa::{bundle_identifier, extract_ipa, find_app_bundle};
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
    install_ipa_with(request, require_program)
}

fn install_ipa_with(
    request: &InstallRequest<'_>,
    require: fn(&str) -> Result<(), String>,
) -> Result<(), String> {
    require_install_tools(request, require)?;
    let ipa_bytes = read_ipa(request.ipa)?;
    ensure_decrypted(ipa_bytes)?;

    let workdir = temp_dir("device-install")?;
    let result = install_in_workdir(request, &workdir);
    let _ = fs::remove_dir_all(&workdir);
    result
}

fn read_ipa(ipa: &Path) -> Result<Vec<u8>, String> {
    fs::read(ipa).map_err(|error| format!("{}: {error}", ipa.display()))
}

fn require_install_tools(
    request: &InstallRequest<'_>,
    mut require: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    require(if request.legacy_device {
        "ideviceinstaller"
    } else {
        "xcrun"
    })?;
    if request.legacy_device && request.launch {
        require("idevicedebug")?;
    }
    Ok(())
}

fn install_in_workdir(request: &InstallRequest<'_>, workdir: &Path) -> Result<(), String> {
    install_in_workdir_with(request, workdir, signing::sign_bundle, run_inherit)
}

fn install_in_workdir_with(
    request: &InstallRequest<'_>,
    workdir: &Path,
    sign: impl FnOnce(&Path, &InstallRequest<'_>, &Path) -> Result<(), String>,
    mut run: impl FnMut(Command) -> Result<(), String>,
) -> Result<(), String> {
    extract_ipa(request.ipa, workdir)?;
    let app = find_app_bundle(workdir)?;
    sign(&app, request, workdir)?;
    run(install_command(&app, request.device, request.legacy_device))?;
    if request.launch {
        run(launch_command(
            &bundle_identifier(&app)?,
            request.device,
            request.legacy_device,
        ))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::signing::collect_sign_targets;

    fn install_request(ipa: &Path, launch: bool) -> InstallRequest<'_> {
        InstallRequest {
            ipa,
            device: "device-id",
            identity: "identity",
            provisioning_profiles: &[],
            entitlements: None,
            launch,
            legacy_device: false,
        }
    }

    fn app_ipa() -> Vec<u8> {
        let info = br#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.app</string></dict></plist>"#;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in [
            ("Payload/Test.app/Info.plist", &info[..]),
            ("Payload/Test.app/TestExec", &b"binary"[..]),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .expect("start IPA entry");
            std::io::Write::write_all(&mut writer, bytes).expect("write IPA entry");
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    #[test]
    fn install_tool_requirements_include_legacy_launch_tool() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let ipa = dir.path().join("app.ipa");
        let request = InstallRequest {
            legacy_device: true,
            launch: true,
            ..install_request(&ipa, false)
        };
        let mut tools = Vec::new();

        require_install_tools(&request, |tool| {
            tools.push(tool.to_string());
            Ok(())
        })
        .expect("tools present");

        assert_eq!(tools, ["ideviceinstaller", "idevicedebug"]);
    }

    #[test]
    fn workdir_install_runs_sign_install_and_launch_steps() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let ipa = dir.path().join("app.ipa");
        fs::write(&ipa, app_ipa()).expect("write IPA");
        let workdir = dir.path().join("work");
        fs::create_dir(&workdir).expect("work directory");
        let request = install_request(&ipa, true);
        let mut commands = Vec::new();

        install_in_workdir_with(
            &request,
            &workdir,
            |app, _, _| {
                assert!(app.join("Info.plist").is_file());
                Ok(())
            },
            |command| {
                commands.push((
                    command.get_program().to_string_lossy().into_owned(),
                    command
                        .get_args()
                        .map(|arg| arg.to_string_lossy().into_owned())
                        .collect::<Vec<_>>(),
                ));
                Ok(())
            },
        )
        .expect("install flow");

        assert_eq!(commands.len(), 2);
        assert!(commands[0].1.contains(&"device-id".into()));
        assert!(commands[1].1.contains(&"com.example.app".into()));
    }

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
        collect_sign_targets(&app, &mut targets, &|_| Ok(true)).unwrap();
        targets.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        assert_eq!(targets[0], dylib);
        assert_eq!(targets[1], framework);
        assert_eq!(targets[2], app);
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

    #[test]
    fn rejects_a_decrypted_ipa_without_a_matching_profile_before_installing() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipa = dir.path().join("decrypted.ipa");
        let info = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.test</string></dict></plist>"#;
        let mut executable = Vec::new();
        for value in [0xfeed_facf_u32, 0x0100_000c, 0, 2, 0, 0, 0, 0] {
            executable.extend(value.to_le_bytes());
        }
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes) in [
            ("Payload/Test.app/Info.plist", info.as_slice()),
            ("Payload/Test.app/TestExec", executable.as_slice()),
        ] {
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut writer, bytes).unwrap();
        }
        fs::write(&ipa, writer.finish().unwrap().into_inner()).unwrap();
        let request = InstallRequest {
            ipa: &ipa,
            device: "device",
            identity: "identity",
            provisioning_profiles: &[],
            entitlements: None,
            launch: false,
            legacy_device: false,
        };

        assert!(
            install_ipa_with(&request, |_| Ok(()))
                .unwrap_err()
                .contains("no provisioning profile matches com.example.test")
        );
    }

    #[test]
    fn workdir_install_rejects_invalid_archives_before_signing_or_device_commands() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipa = dir.path().join("invalid.ipa");
        let workdir = dir.path().join("work");
        fs::create_dir(&workdir).unwrap();
        fs::write(&ipa, b"not a zip archive").unwrap();
        let request = InstallRequest {
            ipa: &ipa,
            device: "device",
            identity: "identity",
            provisioning_profiles: &[],
            entitlements: None,
            launch: false,
            legacy_device: false,
        };
        assert!(install_in_workdir(&request, &workdir).is_err());

        let ipa = dir.path().join("no-app.ipa");
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        writer
            .start_file(
                "Payload/readme.txt",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        std::io::Write::write_all(&mut writer, b"no app").unwrap();
        fs::write(&ipa, writer.finish().unwrap().into_inner()).unwrap();
        let request = InstallRequest {
            ipa: &ipa,
            ..request
        };
        assert!(
            install_in_workdir(&request, &workdir)
                .unwrap_err()
                .contains("did not contain Payload/*.app")
        );
    }

    #[test]
    fn install_rejects_missing_and_invalid_ipa_before_device_commands() {
        let dir = tempfile::TempDir::new().unwrap();
        let ipa = dir.path().join("input.ipa");
        let request = InstallRequest {
            ipa: &ipa,
            device: "device",
            identity: "identity",
            provisioning_profiles: &[],
            entitlements: None,
            launch: false,
            legacy_device: false,
        };

        assert!(install_ipa(&request).is_err());
        let error = install_ipa_with(&request, |_| Ok(())).unwrap_err();
        assert!(error.starts_with(&ipa.display().to_string()), "{error}");
        fs::write(&ipa, b"not an IPA").unwrap();
        assert!(install_ipa_with(&request, |_| Ok(())).is_err());
    }
}
