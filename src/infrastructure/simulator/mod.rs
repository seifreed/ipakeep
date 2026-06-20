//! iOS Simulator helpers for preparing and launching extracted app bundles.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod device;
mod installer;
mod macho;
mod runtime;
pub use device::SimulatorTarget;
use device::simulator_udid;
#[cfg(test)]
use macho::is_arm64_simulator_binary;
#[cfg(test)]
use macho::*;
use macho::{convert_macho_file, ensure_simulator_dylib};
pub use runtime::unlock_runtime_path;

/// Prepare an extracted app bundle or dylib for Apple Silicon iOS Simulator.
///
/// # Errors
///
/// Returns an error if the path cannot be scanned or a Mach-O write fails.
pub fn prepare_path(path: &Path) -> Result<Vec<PathBuf>, String> {
    tracing::debug!(path = %path.display(), "preparing simulator path");
    let mut converted = Vec::new();
    prepare_path_inner(path, &mut converted)?;
    tracing::debug!(
        path = %path.display(),
        converted_count = converted.len(),
        "simulator path prepared"
    );
    Ok(converted)
}

/// Extract, prepare, sign, install, and optionally launch an IPA in Simulator.
///
/// # Errors
///
/// Returns an error if the IPA is FairPlay-encrypted or any Simulator step
/// fails.
pub fn install_ipa(
    ipa: &Path,
    run_after_install: bool,
    console: bool,
    target: &SimulatorTarget,
    entitlements: Option<&Path>,
) -> Result<PathBuf, String> {
    tracing::debug!(
        ipa = %ipa.display(),
        run_after_install,
        console,
        entitlements_present = entitlements.is_some(),
        "installing ipa in simulator"
    );
    let app = installer::install_ipa(ipa, run_after_install, console, target, entitlements)?;
    tracing::debug!(app = %app.display(), "ipa installed in simulator");
    Ok(app)
}

fn prepare_path_inner(path: &Path, converted: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if convert_macho_file(path)? {
            converted.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        prepare_path_inner(&entry.path(), converted)?;
    }

    Ok(())
}

/// Launch an installed app on the first booted Simulator with dylib injection.
///
/// # Errors
///
/// Returns an error if Xcode tools fail, no Simulator is booted, or a dylib
/// cannot be prepared.
pub fn run_app(
    bundle_id: &str,
    dylibs: &[PathBuf],
    console: bool,
    target: &SimulatorTarget,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    tracing::debug!(
        bundle_id,
        dylib_count = dylibs.len(),
        console,
        entitlements_present = entitlements.is_some(),
        "launching simulator app"
    );
    let udid = simulator_udid(target)?;
    for dylib in dylibs {
        ensure_simulator_dylib(dylib, entitlements)?;
    }
    run_checked(build_launch_command(&udid, bundle_id, dylibs, console))
}

/// Build the `simctl launch` command with the same argv/env contract that
/// `run_app` relies on: `--console` is added only when requested, and
/// `SIMCTL_CHILD_DYLD_INSERT_LIBRARIES` only carries dylibs that need
/// injection.
fn build_launch_command(udid: &str, bundle_id: &str, dylibs: &[PathBuf], console: bool) -> Command {
    let mut command = Command::new("/usr/bin/xcrun");
    command.args(["simctl", "launch"]);
    if console {
        command.arg("--console");
    }
    command.args([udid, bundle_id]);
    if !dylibs.is_empty() {
        let joined = dylibs
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");
        command.env("SIMCTL_CHILD_DYLD_INSERT_LIBRARIES", joined);
    }
    command
}

pub(super) fn install_app(app: &Path, target: &SimulatorTarget) -> Result<(), String> {
    let udid = simulator_udid(target)?;
    run_checked(command_with_args(
        "/usr/bin/xcrun",
        &["simctl", "install", &udid, &app.to_string_lossy()],
    ))
}

fn command_with_args(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
}

fn codesign_command(target: &Path, entitlements: Option<&Path>) -> Command {
    let mut command = command_with_args("/usr/bin/codesign", &["-f", "-s", "-"]);
    if let Some(entitlements) = entitlements {
        command.arg("--entitlements").arg(entitlements);
    }
    command.arg(target);
    command
}

fn command_output(mut command: Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_checked(mut command: Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.trim().is_empty() {
            print!("{stdout}");
        }
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(stderr.trim().to_string())
}

pub(super) fn temp_workdir() -> PathBuf {
    let unique = format!(
        "ipakeep-simulator-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    std::env::temp_dir().join(unique)
}

#[cfg(test)]
mod tests;
