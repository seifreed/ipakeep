//! Simulator command handlers.

use crate::infrastructure::simulator::{
    SimulatorTarget, install_ipa, prepare_path, run_app, unlock_runtime_path,
};
use std::path::{Path, PathBuf};

/// Prepare an app bundle or dylib for iOS Simulator.
///
/// # Errors
///
/// Returns an error if the path cannot be scanned or converted.
pub fn handle_prepare(path: &Path) -> Result<(), String> {
    let converted = prepare_path(path)?;
    for path in &converted {
        println!("Prepared: {}", path.display());
    }
    if converted.is_empty() {
        println!("No arm64 Mach-O files needed changes.");
    }
    Ok(())
}

/// Launch an installed Simulator app with optional dylib injection.
///
/// # Errors
///
/// Returns an error if no Simulator is booted or the app cannot launch.
pub fn handle_run(
    bundle_id: &str,
    inject_dylib: &[PathBuf],
    console: bool,
    target: &SimulatorTarget,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    run_app(bundle_id, inject_dylib, console, target, entitlements)
}

/// Install an IPA into the first booted Simulator.
///
/// # Errors
///
/// Returns an error if the IPA is encrypted or Simulator rejects the app.
pub fn handle_install_ipa(
    ipa: &Path,
    run: bool,
    console: bool,
    target: &SimulatorTarget,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    let app = install_ipa(ipa, run, console, target, entitlements)?;
    println!("Installed: {}", app.display());
    Ok(())
}

/// Make a Simulator runtime path read-write.
///
/// # Errors
///
/// Returns an error if the overlay cannot be created.
pub fn handle_unlock_runtime(path: Option<&Path>) -> Result<(), String> {
    unlock_runtime_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_handles_empty_bundle_and_missing_path() {
        let directory = tempfile::tempdir().expect("bundle directory");
        assert!(handle_prepare(directory.path()).is_ok());
        assert!(handle_prepare(&directory.path().join("missing")).is_err());
    }

    #[test]
    fn prepare_handles_a_binary_that_needs_conversion() {
        let directory = tempfile::tempdir().expect("bundle directory");
        let binary = directory.path().join("AppBinary");
        let mut bytes = Vec::new();
        for value in [0xfeed_facf_u32, 0x0100_000c, 0, 0, 0, 0, 0, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        std::fs::write(&binary, bytes).unwrap();

        assert!(handle_prepare(directory.path()).is_ok());
    }

    #[test]
    fn run_rejects_an_empty_explicit_simulator_id() {
        let target = SimulatorTarget {
            udid: Some(" ".into()),
            device: None,
        };
        assert!(handle_run("com.example.app", &[], false, &target, None).is_err());
    }

    #[test]
    fn unlock_rejects_a_path_outside_simulator_runtime() {
        assert!(handle_unlock_runtime(Some(Path::new("/tmp/runtime"))).is_err());
    }
}
