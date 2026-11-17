//! `codesign`-backed entitlement extraction and bundle re-signing.
//!
//! Boundary adapter over Apple's `/usr/bin/codesign`; the parsing and
//! classification it feeds live in the parent module.

use super::{EntitlementVerdict, bundle_executable_on_disk, classify_entitlements_xml};
use crate::infrastructure::exec::observed_output;
use std::path::Path;
use std::process::Command;

/// Re-sign an extracted `.app` bundle, preserving its entitlements.
///
/// When `entitlements_override` is `None`, the original entitlements are read
/// from the bundle's main executable with `codesign -d`.
///
/// # Errors
///
/// Returns an error if entitlements cannot be read or signing fails.
pub fn resign_app(
    app: &Path,
    identity: &str,
    entitlements_override: Option<&Path>,
) -> Result<(), String> {
    if let Some(entitlements) = entitlements_override {
        return crate::infrastructure::simulator::resign_bundle(app, identity, Some(entitlements));
    }

    let executable = bundle_executable_on_disk(app)?;
    let xml = extract_entitlements(&app.join(&executable))?;
    if xml.trim().is_empty() {
        // No custom entitlements to preserve; sign without an override.
        return crate::infrastructure::simulator::resign_bundle(app, identity, None);
    }

    let temp = std::env::temp_dir().join(format!("ipakeep-entitlements-{executable}.plist"));
    std::fs::write(&temp, xml).map_err(|e| format!("{}: {e}", temp.display()))?;
    let result = crate::infrastructure::simulator::resign_bundle(app, identity, Some(&temp));
    let _ = std::fs::remove_file(&temp);
    result
}

pub(crate) fn extract_entitlements(executable: &Path) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["-d", "--entitlements", ":-", "--xml"])
        .arg(executable);
    let output =
        observed_output(&mut command).map_err(|e| format!("failed to run codesign: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Extract and classify a binary's (or bundle's) entitlements by re-sign risk.
///
/// # Errors
///
/// Returns an error if the executable cannot be located or `codesign` fails.
pub fn entitlements_report(path: &Path) -> Result<Vec<EntitlementVerdict>, String> {
    super::entitlements::reject_ipa_archive(path)?;
    let binary = if path.extension().is_some_and(|e| e == "app") {
        path.join(bundle_executable_on_disk(path)?)
    } else {
        path.to_path_buf()
    };
    let xml = extract_entitlements(&binary)?;
    classify_entitlements_xml(&xml)
}
