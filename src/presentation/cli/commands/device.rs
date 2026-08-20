//! Physical-device installation command handlers.

use crate::infrastructure::device::{self, InstallRequest};
use std::path::Path;

/// Install a decrypted IPA on a connected iOS device.
///
/// # Errors
///
/// Returns an error if verification, signing, or `devicectl` fails.
pub fn handle_install(
    ipa: &Path,
    device_id: &str,
    identity: &str,
    provisioning_profile: &Path,
    entitlements: Option<&Path>,
    launch: bool,
) -> Result<(), String> {
    device::install_ipa(&InstallRequest {
        ipa,
        device: device_id,
        identity,
        provisioning_profile,
        entitlements,
        launch,
    })?;
    println!("Installed on device {device_id}: {}", ipa.display());
    Ok(())
}
