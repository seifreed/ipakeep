//! Physical-device installation command handlers.

use crate::infrastructure::device::{self, InstallRequest};

/// Install a decrypted IPA on a connected iOS device.
///
/// # Errors
///
/// Returns an error if verification, signing, or the device tools fail.
pub fn handle_install(request: &InstallRequest<'_>) -> Result<(), String> {
    device::install_ipa(request)?;
    println!(
        "Installed on device {}: {}",
        request.device,
        request.ipa.display()
    );
    Ok(())
}
