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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_reports_missing_ipa_without_running_device_commands() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let ipa = directory.path().join("missing.ipa");
        let request = InstallRequest {
            ipa: &ipa,
            device: "device",
            identity: "identity",
            provisioning_profiles: &[],
            entitlements: None,
            launch: false,
            legacy_device: false,
        };

        assert!(handle_install(&request).is_err());
    }
}
