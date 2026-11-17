//! `com.apple.mobile.installation_proxy` client: the `Install` command and its
//! status stream (`{Status, PercentComplete}` messages ending in
//! `Status = Complete`, or an `Error` / `ErrorDescription` reply).

use super::BoxStream;
use super::codec::{dict, recv_plist, send_plist, string, unsigned};
use plist::Value;

/// lockdownd service name.
pub(crate) const SERVICE: &str = "com.apple.mobile.installation_proxy";

/// Hints for the most common installation errors.
const ERROR_HINTS: &[(&str, &str)] = &[
    (
        "ApplicationVerificationFailed",
        "the device rejected the code signature; check that the signing identity matches the \
         provisioning profile, the profile lists this device's UDID, and Developer Mode is enabled (iOS 16+)",
    ),
    (
        "DeviceOSVersionTooLow",
        "the app's MinimumOSVersion is newer than the device's iOS",
    ),
    (
        "MismatchedApplicationIdentifierEntitlement",
        "an app with this bundle ID from another team is installed; delete it from the device first",
    ),
    (
        "PackageExtractionFailed",
        "the device could not read the staged bundle; the upload may be incomplete",
    ),
    (
        "PackageInspectionFailed",
        "the device could not inspect the staged bundle (missing or invalid Info.plist?)",
    ),
    (
        "IncorrectArchitecture",
        "the app has no executable slice for this device's CPU",
    ),
    (
        "InstallProhibited",
        "app installation is restricted on this device (Screen Time or MDM)",
    ),
];

/// One status update from the install stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) status: String,
    pub(crate) percent: Option<u64>,
}

fn describe(error: &str, description: Option<&str>) -> String {
    let hint = ERROR_HINTS
        .iter()
        .find(|(code, _)| *code == error)
        .map_or("", |(_, hint)| hint);
    let mut message = format!("installation failed: {error}");
    for part in [description.unwrap_or(""), hint] {
        if !part.is_empty() {
            message.push_str(" — ");
            message.push_str(part);
        }
    }
    message
}

/// Install the bundle staged at `package_path` (relative to the AFC root).
pub(crate) fn install(
    mut stream: BoxStream,
    package_path: &str,
    progress: &mut dyn FnMut(&Progress),
) -> Result<(), String> {
    send_plist(
        &mut stream,
        dict([
            ("Command", "Install".into()),
            ("PackagePath", package_path.into()),
            (
                "ClientOptions",
                Value::Dictionary(dict([("PackageType", "Developer".into())])),
            ),
        ]),
    )?;
    loop {
        let reply =
            recv_plist(&mut stream).map_err(|error| format!("installation_proxy: {error}"))?;
        if let Some(error) = string(&reply, "Error") {
            return Err(describe(error, string(&reply, "ErrorDescription")));
        }
        let update = Progress {
            status: string(&reply, "Status").unwrap_or_default().to_string(),
            percent: unsigned(&reply, "PercentComplete"),
        };
        progress(&update);
        if update.status == "Complete" {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_combine_device_description_and_hint() {
        assert_eq!(
            describe("ApplicationVerificationFailed", Some("bad sig")),
            format!(
                "installation failed: ApplicationVerificationFailed — bad sig — {}",
                ERROR_HINTS[0].1
            )
        );
        assert_eq!(describe("Odd", None), "installation failed: Odd");
        for (code, hint) in ERROR_HINTS {
            assert!(describe(code, None).ends_with(hint));
        }
    }
}
