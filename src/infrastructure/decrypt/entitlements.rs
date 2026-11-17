//! Pure classification of code-signing entitlements by re-sign risk.
//!
//! After stripping `FairPlay` you must re-sign, but an ad-hoc or personal
//! development signature cannot *grant* restricted entitlements. This flags,
//! per key, whether it survives re-signing, needs a provisioning profile, or
//! can never be re-granted.

/// How an entitlement fares when the binary is re-signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntitlementRisk {
    /// Re-applied automatically by `codesign`; nothing to do.
    Ok,
    /// Requires a matching provisioning profile (paid account + device).
    NeedsProvisioning,
    /// Apple-private; cannot be re-granted by any third party.
    CannotRegrant,
}

/// A single entitlement key and its re-sign verdict.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntitlementVerdict {
    /// The entitlement key.
    pub key: String,
    /// Whether it survives re-signing.
    pub risk: EntitlementRisk,
    /// Human-readable rationale.
    pub note: String,
}

/// Keys that `codesign` re-derives from the identity/profile, harmless to drop.
const BENIGN: &[&str] = &[
    "get-task-allow",
    "com.apple.developer.team-identifier",
    "application-identifier",
    "com.apple.application-identifier",
];

/// Restricted keys that only a provisioning profile can grant.
const NEEDS_PROFILE: &[&str] = &[
    "com.apple.security.application-groups",
    "keychain-access-groups",
    "aps-environment",
    "com.apple.developer.associated-domains",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.ubiquity-container-identifiers",
    "com.apple.developer.icloud-services",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.networking.vpn.api",
    "inter-app-audio",
];

/// Classify every entitlement key in `dict`.
pub(super) fn classify(dict: &plist::Dictionary) -> Vec<EntitlementVerdict> {
    dict.keys().map(|key| verdict(key)).collect()
}

fn verdict(key: &str) -> EntitlementVerdict {
    let (risk, note) = if key.starts_with("com.apple.private.") {
        (
            EntitlementRisk::CannotRegrant,
            "Apple-private entitlement; no third party can re-grant it — the feature will break.",
        )
    } else if BENIGN.contains(&key) {
        (
            EntitlementRisk::Ok,
            "re-derived from the signing identity/profile on re-sign.",
        )
    } else if NEEDS_PROFILE.contains(&key) || key.starts_with("com.apple.developer.") {
        (
            EntitlementRisk::NeedsProvisioning,
            "needs a matching provisioning profile (paid account + registered device).",
        )
    } else {
        (EntitlementRisk::Ok, "no special provisioning required.")
    };
    EntitlementVerdict {
        key: key.to_string(),
        risk,
        note: note.to_string(),
    }
}

/// Reject an `.ipa` archive where an extracted `.app` or Mach-O is expected.
///
/// `codesign` cannot read inside a zip and reports the archive as "not signed
/// at all", which hides the real mistake.
///
/// # Errors
///
/// Returns an actionable error when `path` has an `.ipa` extension.
pub(super) fn reject_ipa_archive(path: &std::path::Path) -> Result<(), String> {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ipa"))
    {
        return Err(format!(
            "{}: is an IPA archive; unzip it and pass the Payload/<App>.app bundle or a Mach-O",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ipa_archives_but_accepts_bundles_and_binaries() {
        use std::path::Path;
        let err = reject_ipa_archive(Path::new("/tmp/App.IPA")).unwrap_err();
        assert!(err.contains("unzip it"), "{err}");
        assert!(reject_ipa_archive(Path::new("/tmp/Payload/App.app")).is_ok());
        assert!(reject_ipa_archive(Path::new("/tmp/App")).is_ok());
    }

    fn dict(keys: &[&str]) -> plist::Dictionary {
        let mut d = plist::Dictionary::new();
        for k in keys {
            d.insert((*k).to_string(), plist::Value::Boolean(true));
        }
        d
    }

    #[test]
    fn classifies_each_risk_tier() {
        let verdicts = classify(&dict(&[
            "get-task-allow",
            "com.example.custom-entitlement",
            "com.apple.security.application-groups",
            "com.apple.developer.healthkit",
            "com.apple.private.security.no-sandbox",
        ]));
        let risk = |key: &str| {
            verdicts
                .iter()
                .find(|v| v.key == key)
                .map(|v| v.risk)
                .unwrap()
        };
        assert_eq!(risk("get-task-allow"), EntitlementRisk::Ok);
        assert_eq!(risk("com.example.custom-entitlement"), EntitlementRisk::Ok);
        assert_eq!(
            risk("com.apple.security.application-groups"),
            EntitlementRisk::NeedsProvisioning
        );
        assert_eq!(
            risk("com.apple.developer.healthkit"),
            EntitlementRisk::NeedsProvisioning
        );
        assert_eq!(
            risk("com.apple.private.security.no-sandbox"),
            EntitlementRisk::CannotRegrant
        );
    }
}
