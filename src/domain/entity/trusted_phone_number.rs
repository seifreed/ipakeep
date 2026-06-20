//! Trusted phone number entity used by the `GrandSlam` SMS 2FA flow.

/// A trusted phone number registered for an Apple ID's two-factor authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustedPhoneNumber {
    /// Apple's numeric identifier for the phone, sent back as `phoneNumber.id`
    /// when requesting/validating an SMS code.
    pub id: i64,
    /// Human-readable (obfuscated) phone number for display in the picker.
    pub number: String,
}
