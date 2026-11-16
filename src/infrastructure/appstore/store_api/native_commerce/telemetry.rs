//! Secret-free field values for the native Store commerce log events.
//!
//! Store requests and responses carry passwords, 2FA codes, tokens, DSIDs,
//! cookies and machine proofs; events only ever carry what these helpers
//! derive: error variant names, endpoint host and path, and Apple's
//! machine-readable failure codes.

use crate::domain::error::AppStoreError;
use reqwest::Url;

const NO_CODE: &str = "none";
const REDACTED: &str = "redacted";
const INVALID_ENDPOINT: &str = "invalid";
const MAX_CODE_LEN: usize = 64;

/// Stable name of an [`AppStoreError`] variant, without its message.
pub(crate) fn error_type(error: &AppStoreError) -> &'static str {
    match error {
        AppStoreError::AuthenticationFailed(_) => "authentication_failed",
        AppStoreError::AuthCodeRequired { .. } => "auth_code_required",
        AppStoreError::AccountDisabled => "account_disabled",
        AppStoreError::InvalidCredentials => "invalid_credentials",
        AppStoreError::AppNotFound(_) => "app_not_found",
        AppStoreError::AppNotFree(_) => "app_not_free",
        AppStoreError::NoLicense(_) => "no_license",
        AppStoreError::VersionNotAvailable(_) => "version_not_available",
        AppStoreError::PurchaseFailed(_) => "purchase_failed",
        AppStoreError::DownloadFailed(_) => "download_failed",
        AppStoreError::IpaPatchingFailed(_) => "ipa_patching_failed",
        AppStoreError::NetworkError(_) => "network_error",
        AppStoreError::Unexpected(_) => "unexpected",
    }
}

/// `host/path` of `url`: no scheme, credentials, query (which can carry the
/// machine GUID) or fragment.
pub(crate) fn endpoint(url: &str) -> String {
    let Ok(parsed) = Url::parse(url) else {
        return INVALID_ENDPOINT.to_string();
    };
    format!("{}{}", parsed.host_str().unwrap_or_default(), parsed.path())
}

/// Apple's machine-readable `failureType`/`customerMessage` code (`2034`,
/// `MZFinance.BadLogin.Configurator_message`); free text, which can name the
/// account, is replaced by `redacted`.
pub(crate) fn apple_code(value: &str) -> String {
    if value.trim().is_empty() {
        return NO_CODE.to_string();
    }
    known_apple_code(value).unwrap_or_else(|| REDACTED.to_string())
}

/// `value` trimmed when it looks like one of Apple's machine-readable codes;
/// `None` for empty or free text.
pub(crate) fn known_apple_code(value: &str) -> Option<String> {
    let value = value.trim();
    let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
    let code_like = !value.is_empty() && value.len() <= MAX_CODE_LEN && value.bytes().all(allowed);
    code_like.then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::TwoFactorMethod;

    #[test]
    fn error_type_names_every_variant_without_its_message() {
        let cases = [
            (
                AppStoreError::AuthenticationFailed("secret".into()),
                "authentication_failed",
            ),
            (
                AppStoreError::AuthCodeRequired {
                    dsid: "8765".into(),
                    idms_token: "token".into(),
                    method: TwoFactorMethod::TrustedDevice,
                },
                "auth_code_required",
            ),
            (AppStoreError::AccountDisabled, "account_disabled"),
            (AppStoreError::InvalidCredentials, "invalid_credentials"),
            (AppStoreError::AppNotFound("x".into()), "app_not_found"),
            (AppStoreError::AppNotFree(1.0), "app_not_free"),
            (AppStoreError::NoLicense(1), "no_license"),
            (
                AppStoreError::VersionNotAvailable("x".into()),
                "version_not_available",
            ),
            (AppStoreError::PurchaseFailed("x".into()), "purchase_failed"),
            (AppStoreError::DownloadFailed("x".into()), "download_failed"),
            (
                AppStoreError::IpaPatchingFailed("x".into()),
                "ipa_patching_failed",
            ),
            (AppStoreError::NetworkError("x".into()), "network_error"),
            (AppStoreError::Unexpected("x".into()), "unexpected"),
        ];
        for (error, expected) in cases {
            assert_eq!(error_type(&error), expected);
        }
    }

    #[test]
    fn endpoint_keeps_only_host_and_path() {
        assert_eq!(
            endpoint("https://user:pw@p48-buy.itunes.apple.com/a/b?guid=AABBCC#frag"),
            "p48-buy.itunes.apple.com/a/b"
        );
        assert_eq!(endpoint("not a url"), "invalid");
    }

    #[test]
    fn apple_code_keeps_codes_and_redacts_free_text() {
        assert_eq!(apple_code(" 2034 "), "2034");
        assert_eq!(
            apple_code("MZFinance.BadLogin.Configurator_message"),
            "MZFinance.BadLogin.Configurator_message"
        );
        assert_eq!(apple_code(""), "none");
        assert_eq!(apple_code("user@example.com"), "redacted");
        assert_eq!(apple_code("Your password has changed."), "redacted");
        assert_eq!(apple_code(&"9".repeat(65)), "redacted");
    }

    #[test]
    fn known_apple_code_drops_empty_and_free_text() {
        assert_eq!(known_apple_code(" 2034 ").as_deref(), Some("2034"));
        assert_eq!(known_apple_code("  "), None);
        assert_eq!(known_apple_code("Slow down, please."), None);
    }
}
