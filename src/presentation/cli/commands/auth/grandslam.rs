//! Interactive `GrandSlam` 2FA flow for auth login.

use super::{LoginOptions, output::format_login_account};
use crate::domain::entity::TrustedPhoneNumber;
use crate::domain::error::TwoFactorMethod;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::{AuthLogin, GrandslamCredentials};
use crate::presentation::cli::output::OutputFormat;

pub(super) struct GrandSlamLoginContext<'a> {
    pub(super) email: &'a str,
    pub(super) password: &'a str,
    pub(super) guid: &'a str,
    pub(super) store_front: Option<&'a str>,
}

pub(super) struct GrandSlamChallenge<'a> {
    pub(super) dsid: &'a str,
    pub(super) idms_token: &'a str,
    pub(super) method: TwoFactorMethod,
}

pub(super) async fn handle_2fa<R, C>(
    use_case: &AuthLogin<R, C>,
    login: GrandSlamLoginContext<'_>,
    challenge: GrandSlamChallenge<'_>,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    if options.non_interactive {
        return Err("GrandSlam 2FA required. Use interactive mode to complete.".into());
    }

    let credentials = GrandslamCredentials {
        email: login.email,
        password: login.password,
        guid: login.guid,
        store_front: login.store_front,
    };
    let choice = select_2fa_method(challenge.method)?;
    let account = if choice == 0 {
        complete_trusted_device(use_case, &credentials, challenge).await
    } else {
        complete_sms(use_case, &credentials, challenge).await
    }?;

    let output = format_login_account(&account, format);
    println!("{output}");
    Ok(())
}

fn select_2fa_method(method: TwoFactorMethod) -> Result<usize, String> {
    let default = usize::from(method == TwoFactorMethod::Sms);
    dialoguer::Select::new()
        .with_prompt("Choose 2FA method")
        .items(["Trusted device", "SMS"])
        .default(default)
        .interact()
        .map_err(|e| format!("failed to select 2FA method: {e}"))
}

async fn complete_trusted_device<R, C>(
    use_case: &AuthLogin<R, C>,
    credentials: &GrandslamCredentials<'_>,
    challenge: GrandSlamChallenge<'_>,
) -> Result<crate::domain::entity::Account, String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    request_trusted_device_code(use_case, challenge.dsid, challenge.idms_token).await?;

    let code = dialoguer::Input::<String>::new()
        .with_prompt("Enter 6-digit code from trusted device")
        .validate_with(|input: &String| {
            if is_trusted_device_code(input) {
                Ok(())
            } else {
                Err("Enter the 6-digit code shown on a trusted device.".to_string())
            }
        })
        .interact_text()
        .map_err(|e| format!("failed to read 2FA code: {e}"))?;

    use_case
        .complete_trusted_device_grandslam_2fa(
            credentials,
            challenge.dsid,
            challenge.idms_token,
            &code,
        )
        .await
        .map_err(|e| format!("login failed: {e}"))
}

async fn request_trusted_device_code<R, C>(
    use_case: &AuthLogin<R, C>,
    dsid: &str,
    idms_token: &str,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    use_case
        .request_trusted_device_notification(dsid, idms_token)
        .await
        .map_err(|e| format!("failed to request trusted-device code: {e}"))?;
    println!("Requested a verification code on your trusted devices.");
    Ok(())
}

fn is_trusted_device_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit())
}

async fn complete_sms<R, C>(
    use_case: &AuthLogin<R, C>,
    credentials: &GrandslamCredentials<'_>,
    challenge: GrandSlamChallenge<'_>,
) -> Result<crate::domain::entity::Account, String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let phone_id = select_sms_phone_id(use_case, challenge.dsid, challenge.idms_token).await?;
    use_case
        .request_sms(challenge.dsid, challenge.idms_token, phone_id)
        .await
        .map_err(|e| format!("failed to request SMS: {e}"))?;

    let code = dialoguer::Input::<String>::new()
        .with_prompt("Enter SMS code")
        .interact_text()
        .map_err(|e| format!("failed to read SMS code: {e}"))?;

    use_case
        .complete_sms_grandslam_2fa(
            credentials,
            challenge.dsid,
            challenge.idms_token,
            phone_id,
            &code,
        )
        .await
        .map_err(|e| format!("login failed: {e}"))
}

const DEFAULT_PHONE_ID: i64 = 1;

async fn select_sms_phone_id<R, C>(
    use_case: &AuthLogin<R, C>,
    dsid: &str,
    idms_token: &str,
) -> Result<i64, String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let Some(phones) = list_trusted_phones_or_default(use_case, dsid, idms_token).await else {
        return Ok(DEFAULT_PHONE_ID);
    };
    choose_sms_phone_id(&phones)
}

async fn list_trusted_phones_or_default<R, C>(
    use_case: &AuthLogin<R, C>,
    dsid: &str,
    idms_token: &str,
) -> Option<Vec<TrustedPhoneNumber>>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match use_case.list_trusted_phone_numbers(dsid, idms_token).await {
        Ok(phones) if !phones.is_empty() => Some(phones),
        Ok(_) => {
            tracing::warn!(
                service = "ipakeep",
                component = "cli",
                operation = "select_sms_phone_id",
                event_name = "auth.two_factor.phone_list_fallback",
                outcome = "empty",
                "no trusted phone numbers returned; defaulting to phone id 1"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                service = "ipakeep",
                component = "cli",
                operation = "select_sms_phone_id",
                event_name = "auth.two_factor.phone_list_fallback",
                error_type = app_store_error_type(&e),
                "failed to list trusted phone numbers; defaulting to phone id 1"
            );
            None
        }
    }
}

fn choose_sms_phone_id(phones: &[TrustedPhoneNumber]) -> Result<i64, String> {
    if let [only] = phones {
        println!("Sending SMS to {}", only.number);
        return Ok(only.id);
    }

    let items: Vec<&str> = phones.iter().map(|p| p.number.as_str()).collect();
    let selected = dialoguer::Select::new()
        .with_prompt("Choose trusted phone number")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| format!("failed to select phone number: {e}"))?;

    Ok(phones[selected].id)
}

fn app_store_error_type(error: &crate::domain::error::AppStoreError) -> &'static str {
    use crate::domain::error::AppStoreError;

    match error {
        AppStoreError::AuthenticationFailed(_) | AppStoreError::InvalidCredentials => {
            "authentication"
        }
        AppStoreError::AuthCodeRequired { .. } => "two_factor_required",
        AppStoreError::AccountDisabled => "account_disabled",
        AppStoreError::AppNotFound(_) => "app_not_found",
        AppStoreError::AppNotFree(_) => "app_not_free",
        AppStoreError::NoLicense(_) => "no_license",
        AppStoreError::VersionNotAvailable(_) => "version_unavailable",
        AppStoreError::PurchaseFailed(_) => "purchase",
        AppStoreError::DownloadFailed(_) => "download",
        AppStoreError::IpaPatchingFailed(_) => "ipa_patching",
        AppStoreError::NetworkError(_) => "network",
        AppStoreError::Unexpected(_) => "unexpected",
    }
}

#[cfg(test)]
mod tests {
    use super::{app_store_error_type, request_trusted_device_code};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use crate::domain::usecase::AuthLogin;

    #[test]
    fn error_classification_does_not_include_error_content() {
        let error = AppStoreError::NetworkError("secret-token-in-url".into());
        assert_eq!(app_store_error_type(&error), "network");
    }

    #[tokio::test]
    async fn trusted_device_challenge_still_requests_a_notification() {
        let app_store = FakeAppStoreRepository::new();
        let use_case = AuthLogin::new(app_store.clone(), InMemoryCredentialRepository::new());

        request_trusted_device_code(&use_case, "dsid", "idms")
            .await
            .expect("trusted-device request");

        assert_eq!(
            app_store.request_trusted_device_notification_calls(),
            vec![("dsid".into(), "idms".into())]
        );
    }

    #[test]
    fn trusted_device_code_requires_six_ascii_digits() {
        assert!(super::is_trusted_device_code("123456"));
        assert!(!super::is_trusted_device_code("e"));
        assert!(!super::is_trusted_device_code("12345"));
        assert!(!super::is_trusted_device_code("1234567"));
        assert!(!super::is_trusted_device_code("１２３４５６"));
    }
}
