//! Interactive `GrandSlam` 2FA flow for auth login.

use super::{LoginOptions, output::format_login_account};
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
    let method = select_2fa_method()?;
    let account = if method == 0 {
        complete_trusted_device(use_case, &credentials, challenge).await
    } else {
        complete_sms(use_case, &credentials, challenge).await
    }?;

    let output = format_login_account(&account, format);
    println!("{output}");
    Ok(())
}

fn select_2fa_method() -> Result<usize, String> {
    dialoguer::Select::new()
        .with_prompt("Choose 2FA method")
        .items(["Trusted device", "SMS"])
        .default(0)
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
    use_case
        .request_trusted_device_notification(challenge.dsid, challenge.idms_token)
        .await
        .map_err(|e| format!("failed to request trusted device notification: {e}"))?;

    let code = dialoguer::Input::<String>::new()
        .with_prompt("Enter 2FA code from trusted device")
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
    let phones = match use_case.list_trusted_phone_numbers(dsid, idms_token).await {
        Ok(phones) if !phones.is_empty() => phones,
        Ok(_) => {
            tracing::warn!("no trusted phone numbers returned; defaulting to phone id 1");
            return Ok(DEFAULT_PHONE_ID);
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to list trusted phone numbers; defaulting to phone id 1");
            return Ok(DEFAULT_PHONE_ID);
        }
    };

    if let [only] = phones.as_slice() {
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
