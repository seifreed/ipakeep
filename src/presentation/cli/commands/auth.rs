//! Auth command handlers.

use crate::domain::error::{AppStoreError, CredentialError};
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::{AuthInfo, AuthLogin, AuthRevoke};
use crate::presentation::cli::output::{OutputFormat, format_account, format_output};
use serde::Serialize;

/// CLI options that control the login flow.
pub struct LoginOptions<'a> {
    /// Apple ID email (or `None` to prompt).
    pub email: Option<&'a str>,

    /// Apple ID password (or `None` to prompt).
    pub password: Option<&'a str>,

    /// Two-factor authentication code (or `None` to prompt).
    pub code: Option<&'a str>,

    /// Fail if interactive input is required.
    pub non_interactive: bool,

    /// Use the modern `GrandSlam` SRP flow.
    pub grandslam: bool,
}

/// Handle the auth login command.
///
/// # Errors
///
/// Returns an error string if authentication fails or credentials are missing.
pub async fn handle_login<R, C>(
    options: &LoginOptions<'_>,
    app_store: R,
    credentials: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let email = if let Some(e) = options.email {
        e.to_string()
    } else {
        if options.non_interactive {
            return Err("email is required in non-interactive mode".into());
        }
        dialoguer::Input::<String>::new()
            .with_prompt("Apple ID email")
            .interact_text()
            .map_err(|e| format!("failed to read email: {e}"))?
    };

    let password = if let Some(p) = options.password {
        p.to_string()
    } else {
        if options.non_interactive {
            return Err("password is required in non-interactive mode".into());
        }
        dialoguer::Password::new()
            .with_prompt("Apple ID password")
            .interact()
            .map_err(|e| format!("failed to read password: {e}"))?
    };

    let guid = get_guid();
    let use_case = AuthLogin::new(app_store, credentials);

    if options.grandslam {
        handle_grandslam_login(&use_case, &email, &password, &guid, options, format).await
    } else {
        handle_legacy_login(&use_case, &email, &password, &guid, options, format).await
    }
}

async fn handle_grandslam_login<R, C>(
    use_case: &AuthLogin<R, C>,
    email: &str,
    password: &str,
    guid: &str,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match use_case.execute_grandslam(email, password, guid).await {
        Ok(account) => {
            let output = format_login_account(&account, format);
            println!("{output}");
            Ok(())
        }
        Err(AppStoreError::AuthCodeRequired { dsid, idms_token }) => {
            if dsid.is_empty() || idms_token.is_empty() {
                let code = if let Some(c) = options.code {
                    c.to_string()
                } else {
                    if options.non_interactive {
                        return Err(
                            "GrandSlam 2FA code required. Use --code flag to provide the code."
                                .into(),
                        );
                    }
                    dialoguer::Input::<String>::new()
                        .with_prompt("GrandSlam 2FA code")
                        .interact_text()
                        .map_err(|e| format!("failed to read 2FA code: {e}"))?
                };

                let account = use_case
                    .execute_grandslam(email, &format!("{password}{code}"), guid)
                    .await
                    .map_err(|e| format!("login failed: {e}"))?;

                let output = format_login_account(&account, format);
                println!("{output}");
                return Ok(());
            }

            handle_grandslam_2fa(
                use_case,
                GrandSlamLoginContext {
                    email,
                    password,
                    guid,
                },
                GrandSlamChallenge {
                    dsid: &dsid,
                    idms_token: &idms_token,
                },
                options,
                format,
            )
            .await
        }
        Err(e) => Err(format!("login failed: {e}")),
    }
}

struct GrandSlamLoginContext<'a> {
    email: &'a str,
    password: &'a str,
    guid: &'a str,
}

struct GrandSlamChallenge<'a> {
    dsid: &'a str,
    idms_token: &'a str,
}

async fn handle_grandslam_2fa<R, C>(
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
    let method = if options.non_interactive {
        return Err("GrandSlam 2FA required. Use interactive mode to complete.".into());
    } else {
        let items = vec!["Trusted device", "SMS"];

        dialoguer::Select::new()
            .with_prompt("Choose 2FA method")
            .items(&items)
            .default(0)
            .interact()
            .map_err(|e| format!("failed to select 2FA method: {e}"))?
    };

    let account = if method == 0 {
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
                login.email,
                login.password,
                login.guid,
                challenge.dsid,
                challenge.idms_token,
                &code,
            )
            .await
    } else {
        let phone_id = 1_i64;
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
                login.email,
                login.password,
                login.guid,
                challenge.dsid,
                challenge.idms_token,
                phone_id,
                &code,
            )
            .await
    }
    .map_err(|e| format!("login failed: {e}"))?;

    let output = format_login_account(&account, format);
    println!("{output}");
    Ok(())
}

async fn handle_legacy_login<R, C>(
    use_case: &AuthLogin<R, C>,
    email: &str,
    password: &str,
    guid: &str,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match use_case.execute(email, password, guid).await {
        Ok(account) => {
            let output = format_login_account(&account, format);
            println!("{output}");
            Ok(())
        }
        Err(AppStoreError::AuthCodeRequired { .. }) => {
            let code = if let Some(c) = options.code {
                c.to_string()
            } else {
                if options.non_interactive {
                    return Err("2FA code required. Use --code flag to provide the code.".into());
                }
                dialoguer::Input::<String>::new()
                    .with_prompt("2FA code")
                    .interact_text()
                    .map_err(|e| format!("failed to read 2FA code: {e}"))?
            };

            let account = use_case
                .login_with_2fa(email, password, &code, guid)
                .await
                .map_err(|e| format!("login failed: {e}"))?;

            let output = format_login_account(&account, format);
            println!("{output}");
            Ok(())
        }
        Err(e) => Err(format!("login failed: {e}")),
    }
}

/// Handle the auth info command.
///
/// # Errors
///
/// Returns an error string if no credentials are stored or they cannot be loaded.
pub async fn handle_info<C>(credentials: C, format: &OutputFormat) -> Result<(), String>
where
    C: CredentialRepository,
{
    let use_case = AuthInfo::new(credentials);

    match use_case.execute().await {
        Ok(Some(account)) => {
            let output = match format {
                OutputFormat::Json => format_output(&AuthAccountOutput::from(&account), format),
                OutputFormat::Text => format_account(&account),
            };
            println!("{output}");
            Ok(())
        }
        Ok(None) | Err(CredentialError::NotFound) => Err("not logged in".into()),
        Err(e) => Err(format!("failed to load credentials: {e}")),
    }
}

/// Handle the auth revoke command.
///
/// # Errors
///
/// Returns an error string if credential deletion fails.
pub async fn handle_revoke<C>(credentials: C) -> Result<(), String>
where
    C: CredentialRepository,
{
    let use_case = AuthRevoke::new(credentials);

    use_case
        .execute()
        .await
        .map_err(|e| format!("failed to revoke credentials: {e}"))?;

    println!("Credentials revoked successfully.");
    Ok(())
}

/// Get the device GUID (MAC address).
fn get_guid() -> String {
    mac_address::get_mac_address().ok().flatten().map_or_else(
        || "000000000000".to_string(),
        |addr| addr.to_string().replace(':', "").to_uppercase(),
    )
}

fn format_login_account(account: &crate::domain::entity::Account, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json => format_output(&AuthAccountOutput::from(account), format),
        OutputFormat::Text => format_account(account),
    }
}

#[derive(Debug, Serialize)]
struct AuthAccountOutput<'a> {
    email: &'a str,
    name: &'a str,
    store_front: &'a str,
    pod: &'a str,
    has_password_token: bool,
    has_cookies: bool,
    has_idms_token: bool,
    has_grandslam_state: bool,
}

impl<'a> From<&'a crate::domain::entity::Account> for AuthAccountOutput<'a> {
    fn from(account: &'a crate::domain::entity::Account) -> Self {
        Self {
            email: &account.email,
            name: &account.name,
            store_front: &account.store_front,
            pod: &account.pod,
            has_password_token: !account.password_token.is_empty(),
            has_cookies: !account.cookies.is_empty(),
            has_idms_token: account.idms_token.as_deref().is_some_and(|v| !v.is_empty()),
            has_grandslam_state: account
                .grandslam_session_key
                .as_deref()
                .is_some_and(|v| !v.is_empty())
                && account
                    .grandslam_continuation
                    .as_deref()
                    .is_some_and(|v| !v.is_empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::Account;

    fn sensitive_account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "secret-password-token".into(),
            directory_services_id: "dsid123".into(),
            store_front: "143441-1".into(),
            pod: "11".into(),
            idms_token: Some("secret-idms-token".into()),
            dsid: Some("dsid123".into()),
            adsid: Some("adsid123".into()),
            grandslam_session_key: Some("secret-session-key".into()),
            grandslam_continuation: Some("secret-continuation".into()),
            cookies: vec!["secret-cookie=value".into()],
        }
    }

    #[test]
    fn json_login_output_is_sanitized() {
        let output = format_login_account(&sensitive_account(), &OutputFormat::Json);

        assert!(!output.contains("secret-password-token"));
        assert!(!output.contains("secret-idms-token"));
        assert!(!output.contains("secret-session-key"));
        assert!(!output.contains("secret-continuation"));
        assert!(!output.contains("secret-cookie"));

        let value: serde_json::Value = serde_json::from_str(&output).expect("valid json");
        assert_eq!(value["email"], "test@example.com");
        assert_eq!(value["has_password_token"], true);
        assert_eq!(value["has_cookies"], true);
        assert_eq!(value["has_idms_token"], true);
        assert_eq!(value["has_grandslam_state"], true);
    }
}
