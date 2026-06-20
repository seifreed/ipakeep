//! Auth command handlers.

mod grandslam;
mod output;

use crate::domain::error::{AppStoreError, CredentialError};
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::{AuthInfo, AuthLogin, AuthRevoke};
use crate::presentation::cli::commands::get_guid;
use crate::presentation::cli::output::OutputFormat;
use grandslam::{GrandSlamChallenge, GrandSlamLoginContext};
use output::format_login_account;

/// CLI options that control the login flow.
pub struct LoginOptions<'a> {
    /// Apple ID email (or `None` to prompt).
    pub email: Option<&'a str>,

    /// Apple ID password (or `None` to prompt).
    pub password: Option<&'a str>,

    /// Two-factor authentication code (or `None` to prompt).
    pub code: Option<&'a str>,

    /// ISO 3166-1 alpha-2 country for the account's Store Front (or `None` to
    /// derive from the system locale).
    pub country: Option<&'a str>,

    /// Fail if interactive input is required.
    pub non_interactive: bool,

    /// Use the `GrandSlam` SRP flow instead of the default Configurator flow.
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
        let store_front = resolve_store_front(options.country);
        handle_grandslam_login(
            &use_case,
            &email,
            &password,
            &guid,
            store_front.as_deref(),
            options,
            format,
        )
        .await
    } else {
        handle_legacy_login(&use_case, &email, &password, &guid, options, format).await
    }
}

/// Resolve the account's Store Front from the explicit `--country` flag, then the
/// system locale. Returns `None` when neither yields a known country (commerce
/// then falls back to the US default).
fn resolve_store_front(country: Option<&str>) -> Option<String> {
    let country = country
        .map(str::to_string)
        .or_else(crate::infrastructure::appstore::locale_country)?;
    crate::infrastructure::appstore::storefront_for_country(&country)
}

async fn handle_grandslam_login<R, C>(
    use_case: &AuthLogin<R, C>,
    email: &str,
    password: &str,
    guid: &str,
    store_front: Option<&str>,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match use_case
        .execute_grandslam(email, password, guid, store_front)
        .await
    {
        Ok(account) => {
            let output = format_login_account(&account, format);
            println!("{output}");
            Ok(())
        }
        Err(AppStoreError::AuthCodeRequired { dsid, idms_token }) => {
            grandslam::handle_2fa(
                use_case,
                GrandSlamLoginContext {
                    email,
                    password,
                    guid,
                    store_front,
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
            let output = format_login_account(&account, format);
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

#[cfg(test)]
mod tests;
