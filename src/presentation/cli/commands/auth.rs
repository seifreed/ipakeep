//! Auth command handlers.

mod grandslam;
mod output;

use crate::domain::entity::Account;
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

    /// Use the `GrandSlam` SRP flow.
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
    let (email, password) = login_credentials(options)?;
    let guid = get_guid();
    let use_case = AuthLogin::new(app_store, credentials);

    if options.grandslam {
        let store_front = resolve_store_front(options.country);
        handle_grandslam_login(
            &use_case,
            GrandSlamLoginContext {
                email: &email,
                password: &password,
                guid: &guid,
                store_front: store_front.as_deref(),
            },
            options,
            format,
        )
        .await
    } else {
        handle_legacy_login(&use_case, &email, &password, &guid, options, format).await
    }
}

fn login_credentials(options: &LoginOptions<'_>) -> Result<(String, String), String> {
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
    Ok((email, password))
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
    context: GrandSlamLoginContext<'_>,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match use_case
        .execute_grandslam(
            context.email,
            context.password,
            context.guid,
            context.store_front,
        )
        .await
    {
        Ok(account) => {
            print_login_account(&account, format);
            Ok(())
        }
        Err(error) => handle_grandslam_error(error, use_case, context, options, format).await,
    }
}

async fn handle_grandslam_error<R, C>(
    error: AppStoreError,
    use_case: &AuthLogin<R, C>,
    context: GrandSlamLoginContext<'_>,
    options: &LoginOptions<'_>,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    match error {
        AppStoreError::AuthCodeRequired {
            dsid,
            idms_token,
            method,
        } => {
            grandslam::handle_2fa(
                use_case,
                context,
                GrandSlamChallenge {
                    dsid: &dsid,
                    idms_token: &idms_token,
                    method,
                },
                options,
                format,
            )
            .await
        }
        error => Err(format!("login failed: {error}")),
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
            print_login_account(&account, format);
            Ok(())
        }
        Err(AppStoreError::AuthCodeRequired { .. }) => {
            let code = login_code(options)?;

            let account = use_case
                .login_with_2fa(email, password, &code, guid)
                .await
                .map_err(|e| format!("login failed: {e}"))?;

            print_login_account(&account, format);
            Ok(())
        }
        Err(e) => Err(format!("login failed: {e}")),
    }
}

fn login_code(options: &LoginOptions<'_>) -> Result<String, String> {
    if let Some(code) = options.code {
        return Ok(code.to_string());
    }
    if options.non_interactive {
        return Err("2FA code required. Use --code flag to provide the code.".into());
    }
    dialoguer::Input::<String>::new()
        .with_prompt("2FA code")
        .interact_text()
        .map_err(|error| format!("failed to read 2FA code: {error}"))
}

fn print_login_account(account: &Account, format: &OutputFormat) {
    println!("{}", format_login_account(account, format));
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
            print_login_account(&account, format);
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
