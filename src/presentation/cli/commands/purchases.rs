//! Purchases command handler — lists apps owned by the authenticated account.

use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::Purchases;
use crate::presentation::cli::output::{OutputFormat, format_list, format_owned_app};

/// Handle the purchases command.
///
/// # Errors
///
/// Returns an error string if the API call fails or the user is not logged in.
pub async fn handle_purchases<R, C>(
    limit: u32,
    app_store: R,
    credentials: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let use_case = Purchases::new(app_store, credentials);
    let apps = use_case
        .execute(limit, None)
        .await
        .map_err(|e| format!("purchases failed: {e}"))?;

    if apps.is_empty() {
        println!("No purchased apps found.");
        return Ok(());
    }

    let output = format_list(&apps, format, format_owned_app);
    println!("{output}");

    Ok(())
}
