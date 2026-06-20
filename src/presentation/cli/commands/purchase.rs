//! Purchase command handler.

use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::Purchase;
use crate::presentation::cli::commands::get_guid;
use crate::presentation::cli::output::OutputFormat;
use serde::Serialize;

/// Handle the purchase command.
///
/// # Errors
///
/// Returns an error string if the app is not found, not free, or the purchase fails.
pub async fn handle_purchase<R, C>(
    bundle_identifier: &str,
    country: &str,
    app_store: R,
    credentials: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let guid = get_guid();

    let app = app_store
        .lookup(bundle_identifier, country)
        .await
        .map_err(|e| format!("lookup failed: {e}"))?
        .ok_or_else(|| format!("app '{bundle_identifier}' not found"))?;

    if app.price > 0.0 {
        return Err(format!(
            "app '{}' is not free (price: ${:.2}). Only free apps are supported.",
            app.name, app.price
        ));
    }

    let use_case = Purchase::new(app_store, credentials);
    use_case
        .execute(app.id, &guid)
        .await
        .map_err(|e| format!("purchase failed: {e}"))?;

    match format {
        OutputFormat::Json => {
            let result = PurchaseResult {
                success: true,
                app: app.name,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("failed to serialize output: {e}"))?
            );
        }
        OutputFormat::Text => {
            println!("Successfully purchased '{}'.", app.name);
        }
    }

    Ok(())
}

/// Result of a purchase for JSON output.
#[derive(Debug, Serialize)]
struct PurchaseResult {
    success: bool,
    app: String,
}
