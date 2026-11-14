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

    print_purchase_success(format, &app.name)?;

    Ok(())
}

fn print_purchase_success(format: &OutputFormat, app_name: &str) -> Result<(), String> {
    match format {
        OutputFormat::Json => {
            let result = PurchaseResult {
                success: true,
                app: app_name.to_string(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("failed to serialize output: {e}"))?
            );
        }
        OutputFormat::Text => {
            println!("Successfully purchased '{app_name}'.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::test_support::{app, test_account};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

    #[tokio::test]
    async fn purchase_prints_json_success() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(Some(app(7))))
            .with_purchase_result(Ok(()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_purchase(
                "com.example.app",
                "us",
                repository,
                credentials,
                &OutputFormat::Json
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn purchase_prints_text_success() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(Some(app(7))))
            .with_purchase_result(Ok(()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_purchase(
                "com.example.app",
                "us",
                repository,
                credentials,
                &OutputFormat::Text
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn purchase_reports_unknown_app() {
        let repository = FakeAppStoreRepository::new().with_lookup_result(Ok(None));
        let credentials = InMemoryCredentialRepository::new();

        let error = handle_purchase(
            "com.example.app",
            "us",
            repository,
            credentials,
            &OutputFormat::Text,
        )
        .await
        .expect_err("missing apps should fail");

        assert!(error.contains("not found"));
    }

    #[tokio::test]
    async fn purchase_rejects_paid_app() {
        let mut paid_app = app(7);
        paid_app.price = 1.99;
        let repository = FakeAppStoreRepository::new().with_lookup_result(Ok(Some(paid_app)));
        let credentials = InMemoryCredentialRepository::new();

        let error = handle_purchase(
            "com.example.app",
            "us",
            repository,
            credentials,
            &OutputFormat::Text,
        )
        .await
        .expect_err("paid apps must be rejected");

        assert!(error.contains("Only free apps are supported"));
    }

    #[tokio::test]
    async fn purchase_maps_lookup_errors() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Err(AppStoreError::NetworkError("offline".into())));
        let credentials = InMemoryCredentialRepository::new();

        let error = handle_purchase(
            "com.example.app",
            "us",
            repository,
            credentials,
            &OutputFormat::Text,
        )
        .await
        .expect_err("lookup should fail");

        assert!(error.starts_with("lookup failed:"));
    }

    #[tokio::test]
    async fn purchase_maps_purchase_errors() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(Some(app(7))))
            .with_purchase_result(Err(AppStoreError::NetworkError("offline".into())));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let error = handle_purchase(
            "com.example.app",
            "us",
            repository,
            credentials,
            &OutputFormat::Text,
        )
        .await
        .expect_err("purchase should fail");

        assert!(error.starts_with("purchase failed:"));
    }
}

/// Result of a purchase for JSON output.
#[derive(Debug, Serialize)]
struct PurchaseResult {
    success: bool,
    app: String,
}
