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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{OwnedApp, test_support::test_account};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

    fn owned_app() -> OwnedApp {
        OwnedApp {
            id: 7,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            platforms: vec!["iphone".into()],
            purchase_date: None,
        }
    }

    #[tokio::test]
    async fn purchases_prints_results() {
        let repository =
            FakeAppStoreRepository::new().with_list_purchases_result(Ok(vec![owned_app()]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_purchases(10, repository, credentials, &OutputFormat::Json)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn purchases_handles_empty_results() {
        let repository =
            FakeAppStoreRepository::new().with_list_purchases_result(Ok(Vec::<OwnedApp>::new()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_purchases(10, repository, credentials, &OutputFormat::Text)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn purchases_maps_repository_errors() {
        let repository = FakeAppStoreRepository::new()
            .with_list_purchases_result(Err(AppStoreError::NetworkError("offline".into())));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let error = handle_purchases(10, repository, credentials, &OutputFormat::Text)
            .await
            .expect_err("purchases should fail");

        assert!(error.starts_with("purchases failed:"));
    }
}
