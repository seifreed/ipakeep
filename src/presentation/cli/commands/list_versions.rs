//! List-versions command handler.

use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::ListVersions;
use crate::presentation::cli::commands::{get_guid, resolve_app_id};
use crate::presentation::cli::output::{OutputFormat, format_list, format_version};

/// Handle the list-versions command.
///
/// # Errors
///
/// Returns an error string if the API call fails or the user is not logged in.
pub async fn handle_list_versions<R, C>(
    app: &str,
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

    let resolved_app_id = resolve_app_id(&app_store, app, country).await?;

    let use_case = ListVersions::new(app_store, credentials);
    let versions = use_case
        .execute(resolved_app_id, &guid)
        .await
        .map_err(|e| format!("list-versions failed: {e}"))?;

    if versions.is_empty() {
        println!("No versions found for app {resolved_app_id}.");
        return Ok(());
    }

    let output = format_list(&versions, format, format_version);
    println!("{output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{AppVersion, test_support::test_account};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};

    #[tokio::test]
    async fn list_versions_prints_results() {
        let repository =
            FakeAppStoreRepository::new().with_list_versions_result(Ok(vec![AppVersion {
                external_version_id: "42".into(),
                version_string: "1.0".into(),
            }]));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_list_versions("42", "us", repository, credentials, &OutputFormat::Json)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn list_versions_handles_empty_results() {
        let repository =
            FakeAppStoreRepository::new().with_list_versions_result(Ok(Vec::<AppVersion>::new()));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        assert!(
            handle_list_versions("42", "us", repository, credentials, &OutputFormat::Text)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn list_versions_maps_repository_errors() {
        let repository = FakeAppStoreRepository::new()
            .with_list_versions_result(Err(AppStoreError::NetworkError("offline".into())));
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let error = handle_list_versions("42", "us", repository, credentials, &OutputFormat::Text)
            .await
            .expect_err("version listing should fail");

        assert!(error.starts_with("list-versions failed:"));
    }
}
