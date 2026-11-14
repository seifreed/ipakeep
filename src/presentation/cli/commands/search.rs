//! Search command handler.

use crate::domain::repository::AppStoreRepository;
use crate::domain::usecase::Search;
use crate::presentation::cli::output::{OutputFormat, format_app, format_list};

/// Handle the search command.
///
/// # Errors
///
/// Returns an error string if the search API call fails.
pub async fn handle_search<R>(
    term: &str,
    limit: u32,
    country: &str,
    app_store: R,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
{
    let use_case = Search::new(app_store);

    let apps = use_case
        .execute(term, country, limit)
        .await
        .map_err(|e| format!("search failed: {e}"))?;

    if apps.is_empty() {
        println!("No results found for '{term}'.");
        return Ok(());
    }

    let output = format_list(&apps, format, format_app);
    println!("{output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{App, test_support::app};
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::FakeAppStoreRepository;

    #[tokio::test]
    async fn search_prints_results_in_json() {
        let repository = FakeAppStoreRepository::new().with_search_result(Ok(vec![app(7)]));

        assert!(
            handle_search("example", 5, "us", repository, &OutputFormat::Json)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn search_handles_empty_results() {
        let repository = FakeAppStoreRepository::new().with_search_result(Ok(Vec::<App>::new()));

        assert!(
            handle_search("missing", 5, "us", repository, &OutputFormat::Text)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn search_maps_repository_errors() {
        let repository = FakeAppStoreRepository::new()
            .with_search_result(Err(AppStoreError::NetworkError("offline".into())));

        let error = handle_search("example", 5, "us", repository, &OutputFormat::Text)
            .await
            .expect_err("search should fail");

        assert!(error.starts_with("search failed:"));
    }
}
