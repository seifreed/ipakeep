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
