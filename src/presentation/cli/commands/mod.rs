//! CLI command handlers — adapter layer between CLI input and use cases.

pub mod auth;
pub mod download;
pub mod list_versions;
pub mod purchase;
pub mod search;
pub mod simulator;

use crate::domain::repository::AppStoreRepository;

/// Get the device GUID (MAC address) for Apple API requests.
pub fn get_guid() -> String {
    mac_address::get_mac_address().ok().flatten().map_or_else(
        || "000000000000".to_string(),
        |addr| addr.to_string().replace(':', "").to_uppercase(),
    )
}

/// Resolve a user-supplied app reference into a numeric App Store id.
///
/// Accepts a numeric App Store id, a bundle identifier, or an app name, in that
/// resolution order: a pure-digit string is taken as the id directly; otherwise
/// it is tried as a bundle identifier via lookup, then as a search term, using
/// the first matching result.
///
/// # Errors
///
/// Returns an error string if the lookup/search request fails or nothing matches.
pub async fn resolve_app_id<R>(app_store: &R, app: &str, country: &str) -> Result<i64, String>
where
    R: AppStoreRepository,
{
    if let Ok(id) = app.parse::<i64>() {
        tracing::debug!(app_id = id, "resolved app reference as numeric id");
        return Ok(id);
    }

    tracing::debug!(
        app_ref_len = app.len(),
        country,
        "resolving app reference by bundle id"
    );
    if let Some(found) = app_store
        .lookup(app, country)
        .await
        .map_err(|e| format!("lookup failed: {e}"))?
    {
        tracing::debug!(app_id = found.id, "resolved app reference by bundle id");
        return Ok(found.id);
    }

    tracing::debug!(
        app_ref_len = app.len(),
        country,
        "resolving app reference by search"
    );
    let results = app_store
        .search(app, country, 1)
        .await
        .map_err(|e| format!("search failed: {e}"))?;

    let Some(first) = results.into_iter().next() else {
        tracing::debug!("app reference resolution returned no search results");
        return Err(format!("no app found matching '{app}'"));
    };
    tracing::debug!(app_id = first.id, "resolved app reference by search");
    Ok(first.id)
}

#[cfg(test)]
mod tests {
    use super::resolve_app_id;
    use crate::domain::entity::App;
    use crate::domain::repository::FakeAppStoreRepository;
    use crate::domain::usecase::log_capture::LogCapture;

    fn app(id: i64) -> App {
        App {
            id,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            price: 0.0,
        }
    }

    #[tokio::test]
    async fn resolve_app_id_uses_numeric_id_directly() {
        let repo = FakeAppStoreRepository::new();
        assert_eq!(
            resolve_app_id(&repo, "1198143062", "us").await.unwrap(),
            1_198_143_062
        );
        // A numeric reference must not hit the network.
        assert!(repo.lookup_calls().is_empty());
        assert!(repo.search_calls().is_empty());
    }

    #[tokio::test]
    async fn resolve_app_id_resolves_bundle_identifier_via_lookup() {
        let repo = FakeAppStoreRepository::new().with_lookup_result(Ok(Some(app(42))));
        assert_eq!(
            resolve_app_id(&repo, "com.example.app", "us")
                .await
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn resolve_app_id_falls_back_to_search_by_name() {
        let repo = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![app(99)]));
        assert_eq!(resolve_app_id(&repo, "ludo-star", "es").await.unwrap(), 99);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_app_id_logs_resolution_without_app_ref_value() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let repo = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![app(99)]));

        assert_eq!(
            resolve_app_id(&repo, "secret-app-name", "es")
                .await
                .unwrap(),
            99
        );

        let logs = capture.contents();
        assert!(logs.contains("resolving app reference by bundle id"));
        assert!(logs.contains("resolving app reference by search"));
        assert!(logs.contains("resolved app reference by search"));
        assert!(!logs.contains("secret-app-name"));
    }

    #[tokio::test]
    async fn resolve_app_id_errors_when_nothing_matches() {
        let repo = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![]));
        assert!(
            resolve_app_id(&repo, "nonexistent app", "us")
                .await
                .is_err()
        );
    }
}
