use crate::domain::error::AppStoreError;
use crate::domain::repository::AppStoreRepository;

/// Resolve an App Store id, bundle identifier, or app name to a numeric id.
pub struct ResolveApp<'a, R: AppStoreRepository + ?Sized> {
    app_store: &'a R,
}

impl<'a, R: AppStoreRepository + ?Sized> ResolveApp<'a, R> {
    /// Create a use case for resolving app references.
    pub fn new(app_store: &'a R) -> Self {
        Self { app_store }
    }

    /// Resolve the reference in numeric id, bundle identifier, then name order.
    ///
    /// # Errors
    ///
    /// Returns repository errors or `AppStoreError::AppNotFound` when no result
    /// matches the reference.
    pub async fn execute(&self, app: &str, country: &str) -> Result<i64, AppStoreError> {
        if let Ok(id) = app.parse::<i64>() {
            return Ok(id);
        }
        if let Some(found) = self.app_store.lookup(app, country).await? {
            return Ok(found.id);
        }
        self.app_store
            .search(app, country, 1)
            .await?
            .into_iter()
            .next()
            .map(|found| found.id)
            .ok_or_else(|| AppStoreError::AppNotFound(app.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::App;
    use crate::domain::repository::FakeAppStoreRepository;

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
    async fn numeric_id_skips_repository_calls() {
        let repository = FakeAppStoreRepository::new();
        assert_eq!(
            ResolveApp::new(&repository)
                .execute("42", "us")
                .await
                .unwrap(),
            42
        );
        assert!(repository.lookup_calls().is_empty());
        assert!(repository.search_calls().is_empty());
    }

    #[tokio::test]
    async fn bundle_identifier_resolves_before_search() {
        let repository = FakeAppStoreRepository::new().with_lookup_result(Ok(Some(app(42))));
        assert_eq!(
            ResolveApp::new(&repository)
                .execute("com.example.app", "us")
                .await
                .unwrap(),
            42
        );
    }

    #[tokio::test]
    async fn app_name_uses_first_search_result() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![app(99)]));
        assert_eq!(
            ResolveApp::new(&repository)
                .execute("Example", "us")
                .await
                .unwrap(),
            99
        );
    }

    #[tokio::test]
    async fn unmatched_reference_returns_app_not_found() {
        let repository = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(None))
            .with_search_result(Ok(vec![]));
        assert!(matches!(
            ResolveApp::new(&repository).execute("missing", "us").await,
            Err(AppStoreError::AppNotFound(_))
        ));
    }
}
