//! Search use case — finds apps on the App Store.

use crate::domain::entity::App;
use crate::domain::error::AppStoreError;
use crate::domain::repository::AppStoreRepository;

/// Use case for searching the Apple App Store.
pub struct Search<R>
where
    R: AppStoreRepository,
{
    app_store: R,
}

impl<R> Search<R>
where
    R: AppStoreRepository,
{
    /// Create a new search use case.
    pub fn new(app_store: R) -> Self {
        Self { app_store }
    }

    /// Search for apps by term.
    ///
    /// # Errors
    ///
    /// Returns `AppStoreError::NetworkError` if the iTunes API is unreachable.
    pub async fn execute(
        &self,
        term: &str,
        country: &str,
        limit: u32,
    ) -> Result<Vec<App>, AppStoreError> {
        self.app_store.search(term, country, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::FakeAppStoreRepository;

    #[tokio::test]
    async fn search_returns_results() {
        let apps = vec![App {
            id: 123,
            bundle_id: "com.example.app".into(),
            name: "Example App".into(),
            version: "1.0".into(),
            price: 0.0,
        }];

        let app_store = FakeAppStoreRepository::new().with_search_result(Ok(apps));

        let use_case = Search::new(app_store.clone());
        let result: Result<Vec<App>, AppStoreError> = use_case.execute("example", "us", 5).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);

        let calls = app_store.search_calls();
        assert_eq!(calls, vec![("example".into(), "us".into(), 5)]);
    }

    #[tokio::test]
    async fn search_empty_results() {
        let app_store = FakeAppStoreRepository::new().with_search_result(Ok(vec![]));

        let use_case = Search::new(app_store);
        let result: Result<Vec<App>, AppStoreError> =
            use_case.execute("nonexistent", "us", 5).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
