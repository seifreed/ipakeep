//! Search use case — finds apps on the App Store.

use crate::domain::entity::App;
use crate::domain::error::AppStoreError;
use crate::domain::repository::CatalogRepository;

/// Use case for searching the Apple App Store.
pub struct Search<R>
where
    R: CatalogRepository,
{
    app_store: R,
}

impl<R> Search<R>
where
    R: CatalogRepository,
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
        let apps = self.app_store.search(term, country, limit).await?;
        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::error::AppStoreError;
    use crate::domain::repository::AppStoreRepo;

    #[tokio::test]
    async fn search_returns_results() {
        let apps = vec![App {
            id: 123,
            bundle_id: "com.example.app".into(),
            name: "Example App".into(),
            version: "1.0".into(),
            price: 0.0,
        }];

        let mut app_store = AppStoreRepo::new();
        app_store
            .expect_search()
            .withf(|term, country, limit| term == "example" && country == "us" && *limit == 5)
            .return_once(|_, _, _| Ok(apps));

        let use_case = Search::new(app_store);
        let result: Result<Vec<App>, AppStoreError> = use_case.execute("example", "us", 5).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn search_empty_results() {
        let mut app_store = AppStoreRepo::new();
        app_store.expect_search().return_once(|_, _, _| Ok(vec![]));

        let use_case = Search::new(app_store);
        let result: Result<Vec<App>, AppStoreError> =
            use_case.execute("nonexistent", "us", 5).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
