//! URL helpers for App Store transport.

use crate::domain::error::AppStoreError;
use reqwest::Url;

pub(super) fn appstore_query_url(
    base: &str,
    pairs: &[(&str, &str)],
) -> Result<String, AppStoreError> {
    let mut url = Url::parse(base)
        .map_err(|_| AppStoreError::NetworkError("invalid App Store URL".into()))?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}
