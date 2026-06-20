//! URL and cookie helpers for App Store transport.

use crate::domain::error::AppStoreError;
use reqwest::Url;

/// `true` when a store response body carries an error (rather than a success
/// payload), used to decide whether a pod-host retry is warranted.
pub(super) fn response_is_store_error(body: &serde_json::Value) -> bool {
    let non_empty = |key| {
        body.get(key)
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.is_empty())
    };
    non_empty("failureType") || non_empty("customerMessage")
}

/// Extract the numeric pod from an `itspod=<n>` affinity cookie in the response's
/// `Set-Cookie` headers, if present.
pub(super) fn pod_from_cookies(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            let pod = cookie.strip_prefix("itspod=")?.split(';').next()?.trim();
            (!pod.is_empty() && pod.bytes().all(|b| b.is_ascii_digit())).then(|| pod.to_string())
        })
}

pub(super) fn appstore_query_url(
    base: &str,
    pairs: &[(&str, &str)],
) -> Result<String, AppStoreError> {
    let mut url = Url::parse(base)
        .map_err(|e| AppStoreError::NetworkError(format!("invalid App Store URL: {e}")))?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in pairs {
            query.append_pair(key, value);
        }
    }
    Ok(url.to_string())
}
