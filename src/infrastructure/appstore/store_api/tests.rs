use super::parsing::external_version_ids;
use super::*;

#[test]
fn parse_app_keeps_result_missing_optional_fields() {
    // Regression: a result with only the identity fields must not be
    // dropped just because price/version/name are absent.
    let item = serde_json::json!({
        "trackId": 42,
        "bundleId": "com.example.app",
    });

    let app = parse_app(&item).expect("app with identity fields should parse");
    assert_eq!(app.id, 42);
    assert_eq!(app.bundle_id, "com.example.app");
    assert_eq!(app.name, "");
    assert_eq!(app.version, "");
    assert!((app.price - 0.0).abs() < f64::EPSILON);
}

#[test]
fn parse_app_rejects_result_missing_identity() {
    assert!(parse_app(&serde_json::json!({ "bundleId": "com.example.app" })).is_none());
    assert!(parse_app(&serde_json::json!({ "trackId": 42 })).is_none());
}

#[test]
fn external_version_ids_parses_csv_array_and_number() {
    assert_eq!(
        external_version_ids(&serde_json::json!("1, 2 ,,3")),
        vec!["1", "2", "3"]
    );
    assert_eq!(
        external_version_ids(&serde_json::json!([10, "20", ""])),
        vec!["10", "20"]
    );
    assert_eq!(external_version_ids(&serde_json::json!(99)), vec!["99"]);
}

#[test]
fn pod_from_cookies_extracts_itspod() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::SET_COOKIE,
        "wosid-lite=abc; path=/".parse().unwrap(),
    );
    headers.append(
        reqwest::header::SET_COOKIE,
        "itspod=48; version=\"1\"; path=/; domain=.apple.com"
            .parse()
            .unwrap(),
    );
    assert_eq!(pod_from_cookies(&headers).as_deref(), Some("48"));
}

#[test]
fn pod_from_cookies_none_without_itspod() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(
        reqwest::header::SET_COOKIE,
        "wosid-lite=abc; path=/".parse().unwrap(),
    );
    assert_eq!(pod_from_cookies(&headers), None);
}

#[test]
fn response_is_store_error_detects_failure_and_message() {
    assert!(response_is_store_error(
        &serde_json::json!({ "failureType": "5002" })
    ));
    assert!(response_is_store_error(
        &serde_json::json!({ "customerMessage": "could not be found" })
    ));
    assert!(!response_is_store_error(
        &serde_json::json!({ "jingleDocType": "purchaseSuccess" })
    ));
    assert!(!response_is_store_error(
        &serde_json::json!({ "failureType": "" })
    ));
}
