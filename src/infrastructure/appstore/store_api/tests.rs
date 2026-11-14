use super::parsing::external_version_ids;
use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

#[tokio::test]
async fn repository_search_uses_configured_http_endpoint() {
    let body = r#"{"results":[{"trackId":42,"bundleId":"com.example.app","trackName":"Example","version":"1.0","price":0}]}"#;
    let (url, server) = serve_json_once(body);
    let config = AppleApiConfig {
        itunes_search_url: url,
        ..AppleApiConfig::default()
    };
    let repository =
        AppleAppStoreRepository::with_config(AppleHttpClient::new().expect("HTTP client"), config);

    let apps = repository.search("ipakeep", "us", 3).await.expect("search");
    assert_eq!(apps[0].bundle_id, "com.example.app");
    assert_eq!(apps[0].name, "Example");
    let request = server.join().expect("server thread");
    assert!(request.starts_with("GET /?"));
    assert!(request.contains("term=ipakeep"));
    assert!(request.contains("country=us"));
}

fn serve_json_once(body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local server");
    let address = listener.local_addr().expect("local address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("HTTP client connection");
        let request = read_request_headers(&mut stream);
        write_json_response(&mut stream, body);
        request
    });
    (format!("http://{address}"), server)
}

fn read_request_headers(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let count = stream.read(&mut chunk).expect("HTTP request");
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(request).expect("HTTP request headers")
}

fn write_json_response(stream: &mut TcpStream, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("HTTP response");
}

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
