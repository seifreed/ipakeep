use super::parsing::parse_download_item;
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

#[test]
fn read_request_headers_stops_when_the_peer_closes_early() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request_headers(&mut stream)
    });
    let client = TcpStream::connect(address).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    assert_eq!(server.join().unwrap(), "");
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
fn parse_download_item_defaults_missing_optional_data_and_requires_url() {
    assert!(
        parse_download_item(&serde_json::json!({}))
            .unwrap()
            .is_none()
    );

    let item = parse_download_item(&serde_json::json!({ "URL": "https://example.test/app" }))
        .unwrap()
        .unwrap();
    assert_eq!(item.url, "https://example.test/app");
    assert_eq!(item.md5, "");
    assert!(item.sinfs.is_empty());
    assert!(item.metadata.is_empty());
}

#[test]
fn parse_download_item_filters_invalid_sinfs_and_reports_bad_base64() {
    let item = parse_download_item(&serde_json::json!({
        "URL": "https://example.test/app",
        "sinfs": [
            { "id": "invalid", "sinf": "AQ==" },
            { "id": 7, "sinf": "AQ==" },
            { "id": 8, "sinf": "" },
            { "id": 9, "sinf": 42 }
        ],
        "metadata": { "bundleId": "com.example.app" }
    }))
    .unwrap()
    .unwrap();
    assert_eq!(item.sinfs.len(), 3);
    assert_eq!(item.sinfs[0].data, [1]);
    assert_eq!(item.sinfs[1].data, [] as [u8; 0]);
    assert_eq!(item.sinfs[2].data, [] as [u8; 0]);
    assert_eq!(item.metadata["bundleId"], "com.example.app");

    let error = parse_download_item(&serde_json::json!({
        "URL": "https://example.test/app",
        "sinfs": [{ "id": 7, "sinf": "%%%" }]
    }))
    .unwrap_err();
    assert!(matches!(
        error,
        crate::domain::error::AppStoreError::Unexpected(_)
    ));
}

#[test]
fn appstore_query_url_rejects_invalid_base_urls() {
    assert!(matches!(
        appstore_query_url("not a URL", &[]),
        Err(AppStoreError::NetworkError(_))
    ));
}
