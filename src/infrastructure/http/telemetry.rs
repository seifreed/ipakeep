//! Safe metadata logging for outbound HTTP requests.

use reqwest::{Client, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use std::time::Instant;

/// Send an HTTP request and log its method, host, status, and elapsed time.
///
/// The request path, query, headers, and body are deliberately excluded.
pub(crate) async fn send_with_observability(
    client: &Client,
    request: RequestBuilder,
) -> Result<Response, reqwest::Error> {
    let request = request
        .build()
        .inspect_err(|_error| {
            tracing::warn!(
                service = "ipakeep",
                component = "http",
                event_name = "http.request.build_failed",
                error_type = "invalid_request",
                outcome = "failure",
                "HTTP request could not be built"
            );
        })
        .map_err(reqwest::Error::without_url)?;
    let method = request.method().as_str().to_string();
    let host = request.url().host_str().unwrap_or("unknown").to_string();
    let started = Instant::now();
    match client.execute(request).await {
        Ok(response) => {
            let status = response.status().as_u16();
            let duration_ms = elapsed_ms(started);
            let outcome = if response.status().is_success() {
                "success"
            } else {
                "http_error"
            };
            let expected_client_error =
                response.status().is_client_error() && !matches!(status, 408 | 429);
            if response.status().is_success() || expected_client_error {
                tracing::debug!(
                    service = "ipakeep",
                    component = "http",
                    event_name = "http.response.headers_received",
                    method,
                    host,
                    status,
                    outcome,
                    duration_ms,
                    "HTTP response headers received"
                );
            } else {
                tracing::warn!(
                    service = "ipakeep",
                    component = "http",
                    event_name = "http.response.headers_received",
                    method,
                    host,
                    status,
                    outcome,
                    duration_ms,
                    "HTTP response returned a non-success status"
                );
            }
            Ok(response)
        }
        Err(error) => {
            tracing::warn!(
                service = "ipakeep",
                component = "http",
                event_name = "http.request.failed",
                method,
                host,
                outcome = "failure",
                duration_ms = elapsed_ms(started),
                error_type = request_error_type(&error),
                "HTTP request failed"
            );
            Err(error.without_url())
        }
    }
}

pub(crate) async fn read_response_bytes(response: Response) -> Result<Vec<u8>, reqwest::Error> {
    let status = response.status().as_u16();
    let started = Instant::now();
    let result = response.bytes().await;
    match &result {
        Ok(body) => record_body_read(status, started, Some(body.len()), None),
        Err(error) => record_body_read(status, started, None, Some(error)),
    }
    result
        .map(|body| body.to_vec())
        .map_err(reqwest::Error::without_url)
}

pub(crate) async fn read_response_text(response: Response) -> Result<String, reqwest::Error> {
    let status = response.status().as_u16();
    let started = Instant::now();
    let result = response.text().await;
    match &result {
        Ok(body) => record_body_read(status, started, Some(body.len()), None),
        Err(error) => record_body_read(status, started, None, Some(error)),
    }
    result.map_err(reqwest::Error::without_url)
}

pub(crate) async fn read_response_json<T: DeserializeOwned>(
    response: Response,
) -> Result<T, reqwest::Error> {
    let status = response.status().as_u16();
    let started = Instant::now();
    let result = response.json().await;
    match &result {
        Ok(_) => record_body_read(status, started, None, None),
        Err(error) => record_body_read(status, started, None, Some(error)),
    }
    result.map_err(reqwest::Error::without_url)
}

fn record_body_read(
    status: u16,
    started: Instant,
    body_bytes: Option<usize>,
    error: Option<&reqwest::Error>,
) {
    let duration_ms = elapsed_ms(started);
    if let Some(error) = error {
        tracing::warn!(
            component = "http",
            event_name = "http.response.body_read_failed",
            status,
            outcome = "failure",
            duration_ms,
            error_type = request_error_type(error),
            "HTTP response body could not be read"
        );
        return;
    }
    if let Some(body_bytes) = body_bytes {
        tracing::debug!(
            component = "http",
            event_name = "http.response.body_read",
            status,
            outcome = "success",
            duration_ms,
            body_bytes,
            "HTTP response body read"
        );
    } else {
        tracing::debug!(
            component = "http",
            event_name = "http.response.body_read",
            status,
            outcome = "success",
            duration_ms,
            "HTTP response body read"
        );
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn request_error_type(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::{read_response_bytes, send_with_observability};
    use crate::infrastructure::observability::log_capture::LogCapture;
    use reqwest::Client;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test(flavor = "current_thread")]
    async fn logs_safe_http_metadata_without_query_or_response_body() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private"))
            .respond_with(ResponseTemplate::new(503).set_body_string("response-secret"))
            .mount(&server)
            .await;
        let client = Client::new();
        let request = client.get(format!("{}/private?token=query-secret", server.uri()));

        let response = send_with_observability(&client, request)
            .await
            .expect("HTTP response");
        let body = read_response_bytes(response).await.expect("response body");
        let logs = capture.contents();

        assert_eq!(body.len(), "response-secret".len());
        assert!(logs.contains("http.response.headers_received"));
        assert!(logs.contains("http.response.body_read"));
        assert!(logs.contains("status=503"));
        assert!(logs.contains("duration_ms="));
        assert!(!logs.contains("query-secret"));
        assert!(!logs.contains("response-secret"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn json_event_has_normalized_fields_without_request_secrets() {
        let capture = LogCapture::default();
        let _guard = capture.install_json();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = Client::new();
        let request = client.get(format!(
            "{}/private?token=sensitive-query-value",
            server.uri()
        ));

        send_with_observability(&client, request)
            .await
            .expect("HTTP response");

        let logs = capture.contents();
        let event = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|event| event["event_name"] == "http.response.headers_received")
            .expect("HTTP JSON event");
        assert_eq!(event["level"], "DEBUG");
        assert_eq!(event["event_name"], "http.response.headers_received");
        assert_eq!(event["method"], "GET");
        assert_eq!(event["status"], 200);
        assert!(event["duration_ms"].is_number());
        assert!(!logs.contains("sensitive-query-value"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_requests_each_emit_a_completion_event() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = Client::new();
        let (first, second) = tokio::join!(
            send_with_observability(&client, client.get(server.uri())),
            send_with_observability(&client, client.get(server.uri()))
        );

        assert!(first.is_ok() && second.is_ok());
        assert_eq!(
            capture
                .contents()
                .matches("http.response.headers_received")
                .count(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn returned_transport_error_omits_signed_query_values() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local port");
        let address = listener.local_addr().expect("local address");
        drop(listener);
        let url = format!("http://{address}/?signature=private-value");
        let client = Client::new();

        let error = send_with_observability(&client, client.get(url))
            .await
            .expect_err("closed server");

        assert!(!error.to_string().contains("private-value"));
    }
}
