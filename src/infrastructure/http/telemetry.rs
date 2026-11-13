//! Safe metadata logging for outbound HTTP requests.

use reqwest::{Client, RequestBuilder, Response};
use std::time::Instant;

/// Send an HTTP request and log its method, host, status, and elapsed time.
///
/// The request path, query, headers, and body are deliberately excluded.
pub(crate) async fn send_with_observability(
    client: &Client,
    request: RequestBuilder,
) -> Result<Response, reqwest::Error> {
    let request = request.build().inspect_err(|_error| {
        tracing::warn!(
            service = "ipakeep",
            component = "http",
            event_name = "http.request.build_failed",
            error_type = "invalid_request",
            outcome = "failure",
            "HTTP request could not be built"
        );
    })?;
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
            if response.status().is_success() {
                tracing::debug!(
                    service = "ipakeep",
                    component = "http",
                    event_name = "http.request.completed",
                    method,
                    host,
                    status,
                    outcome,
                    duration_ms,
                    "HTTP request completed"
                );
            } else {
                tracing::warn!(
                    service = "ipakeep",
                    component = "http",
                    event_name = "http.request.completed",
                    method,
                    host,
                    status,
                    outcome,
                    duration_ms,
                    "HTTP request returned a non-success status"
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
            Err(error)
        }
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
    use super::send_with_observability;
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
        let logs = capture.contents();

        assert_eq!(response.status().as_u16(), 503);
        assert!(logs.contains("http.request.completed"));
        assert!(logs.contains("status=503"));
        assert!(logs.contains("duration_ms="));
        assert!(!logs.contains("query-secret"));
        assert!(!logs.contains("response-secret"));
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
            capture.contents().matches("http.request.completed").count(),
            2
        );
    }
}
