//! Minimal JSON-RPC 2.0 over stdio transport for an MCP server.
//!
//! The transport reads newline-delimited JSON-RPC messages from a byte stream
//! and writes newline-delimited responses back. It is generic over any
//! [`ToolInvoker`], keeping Apple App Store specifics out of the infrastructure
//! layer, and over the reader/writer so it can be driven by in-memory buffers
//! in tests without touching real stdio.

use crate::infrastructure::mcp::protocol::{
    CallToolResult, DEFAULT_PROTOCOL_VERSION, INTERNAL_ERROR, INVALID_PARAMS, Implementation,
    InitializeResult, JsonRpcRequest, JsonRpcResponse, ListToolsResult, METHOD_NOT_FOUND,
    PARSE_ERROR, ServerCapabilities, ToolDefinition,
};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// A provider of MCP tools, decoupled from the JSON-RPC transport.
#[async_trait]
pub trait ToolInvoker: Send + Sync {
    /// Identity reported in the `initialize` handshake.
    fn server_info(&self) -> Implementation;

    /// Optional usage instructions reported in the handshake.
    fn instructions(&self) -> Option<String>;

    /// The tools advertised by `tools/list`.
    fn list_tools(&self) -> Vec<ToolDefinition>;

    /// Execute the named tool with the given arguments.
    ///
    /// Implementations return a [`CallToolResult`] whose `is_error` flag marks
    /// tool-level failures; transport and protocol errors are handled by the
    /// server and never surface here.
    async fn call_tool(&self, name: &str, arguments: Value) -> CallToolResult;
}

/// Serve MCP requests over the given byte streams until the reader reaches EOF.
///
/// Each line is parsed as one JSON-RPC message. Requests receive a response;
/// notifications do not. Malformed lines produce a JSON-RPC parse error.
///
/// # Errors
///
/// Returns an I/O error if reading from `reader` or writing to `writer` fails.
pub async fn serve<I, R, W>(invoker: &I, reader: R, mut writer: W) -> std::io::Result<()>
where
    I: ToolInvoker + ?Sized,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
            Ok(request) => handle_request(invoker, request).await,
            Err(error) => Some(JsonRpcResponse::error(
                Value::Null,
                PARSE_ERROR,
                format!("parse error: {error}"),
            )),
        };

        if let Some(response) = response {
            write_message(&mut writer, &response).await?;
        }
    }

    Ok(())
}

/// Route a single parsed request to the appropriate handler.
///
/// Returns `None` for notifications, which receive no response.
pub async fn handle_request<I>(invoker: &I, request: JsonRpcRequest) -> Option<JsonRpcResponse>
where
    I: ToolInvoker + ?Sized,
{
    if request.is_notification() {
        return None;
    }

    let id = request.id.clone().unwrap_or(Value::Null);
    let response = match request.method.as_str() {
        "initialize" => initialize_response(invoker, id, request.params.as_ref()),
        "tools/list" => to_success(
            id,
            &ListToolsResult {
                tools: invoker.list_tools(),
            },
        ),
        "tools/call" => call_tool_response(invoker, id, request.params).await,
        "ping" => JsonRpcResponse::success(id, Value::Object(serde_json::Map::new())),
        other => JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("method not found: {other}")),
    };

    Some(response)
}

fn initialize_response<I>(invoker: &I, id: Value, params: Option<&Value>) -> JsonRpcResponse
where
    I: ToolInvoker + ?Sized,
{
    let protocol_version = params
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PROTOCOL_VERSION)
        .to_string();

    let result = InitializeResult {
        protocol_version,
        capabilities: ServerCapabilities::default(),
        server_info: invoker.server_info(),
        instructions: invoker.instructions(),
    };

    to_success(id, &result)
}

async fn call_tool_response<I>(invoker: &I, id: Value, params: Option<Value>) -> JsonRpcResponse
where
    I: ToolInvoker + ?Sized,
{
    let Some(params) = params else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "missing params for tools/call");
    };

    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "tools/call requires a string 'name'");
    };

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));

    let result = invoker.call_tool(name, arguments).await;
    to_success(id, &result)
}

fn to_success<T: Serialize>(id: Value, value: &T) -> JsonRpcResponse {
    match serde_json::to_value(value) {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(error) => JsonRpcResponse::error(
            id,
            INTERNAL_ERROR,
            format!("failed to serialize result: {error}"),
        ),
    }
}

async fn write_message<W>(writer: &mut W, response: &JsonRpcResponse) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut bytes = serde_json::to_vec(response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::mcp::protocol::{JSONRPC_VERSION, ToolContent};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeInvoker {
        calls: Mutex<Vec<(String, Value)>>,
    }

    #[async_trait]
    impl ToolInvoker for FakeInvoker {
        fn server_info(&self) -> Implementation {
            Implementation {
                name: "ipakeep".into(),
                version: "9.9.9".into(),
            }
        }

        fn instructions(&self) -> Option<String> {
            Some("test instructions".into())
        }

        fn list_tools(&self) -> Vec<ToolDefinition> {
            vec![ToolDefinition {
                name: "search".into(),
                description: "Search apps".into(),
                input_schema: serde_json::json!({"type": "object"}),
            }]
        }

        async fn call_tool(&self, name: &str, arguments: Value) -> CallToolResult {
            self.calls
                .lock()
                .expect("lock")
                .push((name.to_string(), arguments.clone()));
            if name == "search" {
                CallToolResult::json(&serde_json::json!({"echo": arguments}))
            } else {
                CallToolResult::error(format!("unknown tool: {name}"))
            }
        }
    }

    fn request(method: &str, id: Option<Value>, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: method.to_string(),
            params,
        }
    }

    #[tokio::test]
    async fn initialize_echoes_client_protocol_version_and_server_info() {
        let invoker = FakeInvoker::default();
        let response = handle_request(
            &invoker,
            request(
                "initialize",
                Some(Value::from(1)),
                Some(serde_json::json!({"protocolVersion": "2025-06-18"})),
            ),
        )
        .await
        .expect("response");

        let result = response.result.expect("result");
        assert_eq!(result["protocolVersion"], "2025-06-18");
        assert_eq!(result["serverInfo"]["name"], "ipakeep");
        assert_eq!(result["instructions"], "test instructions");
    }

    #[tokio::test]
    async fn initialize_falls_back_to_default_protocol_version() {
        let invoker = FakeInvoker::default();
        let response = handle_request(&invoker, request("initialize", Some(Value::from(1)), None))
            .await
            .expect("response");

        let result = response.result.expect("result");
        assert_eq!(result["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_returns_advertised_tools() {
        let invoker = FakeInvoker::default();
        let response = handle_request(&invoker, request("tools/list", Some(Value::from(2)), None))
            .await
            .expect("response");

        let result = response.result.expect("result");
        assert_eq!(result["tools"][0]["name"], "search");
    }

    #[tokio::test]
    async fn tools_call_routes_name_and_arguments_to_invoker() {
        let invoker = FakeInvoker::default();
        let response = handle_request(
            &invoker,
            request(
                "tools/call",
                Some(Value::from(3)),
                Some(serde_json::json!({"name": "search", "arguments": {"term": "x"}})),
            ),
        )
        .await
        .expect("response");

        let calls = invoker.calls.lock().expect("lock");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "search");
        assert_eq!(calls[0].1, serde_json::json!({"term": "x"}));

        let result = response.result.expect("result");
        assert_eq!(result["isError"], false);
    }

    #[tokio::test]
    async fn tools_call_without_name_is_invalid_params() {
        let invoker = FakeInvoker::default();
        let response = handle_request(
            &invoker,
            request(
                "tools/call",
                Some(Value::from(4)),
                Some(serde_json::json!({"arguments": {}})),
            ),
        )
        .await
        .expect("response");

        assert_eq!(response.error.expect("error").code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn unknown_method_is_method_not_found() {
        let invoker = FakeInvoker::default();
        let response = handle_request(
            &invoker,
            request("does/not/exist", Some(Value::from(5)), None),
        )
        .await
        .expect("response");

        assert_eq!(response.error.expect("error").code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn notifications_receive_no_response() {
        let invoker = FakeInvoker::default();
        let response =
            handle_request(&invoker, request("notifications/initialized", None, None)).await;
        assert!(response.is_none());
    }

    #[tokio::test]
    async fn serve_reads_requests_and_writes_newline_delimited_responses() {
        let invoker = FakeInvoker::default();
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            "\n",
        );
        let mut output = Vec::new();

        serve(&invoker, input.as_bytes(), &mut output)
            .await
            .expect("serve");

        let text = String::from_utf8(output).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        // Two requests, one notification (no response) => two response lines.
        assert_eq!(lines.len(), 2);

        let first: JsonRpcResponse = serde_json::from_str(lines[0]).expect("first response");
        assert_eq!(first.id, Value::from(1));
        assert!(first.result.is_some());

        let second: JsonRpcResponse = serde_json::from_str(lines[1]).expect("second response");
        assert_eq!(second.id, Value::from(2));
    }

    #[tokio::test]
    async fn serve_reports_parse_error_for_malformed_line() {
        let invoker = FakeInvoker::default();
        let mut output = Vec::new();

        serve(&invoker, &b"not json\n"[..], &mut output)
            .await
            .expect("serve");

        let response: JsonRpcResponse =
            serde_json::from_str(String::from_utf8(output).expect("utf8").trim())
                .expect("response");
        assert_eq!(response.error.expect("error").code, PARSE_ERROR);
        assert!(response.id.is_null());
    }

    #[test]
    fn call_tool_result_text_content_is_a_text_block() {
        let result = CallToolResult::error("x");
        assert_eq!(result.content[0], ToolContent::Text { text: "x".into() });
    }
}
