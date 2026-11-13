//! JSON-RPC 2.0 and Model Context Protocol message types.
//!
//! These are pure data types with no transport or business logic, so they are
//! trivially (de)serializable and unit-testable without any I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The JSON-RPC protocol version string echoed in every response.
pub const JSONRPC_VERSION: &str = "2.0";

/// Default MCP protocol revision advertised when a client sends none.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";

/// JSON-RPC error code for a malformed JSON payload.
pub const PARSE_ERROR: i64 = -32700;
/// JSON-RPC error code for an unknown method.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC error code for invalid method parameters.
pub const INVALID_PARAMS: i64 = -32602;
/// JSON-RPC error code for an internal server error.
pub const INTERNAL_ERROR: i64 = -32603;

/// An incoming JSON-RPC 2.0 request or notification.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version; expected to be `2.0`.
    #[serde(default)]
    pub jsonrpc: String,
    /// Request identifier. Absent for notifications.
    #[serde(default)]
    pub id: Option<Value>,
    /// The method to invoke.
    pub method: String,
    /// Optional method parameters.
    #[serde(default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Returns `true` when the message is a notification (has no `id`) and thus
    /// expects no response.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A JSON-RPC 2.0 response carrying either a result or an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version; always `2.0`.
    pub jsonrpc: String,
    /// Identifier echoed from the originating request (`null` when unknown).
    pub id: Value,
    /// Successful result payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload, mutually exclusive with `result`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Build a successful response for `id` carrying `result`.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response for `id`.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Identifying information about the server implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Implementation {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
}

/// Declares that the server exposes tools.
///
/// MCP serializes this capability marker as an empty JSON object.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ToolsCapability {}

/// The set of capabilities advertised by the server.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ServerCapabilities {
    /// Tool capability marker.
    pub tools: ToolsCapability,
}

/// Result of the `initialize` handshake.
#[derive(Debug, Clone, Serialize)]
pub struct InitializeResult {
    /// Negotiated protocol revision.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Advertised server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server identity.
    #[serde(rename = "serverInfo")]
    pub server_info: Implementation,
    /// Optional free-form usage guidance for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

/// A single tool advertised by `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolDefinition {
    /// Unique tool name used in `tools/call`.
    pub name: String,
    /// Human-readable description of the tool's behaviour.
    pub description: String,
    /// JSON Schema describing the tool's input arguments.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Result of a `tools/list` request.
#[derive(Debug, Clone, Serialize)]
pub struct ListToolsResult {
    /// The advertised tools.
    pub tools: Vec<ToolDefinition>,
}

/// A piece of content returned from a tool call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    /// A plain-text content block.
    #[serde(rename = "text")]
    Text {
        /// The text payload.
        text: String,
    },
}

/// Result of a `tools/call` request.
#[derive(Debug, Clone, Serialize)]
pub struct CallToolResult {
    /// Ordered content blocks produced by the tool.
    pub content: Vec<ToolContent>,
    /// `true` when the content describes a tool execution failure.
    #[serde(rename = "isError")]
    pub is_error: bool,
}

impl CallToolResult {
    /// Build a successful result with a single JSON text block.
    pub fn json(value: &Value) -> Self {
        let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
        Self {
            content: vec![ToolContent::Text { text }],
            is_error: false,
        }
    }

    /// Build a failing result with a single plain-text block.
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text {
                text: message.into(),
            }],
            is_error: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_without_id_is_a_notification() {
        let request: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .expect("valid request");
        assert!(request.is_notification());
        assert_eq!(request.method, "notifications/initialized");
    }

    #[test]
    fn request_with_id_is_not_a_notification() {
        let request: JsonRpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#)
                .expect("valid request");
        assert!(!request.is_notification());
        assert_eq!(request.id, Some(Value::from(7)));
    }

    #[test]
    fn success_response_serializes_without_error_field() {
        let response = JsonRpcResponse::success(Value::from(1), serde_json::json!({"ok": true}));
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["result"]["ok"], true);
        assert!(json.get("error").is_none());
    }

    #[test]
    fn error_response_serializes_without_result_field() {
        let response = JsonRpcResponse::error(Value::Null, METHOD_NOT_FOUND, "method not found: x");
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(json["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(json["error"]["message"], "method not found: x");
        assert!(json.get("result").is_none());
        assert!(json["id"].is_null());
    }

    #[test]
    fn tool_definition_renames_input_schema() {
        let tool = ToolDefinition {
            name: "search".into(),
            description: "Search apps".into(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        let json = serde_json::to_value(&tool).expect("serialize");
        assert_eq!(json["name"], "search");
        assert_eq!(json["inputSchema"]["type"], "object");
        assert!(json.get("input_schema").is_none());
    }

    #[test]
    fn call_tool_result_json_marks_success_and_embeds_text() {
        let result = CallToolResult::json(&serde_json::json!({"count": 2}));
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["isError"], false);
        assert_eq!(json["content"][0]["type"], "text");
        let text = json["content"][0]["text"].as_str().expect("text block");
        assert!(text.contains("\"count\""));
    }

    #[test]
    fn call_tool_result_error_marks_is_error() {
        let result = CallToolResult::error("boom");
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["isError"], true);
        assert_eq!(json["content"][0]["text"], "boom");
    }

    #[test]
    fn initialize_result_uses_camel_case_keys() {
        let result = InitializeResult {
            protocol_version: DEFAULT_PROTOCOL_VERSION.into(),
            capabilities: ServerCapabilities::default(),
            server_info: Implementation {
                name: "ipakeep".into(),
                version: "0.1.1".into(),
            },
            instructions: Some("hi".into()),
        };
        let json = serde_json::to_value(&result).expect("serialize");
        assert_eq!(json["protocolVersion"], DEFAULT_PROTOCOL_VERSION);
        assert_eq!(json["serverInfo"]["name"], "ipakeep");
        assert!(json["capabilities"]["tools"].is_object());
        assert_eq!(json["instructions"], "hi");
    }
}
