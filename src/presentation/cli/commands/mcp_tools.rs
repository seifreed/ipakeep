use crate::infrastructure::mcp::ToolDefinition;
use serde_json::Value;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        search_tool(),
        app_versions_tool(),
        auth_info_tool(),
        download_tool(),
        purchases_tool(),
    ]
}

fn search_tool() -> ToolDefinition {
    ToolDefinition {
        name: "search".to_string(),
        description: "Search for apps on the App Store.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "term": {"type": "string", "description": "Search term."},
                "country": {
                    "type": "string",
                    "description": "ISO 3166-1 alpha-2 country code; defaults to 'us'."
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Maximum number of results; defaults to 5."
                }
            },
            "required": ["term"]
        }),
    }
}

fn app_versions_tool() -> ToolDefinition {
    ToolDefinition {
        name: "list_versions".to_string(),
        description: "List available version identifiers for an app. Requires login.".to_string(),
        input_schema: app_reference_schema(),
    }
}

fn auth_info_tool() -> ToolDefinition {
    ToolDefinition {
        name: "auth_info".to_string(),
        description: "Show the stored account (never exposes tokens or passwords).".to_string(),
        input_schema: serde_json::json!({"type": "object", "properties": {}}),
    }
}

fn download_tool() -> ToolDefinition {
    ToolDefinition {
        name: "download".to_string(),
        description: "Download an app's IPA to the server's filesystem. Requires login."
            .to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "string",
                    "description": "App Store id, bundle identifier, or app name."
                },
                "country": {
                    "type": "string",
                    "description": "ISO 3166-1 alpha-2 country code; defaults to 'us'."
                },
                "external_version_id": {
                    "type": "string",
                    "description": "Specific external version id; defaults to the latest."
                },
                "output": {
                    "type": "string",
                    "description": "Output directory for the IPA(s); defaults to '.'."
                },
                "no_purchase": {
                    "type": "boolean",
                    "description": "Skip acquiring the free license automatically."
                }
            },
            "required": ["app"]
        }),
    }
}

fn purchases_tool() -> ToolDefinition {
    ToolDefinition {
        name: "purchases".to_string(),
        description: "List apps owned by the authenticated account. Requires login.".to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "page": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Page number starting at 1; defaults to 1."
                },
                "max_results": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Apps per page; defaults to the server default."
                },
                "platform": {
                    "type": "string",
                    "description": "Optional platform filter; defaults to all platforms."
                }
            }
        }),
    }
}

fn app_reference_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "app": {
                "type": "string",
                "description": "App Store id, bundle identifier, or app name."
            },
            "country": {
                "type": "string",
                "description": "ISO 3166-1 alpha-2 country code; defaults to 'us'."
            }
        },
        "required": ["app"]
    })
}
