//! MCP command handler — wires ipakeep use cases to Model Context Protocol tools.
//!
//! This adapter builds the same use cases the CLI commands use (search,
//! list-versions, auth-info, download) and exposes them as MCP tools over the
//! stdio transport in `infrastructure::mcp`. It owns no transport logic: it only
//! declares the tool set, validates arguments, runs the use case, and maps the
//! result (or failure) to MCP content.

use super::mcp_handler::McpToolHandler;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::infrastructure::mcp::serve;

/// Run the ipakeep MCP server over stdio until the client closes the stream.
///
/// Authentication tools are intentionally not exposed; the server uses the
/// account already stored by `ipakeep auth login`.
///
/// # Errors
///
/// Returns an error string if the stdio transport fails.
pub async fn handle_mcp<R, C>(app_store: R, credentials: C) -> Result<(), String>
where
    R: AppStoreRepository + Clone + 'static,
    C: CredentialRepository + Clone + 'static,
{
    let handler = McpToolHandler::new(app_store, credentials);
    serve(&handler, tokio::io::stdin(), tokio::io::stdout())
        .await
        .map_err(|error| format!("MCP server failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::super::mcp_models::{DownloadArgs, SearchArgs, ipa_filename, parse_args};
    use super::super::mcp_tools::tool_definitions;
    use super::*;
    use crate::domain::entity::{Account, App, DownloadMetadata, OwnedApp};
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use crate::infrastructure::mcp::{ToolContent, ToolInvoker};
    use serde_json::Value;

    fn handler() -> McpToolHandler<FakeAppStoreRepository, InMemoryCredentialRepository> {
        McpToolHandler::new(
            FakeAppStoreRepository::new(),
            InMemoryCredentialRepository::new(),
        )
    }

    fn account() -> Account {
        Account {
            email: "test@example.com".into(),
            name: "Test User".into(),
            password_token: "secret-token".into(),
            directory_services_id: "dsid".into(),
            store_front: "143441-2,26".into(),
            pod: "1".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: vec!["cookie=value".into()],
        }
    }

    #[test]
    fn tool_definitions_cover_the_documented_tool_set() {
        let names: Vec<String> = tool_definitions().into_iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            vec![
                "search",
                "list_versions",
                "auth_info",
                "download",
                "purchases"
            ]
        );
    }

    #[test]
    fn every_tool_has_an_object_input_schema() {
        for tool in tool_definitions() {
            assert_eq!(
                tool.input_schema["type"], "object",
                "tool {} must have an object schema",
                tool.name
            );
            assert!(
                !tool.description.is_empty(),
                "tool {} must have a description",
                tool.name
            );
        }
    }

    #[test]
    fn search_schema_requires_term_and_documents_defaults() {
        let search = tool_definitions()
            .into_iter()
            .find(|t| t.name == "search")
            .expect("search tool");
        assert_eq!(search.input_schema["required"][0], "term");
        assert!(search.input_schema["properties"]["limit"].is_object());
    }

    #[test]
    fn search_args_apply_defaults() {
        let args: SearchArgs = parse_args(serde_json::json!({"term": "twitter"})).expect("args");
        assert_eq!(args.country, "us");
        assert_eq!(args.limit, 5);
    }

    #[test]
    fn download_args_default_to_auto_purchase_and_current_directory() {
        let args: DownloadArgs = parse_args(serde_json::json!({"app": "123"})).expect("args");
        assert!(!args.no_purchase);
        assert!(args.output.is_none());
        assert_eq!(args.country, "us");
    }

    #[test]
    fn parse_args_reports_invalid_arguments() {
        let error = parse_args::<SearchArgs>(serde_json::json!({"limit": "not-a-number"}))
            .expect_err("should fail");
        assert!(error.contains("invalid arguments"));
    }

    #[tokio::test]
    async fn search_tool_returns_results_as_json_content() {
        let app_store = FakeAppStoreRepository::new().with_search_result(Ok(vec![App {
            id: 42,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            price: 0.0,
        }]));
        let handler = McpToolHandler::new(app_store, InMemoryCredentialRepository::new());

        let result = handler
            .call_tool("search", serde_json::json!({"term": "example"}))
            .await;

        assert!(!result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        let parsed: Value = serde_json::from_str(text).expect("json content");
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["apps"][0]["id"], 42);
    }

    #[tokio::test]
    async fn empty_search_term_is_a_tool_error() {
        let result = handler()
            .call_tool("search", serde_json::json!({"term": "   "}))
            .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn unknown_tool_is_a_tool_error() {
        let result = handler().call_tool("nope", serde_json::json!({})).await;
        assert!(result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        assert!(text.contains("unknown tool"));
    }

    #[tokio::test]
    async fn auth_info_omits_secrets() {
        let credentials = InMemoryCredentialRepository::new().with_account(account());
        let handler = McpToolHandler::new(FakeAppStoreRepository::new(), credentials);

        let result = handler.call_tool("auth_info", serde_json::json!({})).await;

        assert!(!result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        assert!(!text.contains("secret-token"));
        assert!(!text.contains("cookie=value"));
        let parsed: Value = serde_json::from_str(text).expect("json content");
        assert_eq!(parsed["email"], "test@example.com");
        assert_eq!(parsed["has_password_token"], true);
        assert_eq!(parsed["has_cookies"], true);
    }

    #[tokio::test]
    async fn auth_info_errors_when_not_logged_in() {
        let result = handler()
            .call_tool("auth_info", serde_json::json!({}))
            .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn purchases_tool_errors_when_not_logged_in() {
        let result = handler()
            .call_tool("purchases", serde_json::json!({}))
            .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn purchases_tool_returns_owned_apps_as_json() {
        let app_store =
            FakeAppStoreRepository::new().with_list_purchases_result(Ok(vec![OwnedApp {
                id: 42,
                bundle_id: "com.example.app".into(),
                name: "Example".into(),
                version: "1.0".into(),
                platforms: vec!["iphone".into()],
                purchase_date: None,
            }]));
        let handler = McpToolHandler::new(
            app_store,
            InMemoryCredentialRepository::new().with_account(account()),
        );

        let result = handler
            .call_tool("purchases", serde_json::json!({"max_results": 5}))
            .await;

        assert!(!result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        let parsed: Value = serde_json::from_str(text).expect("json content");
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["apps"][0]["bundle_id"], "com.example.app");
    }

    #[tokio::test]
    async fn purchases_tool_filters_apps_by_platform_case_insensitively() {
        let app_store = FakeAppStoreRepository::new().with_list_purchases_result(Ok(vec![
            OwnedApp {
                id: 42,
                bundle_id: "com.example.iphone".into(),
                name: "iPhone app".into(),
                version: "1.0".into(),
                platforms: vec!["iphone".into()],
                purchase_date: None,
            },
            OwnedApp {
                id: 43,
                bundle_id: "com.example.macos".into(),
                name: "Mac app".into(),
                version: "1.0".into(),
                platforms: vec!["macos".into()],
                purchase_date: None,
            },
        ]));
        let handler = McpToolHandler::new(
            app_store,
            InMemoryCredentialRepository::new().with_account(account()),
        );

        let result = handler
            .call_tool("purchases", serde_json::json!({"platform": "iPhone"}))
            .await;

        assert!(!result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        let parsed: Value = serde_json::from_str(text).expect("json content");
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["apps"][0]["bundle_id"], "com.example.iphone");
    }

    #[tokio::test]
    async fn purchases_tool_rejects_pagination_beyond_first_page() {
        let result = handler()
            .call_tool("purchases", serde_json::json!({"page": 2}))
            .await;
        assert!(result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        assert!(text.contains("page 1"));
    }

    #[test]
    fn ipa_filename_sanitizes_metadata_segments() {
        let metadata = serde_json::json!({
            "softwareVersionBundleId": "../bad\\bundle",
            "bundleShortVersionString": "1/2:3"
        });
        let metadata = metadata.as_object().expect("object");
        assert_eq!(ipa_filename(metadata, 7, 0), ".._bad_bundle_1_2_3_0.ipa");
    }

    #[test]
    fn ipa_filename_falls_back_to_app_id_without_metadata() {
        let metadata = DownloadMetadata::new();
        assert_eq!(ipa_filename(&metadata, 99, 2), "app_99_2.ipa");
    }
}
