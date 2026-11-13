//! MCP command handler — wires ipakeep use cases to Model Context Protocol tools.
//!
//! This adapter builds the same use cases the CLI commands use (search,
//! list-versions, auth-info, download) and exposes them as MCP tools over the
//! stdio transport in `infrastructure::mcp`. It owns no transport logic: it only
//! declares the tool set, validates arguments, runs the use case, and maps the
//! result (or failure) to MCP content.

use crate::domain::entity::{Account, App, AppVersion, DownloadMetadata, metadata_string};
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::{AuthInfo, Download, ListVersions, Search};
use crate::infrastructure::ipa::{patch_ipa, verify_md5};
use crate::infrastructure::mcp::{
    CallToolResult, Implementation, ToolDefinition, ToolInvoker, serve,
};
use crate::presentation::cli::commands::{get_guid, resolve_app_id};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Cursor;
use std::path::PathBuf;

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
    let handler = McpToolHandler {
        app_store,
        credentials,
    };
    serve(&handler, tokio::io::stdin(), tokio::io::stdout())
        .await
        .map_err(|error| format!("MCP server failed: {error}"))
}

/// Concrete [`ToolInvoker`] backed by ipakeep use cases.
struct McpToolHandler<R, C> {
    app_store: R,
    credentials: C,
}

#[async_trait]
impl<R, C> ToolInvoker for McpToolHandler<R, C>
where
    R: AppStoreRepository + Clone + 'static,
    C: CredentialRepository + Clone + 'static,
{
    fn server_info(&self) -> Implementation {
        Implementation {
            name: "ipakeep".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn instructions(&self) -> Option<String> {
        Some(
            "Use the account already stored by ipakeep. If authentication is required, ask the \
             user to run `ipakeep auth login` outside MCP. Only free apps are supported."
                .to_string(),
        )
    }

    fn list_tools(&self) -> Vec<ToolDefinition> {
        tool_definitions()
    }

    async fn call_tool(&self, name: &str, arguments: Value) -> CallToolResult {
        let outcome = match name {
            "search" => self.search(arguments).await,
            "list_versions" => self.list_versions(arguments).await,
            "auth_info" => self.auth_info().await,
            "download" => self.download(arguments).await,
            "purchases" => Self::purchases(arguments),
            other => Err(format!("unknown tool: {other}")),
        };

        match outcome {
            Ok(value) => CallToolResult::json(&value),
            Err(message) => CallToolResult::error(message),
        }
    }
}

impl<R, C> McpToolHandler<R, C>
where
    R: AppStoreRepository + Clone + 'static,
    C: CredentialRepository + Clone + 'static,
{
    async fn search(&self, arguments: Value) -> Result<Value, String> {
        let args: SearchArgs = parse_args(arguments)?;
        if args.term.trim().is_empty() {
            return Err("search term must not be empty".to_string());
        }

        let apps = Search::new(self.app_store.clone())
            .execute(&args.term, &args.country, args.limit)
            .await
            .map_err(|error| format!("search failed: {error}"))?;

        to_value(&SearchOutput {
            count: apps.len(),
            apps,
        })
    }

    async fn list_versions(&self, arguments: Value) -> Result<Value, String> {
        let args: AppArgs = parse_args(arguments)?;
        let guid = get_guid();
        let app_id = resolve_app_id(&self.app_store, &args.app, &args.country).await?;

        let versions = ListVersions::new(self.app_store.clone(), self.credentials.clone())
            .execute(app_id, &guid)
            .await
            .map_err(|error| format!("list-versions failed: {error}"))?;

        to_value(&VersionsOutput {
            app_id,
            count: versions.len(),
            versions,
        })
    }

    async fn auth_info(&self) -> Result<Value, String> {
        let account = AuthInfo::new(self.credentials.clone())
            .execute()
            .await
            .map_err(|error| format!("auth-info failed: {error}"))?;

        match account {
            Some(account) => to_value(&AuthInfoOutput::from(&account)),
            None => Err("not logged in; run `ipakeep auth login` outside MCP".to_string()),
        }
    }

    async fn download(&self, arguments: Value) -> Result<Value, String> {
        let args: DownloadArgs = parse_args(arguments)?;
        let guid = get_guid();
        let app_id = resolve_app_id(&self.app_store, &args.app, &args.country).await?;

        let items = Download::new(self.app_store.clone(), self.credentials.clone())
            .execute(app_id, &guid, args.external_version_id, !args.no_purchase)
            .await
            .map_err(|error| format!("download failed: {error}"))?;

        if items.is_empty() {
            return Err("no download items returned".to_string());
        }

        let directory = PathBuf::from(args.output.as_deref().unwrap_or("."));
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("failed to create output dir: {error}"))?;

        let mut files = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let bytes = self
                .app_store
                .download_bytes(&item.url)
                .await
                .map_err(|error| format!("download failed: {error}"))?;
            verify_md5(&bytes, &item.md5)
                .map_err(|error| format!("MD5 verification failed: {error}"))?;
            if zip::ZipArchive::new(Cursor::new(&bytes)).is_err() {
                return Err("downloaded file is not a valid ZIP archive".to_string());
            }
            let patched = patch_ipa(&bytes, &item.sinfs, &item.metadata)
                .map_err(|error| format!("IPA patching failed: {error}"))?;
            let path = directory.join(ipa_filename(&item.metadata, app_id, index));
            std::fs::write(&path, &patched)
                .map_err(|error| format!("failed to write file: {error}"))?;
            files.push(SavedFile {
                path: path.to_string_lossy().into_owned(),
                size: patched.len(),
            });
        }

        to_value(&DownloadOutput {
            app_id,
            count: files.len(),
            files,
        })
    }

    // TODO(orchestrator): wire this to the `list_purchases` use case being added
    // by the parallel purchases agent. The tool name and input schema are final;
    // only the body below needs replacing, for example:
    //
    //     let args: PurchasesArgs = parse_args(arguments)?;
    //     let output = crate::domain::usecase::ListPurchases::new(
    //         self.app_store.clone(), self.credentials.clone(),
    //     )
    //     .execute(args.page, args.max_results)
    //     .await
    //     .map_err(|error| format!("purchases failed: {error}"))?;
    //     to_value(&output)
    //
    // Until then the tool validates its arguments and returns a clear error so
    // the server still compiles and runs without the parallel work.
    fn purchases(arguments: Value) -> Result<Value, String> {
        let args: PurchasesArgs = parse_args(arguments)?;
        if args.page == Some(0) {
            return Err("page must be greater than 0".to_string());
        }
        if args.max_results == Some(0) {
            return Err("max_results must be greater than 0".to_string());
        }
        let _ = args.platform.as_deref();
        Err(
            "the 'purchases' tool is not yet wired: the list_purchases use case is being added by \
             a parallel agent"
                .to_string(),
        )
    }
}

/// Declare the MCP tool set and its JSON Schemas.
///
/// Kept as a free function so the schema shape can be asserted in tests without
/// constructing a handler or any repositories.
fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
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
        },
        ToolDefinition {
            name: "list_versions".to_string(),
            description: "List available version identifiers for an app. Requires login."
                .to_string(),
            input_schema: app_reference_schema(),
        },
        ToolDefinition {
            name: "auth_info".to_string(),
            description: "Show the stored account (never exposes tokens or passwords).".to_string(),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
        },
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
        },
        ToolDefinition {
            name: "purchases".to_string(),
            description: "List apps owned by the authenticated account. Requires login."
                .to_string(),
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
        },
    ]
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

fn parse_args<T: for<'de> Deserialize<'de>>(arguments: Value) -> Result<T, String> {
    serde_json::from_value(arguments).map_err(|error| format!("invalid arguments: {error}"))
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to serialize result: {error}"))
}

fn ipa_filename(metadata: &DownloadMetadata, app_id: i64, index: usize) -> String {
    let bundle = metadata_string(metadata, "softwareVersionBundleId")
        .or_else(|| metadata_string(metadata, "bundleId"))
        .unwrap_or_else(|| format!("app_{app_id}"));
    let bundle = sanitize_segment(&bundle);
    let version = metadata_string(metadata, "bundleShortVersionString")
        .map(|version| sanitize_segment(&version))
        .unwrap_or_default();
    if version.is_empty() {
        format!("{bundle}_{index}.ipa")
    } else {
        format!("{bundle}_{version}_{index}.ipa")
    }
}

fn sanitize_segment(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "_".to_string()
    } else {
        safe
    }
}

fn default_country() -> String {
    "us".to_string()
}

const fn default_limit() -> u32 {
    5
}

#[derive(Debug, Deserialize)]
struct SearchArgs {
    term: String,
    #[serde(default = "default_country")]
    country: String,
    #[serde(default = "default_limit")]
    limit: u32,
}

#[derive(Debug, Deserialize)]
struct AppArgs {
    app: String,
    #[serde(default = "default_country")]
    country: String,
}

#[derive(Debug, Deserialize)]
struct DownloadArgs {
    app: String,
    #[serde(default = "default_country")]
    country: String,
    #[serde(default)]
    external_version_id: Option<String>,
    #[serde(default)]
    output: Option<String>,
    #[serde(default)]
    no_purchase: bool,
}

#[derive(Debug, Deserialize)]
struct PurchasesArgs {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    max_results: Option<u32>,
    #[serde(default)]
    platform: Option<String>,
}

#[derive(Debug, Serialize)]
struct SearchOutput {
    count: usize,
    apps: Vec<App>,
}

#[derive(Debug, Serialize)]
struct VersionsOutput {
    app_id: i64,
    count: usize,
    versions: Vec<AppVersion>,
}

#[derive(Debug, Serialize)]
struct DownloadOutput {
    app_id: i64,
    count: usize,
    files: Vec<SavedFile>,
}

#[derive(Debug, Serialize)]
struct SavedFile {
    path: String,
    size: usize,
}

/// Sanitized account view that never includes tokens, cookies, or passwords.
#[derive(Debug, Serialize)]
struct AuthInfoOutput {
    email: String,
    name: String,
    store_front: String,
    pod: String,
    has_password_token: bool,
    has_cookies: bool,
}

impl From<&Account> for AuthInfoOutput {
    fn from(account: &Account) -> Self {
        Self {
            email: account.email.clone(),
            name: account.name.clone(),
            store_front: account.store_front.clone(),
            pod: account.pod.clone(),
            has_password_token: !account.password_token.is_empty(),
            has_cookies: !account.cookies.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use crate::infrastructure::mcp::protocol::ToolContent;

    fn handler() -> McpToolHandler<FakeAppStoreRepository, InMemoryCredentialRepository> {
        McpToolHandler {
            app_store: FakeAppStoreRepository::new(),
            credentials: InMemoryCredentialRepository::new(),
        }
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
        let handler = McpToolHandler {
            app_store,
            credentials: InMemoryCredentialRepository::new(),
        };

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
        let handler = McpToolHandler {
            app_store: FakeAppStoreRepository::new(),
            credentials,
        };

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
    async fn purchases_tool_is_flagged_as_not_yet_wired() {
        let result = handler()
            .call_tool("purchases", serde_json::json!({}))
            .await;
        assert!(result.is_error);
        let ToolContent::Text { text } = &result.content[0];
        assert!(text.contains("not yet wired"));
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
