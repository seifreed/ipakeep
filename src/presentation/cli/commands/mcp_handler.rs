use super::mcp_models::{
    AppArgs, AuthInfoOutput, DownloadArgs, DownloadOutput, PurchasesArgs, PurchasesOutput,
    SavedFile, SearchArgs, SearchOutput, VersionsOutput, ipa_filename, parse_args, to_value,
};
use super::mcp_tools::tool_definitions;
use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::domain::usecase::{AuthInfo, Download, ListVersions, Purchases, Search};
use crate::infrastructure::mcp::{CallToolResult, Implementation, ToolDefinition, ToolInvoker};
use crate::presentation::cli::commands::{download_item_to_path, get_guid, resolve_app_id};
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;

pub(super) struct McpToolHandler<R, C> {
    app_store: R,
    credentials: C,
}

impl<R, C> McpToolHandler<R, C> {
    pub(super) fn new(app_store: R, credentials: C) -> Self {
        Self {
            app_store,
            credentials,
        }
    }
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
            "purchases" => self.purchases(arguments).await,
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
            let path = directory.join(ipa_filename(&item.metadata, app_id, index));
            let size = download_item_to_path(&self.app_store, item, &path).await?;
            files.push(SavedFile {
                path: path.to_string_lossy().into_owned(),
                size,
            });
        }
        to_value(&DownloadOutput {
            app_id,
            count: files.len(),
            files,
        })
    }

    async fn purchases(&self, arguments: Value) -> Result<Value, String> {
        let args: PurchasesArgs = parse_args(arguments)?;
        if args.page == Some(0) {
            return Err("page must be greater than 0".to_string());
        }
        if args.page.is_some_and(|page| page > 1) {
            return Err("pagination beyond page 1 is not supported".to_string());
        }
        let limit = match args.max_results {
            Some(0) => return Err("max_results must be greater than 0".to_string()),
            Some(value) if value > 100 => {
                return Err("max_results must not exceed 100".to_string());
            }
            Some(value) => value,
            None => 10,
        };
        let apps = Purchases::new(self.app_store.clone(), self.credentials.clone())
            .execute(limit, args.platform.as_deref())
            .await
            .map_err(|error| format!("purchases failed: {error}"))?;
        to_value(&PurchasesOutput {
            count: apps.len(),
            apps,
        })
    }
}
