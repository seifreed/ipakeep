//! ipakeep CLI entry point.

use clap::Parser;
use ipakeep::domain::repository::CredentialRepository;
use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::keychain::FileKeychain;
use ipakeep::presentation::cli::app::{Cli, Commands};
use ipakeep::presentation::cli::output::OutputFormat;
use std::str::FromStr;

#[cfg(target_os = "macos")]
use ipakeep::infrastructure::keychain::MacOSKeychain;

/// Enum wrapper that delegates to the active credential repository implementation.
///
/// This allows `main.rs` to choose between `FileKeychain` and `MacOSKeychain`
/// without changing the generic handler signatures in the presentation layer.
enum AnyKeychain {
    /// File-based JSON keychain.
    File(FileKeychain),

    /// macOS native keychain (only available on macOS).
    #[cfg(target_os = "macos")]
    MacOS(MacOSKeychain),
}

#[async_trait::async_trait]
impl CredentialRepository for AnyKeychain {
    async fn save_account(
        &self,
        account: &ipakeep::domain::entity::Account,
    ) -> Result<(), ipakeep::domain::error::CredentialError> {
        match self {
            Self::File(k) => k.save_account(account).await,
            #[cfg(target_os = "macos")]
            Self::MacOS(k) => k.save_account(account).await,
        }
    }

    async fn load_account(
        &self,
    ) -> Result<Option<ipakeep::domain::entity::Account>, ipakeep::domain::error::CredentialError>
    {
        match self {
            Self::File(k) => k.load_account().await,
            #[cfg(target_os = "macos")]
            Self::MacOS(k) => k.load_account().await,
        }
    }

    async fn delete_account(&self) -> Result<(), ipakeep::domain::error::CredentialError> {
        match self {
            Self::File(k) => k.delete_account().await,
            #[cfg(target_os = "macos")]
            Self::MacOS(k) => k.delete_account().await,
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let format = OutputFormat::from_str(&cli.format)?;

    let http_client =
        AppleHttpClient::new().map_err(|e| format!("failed to create HTTP client: {e}"))?;
    let app_store = AppleAppStoreRepository::new(http_client);

    let keychain = if cli.file_keychain {
        AnyKeychain::File(
            FileKeychain::new().map_err(|e| format!("failed to initialize file keychain: {e}"))?,
        )
    } else {
        #[cfg(target_os = "macos")]
        {
            AnyKeychain::MacOS(
                MacOSKeychain::new()
                    .map_err(|e| format!("failed to initialize macOS keychain: {e}"))?,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            AnyKeychain::File(
                FileKeychain::new()
                    .map_err(|e| format!("failed to initialize file keychain: {e}"))?,
            )
        }
    };

    match cli.command {
        Commands::Auth { action } => match action {
            ipakeep::presentation::cli::app::AuthCommands::Login {
                email,
                password,
                code,
            } => {
                let options = ipakeep::presentation::cli::commands::auth::LoginOptions {
                    email: email.as_deref(),
                    password: password.as_deref(),
                    code: code.as_deref(),
                    non_interactive: cli.non_interactive,
                    grandslam: cli.grandslam,
                };
                ipakeep::presentation::cli::commands::auth::handle_login(
                    &options, app_store, keychain, &format,
                )
                .await
            }
            ipakeep::presentation::cli::app::AuthCommands::Info => {
                ipakeep::presentation::cli::commands::auth::handle_info(keychain, &format).await
            }
            ipakeep::presentation::cli::app::AuthCommands::Revoke => {
                ipakeep::presentation::cli::commands::auth::handle_revoke(keychain).await
            }
        },
        Commands::Search {
            term,
            limit,
            country,
        } => {
            ipakeep::presentation::cli::commands::search::handle_search(
                &term, limit, &country, app_store, &format,
            )
            .await
        }
        Commands::Purchase {
            bundle_identifier,
            country,
        } => {
            ipakeep::presentation::cli::commands::purchase::handle_purchase(
                &bundle_identifier,
                &country,
                app_store,
                keychain,
                &format,
            )
            .await
        }
        Commands::Download {
            app_id,
            bundle_identifier,
            external_version_id,
            output,
            purchase,
        } => {
            ipakeep::presentation::cli::commands::download::handle_download(
                app_id,
                bundle_identifier.as_deref(),
                external_version_id,
                output.as_deref(),
                purchase,
                app_store,
                keychain,
                &format,
            )
            .await
        }
        Commands::ListVersions {
            app_id,
            bundle_identifier,
        } => {
            ipakeep::presentation::cli::commands::list_versions::handle_list_versions(
                app_id,
                bundle_identifier.as_deref(),
                app_store,
                keychain,
                &format,
            )
            .await
        }
    }
}

fn init_logging(verbose: bool) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_log_filter(verbose).into()),
        )
        .init();
}

fn default_log_filter(verbose: bool) -> &'static str {
    if verbose { "debug" } else { "warn" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_switches_default_log_filter_to_debug() {
        assert_eq!(default_log_filter(false), "warn");
        assert_eq!(default_log_filter(true), "debug");
    }
}
