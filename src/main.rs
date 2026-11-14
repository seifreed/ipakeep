//! ipakeep CLI entry point.

use clap::Parser;
use ipakeep::domain::repository::CredentialRepository;
use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::keychain::FileKeychain;
use ipakeep::infrastructure::observability;
use ipakeep::presentation::cli::app::Cli;
use ipakeep::presentation::cli::commands::dispatch::{command_name, dispatch_command};
use ipakeep::presentation::cli::output::OutputFormat;
use std::str::FromStr;
use std::time::Instant;
use tracing::Instrument;

#[cfg(target_os = "macos")]
use ipakeep::infrastructure::keychain::MacOSKeychain;

/// Enum wrapper that delegates to the active credential repository implementation.
///
/// This allows `main.rs` to choose between `FileKeychain` and `MacOSKeychain`
/// without changing the generic handler signatures in the presentation layer.
#[derive(Clone)]
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

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    observability::init_logging(cli.verbose)?;
    observability::install_panic_hook();
    tracing::info!(
        service = "ipakeep",
        component = "cli",
        version = env!("CARGO_PKG_VERSION"),
        event_name = "application.started",
        "application started"
    );

    let operation = command_name(&cli.command);
    let span = tracing::info_span!(
        "cli.command",
        service = "ipakeep",
        component = "cli",
        environment = %observability::environment(),
        operation,
        outcome = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    );
    let started = Instant::now();
    tracing::info!(parent: &span, service = "ipakeep", component = "cli", operation, event_name = "command.started", "command started");
    let result = run_command(cli).instrument(span.clone()).await;
    record_command_result(&span, &result, started, operation);
    tracing::info!(
        service = "ipakeep",
        component = "cli",
        event_name = "application.stopped",
        "application stopped"
    );
    result
}

fn record_command_result(
    span: &tracing::Span,
    result: &Result<(), String>,
    started: Instant,
    operation: &str,
) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = if result.is_ok() { "success" } else { "failure" };
    span.record("outcome", outcome);
    span.record("duration_ms", duration_ms);
    if result.is_ok() {
        tracing::info!(parent: span, service = "ipakeep", component = "cli", operation, event_name = "command.completed", outcome, duration_ms, "command completed");
    } else {
        tracing::error!(parent: span, service = "ipakeep", component = "cli", operation, event_name = "command.failed", outcome, duration_ms, error_type = "command_error", "command failed; see stderr for details");
    }
}

async fn run_command(cli: Cli) -> Result<(), String> {
    let format = OutputFormat::from_str(&cli.format)?;

    let http_client =
        AppleHttpClient::new().map_err(|e| format!("failed to create HTTP client: {e}"))?;
    let app_store = AppleAppStoreRepository::new(http_client);

    let keychain = build_keychain(cli.file_keychain)?;

    dispatch_command(cli, app_store, keychain, &format).await
}

fn build_keychain(file_keychain: bool) -> Result<AnyKeychain, String> {
    if file_keychain {
        return Ok(AnyKeychain::File(FileKeychain::new().map_err(|e| {
            format!("failed to initialize file keychain: {e}")
        })?));
    }

    #[cfg(target_os = "macos")]
    {
        Ok(AnyKeychain::MacOS(MacOSKeychain::new().map_err(|e| {
            format!("failed to initialize macOS keychain: {e}")
        })?))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(AnyKeychain::File(FileKeychain::new().map_err(|e| {
            format!("failed to initialize file keychain: {e}")
        })?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_store_login_and_accepts_grandslam_flag() {
        let default = Cli::try_parse_from(["ipakeep", "auth", "login"]).expect("CLI options");
        let grandslam =
            Cli::try_parse_from(["ipakeep", "--grandslam", "auth", "login"]).expect("CLI options");

        assert!(!default.grandslam);
        assert!(grandslam.grandslam);
    }
}
