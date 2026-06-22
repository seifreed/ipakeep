//! ipakeep CLI entry point.

use clap::Parser;
use ipakeep::domain::repository::CredentialRepository;
use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::keychain::FileKeychain;
use ipakeep::presentation::cli::app::{
    AuthCommands, Cli, Commands, DecryptCommands, SimulatorCommands,
};
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

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

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

async fn dispatch_command(
    cli: Cli,
    app_store: AppleAppStoreRepository,
    keychain: AnyKeychain,
    format: &OutputFormat,
) -> Result<(), String> {
    let non_interactive = cli.non_interactive;
    let grandslam = cli.grandslam && !cli.legacy;
    match cli.command {
        Commands::Auth { action } => {
            dispatch_auth(
                action,
                non_interactive,
                grandslam,
                app_store,
                keychain,
                format,
            )
            .await
        }
        Commands::Search {
            term,
            limit,
            country,
        } => {
            ipakeep::presentation::cli::commands::search::handle_search(
                &term, limit, &country, app_store, format,
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
                format,
            )
            .await
        }
        Commands::Download {
            app,
            country,
            external_version_id,
            output,
            no_purchase,
            simulator_install,
            simulator_run,
        } => {
            ipakeep::presentation::cli::commands::download::handle_download(
                ipakeep::presentation::cli::commands::download::DownloadRequest {
                    app: &app,
                    country: &country,
                    external_version_id,
                    output: output.as_deref(),
                    auto_purchase: !no_purchase,
                    simulator_run: simulator_install || simulator_run,
                    simulator_launch: simulator_run,
                },
                app_store,
                keychain,
                format,
            )
            .await
        }
        Commands::ListVersions { app, country } => {
            ipakeep::presentation::cli::commands::list_versions::handle_list_versions(
                &app, &country, app_store, keychain, format,
            )
            .await
        }
        Commands::Simulator { action } => dispatch_simulator(action),
        Commands::Decrypt { action } => dispatch_decrypt(action, format),
    }
}

fn dispatch_decrypt(action: DecryptCommands, format: &OutputFormat) -> Result<(), String> {
    use ipakeep::presentation::cli::commands::decrypt;
    match action {
        DecryptCommands::Inspect { ipa } => decrypt::handle_inspect(&ipa, format),
        DecryptCommands::Patch { ipa, from, output } => {
            decrypt::handle_patch(&ipa, &from, output.as_deref())
        }
        DecryptCommands::Resign {
            app,
            identity,
            entitlements,
        } => decrypt::handle_resign(&app, identity.as_deref(), entitlements.as_deref()),
    }
}

fn dispatch_simulator(action: SimulatorCommands) -> Result<(), String> {
    use ipakeep::presentation::cli::commands::simulator;
    match action {
        SimulatorCommands::Prepare { path } => simulator::handle_prepare(&path),
        SimulatorCommands::Run {
            bundle_id,
            inject_dylib,
            udid,
            device,
            entitlements,
            console,
        } => simulator::handle_run(
            &bundle_id,
            &inject_dylib,
            console,
            &ipakeep::infrastructure::simulator::SimulatorTarget { udid, device },
            entitlements.as_deref(),
        ),
        SimulatorCommands::InstallIpa {
            ipa,
            run,
            console,
            udid,
            device,
            entitlements,
        } => simulator::handle_install_ipa(
            &ipa,
            run,
            console,
            &ipakeep::infrastructure::simulator::SimulatorTarget { udid, device },
            entitlements.as_deref(),
        ),
        SimulatorCommands::UnlockRuntime { path } => {
            simulator::handle_unlock_runtime(path.as_deref())
        }
    }
}

async fn dispatch_auth(
    action: AuthCommands,
    non_interactive: bool,
    grandslam: bool,
    app_store: AppleAppStoreRepository,
    keychain: AnyKeychain,
    format: &OutputFormat,
) -> Result<(), String> {
    use ipakeep::presentation::cli::commands::auth;
    match action {
        AuthCommands::Login {
            email,
            password,
            code,
            country,
        } => {
            let options = auth::LoginOptions {
                email: email.as_deref(),
                password: password.as_deref(),
                code: code.as_deref(),
                country: country.as_deref(),
                non_interactive,
                grandslam,
            };
            auth::handle_login(&options, app_store, keychain, format).await
        }
        AuthCommands::Info => auth::handle_info(keychain, format).await,
        AuthCommands::Revoke => auth::handle_revoke(keychain).await,
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
