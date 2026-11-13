//! ipakeep CLI entry point.

use clap::Parser;
use ipakeep::domain::repository::CredentialRepository;
use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
use ipakeep::infrastructure::http::AppleHttpClient;
use ipakeep::infrastructure::keychain::FileKeychain;
use ipakeep::infrastructure::observability;
use ipakeep::presentation::cli::app::{
    AuthCommands, Cli, Commands, DecryptCommands, DeviceCommands, SimulatorCommands,
};
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
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let outcome = if result.is_ok() { "success" } else { "failure" };
    span.record("outcome", outcome);
    span.record("duration_ms", duration_ms);
    if result.is_ok() {
        tracing::info!(parent: &span, service = "ipakeep", component = "cli", operation, event_name = "command.completed", outcome, duration_ms, "command completed");
    } else {
        tracing::error!(parent: &span, service = "ipakeep", component = "cli", operation, event_name = "command.failed", outcome, duration_ms, error_type = "command_error", "command failed; see stderr for details");
    }
    tracing::info!(
        service = "ipakeep",
        component = "cli",
        event_name = "application.stopped",
        "application stopped"
    );
    result
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

async fn dispatch_command(
    cli: Cli,
    app_store: AppleAppStoreRepository,
    keychain: AnyKeychain,
    format: &OutputFormat,
) -> Result<(), String> {
    let non_interactive = cli.non_interactive;
    let grandslam = use_grandslam(&cli);
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
        Commands::Purchases { limit } => {
            ipakeep::presentation::cli::commands::purchases::handle_purchases(
                limit, app_store, keychain, format,
            )
            .await
        }
        Commands::Simulator { action } => dispatch_simulator(action),
        Commands::Device { action } => dispatch_device(action),
        Commands::Decrypt { action } => dispatch_decrypt(action, format, keychain).await,
        Commands::Mcp => {
            ipakeep::presentation::cli::commands::mcp::handle_mcp(app_store, keychain).await
        }
    }
}

fn dispatch_device(action: DeviceCommands) -> Result<(), String> {
    use ipakeep::infrastructure::device::InstallRequest;
    use ipakeep::presentation::cli::commands::device;
    match action {
        DeviceCommands::InstallIpa {
            ipa,
            device: device_id,
            identity,
            provisioning_profile,
            entitlements,
            run,
            legacy_device,
        } => device::handle_install(&InstallRequest {
            ipa: &ipa,
            device: &device_id,
            identity: &identity,
            provisioning_profiles: &provisioning_profile,
            entitlements: entitlements.as_deref(),
            launch: run,
            legacy_device,
        }),
    }
}

async fn dispatch_decrypt(
    action: DecryptCommands,
    format: &OutputFormat,
    keychain: AnyKeychain,
) -> Result<(), String> {
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
        DecryptCommands::Verify { ipa } => decrypt::handle_verify(&ipa, format),
        DecryptCommands::Entitlements { path } => decrypt::handle_entitlements(&path, format),
        DecryptCommands::SetMinOs {
            ipa,
            version,
            output,
        } => decrypt::handle_set_min_os(&ipa, &version, output.as_deref()),
        DecryptCommands::Dump {
            bundle_id,
            dumper,
            ipa,
            device,
            agent,
            spawn,
            settle,
            output,
            drop_undumped_extensions,
            ssh_host,
            ssh_port,
            ssh_user,
        } => decrypt::handle_dump(&decrypt::DumpArgs {
            bundle_id: &bundle_id,
            dumper: &dumper,
            ipa: ipa.as_deref(),
            device: &device,
            agent: agent.as_deref(),
            spawn,
            settle,
            output: output.as_deref(),
            drop_undumped_extensions,
            ssh_host: &ssh_host,
            ssh_port,
            ssh_user: &ssh_user,
        }),
        DecryptCommands::Offline {
            ipa,
            output,
            no_on_device,
        } => decrypt::handle_offline(&ipa, output.as_deref(), !no_on_device),
        DecryptCommands::DumpMac {
            bundle_id,
            ipa,
            agent,
            settle,
            output,
        } => decrypt::handle_dump_mac(
            &bundle_id,
            &ipa,
            agent.as_deref(),
            settle,
            output.as_deref(),
        ),
        DecryptCommands::Provision {
            app,
            device_udid,
            team,
            app_id_id,
            output,
        } => {
            decrypt::handle_provision(
                &app,
                &device_udid,
                team.as_deref(),
                &app_id_id,
                output.as_deref(),
                keychain,
            )
            .await
        }
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

fn command_name(command: &Commands) -> &'static str {
    match command {
        Commands::Auth { action } => match action {
            AuthCommands::Login { .. } => "auth.login",
            AuthCommands::Info => "auth.info",
            AuthCommands::Revoke => "auth.revoke",
        },
        Commands::Search { .. } => "search",
        Commands::Purchase { .. } => "purchase",
        Commands::Download { .. } => "download",
        Commands::ListVersions { .. } => "list_versions",
        Commands::Purchases { .. } => "purchases",
        Commands::Simulator { action } => match action {
            SimulatorCommands::Prepare { .. } => "simulator.prepare",
            SimulatorCommands::Run { .. } => "simulator.run",
            SimulatorCommands::InstallIpa { .. } => "simulator.install_ipa",
            SimulatorCommands::UnlockRuntime { .. } => "simulator.unlock_runtime",
        },
        Commands::Device { action } => match action {
            DeviceCommands::InstallIpa { .. } => "device.install_ipa",
        },
        Commands::Decrypt { action } => match action {
            DecryptCommands::Inspect { .. } => "decrypt.inspect",
            DecryptCommands::Patch { .. } => "decrypt.patch",
            DecryptCommands::Resign { .. } => "decrypt.resign",
            DecryptCommands::Verify { .. } => "decrypt.verify",
            DecryptCommands::Entitlements { .. } => "decrypt.entitlements",
            DecryptCommands::SetMinOs { .. } => "decrypt.set_min_os",
            DecryptCommands::Dump { .. } => "decrypt.dump",
            DecryptCommands::Offline { .. } => "decrypt.offline",
            DecryptCommands::DumpMac { .. } => "decrypt.dump_mac",
            DecryptCommands::Provision { .. } => "decrypt.provision",
        },
        Commands::Mcp => "mcp",
    }
}

fn use_grandslam(cli: &Cli) -> bool {
    cli.grandslam
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_names_are_stable_and_do_not_include_user_arguments() {
        let command =
            Cli::try_parse_from(["ipakeep", "search", "secret query"]).expect("CLI options");
        assert_eq!(command_name(&command.command), "search");
    }

    #[test]
    fn defaults_to_store_login_and_accepts_grandslam_flag() {
        let default = Cli::try_parse_from(["ipakeep", "auth", "login"]).expect("CLI options");
        let grandslam =
            Cli::try_parse_from(["ipakeep", "--grandslam", "auth", "login"]).expect("CLI options");

        assert!(!use_grandslam(&default));
        assert!(use_grandslam(&grandslam));
    }
}
