//! Routes parsed CLI commands to their presentation handlers.

use crate::domain::repository::{AppStoreRepository, CredentialRepository};
use crate::infrastructure::device::InstallRequest;
use crate::infrastructure::simulator::SimulatorTarget;
use crate::presentation::cli::app::{
    AuthCommands, Cli, Commands, DecryptCommands, DeviceCommands, SimulatorCommands,
};
use crate::presentation::cli::commands as handlers;
use crate::presentation::cli::output::OutputFormat;

/// Dispatch a parsed command using the configured application repositories.
///
/// # Errors
///
/// Returns an error if the selected command handler fails.
pub async fn dispatch_command<R, C>(
    cli: Cli,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository + Clone + 'static,
    C: CredentialRepository + Clone + 'static,
{
    let options = AuthOptions {
        non_interactive: cli.non_interactive,
        grandslam: cli.grandslam,
    };
    match cli.command {
        Commands::Auth { action } => {
            dispatch_auth(action, options, app_store, keychain, format).await
        }
        command @ Commands::Search { .. } => {
            dispatch_search_command(command, app_store, format).await
        }
        command @ Commands::Purchase { .. } => {
            dispatch_purchase_command(command, app_store, keychain, format).await
        }
        command @ Commands::Download { .. } => {
            dispatch_download_command(command, app_store, keychain, format).await
        }
        Commands::ListVersions { app, country } => {
            dispatch_list_versions(app, country, app_store, keychain, format).await
        }
        Commands::Purchases { limit } => {
            dispatch_purchases(limit, app_store, keychain, format).await
        }
        Commands::Simulator { action } => dispatch_simulator(action),
        Commands::Device { action } => dispatch_device(action),
        Commands::Decrypt { action } => dispatch_decrypt(action, format, keychain).await,
        Commands::Mcp => handlers::mcp::handle_mcp(app_store, keychain).await,
    }
}

struct AuthOptions {
    non_interactive: bool,
    grandslam: bool,
}

async fn dispatch_download_command<R, C>(
    command: Commands,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository + Clone,
    C: CredentialRepository,
{
    let Commands::Download {
        app,
        country,
        external_version_id,
        output,
        no_purchase,
        simulator_install,
        simulator_run,
    } = command
    else {
        return Err("expected a download command".into());
    };
    let request = handlers::download::DownloadRequest {
        app: &app,
        country: &country,
        external_version_id,
        output: output.as_deref(),
        auto_purchase: !no_purchase,
        simulator_run: simulator_install || simulator_run,
        simulator_launch: simulator_run,
    };
    dispatch_download(request, app_store, keychain, format).await
}

async fn dispatch_search<R: AppStoreRepository>(
    term: String,
    limit: u32,
    country: String,
    app_store: R,
    format: &OutputFormat,
) -> Result<(), String> {
    handlers::search::handle_search(&term, limit, &country, app_store, format).await
}

async fn dispatch_search_command<R: AppStoreRepository>(
    command: Commands,
    app_store: R,
    format: &OutputFormat,
) -> Result<(), String> {
    let Commands::Search {
        term,
        limit,
        country,
    } = command
    else {
        return Err("expected a search command".into());
    };
    dispatch_search(term, limit, country, app_store, format).await
}

async fn dispatch_purchase<R, C>(
    bundle_identifier: String,
    country: String,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    handlers::purchase::handle_purchase(&bundle_identifier, &country, app_store, keychain, format)
        .await
}

async fn dispatch_purchase_command<R, C>(
    command: Commands,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    let Commands::Purchase {
        bundle_identifier,
        country,
    } = command
    else {
        return Err("expected a purchase command".into());
    };
    dispatch_purchase(bundle_identifier, country, app_store, keychain, format).await
}

async fn dispatch_download<R, C>(
    request: handlers::download::DownloadRequest<'_>,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository + Clone,
    C: CredentialRepository,
{
    handlers::download::handle_download(request, app_store, keychain, format).await
}

async fn dispatch_list_versions<R, C>(
    app: String,
    country: String,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    handlers::list_versions::handle_list_versions(&app, &country, app_store, keychain, format).await
}

async fn dispatch_purchases<R, C>(
    limit: u32,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    handlers::purchases::handle_purchases(limit, app_store, keychain, format).await
}

fn dispatch_device(action: DeviceCommands) -> Result<(), String> {
    match action {
        DeviceCommands::InstallIpa {
            ipa,
            device: device_id,
            identity,
            provisioning_profile,
            entitlements,
            run,
            legacy_device,
        } => handlers::device::handle_install(&InstallRequest {
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

async fn dispatch_decrypt<C>(
    action: DecryptCommands,
    format: &OutputFormat,
    keychain: C,
) -> Result<(), String>
where
    C: CredentialRepository,
{
    use handlers::decrypt;
    match action {
        DecryptCommands::Inspect { ipa } => decrypt::handle_inspect(&ipa, format),
        DecryptCommands::Patch { ipa, from, output } => {
            decrypt::handle_patch(&ipa, &from, output.as_deref())
        }
        command @ DecryptCommands::Resign { .. } => dispatch_resign(command),
        DecryptCommands::Verify { ipa } => decrypt::handle_verify(&ipa, format),
        DecryptCommands::Entitlements { path } => decrypt::handle_entitlements(&path, format),
        command @ DecryptCommands::SetMinOs { .. } => dispatch_set_min_os(command),
        command @ DecryptCommands::Dump { .. } => dispatch_dump(command),
        DecryptCommands::Offline {
            ipa,
            output,
            no_on_device,
        } => decrypt::handle_offline(&ipa, output.as_deref(), !no_on_device),
        command @ DecryptCommands::DumpMac { .. } => dispatch_dump_mac(command),
        command @ DecryptCommands::Provision { .. } => dispatch_provision(command, keychain).await,
    }
}

fn dispatch_resign(command: DecryptCommands) -> Result<(), String> {
    let DecryptCommands::Resign {
        app,
        identity,
        entitlements,
    } = command
    else {
        return Err("expected a resign command".into());
    };
    handlers::decrypt::handle_resign(&app, identity.as_deref(), entitlements.as_deref())
}

fn dispatch_set_min_os(command: DecryptCommands) -> Result<(), String> {
    let DecryptCommands::SetMinOs {
        ipa,
        version,
        output,
    } = command
    else {
        return Err("expected a minimum OS command".into());
    };
    handlers::decrypt::handle_set_min_os(&ipa, &version, output.as_deref())
}

fn dispatch_dump(command: DecryptCommands) -> Result<(), String> {
    let DecryptCommands::Dump {
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
    } = command
    else {
        return Err("expected a dump command".into());
    };
    let args = handlers::decrypt::DumpArgs {
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
    };
    handlers::decrypt::handle_dump(&args)
}

fn dispatch_dump_mac(command: DecryptCommands) -> Result<(), String> {
    let DecryptCommands::DumpMac {
        bundle_id,
        ipa,
        agent,
        settle,
        output,
    } = command
    else {
        return Err("expected a Mac dump command".into());
    };
    handlers::decrypt::handle_dump_mac(
        &bundle_id,
        &ipa,
        agent.as_deref(),
        settle,
        output.as_deref(),
    )
}

async fn dispatch_provision<C: CredentialRepository>(
    command: DecryptCommands,
    keychain: C,
) -> Result<(), String> {
    let DecryptCommands::Provision {
        app,
        device_udid,
        team,
        app_id_id,
        output,
    } = command
    else {
        return Err("expected a provision command".into());
    };
    handlers::decrypt::handle_provision(
        &app,
        &device_udid,
        team.as_deref(),
        &app_id_id,
        output.as_deref(),
        keychain,
    )
    .await
}

fn dispatch_simulator(action: SimulatorCommands) -> Result<(), String> {
    use handlers::simulator;
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
            &SimulatorTarget { udid, device },
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
            &SimulatorTarget { udid, device },
            entitlements.as_deref(),
        ),
        SimulatorCommands::UnlockRuntime { path } => {
            simulator::handle_unlock_runtime(path.as_deref())
        }
    }
}

async fn dispatch_auth<R, C>(
    action: AuthCommands,
    options: AuthOptions,
    app_store: R,
    keychain: C,
    format: &OutputFormat,
) -> Result<(), String>
where
    R: AppStoreRepository,
    C: CredentialRepository,
{
    use handlers::auth;
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
                non_interactive: options.non_interactive,
                grandslam: options.grandslam,
            };
            auth::handle_login(&options, app_store, keychain, format).await
        }
        AuthCommands::Info => auth::handle_info(keychain, format).await,
        AuthCommands::Revoke => auth::handle_revoke(keychain).await,
    }
}

/// Return the stable telemetry name for a parsed command.
pub fn command_name(command: &Commands) -> &'static str {
    match command {
        Commands::Auth { action } => auth_command_name(action),
        Commands::Search { .. } => "search",
        Commands::Purchase { .. } => "purchase",
        Commands::Download { .. } => "download",
        Commands::ListVersions { .. } => "list_versions",
        Commands::Purchases { .. } => "purchases",
        Commands::Simulator { action } => simulator_command_name(action),
        Commands::Device { action } => device_command_name(action),
        Commands::Decrypt { action } => decrypt_command_name(action),
        Commands::Mcp => "mcp",
    }
}

fn auth_command_name(action: &AuthCommands) -> &'static str {
    match action {
        AuthCommands::Login { .. } => "auth.login",
        AuthCommands::Info => "auth.info",
        AuthCommands::Revoke => "auth.revoke",
    }
}

fn simulator_command_name(action: &SimulatorCommands) -> &'static str {
    match action {
        SimulatorCommands::Prepare { .. } => "simulator.prepare",
        SimulatorCommands::Run { .. } => "simulator.run",
        SimulatorCommands::InstallIpa { .. } => "simulator.install_ipa",
        SimulatorCommands::UnlockRuntime { .. } => "simulator.unlock_runtime",
    }
}

fn device_command_name(action: &DeviceCommands) -> &'static str {
    match action {
        DeviceCommands::InstallIpa { .. } => "device.install_ipa",
    }
}

fn decrypt_command_name(action: &DecryptCommands) -> &'static str {
    match action {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{
        OwnedApp,
        test_support::{app, test_account},
    };
    use crate::domain::repository::{FakeAppStoreRepository, InMemoryCredentialRepository};
    use clap::Parser;
    use std::path::PathBuf;

    fn cli(command: Commands) -> Cli {
        Cli {
            format: "text".into(),
            verbose: false,
            non_interactive: true,
            file_keychain: true,
            legacy: false,
            grandslam: false,
            command,
        }
    }

    #[test]
    fn command_names_are_stable_and_do_not_include_user_arguments() {
        let command =
            Cli::try_parse_from(["ipakeep", "search", "secret query"]).expect("CLI options");
        assert_eq!(command_name(&command.command), "search");
    }

    #[tokio::test]
    async fn dispatch_routes_search_purchase_versions_and_purchases() {
        let app = app(7);
        let versions = vec![crate::domain::entity::AppVersion {
            external_version_id: "42".into(),
            version_string: "1.0".into(),
        }];
        let owned = OwnedApp {
            id: app.id,
            bundle_id: app.bundle_id.clone(),
            name: app.name.clone(),
            version: app.version.clone(),
            platforms: vec!["iphone".into()],
            purchase_date: None,
        };
        let credentials = InMemoryCredentialRepository::new().with_account(test_account());

        let search = FakeAppStoreRepository::new().with_search_result(Ok(vec![app.clone()]));
        assert!(
            dispatch_command(
                cli(Commands::Search {
                    term: "example".into(),
                    limit: 5,
                    country: "us".into(),
                }),
                search,
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );

        let purchase = FakeAppStoreRepository::new()
            .with_lookup_result(Ok(Some(app.clone())))
            .with_purchase_result(Ok(()));
        assert!(
            dispatch_command(
                cli(Commands::Purchase {
                    bundle_identifier: app.bundle_id.clone(),
                    country: "us".into(),
                }),
                purchase,
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );

        let versions_repo = FakeAppStoreRepository::new().with_list_versions_result(Ok(versions));
        assert!(
            dispatch_command(
                cli(Commands::ListVersions {
                    app: app.id.to_string(),
                    country: "us".into(),
                }),
                versions_repo,
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );

        let purchases = FakeAppStoreRepository::new().with_list_purchases_result(Ok(vec![owned]));
        assert!(
            dispatch_command(
                cli(Commands::Purchases { limit: 10 }),
                purchases,
                credentials,
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn dispatch_routes_auth_info_revoke_and_login() {
        let account = test_account();
        let credentials = InMemoryCredentialRepository::new().with_account(account.clone());
        let info = cli(Commands::Auth {
            action: AuthCommands::Info,
        });
        assert!(
            dispatch_command(
                info,
                FakeAppStoreRepository::new(),
                credentials.clone(),
                &OutputFormat::Json,
            )
            .await
            .is_ok()
        );

        let revoke = cli(Commands::Auth {
            action: AuthCommands::Revoke,
        });
        assert!(
            dispatch_command(
                revoke,
                FakeAppStoreRepository::new(),
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );

        let login_repo = FakeAppStoreRepository::new().with_authenticate_result(Ok(account));
        let login = cli(Commands::Auth {
            action: AuthCommands::Login {
                email: Some("user@example.com".into()),
                password: Some("password".into()),
                code: None,
                country: Some("us".into()),
            },
        });
        assert!(
            dispatch_command(
                login,
                login_repo,
                InMemoryCredentialRepository::new(),
                &OutputFormat::Json,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn dispatch_handles_simulator_prepare_and_offline_decrypt_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let prepare = cli(Commands::Simulator {
            action: SimulatorCommands::Prepare {
                path: directory.path().to_path_buf(),
            },
        });
        assert!(
            dispatch_command(
                prepare,
                FakeAppStoreRepository::new(),
                InMemoryCredentialRepository::new(),
                &OutputFormat::Text,
            )
            .await
            .is_ok()
        );

        let offline = cli(Commands::Decrypt {
            action: DecryptCommands::Offline {
                ipa: PathBuf::from("invalid.txt"),
                output: None,
                no_on_device: true,
            },
        });
        assert!(
            dispatch_command(
                offline,
                FakeAppStoreRepository::new(),
                InMemoryCredentialRepository::new(),
                &OutputFormat::Json,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn dispatch_routes_download_device_and_simulator_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let download = cli(Commands::Download {
            app: "7".into(),
            country: "us".into(),
            external_version_id: None,
            output: None,
            no_purchase: true,
            simulator_install: false,
            simulator_run: false,
        });
        assert!(
            dispatch_command(
                download,
                FakeAppStoreRepository::new(),
                InMemoryCredentialRepository::new(),
                &OutputFormat::Text,
            )
            .await
            .is_err()
        );

        let device = cli(Commands::Device {
            action: DeviceCommands::InstallIpa {
                ipa: directory.path().join("missing.ipa"),
                device: "USB-UDID".into(),
                identity: "test-identity".into(),
                provisioning_profile: vec![PathBuf::from("profile.mobileprovision")],
                entitlements: None,
                run: false,
                legacy_device: true,
            },
        });
        assert!(
            dispatch_command(
                device,
                FakeAppStoreRepository::new(),
                InMemoryCredentialRepository::new(),
                &OutputFormat::Text,
            )
            .await
            .is_err()
        );

        assert!(
            dispatch_simulator(SimulatorCommands::Run {
                bundle_id: "com.example.app".into(),
                inject_dylib: Vec::new(),
                udid: Some(" ".into()),
                device: None,
                entitlements: None,
                console: false,
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn dispatch_routes_file_based_decrypt_commands() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing_ipa = directory.path().join("missing.ipa");
        let credentials = InMemoryCredentialRepository::new();
        for action in [
            DecryptCommands::Inspect {
                ipa: missing_ipa.clone(),
            },
            DecryptCommands::Verify {
                ipa: missing_ipa.clone(),
            },
            DecryptCommands::Patch {
                ipa: missing_ipa.clone(),
                from: directory.path().to_path_buf(),
                output: None,
            },
            DecryptCommands::Entitlements {
                path: directory.path().join("missing.app"),
            },
        ] {
            assert!(
                dispatch_decrypt(action, &OutputFormat::Json, credentials.clone())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn malformed_dispatch_helpers_return_expected_command_errors() {
        let repository = FakeAppStoreRepository::new();
        let credentials = InMemoryCredentialRepository::new();
        assert!(
            dispatch_search_command(Commands::Mcp, repository.clone(), &OutputFormat::Text)
                .await
                .is_err()
        );
        assert!(
            dispatch_purchase_command(
                Commands::Mcp,
                repository.clone(),
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_err()
        );
        assert!(
            dispatch_download_command(
                Commands::Mcp,
                repository,
                credentials.clone(),
                &OutputFormat::Text,
            )
            .await
            .is_err()
        );
        assert!(
            dispatch_resign(DecryptCommands::Inspect {
                ipa: PathBuf::new(),
            })
            .is_err()
        );
        assert!(
            dispatch_set_min_os(DecryptCommands::Inspect {
                ipa: PathBuf::new(),
            })
            .is_err()
        );
        assert!(
            dispatch_dump(DecryptCommands::Inspect {
                ipa: PathBuf::new(),
            })
            .is_err()
        );
        assert!(
            dispatch_dump_mac(DecryptCommands::Inspect {
                ipa: PathBuf::new(),
            })
            .is_err()
        );
        assert!(
            dispatch_provision(
                DecryptCommands::Inspect {
                    ipa: PathBuf::new(),
                },
                credentials,
            )
            .await
            .is_err()
        );
    }
}
