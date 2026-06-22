use super::*;
use clap::Parser;

#[test]
fn download_accepts_positional_app_reference() {
    let cli = Cli::try_parse_from(["ipakeep", "download", "ludo-star"])
        .expect("positional app reference should parse");

    assert!(matches!(
        cli.command,
        Commands::Download { app, no_purchase: false, .. } if app == "ludo-star"
    ));
}

#[test]
fn download_requires_an_app_reference() {
    assert!(Cli::try_parse_from(["ipakeep", "download"]).is_err());
}

#[test]
fn app_reference_commands_reject_empty_values() {
    assert!(Cli::try_parse_from(["ipakeep", "download", ""]).is_err());
    assert!(Cli::try_parse_from(["ipakeep", "list-versions", ""]).is_err());
}

#[test]
fn download_no_purchase_flag_disables_auto_purchase() {
    let cli = Cli::try_parse_from(["ipakeep", "download", "123", "--no-purchase"]).expect("flag");

    assert!(matches!(
        cli.command,
        Commands::Download {
            no_purchase: true,
            ..
        }
    ));
}

#[test]
fn download_accepts_simulator_run_flag() {
    let cli = Cli::try_parse_from(["ipakeep", "download", "ludo-star", "--simulator-run"])
        .expect("simulator run flag should parse");

    assert!(matches!(
        cli.command,
        Commands::Download {
            simulator_run: true,
            ..
        }
    ));
}

#[test]
fn list_versions_accepts_positional_app_reference() {
    let cli = Cli::try_parse_from(["ipakeep", "list-versions", "com.example.app"])
        .expect("positional app reference should parse");

    assert!(matches!(
        cli.command,
        Commands::ListVersions { app, .. } if app == "com.example.app"
    ));
}

#[test]
fn country_flags_require_two_letters() {
    assert!(Cli::try_parse_from(["ipakeep", "search", "twitter", "--country", "es"]).is_ok());
    assert!(Cli::try_parse_from(["ipakeep", "search", "twitter", "--country", "esp"]).is_err());
    assert!(Cli::try_parse_from(["ipakeep", "auth", "login", "--country", "1s"]).is_err());
}

#[test]
fn country_flags_are_normalized_to_lowercase() {
    let cli = Cli::try_parse_from(["ipakeep", "search", "twitter", "--country", "ES"])
        .expect("country should parse");

    assert!(matches!(cli.command, Commands::Search { country, .. } if country == "es"));
}

#[test]
fn grandslam_flag_selects_srp_login() {
    let cli = Cli::try_parse_from(["ipakeep", "--grandslam", "auth", "login"])
        .expect("grandslam flag should parse");

    assert!(cli.grandslam);
}

#[test]
fn legacy_and_grandslam_flags_conflict() {
    assert!(Cli::try_parse_from(["ipakeep", "--legacy", "--grandslam", "auth", "login"]).is_err());
}

#[test]
fn simulator_prepare_accepts_path() {
    let cli = Cli::try_parse_from(["ipakeep", "simulator", "prepare", "/tmp/App.app"])
        .expect("simulator prepare should parse");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::Prepare { path }
        } if path == *"/tmp/App.app"
    ));
}

#[test]
fn simulator_run_accepts_injected_dylibs() {
    let cli = Cli::try_parse_from([
        "ipakeep",
        "simulator",
        "run",
        "--bundle-id",
        "com.example.app",
        "--inject-dylib",
        "/tmp/tweak.dylib",
    ])
    .expect("simulator run should parse");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::Run {
                bundle_id,
                inject_dylib,
                ..
            }
        } if bundle_id == "com.example.app"
            && inject_dylib == vec![PathBuf::from("/tmp/tweak.dylib")]
    ));
}

#[test]
fn simulator_run_accepts_target_and_entitlements() {
    let cli = Cli::try_parse_from([
        "ipakeep",
        "simulator",
        "run",
        "--bundle-id",
        "com.example.app",
        "--device",
        "iPhone 16",
        "--entitlements",
        "/tmp/entitlements.plist",
    ])
    .expect("simulator run should parse");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::Run {
                device: Some(device),
                entitlements: Some(entitlements),
                ..
            }
        } if device == "iPhone 16" && entitlements == *"/tmp/entitlements.plist"
    ));
}

#[test]
fn simulator_run_rejects_empty_target_values() {
    assert!(
        Cli::try_parse_from([
            "ipakeep",
            "simulator",
            "run",
            "--bundle-id",
            "com.example",
            "--udid",
            ""
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "ipakeep",
            "simulator",
            "run",
            "--bundle-id",
            "com.example",
            "--device",
            ""
        ])
        .is_err()
    );
    assert!(Cli::try_parse_from(["ipakeep", "simulator", "run", "--bundle-id", ""]).is_err());
}

#[test]
fn simulator_install_ipa_accepts_run_flag() {
    let cli = Cli::try_parse_from([
        "ipakeep",
        "simulator",
        "install-ipa",
        "/tmp/app.ipa",
        "--run",
    ])
    .expect("simulator install-ipa should parse");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::InstallIpa { ipa, run: true, .. }
        } if ipa == *"/tmp/app.ipa"
    ));
}

#[test]
fn simulator_install_ipa_accepts_udid_and_entitlements() {
    let cli = Cli::try_parse_from([
        "ipakeep",
        "simulator",
        "install-ipa",
        "/tmp/app.ipa",
        "--udid",
        "UDID-1",
        "--entitlements",
        "/tmp/entitlements.plist",
    ])
    .expect("simulator install-ipa should parse");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::InstallIpa {
                udid: Some(udid),
                entitlements: Some(entitlements),
                ..
            }
        } if udid == "UDID-1" && entitlements == *"/tmp/entitlements.plist"
    ));
}

#[test]
fn simulator_install_ipa_rejects_empty_target_values() {
    assert!(
        Cli::try_parse_from([
            "ipakeep",
            "simulator",
            "install-ipa",
            "/tmp/app.ipa",
            "--udid",
            ""
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "ipakeep",
            "simulator",
            "install-ipa",
            "/tmp/app.ipa",
            "--device",
            "",
        ])
        .is_err()
    );
}

#[test]
fn simulator_unlock_runtime_accepts_missing_path() {
    let cli = Cli::try_parse_from(["ipakeep", "simulator", "unlock-runtime"])
        .expect("simulator unlock-runtime should parse without path");

    assert!(matches!(
        cli.command,
        Commands::Simulator {
            action: SimulatorCommands::UnlockRuntime { path: None }
        }
    ));
}

#[test]
fn decrypt_inspect_accepts_ipa_path() {
    let cli = Cli::try_parse_from(["ipakeep", "decrypt", "inspect", "/tmp/app.ipa"])
        .expect("decrypt inspect should parse");

    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::Inspect { ipa }
        } if ipa == *"/tmp/app.ipa"
    ));
}

#[test]
fn decrypt_patch_requires_from() {
    assert!(Cli::try_parse_from(["ipakeep", "decrypt", "patch", "/tmp/app.ipa"]).is_err());

    let cli = Cli::try_parse_from([
        "ipakeep",
        "decrypt",
        "patch",
        "/tmp/app.ipa",
        "--from",
        "/tmp/dump",
    ])
    .expect("decrypt patch should parse with --from");

    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::Patch { from, output: None, .. }
        } if from == *"/tmp/dump"
    ));
}

#[test]
fn decrypt_resign_defaults_identity_to_none() {
    let cli = Cli::try_parse_from(["ipakeep", "decrypt", "resign", "/tmp/App.app"])
        .expect("decrypt resign should parse");

    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::Resign {
                identity: None,
                entitlements: None,
                ..
            }
        }
    ));
}

#[test]
fn decrypt_set_min_os_requires_version() {
    assert!(Cli::try_parse_from(["ipakeep", "decrypt", "set-min-os", "/tmp/a.ipa"]).is_err());
    let cli = Cli::try_parse_from([
        "ipakeep",
        "decrypt",
        "set-min-os",
        "/tmp/a.ipa",
        "--version",
        "16.0",
    ])
    .expect("set-min-os should parse with --version");
    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::SetMinOs { version, .. }
        } if version == "16.0"
    ));
}

#[test]
fn decrypt_dump_defaults_to_builtin_usb() {
    let cli = Cli::try_parse_from(["ipakeep", "decrypt", "dump", "com.example.App"])
        .expect("decrypt dump should parse");
    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::Dump { bundle_id, dumper, device, .. }
        } if bundle_id == "com.example.App" && dumper == "builtin" && device == "usb"
    ));
}

#[test]
fn decrypt_dump_mac_requires_ipa() {
    assert!(Cli::try_parse_from(["ipakeep", "decrypt", "dump-mac", "com.example.App"]).is_err());
    let cli = Cli::try_parse_from([
        "ipakeep",
        "decrypt",
        "dump-mac",
        "com.example.App",
        "--ipa",
        "/tmp/a.ipa",
    ])
    .expect("dump-mac should parse with --ipa");
    assert!(matches!(
        cli.command,
        Commands::Decrypt {
            action: DecryptCommands::DumpMac { bundle_id, .. }
        } if bundle_id == "com.example.App"
    ));
}
