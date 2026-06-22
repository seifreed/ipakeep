//! CLI application definition using Clap derive macros.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Download IPA files from the Apple App Store.
#[derive(Parser, Debug)]
#[command(
    name = "ipakeep",
    version,
    about = "Download IPA files from the Apple App Store"
)]
pub struct Cli {
    /// Output format (text or json).
    #[arg(long, global = true, default_value = "text")]
    pub format: String,

    /// Enable verbose logging.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Run in non-interactive mode (no prompts).
    #[arg(long, global = true)]
    pub non_interactive: bool,

    /// Force the use of the file-based keychain instead of the macOS Keychain.
    #[arg(long, global = true)]
    pub file_keychain: bool,

    /// Use the legacy Configurator login flow. This is the default because
    /// purchase/download require an App Store purchase token.
    #[arg(long, global = true, conflicts_with = "grandslam")]
    pub legacy: bool,

    /// Use the `GrandSlam` SRP login flow.
    #[arg(long, global = true)]
    pub grandslam: bool,

    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available CLI commands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Authenticate with the Apple App Store.
    Auth {
        /// The auth subcommand.
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Search for apps on the App Store.
    Search {
        /// Search term.
        #[arg(value_parser = parse_non_empty)]
        term: String,

        /// Maximum number of results.
        #[arg(short, long, default_value = "5", value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us", value_parser = parse_country)]
        country: String,
    },

    /// Purchase (acquire a license for) an app.
    Purchase {
        /// Bundle identifier of the app.
        #[arg(short, long, value_parser = parse_non_empty)]
        bundle_identifier: String,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us", value_parser = parse_country)]
        country: String,
    },

    /// Download an IPA file from the App Store.
    ///
    /// The app may be given as a numeric App Store id, a bundle identifier, or
    /// an app name (resolved via search). The free license is acquired
    /// automatically unless `--no-purchase` is set.
    Download {
        /// App Store id, bundle identifier, or app name.
        #[arg(value_parser = parse_non_empty)]
        app: String,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us", value_parser = parse_country)]
        country: String,

        /// Specific version to download (external version ID).
        #[arg(long)]
        external_version_id: Option<String>,

        /// Output file path, or directory for multiple downloads.
        #[arg(short, long)]
        output: Option<String>,

        /// Do not acquire the license automatically (download only).
        #[arg(long)]
        no_purchase: bool,

        /// Try installing the downloaded IPA in the first booted iOS Simulator.
        #[arg(long)]
        simulator_install: bool,

        /// Try installing and launching the downloaded IPA in the first booted iOS Simulator.
        #[arg(long)]
        simulator_run: bool,
    },

    /// List available versions for an app.
    ListVersions {
        /// App Store id, bundle identifier, or app name.
        #[arg(value_parser = parse_non_empty)]
        app: String,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us", value_parser = parse_country)]
        country: String,
    },

    /// Prepare and run extracted apps on iOS Simulator.
    Simulator {
        /// The simulator subcommand.
        #[command(subcommand)]
        action: SimulatorCommands,
    },

    /// Inspect, patch, and re-sign FairPlay-decrypted IPAs.
    Decrypt {
        /// The decrypt subcommand.
        #[command(subcommand)]
        action: DecryptCommands,
    },
}

/// `FairPlay` decrypt subcommands.
#[derive(Subcommand, Debug)]
pub enum DecryptCommands {
    /// Report each Mach-O's arch, encryption info, and dumpability.
    Inspect {
        /// Path to the IPA.
        ipa: PathBuf,
    },

    /// Patch on-device-dumped plaintext slices back into an IPA.
    Patch {
        /// Path to the encrypted IPA.
        ipa: PathBuf,

        /// Directory of dumped slices (named as `inspect` reports).
        #[arg(long)]
        from: PathBuf,

        /// Output IPA path (default: `<ipa-stem>-decrypted.ipa`).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Re-sign an extracted .app bundle, preserving its entitlements.
    Resign {
        /// Path to the extracted .app bundle.
        app: PathBuf,

        /// Signing identity (default: `-`, ad-hoc).
        #[arg(long, value_parser = parse_non_empty)]
        identity: Option<String>,

        /// Entitlements plist to apply instead of the binary's own.
        #[arg(long)]
        entitlements: Option<PathBuf>,
    },

    /// Verify a (decrypted) IPA: every slice has cryptid=0 and looks decrypted.
    Verify {
        /// Path to the IPA.
        ipa: PathBuf,
    },

    /// Report which entitlements will break after re-signing.
    Entitlements {
        /// Path to an extracted .app bundle or a Mach-O binary.
        path: PathBuf,
    },

    /// Lower the minimum iOS version so the IPA installs on older iOS (often crashes).
    SetMinOs {
        /// Path to the IPA.
        ipa: PathBuf,

        /// Target minimum iOS version, e.g. `16.0`.
        #[arg(long, value_parser = parse_non_empty)]
        version: String,

        /// Output IPA path (default: `<ipa-stem>-minos.ipa`).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Drive a dumper (builtin/frida-ios-dump/bagbak/r2flutch) to decrypt an app.
    Dump {
        /// App bundle id to dump on the device.
        #[arg(value_parser = parse_non_empty)]
        bundle_id: String,

        /// Dumper backend.
        #[arg(long, default_value = "builtin", value_parser = parse_non_empty)]
        dumper: String,

        /// Encrypted IPA to patch (required by the builtin dumper).
        #[arg(long)]
        ipa: Option<PathBuf>,

        /// Frida device: `usb` (device) or `local` (Mac).
        #[arg(long, default_value = "usb")]
        device: String,

        /// Path to the builtin Frida runner.
        #[arg(long, default_value = "scripts/frida/ipakeep_dump.py")]
        agent: PathBuf,

        /// Spawn the app instead of attaching (builtin).
        #[arg(long)]
        spawn: bool,

        /// Seconds to wait for lazily-loaded frameworks (builtin).
        #[arg(long, default_value = "5")]
        settle: f64,

        /// Output IPA path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Dump an iOS app running on this Apple Silicon Mac (no jailbreak).
    DumpMac {
        /// Mac bundle id of the iOS-on-Mac app.
        #[arg(value_parser = parse_non_empty)]
        bundle_id: String,

        /// Encrypted IPA to patch.
        #[arg(long)]
        ipa: PathBuf,

        /// Path to the builtin Frida runner.
        #[arg(long, default_value = "scripts/frida/ipakeep_dump.py")]
        agent: PathBuf,

        /// Seconds to wait for lazily-loaded frameworks.
        #[arg(long, default_value = "5")]
        settle: f64,

        /// Output IPA path.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Auth subcommands.
#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Sign in to the Apple App Store.
    Login {
        /// Apple ID email address.
        #[arg(short, long)]
        email: Option<String>,

        /// Apple ID password.
        #[arg(short, long)]
        password: Option<String>,

        /// Two-factor authentication code.
        #[arg(short, long)]
        code: Option<String>,

        /// ISO 3166-1 alpha-2 country for the account's Store Front
        /// (defaults to the system locale).
        #[arg(long, value_parser = parse_country)]
        country: Option<String>,
    },

    /// Display current account information.
    Info,

    /// Remove stored Apple account credentials.
    Revoke,
}

/// iOS Simulator subcommands.
#[derive(Subcommand, Debug)]
pub enum SimulatorCommands {
    /// Patch an extracted .app bundle or dylib for iOS Simulator.
    Prepare {
        /// Path to an extracted .app bundle, framework, binary, or dylib.
        path: PathBuf,
    },

    /// Launch an installed app on the first booted Simulator.
    Run {
        /// Bundle identifier of the installed app.
        #[arg(long, value_parser = parse_non_empty)]
        bundle_id: String,

        /// Dylib to inject. Repeat for multiple dylibs.
        #[arg(long)]
        inject_dylib: Vec<PathBuf>,

        /// Simulator UDID to launch on.
        #[arg(long, conflicts_with = "device", value_parser = parse_non_empty)]
        udid: Option<String>,

        /// Booted simulator name to launch on.
        #[arg(long, value_parser = parse_non_empty)]
        device: Option<String>,

        /// Entitlements plist used when signing injected dylibs.
        #[arg(long)]
        entitlements: Option<PathBuf>,

        /// Attach console output and wait until the app exits.
        #[arg(long)]
        console: bool,
    },

    /// Install an IPA into the first booted Simulator.
    InstallIpa {
        /// Path to the IPA.
        ipa: PathBuf,

        /// Launch the app after installation.
        #[arg(long)]
        run: bool,

        /// Attach console output and wait until the app exits.
        #[arg(long, requires = "run")]
        console: bool,

        /// Simulator UDID to install into.
        #[arg(long, conflicts_with = "device", value_parser = parse_non_empty)]
        udid: Option<String>,

        /// Booted simulator name to install into.
        #[arg(long, value_parser = parse_non_empty)]
        device: Option<String>,

        /// Entitlements plist used when signing bundles and dylibs.
        #[arg(long)]
        entitlements: Option<PathBuf>,
    },

    /// Mount a read-write overlay over a path in a Simulator runtime.
    UnlockRuntime {
        /// Path inside an iOS .simruntime. Defaults to the booted Simulator runtime root.
        path: Option<PathBuf>,
    },
}

fn parse_country(value: &str) -> Result<String, String> {
    if value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Ok(value.to_ascii_lowercase());
    }
    Err("country must be a two-letter ISO 3166-1 alpha-2 code".into())
}

fn parse_non_empty(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests;
