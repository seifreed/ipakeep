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
