//! CLI application definition using Clap derive macros.

use clap::{ArgGroup, Parser, Subcommand};

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

    /// Use `GrandSlam` SRP authentication (supports trusted-device 2FA).
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
        term: String,

        /// Maximum number of results.
        #[arg(short, long, default_value = "5")]
        limit: u32,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us")]
        country: String,
    },

    /// Purchase (acquire a license for) an app.
    Purchase {
        /// Bundle identifier of the app.
        #[arg(short, long)]
        bundle_identifier: String,

        /// ISO 3166-1 alpha-2 country code.
        #[arg(short, long, default_value = "us")]
        country: String,
    },

    /// Download an IPA file from the App Store.
    #[command(group(
        ArgGroup::new("app_ref")
            .required(true)
            .args(["app_id", "bundle_identifier"])
    ))]
    Download {
        /// App Store ID of the app.
        #[arg(short, long)]
        app_id: Option<i64>,

        /// Bundle identifier (overrides `app_id` for lookup).
        #[arg(short, long)]
        bundle_identifier: Option<String>,

        /// Specific version to download (external version ID).
        #[arg(long)]
        external_version_id: Option<String>,

        /// Output file path, or directory for multiple downloads.
        #[arg(short, long)]
        output: Option<String>,

        /// Automatically purchase the app if no license exists.
        #[arg(long)]
        purchase: bool,
    },

    /// List available versions for an app.
    #[command(group(
        ArgGroup::new("app_ref")
            .required(true)
            .args(["app_id", "bundle_identifier"])
    ))]
    ListVersions {
        /// App Store ID of the app.
        #[arg(short, long)]
        app_id: Option<i64>,

        /// Bundle identifier (overrides `app_id`).
        #[arg(short, long)]
        bundle_identifier: Option<String>,
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
    },

    /// Display current account information.
    Info,

    /// Remove stored Apple account credentials.
    Revoke,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_accepts_bundle_identifier_without_app_id() {
        let cli = Cli::try_parse_from([
            "ipakeep",
            "download",
            "--bundle-identifier",
            "com.example.app",
        ])
        .expect("bundle identifier should satisfy app reference");

        assert!(matches!(
            cli.command,
            Commands::Download {
                app_id: None,
                bundle_identifier: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn list_versions_accepts_bundle_identifier_without_app_id() {
        let cli = Cli::try_parse_from([
            "ipakeep",
            "list-versions",
            "--bundle-identifier",
            "com.example.app",
        ])
        .expect("bundle identifier should satisfy app reference");

        assert!(matches!(
            cli.command,
            Commands::ListVersions {
                app_id: None,
                bundle_identifier: Some(_),
            }
        ));
    }
}
