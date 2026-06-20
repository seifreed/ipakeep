//! Output formatting — text and JSON output for CLI commands.

use serde::Serialize;
use std::str::FromStr;

/// Output format selector.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    /// Human-readable text output.
    Text,
    /// Machine-readable JSON output.
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            other => Err(format!("unknown output format: {other}")),
        }
    }
}

/// Format a value for display based on the output format.
pub fn format_output<T: Serialize>(value: &T, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(value)
            .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}")),
        OutputFormat::Text => format_text(value),
    }
}

/// Format a list of items for display.
pub fn format_list<T: Serialize>(
    items: &[T],
    format: &OutputFormat,
    formatter: fn(&T) -> String,
) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(items)
            .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}")),
        OutputFormat::Text => items.iter().map(formatter).collect::<Vec<_>>().join("\n"),
    }
}

/// Default text formatter for generic types (falls back to JSON-like representation).
fn format_text<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("(unable to format: {e})"))
}

/// Format an account for text display.
pub fn format_account(account: &crate::domain::entity::Account) -> String {
    format!(
        "Apple ID: {}\nName: {}\nStore Front: {}\nPod: {}",
        account.email, account.name, account.store_front, account.pod
    )
}

/// Format an app for text display.
pub fn format_app(app: &crate::domain::entity::App) -> String {
    let price = if app.price == 0.0 {
        "Free".to_string()
    } else {
        format!("${:.2}", app.price)
    };
    format!(
        "{} ({}) - {} [{}] - {}",
        app.name, app.bundle_id, app.version, app.id, price
    )
}

/// Format an app version for text display.
pub fn format_version(version: &crate::domain::entity::AppVersion) -> String {
    format!(
        "{} ({})",
        version.version_string, version.external_version_id
    )
}
