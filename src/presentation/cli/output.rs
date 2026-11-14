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

/// Format an owned (purchased) app for text display.
pub fn format_owned_app(app: &crate::domain::entity::OwnedApp) -> String {
    let platforms = if app.platforms.is_empty() {
        String::new()
    } else {
        format!(" {{{}}}", app.platforms.join(", "))
    };
    let purchased = app
        .purchase_date
        .as_deref()
        .map(|date| format!(" - purchased {date}"))
        .unwrap_or_default();
    format!(
        "{} ({}) - {} [{}]{}{}",
        app.name, app.bundle_id, app.version, app.id, platforms, purchased
    )
}

/// Format an app version for text display.
pub fn format_version(version: &crate::domain::entity::AppVersion) -> String {
    format!(
        "{} ({})",
        version.version_string, version.external_version_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entity::{Account, App, AppVersion, OwnedApp};

    struct BrokenSerialize;

    impl Serialize for BrokenSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("expected failure"))
        }
    }

    fn account() -> Account {
        Account {
            email: "user@example.com".into(),
            name: "Test User".into(),
            password_token: String::new(),
            directory_services_id: "123".into(),
            store_front: "143441-1".into(),
            pod: "7".into(),
            idms_token: None,
            dsid: None,
            adsid: None,
            grandslam_session_key: None,
            grandslam_continuation: None,
            cookies: Vec::new(),
        }
    }

    fn app(price: f64) -> App {
        App {
            id: 7,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            price,
        }
    }

    fn owned_app(platforms: Vec<String>, purchase_date: Option<&str>) -> OwnedApp {
        OwnedApp {
            id: 7,
            bundle_id: "com.example.app".into(),
            name: "Example".into(),
            version: "1.0".into(),
            platforms,
            purchase_date: purchase_date.map(str::to_owned),
        }
    }

    #[test]
    fn output_format_parses_supported_values_and_rejects_unknown_values() {
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
        assert!("yaml".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn format_output_supports_json_and_text_and_serialization_errors() {
        assert!(format_output(&app(0.0), &OutputFormat::Json).contains("com.example.app"));
        assert!(format_output(&app(2.0), &OutputFormat::Text).contains("Example"));
        assert!(
            format_output(&BrokenSerialize, &OutputFormat::Json).contains("serialization failed")
        );
        assert!(format_output(&BrokenSerialize, &OutputFormat::Text).contains("unable to format"));
    }

    #[test]
    fn format_list_supports_json_text_and_serialization_errors() {
        let values = [1, 2];
        assert_eq!(
            format_list(&values, &OutputFormat::Text, i32::to_string),
            "1\n2"
        );
        assert!(format_list(&values, &OutputFormat::Json, i32::to_string).contains("\n"));
        assert!(
            format_list(&[BrokenSerialize], &OutputFormat::Json, |_| String::new())
                .contains("serialization failed")
        );
    }

    #[test]
    fn formatters_cover_account_apps_owned_apps_and_versions() {
        assert!(format_account(&account()).contains("user@example.com"));
        assert!(format_app(&app(0.0)).contains("Free"));
        assert!(format_app(&app(2.0)).contains("$2.00"));
        assert!(format_owned_app(&owned_app(vec![], None)).contains("Example"));
        assert!(
            format_owned_app(&owned_app(vec!["iphone".into()], Some("2026-01-01")))
                .contains("purchased 2026-01-01")
        );
        assert_eq!(
            format_version(&AppVersion {
                external_version_id: "42".into(),
                version_string: "1.0".into(),
            }),
            "1.0 (42)"
        );
    }
}
