//! Process-level tracing setup for the CLI binary.

use std::io;
use tracing_subscriber::EnvFilter;

const DEFAULT_ENVIRONMENT: &str = "unspecified";

#[derive(Debug, PartialEq, Eq)]
enum LogFormat {
    Text,
    Json,
}

#[derive(Debug)]
struct LoggingConfig {
    filter: EnvFilter,
    format: LogFormat,
}

impl LoggingConfig {
    fn from_env(verbose: bool) -> Result<Self, String> {
        let filter = read_env("RUST_LOG")?;
        let format = read_env("IPAKEEP_LOG_FORMAT")?;
        Self::from_values(filter.as_deref(), format.as_deref(), verbose)
    }

    fn from_values(
        filter: Option<&str>,
        format: Option<&str>,
        verbose: bool,
    ) -> Result<Self, String> {
        let filter = match filter {
            Some(value) if !value.trim().is_empty() => {
                EnvFilter::try_new(value).map_err(|_| "invalid RUST_LOG filter".to_string())?
            }
            Some(_) => return Err("RUST_LOG must not be empty".into()),
            None => EnvFilter::new(if verbose { "debug" } else { "info" }),
        };
        let format = match format
            .unwrap_or("text")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "text" => LogFormat::Text,
            "json" => LogFormat::Json,
            _ => return Err("IPAKEEP_LOG_FORMAT must be 'text' or 'json'".into()),
        };
        Ok(Self { filter, format })
    }
}

/// Initialize stderr logging using `RUST_LOG` and `IPAKEEP_LOG_FORMAT`.
///
/// `RUST_LOG` takes precedence over `--verbose`; the default is `info` or
/// `debug` when verbose mode is enabled. `IPAKEEP_LOG_FORMAT` accepts `text`
/// or `json` and defaults to `text`.
///
/// # Errors
///
/// Returns an error when logging configuration is invalid or another global
/// subscriber is already installed.
pub fn init_logging(verbose: bool) -> Result<(), String> {
    let config = LoggingConfig::from_env(verbose)?;
    let result = match config.format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(config.filter)
            .with_writer(io::stderr)
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_env_filter(config.filter)
            .with_writer(io::stderr)
            .try_init(),
    };
    result.map_err(|_| "could not install the global logging subscriber".into())
}

/// Return a sanitized deployment environment label for structured spans.
#[must_use]
pub fn environment() -> String {
    read_env("IPAKEEP_ENV")
        .ok()
        .flatten()
        .map(|value| sanitize_environment(&value))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ENVIRONMENT.into())
}

fn read_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must contain valid UTF-8")),
    }
}

fn sanitize_environment(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "_.-".contains(*character))
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, LoggingConfig, sanitize_environment};

    #[test]
    fn defaults_to_info_text_and_honors_verbose() {
        let quiet = LoggingConfig::from_values(None, None, false).expect("default config");
        let verbose = LoggingConfig::from_values(None, None, true).expect("verbose config");

        assert_eq!(quiet.filter.to_string(), "info");
        assert_eq!(verbose.filter.to_string(), "debug");
        assert_eq!(quiet.format, LogFormat::Text);
    }

    #[test]
    fn explicit_filter_and_json_format_override_defaults() {
        let config = LoggingConfig::from_values(Some("ipakeep=trace"), Some("JSON"), false)
            .expect("configured logging");

        assert_eq!(config.filter.to_string(), "ipakeep=trace");
        assert_eq!(config.format, LogFormat::Json);
    }

    #[test]
    fn rejects_invalid_configuration_without_echoing_user_input() {
        assert_eq!(
            LoggingConfig::from_values(Some("ipakeep=notalevel"), None, false)
                .expect_err("invalid filter")
                .as_str(),
            "invalid RUST_LOG filter"
        );
        assert!(LoggingConfig::from_values(None, Some("xml"), false).is_err());
    }

    #[test]
    fn environment_label_is_safe_and_bounded() {
        assert_eq!(sanitize_environment("prod\n\u{1b}[31m!"), "prod31m");
        assert_eq!(sanitize_environment(&"a".repeat(100)).len(), 64);
    }
}
