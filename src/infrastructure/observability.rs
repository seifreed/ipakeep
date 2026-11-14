//! Process-level tracing setup for the CLI binary.

use std::any::Any;
use std::io;
use std::path::Path;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

const DEFAULT_ENVIRONMENT: &str = "unspecified";

/// Convert elapsed time to whole milliseconds, saturating if it exceeds `u64`.
pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
pub(crate) mod log_capture;

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

/// Install a panic hook that records crash location without panic payload data.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let (source_file, line) = panic_location(info.location());
        tracing::error!(
            service = "ipakeep",
            component = "runtime",
            event_name = "application.panic",
            source_file,
            line,
            panic_payload_type = panic_payload_type(info.payload()),
            "application panicked"
        );
    }));
}

fn panic_payload_type(payload: &(dyn Any + Send)) -> &'static str {
    if payload.is::<String>() || payload.is::<&str>() {
        "string"
    } else {
        "non_string"
    }
}

fn panic_location(location: Option<&std::panic::Location<'_>>) -> (String, u32) {
    match location {
        Some(location) => (
            Path::new(location.file())
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            location.line(),
        ),
        None => ("unknown".into(), 0),
    }
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
    read_env_result(name, std::env::var(name))
}

fn read_env_result(
    name: &str,
    value: Result<String, std::env::VarError>,
) -> Result<Option<String>, String> {
    match value {
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
    use super::{
        LogFormat, LoggingConfig, environment, install_panic_hook, panic_location,
        panic_payload_type, read_env_result, sanitize_environment,
    };
    use crate::infrastructure::observability::log_capture::LogCapture;
    use std::io::{self, Write};
    use std::os::unix::ffi::OsStringExt;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("destination unavailable"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("destination unavailable"))
        }
    }

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
        assert!(LoggingConfig::from_values(Some("  "), None, false).is_err());
        assert!(LoggingConfig::from_values(None, Some("xml"), false).is_err());
    }

    #[test]
    fn environment_label_is_safe_and_bounded() {
        assert_eq!(sanitize_environment("prod\n\u{1b}[31m!"), "prod31m");
        assert_eq!(sanitize_environment(&"a".repeat(100)).len(), 64);
    }

    #[test]
    fn panic_payload_classification_never_returns_payload_content() {
        let payload = String::from("credential-secret");
        assert_eq!(panic_payload_type(&payload), "string");
        assert_eq!(panic_payload_type(&42_u8), "non_string");
    }

    #[test]
    fn panic_location_handles_missing_source_metadata() {
        assert_eq!(panic_location(None), ("unknown".into(), 0));
    }

    #[test]
    fn environment_reader_rejects_non_utf8_values() {
        let error = read_env_result(
            "IPAKEEP_TEST",
            Err(std::env::VarError::NotUnicode(
                std::ffi::OsString::from_vec(vec![0xff]),
            )),
        )
        .unwrap_err();
        assert_eq!(error, "IPAKEEP_TEST must contain valid UTF-8");
    }

    #[test]
    fn installed_panic_hook_logs_location_and_payload_type_only() {
        let capture = LogCapture::default();
        let subscriber = capture.install();
        let previous = std::panic::take_hook();
        install_panic_hook();
        let string_panic = std::panic::catch_unwind(|| panic!("credential-secret"));
        let non_string_panic = std::panic::catch_unwind(|| std::panic::panic_any(42_u8));
        std::panic::set_hook(previous);
        drop(subscriber);

        let logs = capture.contents();
        assert!(string_panic.is_err());
        assert!(non_string_panic.is_err());
        assert!(logs.contains("application.panic"));
        assert!(logs.contains("panic_payload_type=\"string\""));
        assert!(logs.contains("panic_payload_type=\"non_string\""));
        assert!(!logs.contains("credential-secret"));
    }

    #[test]
    fn environment_is_a_nonempty_sanitized_label() {
        let environment = environment();
        assert!(!environment.is_empty());
        assert!(environment.len() <= 64);
        assert!(
            environment
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character))
        );
    }

    #[test]
    fn destination_write_failure_does_not_interrupt_the_operation() {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| FailingWriter)
            .finish();

        let result = tracing::subscriber::with_default(subscriber, || {
            tracing::info!(event_name = "test.destination.failure", "test event");
            42
        });

        assert_eq!(result, 42);
    }
}
