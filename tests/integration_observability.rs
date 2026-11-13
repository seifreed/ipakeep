//! Process-level checks for the CLI logging composition root.

use serde_json::Value;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn json_logs_are_structured_on_stderr_and_correlated_to_the_command() {
    let directory = TempDir::new().expect("temporary directory");
    let missing_ipa = directory.path().join("private-path-marker.ipa");
    let output = Command::new(env!("CARGO_BIN_EXE_ipakeep"))
        .args(["--format", "json", "decrypt", "inspect"])
        .arg(&missing_ipa)
        .env("RUST_LOG", "info")
        .env("IPAKEEP_LOG_FORMAT", "json")
        .env("IPAKEEP_ENV", "test")
        .output()
        .expect("run CLI");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let events: Vec<Value> = stderr
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let event_names: Vec<&str> = events
        .iter()
        .filter_map(|event| event["event_name"].as_str())
        .collect();

    assert!(event_names.contains(&"application.started"));
    assert!(event_names.contains(&"command.started"));
    assert!(event_names.contains(&"command.failed"));
    assert!(event_names.contains(&"application.stopped"));
    assert!(
        events
            .iter()
            .filter(|event| matches!(
                event["event_name"].as_str(),
                Some("command.started" | "command.failed")
            ))
            .all(|event| event.to_string().contains("\"environment\":\"test\""))
    );
    assert!(
        !events
            .iter()
            .any(|event| event.to_string().contains("private-path-marker"))
    );
}
