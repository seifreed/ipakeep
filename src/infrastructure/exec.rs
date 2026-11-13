//! Minimal helpers for shelling out to external tools (dumpers, openssl, …).
//!
//! Kept separate from `simulator`'s private process helpers so the `decrypt`
//! flow does not depend on the simulator module.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::Instant;

/// Resolve `program` against `PATH` (or as a literal path when it contains `/`).
pub(crate) fn find_in_path(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let path = PathBuf::from(program);
        return path.is_file().then_some(path);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

/// Error out early with a friendly message if `program` is not on `PATH`.
pub(crate) fn require_program(program: &str) -> Result<(), String> {
    if find_in_path(program).is_some() {
        Ok(())
    } else {
        Err(format!(
            "`{program}` not found on PATH — install it or pass its full path"
        ))
    }
}

/// Run `command` inheriting stdio (so the tool's progress is visible) and fail
/// on a non-zero exit.
pub(crate) fn run_inherit(mut command: Command) -> Result<(), String> {
    let status =
        observed_status(&mut command).map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{command:?} exited with {status}"))
    }
}

/// Run `command` capturing output; on failure return its trimmed stderr.
pub(crate) fn run_quiet(mut command: Command) -> Result<(), String> {
    let output =
        observed_output(&mut command).map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

pub(crate) fn observed_output(command: &mut Command) -> std::io::Result<Output> {
    let program = process_name(command);
    let started = Instant::now();
    let result = command.output();
    record_process_result(
        &program,
        started,
        result.as_ref().map(|output| output.status),
    );
    result
}

pub(crate) fn observed_status(command: &mut Command) -> std::io::Result<ExitStatus> {
    let program = process_name(command);
    let started = Instant::now();
    let result = command.status();
    record_process_result(&program, started, result.as_ref().copied());
    result
}

#[cfg(not(target_os = "macos"))]
pub(crate) async fn observed_tokio_output(
    command: &mut tokio::process::Command,
) -> std::io::Result<Output> {
    let program = std::path::Path::new(command.as_std().get_program())
        .file_name()
        .unwrap_or(command.as_std().get_program())
        .to_string_lossy()
        .into_owned();
    let started = Instant::now();
    let result = command.output().await;
    record_process_result(
        &program,
        started,
        result.as_ref().map(|output| output.status),
    );
    result
}

fn process_name(command: &Command) -> String {
    std::path::Path::new(command.get_program())
        .file_name()
        .unwrap_or(command.get_program())
        .to_string_lossy()
        .into_owned()
}

fn record_process_result(
    program: &str,
    started: Instant,
    status: Result<ExitStatus, &std::io::Error>,
) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match status {
        Ok(status) if status.success() => tracing::debug!(
            service = "ipakeep",
            component = "external_process",
            event_name = "process.completed",
            program,
            outcome = "success",
            exit_code = status.code(),
            duration_ms,
            "external process completed"
        ),
        Ok(status) => tracing::warn!(
            service = "ipakeep",
            component = "external_process",
            event_name = "process.completed",
            program,
            outcome = "failure",
            exit_code = status.code(),
            duration_ms,
            "external process returned a failure status"
        ),
        Err(error) => tracing::warn!(
            service = "ipakeep",
            component = "external_process",
            event_name = "process.spawn_failed",
            program,
            error_type = ?error.kind(),
            outcome = "failure",
            duration_ms,
            "external process could not start"
        ),
    }
}

/// Create a fresh, uniquely named working directory under the system temp dir.
///
/// # Errors
///
/// Returns an error if the directory cannot be created.
pub(crate) fn temp_dir(prefix: &str) -> Result<PathBuf, String> {
    let unique = format!(
        "ipakeep-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}

/// The newest `*.ipa` under `dir` (external dumpers write there).
pub(crate) fn newest_ipa(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "ipa") {
            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(t, _)| mtime >= *t) {
                best = Some((mtime, path));
            }
        }
    }
    best.map(|(_, path)| path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::observed_output;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use std::process::Command;

    #[test]
    fn process_event_records_outcome_without_arguments_or_output() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let mut command = Command::new("sh");
        command.args(["-c", "printf process-secret; exit 7"]);

        let output = observed_output(&mut command).expect("process starts");
        let logs = capture.contents();

        assert_eq!(output.status.code(), Some(7));
        assert!(logs.contains("process.completed"));
        assert!(logs.contains("outcome=\"failure\""));
        assert!(logs.contains("duration_ms="));
        assert!(!logs.contains("process-secret"));
        assert!(!logs.contains("exit 7"));
    }
}
