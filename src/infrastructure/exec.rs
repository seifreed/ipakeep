//! Minimal helpers for shelling out to external tools (dumpers, openssl, …).
//!
//! Kept separate from `simulator`'s private process helpers so the `decrypt`
//! flow does not depend on the simulator module.

use std::path::{Path, PathBuf};
use std::process::Command;

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
    let status = command
        .status()
        .map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{command:?} exited with {status}"))
    }
}

/// Run `command` capturing output; on failure return its trimmed stderr.
pub(crate) fn run_quiet(mut command: Command) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|e| format!("failed to run {command:?}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
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
