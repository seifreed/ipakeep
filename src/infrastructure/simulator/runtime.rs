use std::fs;
use std::path::{Path, PathBuf};

use super::{command_output, command_with_args, run_checked};

/// Create a read-write tmpfs overlay for a Simulator runtime path.
///
/// # Errors
///
/// Returns an error if the platform is not macOS, the process is not root, or
/// the mount/copy commands fail.
pub fn unlock_runtime_path(path: Option<&Path>) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let detected;
        let path = if let Some(path) = path {
            path
        } else {
            detected = booted_simulator_runtime_root()?;
            detected.as_path()
        };
        if !path.to_string_lossy().contains(".simruntime") {
            return Err("path must be inside an iOS .simruntime".into());
        }
        if is_tmpfs_mount(path)? {
            return Ok(());
        }
        if !is_root() {
            return Err("unlock-runtime requires root; run with sudo".into());
        }

        let backup = tempfile_like_backup_path();
        fs::create_dir(&backup).map_err(|e| format!("{}: {e}", backup.display()))?;
        let path_str = path.to_string_lossy().to_string();
        let backup_str = backup.to_string_lossy().to_string();
        run_checked(command_with_args(
            "cp",
            &["-R", &format!("{path_str}/."), &backup_str],
        ))?;
        run_checked(command_with_args("mount_tmpfs", &[&path_str]))?;
        run_checked(command_with_args(
            "cp",
            &["-R", &format!("{backup_str}/."), &path_str],
        ))?;
        fs::remove_dir_all(&backup).map_err(|e| format!("{}: {e}", backup.display()))?;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err("unlock-runtime is only available on macOS".into())
    }
}

#[cfg(target_os = "macos")]
fn booted_simulator_runtime_root() -> Result<PathBuf, String> {
    let pid = command_output(command_with_args("pgrep", &["-n", "launchd_sim"]))?;
    if let Ok(path) = runtime_root_from_pid_path(pid.trim()) {
        return Ok(path);
    }
    runtime_root_from_lsof(pid.trim())
}

#[cfg(target_os = "macos")]
fn runtime_root_from_pid_path(pid: &str) -> Result<PathBuf, String> {
    let output = command_output(command_with_args("ps", &["-p", pid, "-o", "command="]))?;
    let path = PathBuf::from(output.trim());
    path.parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .filter(|path| path.to_string_lossy().contains(".simruntime"))
        .ok_or_else(|| "proc path did not point inside a Simulator runtime".into())
}

#[cfg(target_os = "macos")]
fn runtime_root_from_lsof(pid: &str) -> Result<PathBuf, String> {
    let output = command_output(command_with_args("lsof", &["-p", pid]))?;
    output
        .lines()
        .filter_map(|line| line.find('/').map(|index| &line[index..]))
        .find_map(|path| {
            let marker = ".simruntime/Contents/Resources/RuntimeRoot";
            path.find(marker)
                .map(|index| PathBuf::from(&path[..index + marker.len()]))
        })
        .ok_or_else(|| "could not detect booted Simulator runtime root".into())
}

#[cfg(target_os = "macos")]
fn is_root() -> bool {
    command_output(command_with_args("id", &["-u"])).is_ok_and(|uid| uid.trim() == "0")
}

#[cfg(target_os = "macos")]
fn is_tmpfs_mount(path: &Path) -> Result<bool, String> {
    let path_str = path.to_string_lossy().to_string();
    command_output(command_with_args("/usr/bin/stat", &["-f", "%T", &path_str]))
        .map(|fs_type| fs_type.trim() == "tmpfs")
}

#[cfg(target_os = "macos")]
fn tempfile_like_backup_path() -> PathBuf {
    let unique = format!(
        "ipakeep-simruntime-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    );
    std::env::temp_dir().join(unique)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn tmpfs_detection_uses_macos_stat() {
        let dir = tempfile::TempDir::new().unwrap();

        assert!(!is_tmpfs_mount(dir.path()).unwrap());
    }
}
