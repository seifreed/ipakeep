//! CLI integration tests.

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

#[test]
fn help_shows_usage() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(contains("Download IPA files"));
}

#[test]
fn invalid_format_fails() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.args(["--format", "yaml", "search", "foo"]);
    cmd.assert()
        .failure()
        .stderr(contains("unknown output format: yaml"));
}

#[test]
fn auth_info_fails_when_not_logged_in() {
    let dir = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["--file-keychain", "auth", "info"]);
    cmd.assert()
        .failure()
        .stderr(contains("Error: not logged in"));
}

#[test]
fn search_requires_term() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("search");
    cmd.assert().failure().stderr(contains("required"));
}

#[test]
fn search_rejects_empty_term() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.args(["search", ""]);
    cmd.assert()
        .failure()
        .stderr(contains("value cannot be empty"));
}

#[test]
fn search_rejects_zero_limit() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.args(["search", "twitter", "--limit", "0"]);
    cmd.assert().failure().stderr(contains("invalid value"));
}

#[test]
fn search_rejects_invalid_country() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.args(["search", "twitter", "--country", "invalid-country"]);
    cmd.assert()
        .failure()
        .stderr(contains("country must be a two-letter"));
}

#[test]
fn download_requires_app_reference() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("download");
    cmd.assert().failure().stderr(contains("required"));
}

#[test]
fn purchase_requires_bundle_id() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("purchase");
    cmd.assert().failure().stderr(contains("required"));
}

#[test]
fn purchase_rejects_empty_bundle_id() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.args(["purchase", "--bundle-identifier", ""]);
    cmd.assert()
        .failure()
        .stderr(contains("value cannot be empty"));
}

#[test]
fn list_versions_requires_app_reference() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("list-versions");
    cmd.assert().failure().stderr(contains("required"));
}

#[cfg(unix)]
#[test]
fn builtin_dump_runner_is_available_outside_the_repository() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let python = dir.path().join("python3");
    std::fs::write(
        &python,
        concat!(
            "#!/bin/sh\n",
            "test -f \"$1\" || exit 91\n",
            "test -f \"$(dirname \"$1\")/ipakeep_dump.js\" || exit 92\n",
            "echo bundled-runner-found >&2\nexit 93\n",
        ),
    )
    .unwrap();
    std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![dir.path().to_path_buf()];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.current_dir(dir.path())
        .env("PATH", std::env::join_paths(paths).unwrap())
        .args(["decrypt", "dump", "com.example.test", "--ipa", "test.ipa"]);
    cmd.assert()
        .failure()
        .stderr(contains("bundled-runner-found"));
}
