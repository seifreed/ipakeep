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
fn download_requires_app_id_or_bundle_id() {
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
fn list_versions_requires_app_id_or_bundle_id() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.arg("list-versions");
    cmd.assert().failure().stderr(contains("required"));
}
