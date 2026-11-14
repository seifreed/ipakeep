//! CLI integration tests.

use assert_cmd::Command;
use predicates::str::contains;
use std::path::Path;
use tempfile::TempDir;

fn write_empty_ipa(path: &Path) {
    zip::ZipWriter::new(std::fs::File::create(path).unwrap())
        .finish()
        .unwrap();
}

fn offline_command(home: &Path, ipa: &Path) -> Command {
    let mut command = Command::cargo_bin("ipakeep").unwrap();
    command
        .env("HOME", home)
        .env_remove("IPAKEEP_FAIRPLAY_CREDENTIAL")
        .env_remove("IPAKEEP_FAIRPLAY_ARCADE_CREDENTIAL")
        .args(["--file-keychain", "decrypt", "offline", "--no-on-device"])
        .arg(ipa);
    command
}

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
fn mcp_server_exits_cleanly_when_stdin_closes() {
    use std::process::Stdio;

    let dir = TempDir::new().unwrap();
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("ipakeep"));
    command
        .env("HOME", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["--file-keychain", "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("start MCP server");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("MCP process output");

    assert!(
        output.status.success(),
        "MCP server failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn offline_decrypt_uses_explicit_fairplay_credential() {
    let home = TempDir::new().unwrap();
    let ipa = home.path().join("empty.ipa");
    let credential = home.path().join("account.bin");
    write_empty_ipa(&ipa);
    std::fs::write(&credential, [7_u8; 16]).unwrap();

    offline_command(home.path(), &ipa)
        .env("IPAKEEP_FAIRPLAY_CREDENTIAL", credential)
        .assert()
        .failure()
        .stderr(contains("no encrypted binaries"));
}

#[test]
fn offline_decrypt_finds_one_cached_fairplay_credential() {
    let home = TempDir::new().unwrap();
    let credentials = home
        .path()
        .join("Library/Application Support/ipakeep/credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join("account.bin"), [7_u8; 16]).unwrap();
    let ipa = home.path().join("empty.ipa");
    write_empty_ipa(&ipa);

    offline_command(home.path(), &ipa)
        .assert()
        .failure()
        .stderr(contains("no encrypted binaries"));
}

#[test]
fn offline_decrypt_reports_missing_and_ambiguous_cached_credentials() {
    let home = TempDir::new().unwrap();
    let ipa = home.path().join("empty.ipa");
    write_empty_ipa(&ipa);

    offline_command(home.path(), &ipa)
        .assert()
        .failure()
        .stderr(contains("no FairPlay credential found"));

    let credentials = home
        .path()
        .join("Library/Application Support/ipakeep/credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join("first.bin"), [1_u8; 16]).unwrap();
    std::fs::write(credentials.join("second.bin"), [2_u8; 16]).unwrap();

    offline_command(home.path(), &ipa)
        .assert()
        .failure()
        .stderr(contains("multiple credentials found"));
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
            "[ \"$1\" != -c ] || exit 0\n",
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

#[test]
fn legacy_device_install_checks_tools_before_signing() {
    let mut cmd = Command::cargo_bin("ipakeep").unwrap();
    cmd.env("PATH", "").args([
        "device",
        "install-ipa",
        "test.ipa",
        "--device",
        "UDID",
        "--identity",
        "Test",
        "--provisioning-profile",
        "test.mobileprovision",
        "--legacy-device",
    ]);
    cmd.assert()
        .failure()
        .stderr(contains("`ideviceinstaller` not found on PATH"));
}
