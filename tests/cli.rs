//! CLI integration tests.

use aes::Aes128;
use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use assert_cmd::Command;
use cbc::Encryptor;
use predicates::str::contains;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;

fn write_empty_ipa(path: &Path) {
    zip::ZipWriter::new(std::fs::File::create(path).unwrap())
        .finish()
        .unwrap();
}

fn atom(tag: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(payload.len() + 8);
    bytes.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
    bytes.extend_from_slice(&tag);
    bytes.extend_from_slice(payload);
    bytes
}

fn encrypted_sinf(credential: &[u8; 16]) -> Vec<u8> {
    let iviv = [0x5A; 16];
    let mut clear = vec![0; 448];
    clear[..4].copy_from_slice(b"itun");
    clear[20..24].copy_from_slice(b"key ");
    clear[24..40].copy_from_slice(&[0xA5; 16]);
    clear[44..48].copy_from_slice(b"iviv");

    let key = credential.map(|byte| byte ^ b'0');
    let mut iv_input = b"app".to_vec();
    iv_input.extend_from_slice(&iviv);
    let iv = md5::compute(iv_input);
    let mut encrypted = clear;
    let length = encrypted.len();
    Encryptor::<Aes128>::new_from_slices(&key, &iv.0)
        .unwrap()
        .encrypt_padded_mut::<NoPadding>(&mut encrypted, length)
        .unwrap();

    atom(
        *b"sinf",
        &atom(
            *b"schi",
            &[
                atom(*b"name", b"app\0"),
                atom(*b"iviv", &iviv),
                atom(*b"priv", &encrypted),
            ]
            .concat(),
        ),
    )
}

fn encrypted_arm64_macho() -> Vec<u8> {
    let mut bytes = vec![0; 8192];
    bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&24_u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0x2c_u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&24_u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&4096_u32.to_le_bytes());
    bytes[44..48].copy_from_slice(&4096_u32.to_le_bytes());
    bytes[48..52].copy_from_slice(&1_u32.to_le_bytes());
    bytes
}

fn supf_record() -> Vec<u8> {
    [
        &[5][..],
        b"502",
        &[0; 4],
        &1_u32.to_be_bytes(),
        &44_u32.to_be_bytes(),
        &0x0100_000c_u32.to_be_bytes(),
        &0_u32.to_be_bytes(),
        &1_u32.to_be_bytes(),
        &[0; 32],
    ]
    .concat()
}

fn write_encrypted_ipa(path: &Path, credential: &[u8; 16]) {
    let macho = encrypted_arm64_macho();
    let sinf = encrypted_sinf(credential);
    let supf = supf_record();
    let mut archive = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
    let options = SimpleFileOptions::default();
    for (name, data) in [
        ("Payload/Game.app/Info.plist", b"plist" as &[u8]),
        ("Payload/Game.app/Game", macho.as_slice()),
        ("Payload/Game.app/SC_Info/Game.sinf", sinf.as_slice()),
        ("Payload/Game.app/SC_Info/Game.supf", supf.as_slice()),
    ] {
        archive.start_file(name, options).unwrap();
        archive.write_all(data).unwrap();
    }
    archive.finish().unwrap();
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
fn offline_decrypts_a_fairplay_ipa_end_to_end() {
    let home = TempDir::new().unwrap();
    let credential = [0x31; 16];
    let standard = home.path().join("standard.bin");
    let arcade = home.path().join("arcade.bin");
    let ipa = home.path().join("encrypted.ipa");
    let output = home.path().join("decrypted.ipa");
    std::fs::write(&standard, credential).unwrap();
    std::fs::write(&arcade, credential).unwrap();
    write_encrypted_ipa(&ipa, &credential);

    offline_command(home.path(), &ipa)
        .env("IPAKEEP_FAIRPLAY_CREDENTIAL", standard)
        .env("IPAKEEP_FAIRPLAY_ARCADE_CREDENTIAL", arcade)
        .args(["--output"])
        .arg(&output)
        .assert()
        .success()
        .stdout(contains("Wrote decrypted IPA"));
    assert!(output.is_file());
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
