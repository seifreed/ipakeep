//! Local modern ADI Anisette provider for macOS.

use crate::domain::entity::Account;
use crate::domain::error::{AppStoreError, TwoFactorMethod};
use crate::infrastructure::exec::observed_output;
use crate::infrastructure::grandslam::anisette::AnisetteData;
use crate::infrastructure::grandslam::anisette::from_headers;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_HELPER_OUTPUT: usize = 64 * 1024;
const MAX_STORE_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_HEADER_VALUE: usize = 8192;
const HELPER_BINARY: &[u8] = include_bytes!(env!("IPAKEEP_MODERN_ANISETTE_HELPER"));
const DEVICE_MODEL: &str = "MacBookPro13,3";
const DEVICE_OS: &str = "Mac OS X 10.12.6";
const SYSTEM_VERSION: &str = "16G29";

#[derive(Deserialize)]
struct HelperResponse {
    headers: HashMap<String, String>,
}

static PROCESS_ANISETTE: OnceLock<AnisetteData> = OnceLock::new();

/// Generate Anisette using Apple's current Store ADI implementation.
///
/// The helper re-provisions the machine on every run, so each call would yield
/// a new `X-Apple-I-MD-M`. Apple binds the IDMS token issued during SRP to that
/// provisioning, and 2FA requests carrying a different one fail with HTTP 401,
/// so the first result is reused for the rest of the process.
// ponytail: OTP reused for the whole process; add a TTL refresh if long-running commands start failing.
pub(super) async fn generate() -> Result<AnisetteData, AppStoreError> {
    cached(&PROCESS_ANISETTE, generate_fresh).await
}

async fn cached<F, Fut>(
    cell: &OnceLock<AnisetteData>,
    fresh: F,
) -> Result<AnisetteData, AppStoreError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<AnisetteData, AppStoreError>>,
{
    if let Some(data) = cell.get() {
        return Ok(data.clone());
    }
    let data = fresh().await?;
    Ok(cell.get_or_init(|| data).clone())
}

async fn generate_fresh() -> Result<AnisetteData, AppStoreError> {
    let span = tracing::Span::current();
    let output = tokio::task::spawn_blocking(move || span.in_scope(run_helper))
        .await
        .map_err(|error| {
            AppStoreError::NetworkError(format!("modern Anisette task failed: {error}"))
        })??;
    let value: HelperResponse = serde_json::from_slice(&output).map_err(|error| {
        AppStoreError::NetworkError(format!(
            "modern Anisette helper returned invalid JSON: {error}"
        ))
    })?;
    validate_headers(&value.headers)?;
    build_anisette_data(value.headers)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreLoginResponse {
    #[serde(default)]
    auth_code_required: bool,
    #[serde(default)]
    account: StoreAccount,
    #[serde(default)]
    cookies: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct StoreAccount {
    email: String,
    name: String,
    password_token: String,
    directory_services_identifier: String,
    store_front: String,
    pod: String,
}

/// Log in to the App Store `MZFinance` endpoint through the bundled ipatool
/// helper, which signs the request with the Store AMD proof and SAP action
/// signature Apple now requires to issue a purchase `passwordToken`.
///
/// Without `code`, Apple pushes a 2FA code to trusted devices and this returns
/// `AuthCodeRequired`; call again with the code to finish.
///
/// # Errors
///
/// Returns `AuthCodeRequired` when Apple wants a 2FA code, otherwise
/// `AuthenticationFailed` if the helper or Apple rejects the login.
pub async fn store_login(
    email: &str,
    password: &str,
    code: Option<&str>,
) -> Result<Account, AppStoreError> {
    let request = serde_json::to_vec(&serde_json::json!({
        "email": email,
        "password": password,
        "code": code.unwrap_or_default(),
    }))
    .map_err(|error| AppStoreError::Unexpected(error.to_string()))?;
    let span = tracing::Span::current();
    let output = tokio::task::spawn_blocking(move || span.in_scope(|| run_login_helper(&request)))
        .await
        .map_err(|error| {
            AppStoreError::NetworkError(format!("App Store login task failed: {error}"))
        })??;
    parse_store_login(&output)
}

fn run_login_helper(request: &[u8]) -> Result<Vec<u8>, AppStoreError> {
    let output = run_helper_command("login", request)?;
    if !output.status.success() {
        return Err(AppStoreError::AuthenticationFailed(helper_error(&output)));
    }
    if output.stdout.len() > MAX_HELPER_OUTPUT {
        return Err(AppStoreError::NetworkError(
            "App Store login helper output exceeds size limit".into(),
        ));
    }
    Ok(output.stdout)
}

/// Run an App Store commerce `operation` (`purchase`, `list-versions` or
/// `download`) through the bundled ipatool helper, which signs it with the
/// Store AMD proof, kbsync and the session cookies saved at login.
///
/// The helper reports Apple-side failures inside the returned JSON object.
///
/// # Errors
///
/// Returns `NetworkError` if the helper cannot run or returns invalid JSON.
pub async fn store_request(
    operation: &'static str,
    request: &Value,
) -> Result<Value, AppStoreError> {
    let request = serde_json::to_vec(request)
        .map_err(|error| AppStoreError::Unexpected(error.to_string()))?;
    let span = tracing::Span::current();
    let output = tokio::task::spawn_blocking(move || {
        span.in_scope(|| run_helper_command(operation, &request))
    })
    .await
    .map_err(|error| {
        AppStoreError::NetworkError(format!("App Store {operation} task failed: {error}"))
    })??;
    if !output.status.success() {
        return Err(AppStoreError::NetworkError(format!(
            "App Store {operation} helper failed: {}",
            helper_error(&output)
        )));
    }
    if output.stdout.len() > MAX_STORE_OUTPUT {
        return Err(AppStoreError::NetworkError(format!(
            "App Store {operation} helper output exceeds size limit"
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        AppStoreError::NetworkError(format!(
            "App Store {operation} helper returned invalid JSON: {error}"
        ))
    })
}

fn run_helper_command(operation: &str, request: &[u8]) -> Result<Output, AppStoreError> {
    let mut child = Command::new(helper_path()?)
        .arg(operation)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            AppStoreError::NetworkError(format!(
                "could not start App Store {operation} helper: {error}"
            ))
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(request).map_err(|error| {
            AppStoreError::NetworkError(format!("send App Store {operation} request: {error}"))
        })?;
    }
    child.wait_with_output().map_err(|error| {
        AppStoreError::NetworkError(format!("App Store {operation} helper failed: {error}"))
    })
}

fn helper_error(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(512)
        .collect()
}

fn parse_store_login(output: &[u8]) -> Result<Account, AppStoreError> {
    let response: StoreLoginResponse = serde_json::from_slice(output).map_err(|error| {
        AppStoreError::NetworkError(format!(
            "App Store login helper returned invalid JSON: {error}"
        ))
    })?;
    if response.auth_code_required {
        return Err(AppStoreError::AuthCodeRequired {
            dsid: String::new(),
            idms_token: String::new(),
            method: TwoFactorMethod::TrustedDevice,
        });
    }
    let account = response.account;
    if account.password_token.is_empty() || account.directory_services_identifier.is_empty() {
        return Err(AppStoreError::AuthenticationFailed(
            "App Store login did not return a purchase token".into(),
        ));
    }
    Ok(Account {
        email: account.email,
        name: account.name,
        password_token: account.password_token,
        dsid: Some(account.directory_services_identifier.clone()),
        directory_services_id: account.directory_services_identifier,
        store_front: account.store_front,
        pod: account.pod,
        idms_token: None,
        adsid: None,
        grandslam_session_key: None,
        grandslam_continuation: None,
        cookies: response.cookies,
    })
}

fn build_anisette_data(headers: HashMap<String, String>) -> Result<AnisetteData, AppStoreError> {
    let mut data = from_headers(headers)?;
    data.cpd["dt"] = Value::String(DEVICE_MODEL.into());
    data.cpd["os"] = Value::String(DEVICE_OS.into());
    data.cpd["sv"] = Value::String(SYSTEM_VERSION.into());
    Ok(data)
}

fn run_helper() -> Result<Vec<u8>, AppStoreError> {
    let helper_path = helper_path()?;
    let mut command = Command::new(helper_path);
    let output = observed_output(&mut command).map_err(|error| {
        AppStoreError::NetworkError(format!("could not start modern Anisette helper: {error}"))
    })?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(AppStoreError::NetworkError(format!(
            "modern Anisette helper failed: {}",
            error.trim().chars().take(512).collect::<String>()
        )));
    }
    if output.stdout.len() > MAX_HELPER_OUTPUT {
        return Err(AppStoreError::NetworkError(
            "modern Anisette helper output exceeds size limit".into(),
        ));
    }
    Ok(output.stdout)
}

fn helper_path() -> Result<PathBuf, AppStoreError> {
    let app_directory = dirs::config_dir()
        .ok_or_else(|| AppStoreError::NetworkError("cannot find user config directory".into()))?
        .join("ipakeep");
    ensure_private_directory(&app_directory)?;
    install_helper(&app_directory.join("bin"), HELPER_BINARY)
}

fn install_helper(directory: &Path, binary: &[u8]) -> Result<PathBuf, AppStoreError> {
    ensure_private_directory(directory)?;

    let digest = hex::encode(Sha256::digest(binary));
    let path = directory.join(format!("modern-anisette-{digest}"));
    if path.exists() {
        verify_helper(&path, binary)?;
        return Ok(path);
    }

    let temporary = write_temporary_helper(directory, binary)?;
    std::fs::rename(&temporary.0, &path).map_err(|error| {
        AppStoreError::NetworkError(format!("install modern Anisette helper: {error}"))
    })?;
    verify_helper(&path, binary)?;
    Ok(path)
}

fn ensure_private_directory(directory: &Path) -> Result<(), AppStoreError> {
    std::fs::create_dir_all(directory).map_err(|error| {
        AppStoreError::NetworkError(format!("create modern Anisette helper directory: {error}"))
    })?;
    if !std::fs::symlink_metadata(directory)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err(AppStoreError::NetworkError(
            "modern Anisette helper path is not a real directory".into(),
        ));
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        AppStoreError::NetworkError(format!("secure modern Anisette helper directory: {error}"))
    })
}

struct TemporaryHelper(PathBuf);

impl Drop for TemporaryHelper {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_temporary_helper(
    directory: &Path,
    binary: &[u8],
) -> Result<TemporaryHelper, AppStoreError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AppStoreError::NetworkError(error.to_string()))?
        .as_nanos();
    let path = directory.join(format!(
        ".modern-anisette-{}-{nonce}.tmp",
        std::process::id()
    ));
    let temporary = TemporaryHelper(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary.0)
        .map_err(|error| {
            AppStoreError::NetworkError(format!("create modern Anisette helper: {error}"))
        })?;
    file.write_all(binary).map_err(|error| {
        AppStoreError::NetworkError(format!("write modern Anisette helper: {error}"))
    })?;
    file.sync_all().map_err(|error| {
        AppStoreError::NetworkError(format!("sync modern Anisette helper: {error}"))
    })?;
    drop(file);
    Ok(temporary)
}

fn verify_helper(path: &Path, expected: &[u8]) -> Result<(), AppStoreError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            AppStoreError::NetworkError(format!("open installed Anisette helper: {error}"))
        })?;
    let metadata = file.metadata().map_err(|error| {
        AppStoreError::NetworkError(format!("inspect installed Anisette helper: {error}"))
    })?;
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Err(AppStoreError::NetworkError(
            "installed Anisette helper failed integrity validation".into(),
        ));
    }
    let mut installed = Vec::with_capacity(expected.len());
    file.read_to_end(&mut installed).map_err(|error| {
        AppStoreError::NetworkError(format!("read installed Anisette helper: {error}"))
    })?;
    if Sha256::digest(installed) != Sha256::digest(expected) {
        return Err(AppStoreError::NetworkError(
            "installed Anisette helper failed integrity validation".into(),
        ));
    }
    Ok(())
}

fn validate_headers(headers: &HashMap<String, String>) -> Result<(), AppStoreError> {
    if headers.len() > 32 {
        return Err(AppStoreError::AuthenticationFailed(
            "modern Anisette helper returned too many headers".into(),
        ));
    }
    if headers.values().any(|value| {
        value.is_empty() || value.len() > MAX_HEADER_VALUE || value.contains(['\r', '\n'])
    }) {
        return Err(AppStoreError::AuthenticationFailed(
            "modern Anisette helper returned invalid headers".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpd_matches_the_modern_adi_client_identity() {
        let headers = HashMap::from([
            ("X-Apple-I-Md".into(), "otp".into()),
            ("X-Apple-I-Md-M".into(), "machine".into()),
            (
                "X-Mme-Client-Info".into(),
                "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
            ),
        ]);

        let data = build_anisette_data(headers).expect("Anisette data");

        assert_eq!(data.cpd["dt"], DEVICE_MODEL);
        assert_eq!(data.cpd["os"], DEVICE_OS);
        assert_eq!(data.cpd["sv"], SYSTEM_VERSION);
    }

    #[test]
    fn rejects_empty_header_values() {
        let headers = HashMap::from([("X-Apple-I-MD".into(), String::new())]);

        assert!(validate_headers(&headers).is_err());
    }

    #[test]
    fn installs_helper_as_private_executable() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let binary = b"helper bytes";

        let path = install_helper(directory.path(), binary).expect("install helper");

        assert_eq!(std::fs::read(&path).expect("helper bytes"), binary);
        assert_eq!(
            std::fs::metadata(path)
                .expect("helper metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn embeds_the_compiled_modern_adi_helper() {
        let directory = tempfile::tempdir().expect("temporary directory");

        let path = install_helper(directory.path(), HELPER_BINARY).expect("install helper");

        assert!(
            std::fs::metadata(path)
                .expect("helper metadata")
                .permissions()
                .mode()
                & 0o111
                != 0
        );
    }

    #[test]
    fn refuses_a_symlink_helper_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::create_dir(&target).expect("target directory");
        std::os::unix::fs::symlink(&target, &link).expect("directory symlink");

        assert!(ensure_private_directory(&link).is_err());
    }

    #[test]
    fn rejects_line_breaks_in_header_values() {
        let headers = HashMap::from([("X-Apple-I-MD".into(), "token\nInjected: yes".into())]);

        assert!(validate_headers(&headers).is_err());
    }

    #[test]
    fn store_login_maps_helper_responses() {
        let account = parse_store_login(
            br#"{"account":{"email":"a@b.c","name":"A B","passwordToken":"tok","directoryServicesIdentifier":"42","storeFront":"143454-8,32","pod":"71"},"cookies":["mz_at0-42=x; Domain=apple.com"]}"#,
        )
        .unwrap();
        assert_eq!(account.password_token, "tok");
        assert_eq!(account.directory_services_id, "42");
        assert_eq!(account.store_front, "143454-8,32");
        assert_eq!(account.cookies.len(), 1);

        assert!(matches!(
            parse_store_login(br#"{"authCodeRequired":true,"account":{}}"#),
            Err(AppStoreError::AuthCodeRequired { .. })
        ));
        assert!(matches!(
            parse_store_login(br#"{"account":{"email":"a@b.c"}}"#),
            Err(AppStoreError::AuthenticationFailed(_))
        ));
    }

    #[tokio::test]
    async fn reuses_the_first_provisioning_for_later_requests() {
        let cell = OnceLock::new();
        let provision = |md_m: &'static str| async move {
            build_anisette_data(HashMap::from([
                ("X-Apple-I-MD".into(), "otp".into()),
                ("X-Apple-I-MD-M".into(), md_m.into()),
            ]))
        };

        let first = cached(&cell, || provision("first")).await.unwrap();
        let second = cached(&cell, || provision("second")).await.unwrap();

        assert_eq!(first.headers["X-Apple-I-MD-M"], "first");
        assert_eq!(second.headers["X-Apple-I-MD-M"], "first");
    }

    #[tokio::test]
    #[ignore = "requires Apple network access and local ADI provisioning"]
    async fn provider_generates_headers_and_cpd() {
        let data = generate().await.expect("modern Anisette data");

        assert!(!data.headers["X-Apple-I-MD"].is_empty());
        assert!(!data.headers["X-Apple-I-MD-M"].is_empty());
        assert_eq!(data.cpd["dt"], DEVICE_MODEL);
    }
}
