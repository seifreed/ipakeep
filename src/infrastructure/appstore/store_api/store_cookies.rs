//! Store session cookies persisted between ipakeep runs.
//!
//! Apple ties the 2FA code it pushes on the code-less sign-in attempt to that
//! attempt's cookie session, and later commerce requests rely on the cookies
//! the sign-in set. Each run is a separate process, so the jar is written to a
//! private JSON file (`store-cookies.json`, next to `anisette-v4.json`) after
//! every response that sets cookies, session cookies included.

use crate::domain::error::AppStoreError;
use cookie_store::{CookieStore, RawCookie};
use reqwest::Url;
use reqwest::header::HeaderValue;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// File name of the persisted jar inside the ipakeep state directory.
pub const STORE_COOKIES_FILE: &str = "store-cookies.json";
const TEMPORARY_SUFFIX: &str = ".tmp";
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// A `reqwest` cookie store backed by a private JSON file.
pub struct PersistentCookies {
    path: PathBuf,
    store: Mutex<CookieStore>,
}

impl PersistentCookies {
    /// Load the jar at `path`; a missing or unreadable file starts empty (the
    /// user then signs in again).
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        let store = read_store(&path).unwrap_or_default();
        Self {
            path,
            store: Mutex::new(store),
        }
    }

    /// Write the jar to its file (owner-only permissions, atomic replace).
    ///
    /// # Errors
    ///
    /// Returns [`AppStoreError::Unexpected`] when the file cannot be written.
    pub fn save(&self) -> Result<(), AppStoreError> {
        let mut encoded = Vec::new();
        {
            let store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
            encode_store(&store, &mut encoded)?;
        }
        write_private(&self.path, &encoded).map_err(|error| save_error(&error.to_string()))
    }
}

/// Serialize every cookie, expired and session ones included, as JSON.
fn encode_store(store: &CookieStore, writer: &mut impl Write) -> Result<(), AppStoreError> {
    cookie_store::serde::json::save_incl_expired_and_nonpersistent(store, writer)
        .map_err(|error| save_error(&error.to_string()))
}

fn save_error(detail: &str) -> AppStoreError {
    AppStoreError::Unexpected(format!("save Store cookies: {detail}"))
}

/// Read the whole file before parsing so every I/O failure (including a
/// directory in the jar's place, which opens fine on Unix) is reported as
/// unreadable rather than as corrupt JSON.
fn read_store(path: &Path) -> Option<CookieStore> {
    let bytes = std::fs::read(path).inspect_err(warn_unreadable).ok()?;
    let store = cookie_store::serde::json::load_all(bytes.as_slice());
    store.inspect_err(|_| warn_corrupt()).ok()
}

/// A missing jar is the normal first run.
fn warn_unreadable(error: &std::io::Error) {
    if error.kind() != std::io::ErrorKind::NotFound {
        tracing::warn!(service = "ipakeep", component = "appstore", operation = "store_cookies", event_name = "appstore.cookies.load_failed", outcome = "failure", error_type = ?error.kind(), "failed to read Store cookies; starting with an empty jar");
    }
}

fn warn_corrupt() {
    tracing::warn!(
        service = "ipakeep",
        component = "appstore",
        operation = "store_cookies",
        event_name = "appstore.cookies.load_failed",
        outcome = "failure",
        error_type = "invalid_json",
        "ignoring unreadable Store cookies; starting with an empty jar"
    );
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(directory) = path.parent() {
        std::fs::create_dir_all(directory)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(TEMPORARY_SUFFIX);
    let temporary = PathBuf::from(temporary);
    let mut file = private_file(&temporary)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}

#[cfg(unix)]
fn private_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    Ok(file)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> std::io::Result<File> {
    File::create(path)
}

impl reqwest::cookie::CookieStore for PersistentCookies {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let cookies: Vec<RawCookie<'static>> = cookie_headers
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| RawCookie::parse(value.to_owned()).ok())
            .collect();
        if cookies.is_empty() {
            return;
        }
        self.store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .store_response_cookies(cookies.into_iter(), url);
        if let Err(error) = self.save() {
            tracing::warn!(service = "ipakeep", component = "appstore", operation = "store_cookies", event_name = "appstore.cookies.save_failed", outcome = "failure", error = %error, "failed to persist Store cookies");
        }
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let store = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        let header = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        drop(store);
        if header.is_empty() {
            return None;
        }
        HeaderValue::from_str(&header).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use reqwest::cookie::CookieStore as _;

    fn apple_url() -> Url {
        Url::parse("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")
            .expect("URL")
    }

    fn set(cookies: &PersistentCookies, header: &str) {
        let value = HeaderValue::from_str(header).expect("header");
        cookies.set_cookies(&mut std::iter::once(&value), &apple_url());
    }

    /// Writer whose every write fails, as a full disk or closed pipe would.
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reports_cookie_serialization_write_failures() {
        let error = encode_store(&CookieStore::default(), &mut FailingWriter).expect_err("write");
        assert!(
            matches!(&error, AppStoreError::Unexpected(m) if m.starts_with("save Store cookies: ") && m.contains("disk full")),
            "{error}"
        );
    }

    #[test]
    fn session_cookies_survive_a_reload() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(STORE_COOKIES_FILE);
        set(
            &PersistentCookies::load(path.clone()),
            "mz_at0-42=token; Domain=apple.com; Path=/",
        );

        let reloaded = PersistentCookies::load(path);

        assert_eq!(
            reloaded.cookies(&apple_url()).expect("cookie header"),
            "mz_at0-42=token"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cookie_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(STORE_COOKIES_FILE);
        set(&PersistentCookies::load(path.clone()), "itspod=48; Path=/");

        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[test]
    fn corrupt_or_missing_files_start_empty() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(STORE_COOKIES_FILE);
        assert!(
            PersistentCookies::load(path.clone())
                .cookies(&apple_url())
                .is_none()
        );

        std::fs::write(&path, b"not json").expect("corrupt file");
        assert!(
            PersistentCookies::load(path)
                .cookies(&apple_url())
                .is_none()
        );
    }

    /// `std::fs::read` of a directory fails on every OS and for every user
    /// (root included): `EISDIR` on Unix, `ERROR_ACCESS_DENIED` on Windows.
    #[cfg(unix)]
    const DIRECTORY_READ_ERROR: &str = "error_type=IsADirectory";
    #[cfg(windows)]
    const DIRECTORY_READ_ERROR: &str = "error_type=PermissionDenied";

    #[test]
    fn unreadable_jars_are_logged_without_their_contents() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join(STORE_COOKIES_FILE);
        drop(PersistentCookies::load(missing.clone()));
        assert_eq!(capture.contents(), "");

        std::fs::write(&missing, b"{\"mz_at0-42\":\"cookie-secret\"").expect("corrupt file");
        drop(PersistentCookies::load(missing));
        let unreadable = directory.path().join("unreadable").join(STORE_COOKIES_FILE);
        std::fs::create_dir_all(&unreadable).expect("directory in the jar's place");
        drop(PersistentCookies::load(unreadable));

        let logs = capture.contents();
        assert_eq!(logs.matches("appstore.cookies.load_failed").count(), 2);
        assert!(logs.contains("error_type=\"invalid_json\""), "{logs}");
        assert!(logs.contains(DIRECTORY_READ_ERROR), "{logs}");
        assert!(!logs.contains("cookie-secret") && !logs.contains("mz_at0"));
    }

    #[test]
    fn responses_without_cookies_leave_the_jar_untouched() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join(STORE_COOKIES_FILE);
        let cookies = PersistentCookies::load(path.clone());

        cookies.set_cookies(&mut std::iter::empty(), &apple_url());

        assert!(cookies.cookies(&apple_url()).is_none());
        assert!(!path.exists());
    }

    #[test]
    fn unwritable_jar_keeps_cookies_in_memory_and_reports_save_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let blocker = directory.path().join("file");
        std::fs::write(&blocker, b"x").expect("blocker file");
        let cookies = PersistentCookies::load(blocker.join(STORE_COOKIES_FILE));

        set(&cookies, "itspod=48; Path=/");

        assert_eq!(
            cookies.cookies(&apple_url()).expect("cookie header"),
            "itspod=48"
        );
        let error = cookies.save().expect_err("parent is a file");
        assert!(matches!(
            error,
            AppStoreError::Unexpected(message) if message.starts_with("save Store cookies: ")
        ));
    }
}
