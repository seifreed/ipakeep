//! Cache of the last kbsync blob that served a valid `ent/download` response.
//!
//! Ported from ipatool `pkg/appstore/appstore_kbsync_cache.go`. Upstream keeps
//! the entry in its keychain under `kbsync-v1`; here it is a private JSON file
//! in the ipakeep config directory. A single account/device pair is cached,
//! apart from the account so a token refresh never overwrites it. Persistence
//! is best effort: a failing disk never fails a download.

use crate::domain::error::AppStoreError;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Versioned cache name; bump when the pinned `StoreAgent` profile or the
/// cache format changes.
pub const KBSYNC_CACHE_KEY: &str = "kbsync-v1";
const APP_DIRECTORY: &str = "ipakeep";
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KbsyncCacheEntry {
    dsid: u64,
    guid: String,
    data: String,
}

/// In-memory and on-disk cache of one base64 kbsync blob.
pub struct KbsyncCache {
    path: PathBuf,
    entry: Mutex<Option<KbsyncCacheEntry>>,
}

impl KbsyncCache {
    /// Cache persisted at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            entry: Mutex::new(None),
        }
    }

    /// Cache at `<config dir>/ipakeep/kbsync-v1.json`.
    ///
    /// # Errors
    ///
    /// Returns [`AppStoreError::NetworkError`] when the platform has no user
    /// config directory.
    pub fn in_config_directory() -> Result<Self, AppStoreError> {
        Self::in_directory(dirs::config_dir())
    }

    fn in_directory(config_directory: Option<PathBuf>) -> Result<Self, AppStoreError> {
        let directory = config_directory.ok_or_else(|| {
            AppStoreError::NetworkError("cannot find user config directory".into())
        })?;
        Ok(Self::new(
            directory
                .join(APP_DIRECTORY)
                .join(format!("{KBSYNC_CACHE_KEY}.json")),
        ))
    }

    /// Cached base64 blob for `dsid` and `guid`, if any.
    #[must_use]
    pub fn cached(&self, dsid: u64, guid: &str) -> Option<String> {
        let mut memory = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = memory.as_ref().filter(|entry| entry.matches(dsid, guid)) {
            return (!entry.data.is_empty()).then(|| entry.data.clone());
        }
        let entry = self
            .read_file()
            .filter(|entry| entry.matches(dsid, guid) && entry.has_valid_data())?;
        let data = entry.data.clone();
        *memory = Some(entry);
        Some(data)
    }

    /// Remember `data`, which just served a valid response.
    pub fn store(&self, dsid: u64, guid: &str, data: &str) {
        let entry = KbsyncCacheEntry {
            dsid,
            guid: guid.to_string(),
            data: data.to_string(),
        };
        let mut memory = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(error) = write_private_json(&self.path, &entry) {
            warn_persistence(&error);
        }
        *memory = Some(entry);
    }

    /// Forget `data` after Apple rejected it; a different or newer entry
    /// cached meanwhile is kept.
    pub fn invalidate(&self, dsid: u64, guid: &str, data: &str) {
        let rejected = KbsyncCacheEntry {
            dsid,
            guid: guid.to_string(),
            data: data.to_string(),
        };
        log_invalidated();
        let mut memory = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        if memory.as_ref() == Some(&rejected) {
            *memory = None;
        }
        if self.read_file().as_ref() == Some(&rejected)
            && let Err(error) = std::fs::remove_file(&self.path)
        {
            warn_persistence(&error);
        }
    }

    fn read_file(&self) -> Option<KbsyncCacheEntry> {
        let bytes = std::fs::read(&self.path)
            .inspect_err(warn_unreadable)
            .ok()?;
        serde_json::from_slice(&bytes)
            .inspect_err(warn_corrupt)
            .ok()
    }
}

impl KbsyncCacheEntry {
    fn matches(&self, dsid: u64, guid: &str) -> bool {
        self.dsid == dsid && self.guid == guid
    }

    fn has_valid_data(&self) -> bool {
        base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .is_ok_and(|decoded| !decoded.is_empty())
    }
}

fn write_private_json(path: &Path, entry: &KbsyncCacheEntry) -> std::io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("kbsync cache path has no parent"))?;
    std::fs::create_dir_all(directory)?;
    #[cfg(unix)]
    set_mode(directory, PRIVATE_DIRECTORY_MODE)?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serde_json::to_vec(entry)?)?;
    #[cfg(unix)]
    set_mode(&temporary, PRIVATE_FILE_MODE)?;
    std::fs::rename(&temporary, path)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn log_invalidated() {
    tracing::debug!(
        service = "ipakeep",
        component = "appstore",
        operation = "download",
        event_name = "appstore.kbsync_cache.invalidated",
        outcome = "invalidated",
        "Apple rejected the cached kbsync; generating a fresh one"
    );
}

/// A missing file is the normal cold cache.
fn warn_unreadable(error: &std::io::Error) {
    if error.kind() != std::io::ErrorKind::NotFound {
        tracing::warn!(service = "ipakeep", component = "appstore", operation = "download", event_name = "appstore.kbsync_cache.read_failed", outcome = "failure", error_type = ?error.kind(), "failed to read kbsync cache");
    }
}

fn warn_corrupt(_error: &serde_json::Error) {
    tracing::warn!(
        service = "ipakeep",
        component = "appstore",
        operation = "download",
        event_name = "appstore.kbsync_cache.read_failed",
        outcome = "failure",
        error_type = "invalid_json",
        "ignoring unreadable kbsync cache"
    );
}

fn warn_persistence(error: &std::io::Error) {
    tracing::warn!(service = "ipakeep", component = "appstore", operation = "download", event_name = "appstore.kbsync_cache.persist_failed", outcome = "failure", error_type = ?error.kind(), "failed to persist kbsync cache");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;

    const GUID: &str = "001122334455";
    const BLOB: &str = "a2JzeW5jIGJsb2I=";

    fn cache_in(directory: &tempfile::TempDir) -> KbsyncCache {
        KbsyncCache::new(directory.path().join("ipakeep").join("kbsync-v1.json"))
    }

    #[test]
    fn persists_one_account_device_pair() {
        let directory = tempfile::tempdir().expect("temporary directory");
        cache_in(&directory).store(7, GUID, BLOB);

        let reopened = cache_in(&directory);
        assert_eq!(reopened.cached(7, GUID).as_deref(), Some(BLOB));
        assert_eq!(reopened.cached(8, GUID), None);
        assert_eq!(reopened.cached(7, "AABBCCDDEEFF"), None);
        let stored: serde_json::Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("ipakeep/kbsync-v1.json")).expect("file"),
        )
        .expect("json");
        assert_eq!(
            stored,
            serde_json::json!({"dsid": 7, "guid": GUID, "data": BLOB})
        );
    }

    #[cfg(unix)]
    #[test]
    fn keeps_the_cache_file_private() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("temporary directory");
        cache_in(&directory).store(7, GUID, BLOB);
        let mode = std::fs::metadata(directory.path().join("ipakeep/kbsync-v1.json"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[test]
    fn ignores_corrupt_or_empty_persisted_blobs() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("kbsync-v1.json");
        std::fs::write(&path, br#"{"dsid":7,"guid":"001122334455","data":"!!"}"#).expect("write");
        assert_eq!(KbsyncCache::new(path.clone()).cached(7, GUID), None);
        std::fs::write(&path, br#"{"dsid":7,"guid":"001122334455","data":""}"#).expect("write");
        assert_eq!(KbsyncCache::new(path.clone()).cached(7, GUID), None);
        std::fs::write(&path, b"not json").expect("write");
        assert_eq!(KbsyncCache::new(path).cached(7, GUID), None);
    }

    #[test]
    fn invalidates_only_the_rejected_entry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = cache_in(&directory);
        cache.store(7, GUID, BLOB);
        cache.invalidate(7, GUID, "b3RoZXI=");
        assert_eq!(cache.cached(7, GUID).as_deref(), Some(BLOB));

        cache.invalidate(7, GUID, BLOB);
        assert_eq!(cache.cached(7, GUID), None);
        assert!(!directory.path().join("ipakeep/kbsync-v1.json").exists());
    }

    /// `std::fs::read` of a directory fails on every OS and for every user
    /// (root included): `EISDIR` on Unix, `ERROR_ACCESS_DENIED` on Windows.
    #[cfg(unix)]
    const DIRECTORY_READ_ERROR: &str = "error_type=IsADirectory";
    #[cfg(windows)]
    const DIRECTORY_READ_ERROR: &str = "error_type=PermissionDenied";

    #[test]
    fn logs_unreadable_files_and_rejections_without_the_blob() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("kbsync-v1.json");
        std::fs::write(&path, format!("{{\"data\":\"{BLOB}\"")).expect("write");
        assert_eq!(KbsyncCache::new(path).cached(7, GUID), None);
        let unreadable = directory.path().join("unreadable").join("kbsync-v1.json");
        std::fs::create_dir_all(&unreadable).expect("directory in the cache's place");
        KbsyncCache::new(unreadable).invalidate(7, GUID, BLOB);
        assert_eq!(cache_in(&directory).cached(7, GUID), None);

        let logs = capture.contents();
        assert_eq!(logs.matches("appstore.kbsync_cache.read_failed").count(), 2);
        assert!(logs.contains("error_type=\"invalid_json\""), "{logs}");
        assert!(logs.contains(DIRECTORY_READ_ERROR), "{logs}");
        assert!(logs.contains("appstore.kbsync_cache.invalidated"));
        assert!(!logs.contains(BLOB) && !logs.contains(GUID));
    }

    #[test]
    fn keeps_working_in_memory_when_the_disk_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let blocker = directory.path().join("file");
        std::fs::write(&blocker, b"x").expect("write");
        let cache = KbsyncCache::new(blocker.join("kbsync-v1.json"));
        cache.store(7, GUID, BLOB);
        assert_eq!(cache.cached(7, GUID).as_deref(), Some(BLOB));
    }

    #[test]
    fn lives_in_the_ipakeep_config_directory() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = KbsyncCache::in_directory(Some(directory.path().to_path_buf())).expect("cache");
        assert_eq!(
            cache.path,
            directory.path().join("ipakeep").join("kbsync-v1.json")
        );
        assert!(KbsyncCache::in_config_directory().is_ok());
        assert!(matches!(
            KbsyncCache::in_directory(None),
            Err(AppStoreError::NetworkError(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn keeps_working_when_the_rejected_file_cannot_be_removed() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("temporary directory");
        let cache = cache_in(&directory);
        cache.store(7, GUID, BLOB);
        let parent = directory.path().join("ipakeep");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500))
            .expect("read-only directory");
        let permissions_enforced = std::fs::File::create(parent.join("probe")).is_err();

        cache.invalidate(7, GUID, BLOB);
        let file_kept = parent.join("kbsync-v1.json").exists();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("restore directory");

        // Root (e.g. a Docker build container) bypasses directory permissions.
        assert_eq!(file_kept, permissions_enforced);
        assert_eq!(
            cache.cached(7, GUID).as_deref(),
            permissions_enforced.then_some(BLOB)
        );
    }
}
