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
        let directory = dirs::config_dir().ok_or_else(|| {
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
        let bytes = std::fs::read(&self.path).ok()?;
        serde_json::from_slice(&bytes).ok()
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

fn warn_persistence(error: &std::io::Error) {
    tracing::warn!(service = "ipakeep", component = "appstore", operation = "download", event_name = "appstore.kbsync_cache.persist_failed", outcome = "failure", error_type = ?error.kind(), "failed to persist kbsync cache");
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn keeps_working_in_memory_when_the_disk_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let blocker = directory.path().join("file");
        std::fs::write(&blocker, b"x").expect("write");
        let cache = KbsyncCache::new(blocker.join("kbsync-v1.json"));
        cache.store(7, GUID, BLOB);
        assert_eq!(cache.cached(7, GUID).as_deref(), Some(BLOB));
    }
}
