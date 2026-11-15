//! The persisted `anisette-v4.json` machine provisioning.
//!
//! Same file, JSON shape and protection as the former Go helper
//! (`tools/modern-anisette`): `<config dir>/ipakeep/anisette-v4.json`, a
//! `0700` directory, `0600` files, an exclusive `flock` on
//! `anisette-v4.json.lock` and an atomic replace, so existing users keep their
//! provisioning.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::error::{StoreAuthError, StoreAuthResult};

/// Largest accepted state file and provisioning blob (Go `maxStateSize`).
pub const MAX_STATE_SIZE: usize = 1 << 20;
/// Length of the ADI host identifier.
pub const IDENTIFIER_SIZE: usize = 16;
const APP_DIRECTORY: &str = "ipakeep";
const STATE_FILE_NAME: &str = "anisette-v4.json";
const LOCK_SUFFIX: &str = ".lock";
const TEMPORARY_PREFIX: &str = ".anisette-v4-";
const TEMPORARY_SUFFIX: &str = ".tmp";
#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// Upstream `anisetteState`: Go encodes the byte slices as standard base64
/// and a missing provisioning as `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnisetteState {
    /// ADI host UUID (16 bytes).
    #[serde(rename = "Identifier", with = "go_bytes")]
    pub identifier: Vec<u8>,
    /// The daemon's `adi.pb`; empty when not provisioned.
    #[serde(rename = "Provisioning", with = "go_bytes", default)]
    pub provisioning: Vec<u8>,
    /// GSA `X-Apple-I-MD-RINFO`; zero when not provisioned.
    #[serde(rename = "RoutingInfo", default, deserialize_with = "routing_info")]
    pub routing_info: u64,
}

impl AnisetteState {
    /// A not-yet-provisioned state for `identifier`.
    #[must_use]
    pub fn new(identifier: [u8; IDENTIFIER_SIZE]) -> Self {
        Self {
            identifier: identifier.to_vec(),
            provisioning: Vec::new(),
            routing_info: 0,
        }
    }

    /// Parses and validates the JSON written by ipatool / the Go helper.
    ///
    /// # Errors
    /// Fails on malformed JSON, a wrong identifier length or an oversized
    /// provisioning blob.
    pub fn decode(encoded: &[u8]) -> StoreAuthResult<Self> {
        let state: Self =
            serde_json::from_slice(encoded).map_err(|_| StoreAuthError::State("malformed JSON"))?;
        if state.identifier.len() != IDENTIFIER_SIZE {
            return Err(StoreAuthError::State("identifier must be 16 bytes"));
        }
        if state.provisioning.len() > MAX_STATE_SIZE {
            return Err(StoreAuthError::State("provisioning exceeds the size limit"));
        }
        Ok(state)
    }

    /// Serialises the state exactly like Go's `json.Marshal`.
    ///
    /// # Errors
    /// Fails only if serialisation fails.
    pub fn encode(&self) -> StoreAuthResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| StoreAuthError::State("cannot encode state"))
    }

    /// Whether GSA machine provisioning completed for this state.
    #[must_use]
    pub fn is_provisioned(&self) -> bool {
        !self.provisioning.is_empty()
    }
}

/// A JSON number (Go's encoding) or a decimal string (the golden fixture).
fn routing_info<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Routing {
        Number(u64),
        Text(String),
    }
    match Routing::deserialize(deserializer)? {
        Routing::Number(value) => Ok(value),
        Routing::Text(text) => text.parse().map_err(serde::de::Error::custom),
    }
}

mod go_bytes {
    use super::{Deserialize, Deserializer, STANDARD, Serializer};
    use base64::Engine as _;

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.is_empty() {
            serializer.serialize_none()
        } else {
            serializer.serialize_str(&STANDARD.encode(bytes))
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        let decoded = STANDARD.decode(encoded);
        decoded.map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// Location of `anisette-v4.json` and its lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateStore {
    path: PathBuf,
}

/// Holds the exclusive state lock until dropped.
#[derive(Debug)]
pub struct StateLock {
    _file: File,
}

impl StateStore {
    /// A store over the state file at `path`.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `<user config dir>/ipakeep/anisette-v4.json`, as the Go helper used.
    ///
    /// # Errors
    /// Fails when the platform has no user configuration directory.
    pub fn in_config_directory() -> StoreAuthResult<Self> {
        let directory = dirs::config_dir().ok_or(StoreAuthError::Io {
            action: "find user config directory",
            source: std::io::Error::from(ErrorKind::NotFound),
        })?;
        Ok(Self::new(
            directory.join(APP_DIRECTORY).join(STATE_FILE_NAME),
        ))
    }

    /// The state file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates the private directory and takes the exclusive file lock.
    ///
    /// # Errors
    /// Fails when the directory is not a real directory or the lock cannot
    /// be opened (it must not be a symlink) or taken.
    pub fn lock(&self) -> StoreAuthResult<StateLock> {
        ensure_private_directory(self.directory())?;
        let mut lock_path = self.path.clone().into_os_string();
        lock_path.push(LOCK_SUFFIX);
        let file = private_file(
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false),
        )
        .open(PathBuf::from(lock_path))
        .map_err(io("open anisette state lock"))?;
        secure_file(&file).map_err(io("secure anisette state lock"))?;
        file.lock().map_err(io("lock anisette state"))?;
        Ok(StateLock { _file: file })
    }

    /// Reads the state; `None` when the file is missing or empty.
    ///
    /// # Errors
    /// Fails on an I/O error, a symlinked or oversized file or invalid JSON.
    pub fn read(&self, _lock: &StateLock) -> StoreAuthResult<Option<AnisetteState>> {
        let file = private_file(OpenOptions::new().read(true)).open(&self.path);
        let file = match file {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            other => other.map_err(io("open anisette state"))?,
        };
        let mut encoded = Vec::new();
        file.take(MAX_STATE_SIZE as u64 + 1)
            .read_to_end(&mut encoded)
            .map_err(io("read anisette state"))?;
        if encoded.len() > MAX_STATE_SIZE {
            return Err(StoreAuthError::State("state file exceeds the size limit"));
        }
        if encoded.is_empty() {
            return Ok(None);
        }
        AnisetteState::decode(&encoded).map(Some)
    }

    /// Atomically replaces the state file with `state` (mode `0600`).
    ///
    /// # Errors
    /// Fails on an I/O error or an oversized state.
    pub fn write(&self, _lock: &StateLock, state: &AnisetteState) -> StoreAuthResult<()> {
        let encoded = state.encode()?;
        if encoded.len() > MAX_STATE_SIZE {
            return Err(StoreAuthError::State("state exceeds the size limit"));
        }
        let temporary = TemporaryFile::create(self.directory());
        temporary.write(&encoded)?;
        std::fs::rename(&temporary.path, &self.path).map_err(io("replace anisette state"))
    }

    fn directory(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }
}

fn io(action: &'static str) -> impl FnOnce(std::io::Error) -> StoreAuthError {
    move |source| StoreAuthError::Io { action, source }
}

fn ensure_private_directory(path: &Path) -> StoreAuthResult<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(PRIVATE_DIRECTORY_MODE);
    builder
        .create(path)
        .map_err(io("create anisette state directory"))?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(io("inspect anisette state directory"))?;
    if !metadata.file_type().is_dir() {
        return Err(StoreAuthError::State("state path is not a real directory"));
    }
    #[cfg(unix)]
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
    )
    .map_err(io("secure anisette state directory"))?;
    Ok(())
}

/// Applies the owner-only mode and refuses symlinks where the OS supports it.
fn private_file(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    options
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW);
    options
}

fn secure_file(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

/// A private temporary file removed on drop unless renamed away.
struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn create(directory: &Path) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let name = format!(
            "{TEMPORARY_PREFIX}{}-{nonce}{TEMPORARY_SUFFIX}",
            std::process::id()
        );
        Self {
            path: directory.join(name),
        }
    }

    fn write(&self, contents: &[u8]) -> StoreAuthResult<()> {
        let mut file = private_file(OpenOptions::new().write(true).create_new(true))
            .open(&self.path)
            .map_err(io("create anisette state file"))?;
        secure_file(&file).map_err(io("secure anisette state file"))?;
        file.write_all(contents)
            .map_err(io("write anisette state"))?;
        file.sync_all().map_err(io("sync anisette state"))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        // Already renamed into place on success; nothing to clean up then.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn fixture_state() -> serde_json::Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/apple_sap/golden/adi.json");
        let golden: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        golden["anisette_state_json"].clone()
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn decodes_the_golden_state_and_reencodes_like_go() {
        let golden = fixture_state();
        let encoded = serde_json::to_vec(&golden).unwrap();
        let state = AnisetteState::decode(&encoded).unwrap();
        assert_eq!(
            hex::encode(&state.identifier),
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(state.routing_info, 84_215_040);
        let reencoded: serde_json::Value =
            serde_json::from_slice(&state.encode().unwrap()).unwrap();
        assert_eq!(reencoded["Identifier"], golden["Identifier"]);
        assert_eq!(reencoded["Provisioning"], golden["Provisioning"]);
        assert_eq!(reencoded["RoutingInfo"], serde_json::json!(84_215_040));
    }

    #[test]
    fn field_order_and_null_provisioning_match_go_json() {
        let state = AnisetteState::new([1; IDENTIFIER_SIZE]);
        assert_eq!(
            String::from_utf8(state.encode().unwrap()).unwrap(),
            r#"{"Identifier":"AQEBAQEBAQEBAQEBAQEBAQ==","Provisioning":null,"RoutingInfo":0}"#
        );
        let decoded = AnisetteState::decode(&state.encode().unwrap()).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn rejects_invalid_states() {
        assert!(AnisetteState::decode(b"not json").is_err());
        assert!(AnisetteState::decode(br#"{"Identifier":"AAEC"}"#).is_err());
        let oversized = AnisetteState {
            identifier: vec![0; IDENTIFIER_SIZE],
            provisioning: vec![0; MAX_STATE_SIZE + 1],
            routing_info: 1,
        };
        assert!(AnisetteState::decode(&oversized.encode().unwrap()).is_err());
    }

    #[test]
    fn missing_fields_default_like_go() {
        let state = AnisetteState::decode(br#"{"Identifier":"AAECAwQFBgcICQoLDA0ODw=="}"#).unwrap();
        assert!(!state.is_provisioned());
        assert_eq!(state.routing_info, 0);
    }

    #[test]
    fn refuses_to_write_an_oversized_state() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::new(root.path().join(STATE_FILE_NAME));
        let lock = store.lock().unwrap();
        let state = AnisetteState {
            identifier: vec![7; IDENTIFIER_SIZE],
            provisioning: vec![1; MAX_STATE_SIZE],
            routing_info: 1,
        };
        assert!(matches!(
            store.write(&lock, &state),
            Err(StoreAuthError::State("state exceeds the size limit"))
        ));
        assert!(!store.path().exists());
    }

    #[test]
    fn round_trips_through_a_private_file() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::new(root.path().join("ipakeep").join(STATE_FILE_NAME));
        let lock = store.lock().unwrap();
        assert_eq!(store.read(&lock).unwrap(), None);
        let state = AnisetteState {
            identifier: vec![7; IDENTIFIER_SIZE],
            provisioning: vec![1, 2, 3],
            routing_info: 42,
        };
        store.write(&lock, &state).unwrap();
        assert_eq!(store.read(&lock).unwrap(), Some(state));
        #[cfg(unix)]
        {
            assert_eq!(mode(store.path()), PRIVATE_FILE_MODE);
            assert_eq!(mode(store.directory()), PRIVATE_DIRECTORY_MODE);
            let lock_path = root.path().join("ipakeep").join("anisette-v4.json.lock");
            assert_eq!(mode(&lock_path), PRIVATE_FILE_MODE);
        }
        let leftovers = std::fs::read_dir(store.directory())
            .unwrap()
            .filter(|entry| {
                let name = entry.as_ref().unwrap().file_name();
                name.to_string_lossy().ends_with(TEMPORARY_SUFFIX)
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    #[cfg(unix)]
    fn tightens_an_existing_loose_directory() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ipakeep");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let store = StateStore::new(directory.join(STATE_FILE_NAME));
        drop(store.lock().unwrap());
        assert_eq!(mode(&directory), PRIVATE_DIRECTORY_MODE);
    }

    #[test]
    #[cfg(unix)]
    fn refuses_symlinked_state_lock_and_directory() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ipakeep");
        std::fs::create_dir(&directory).unwrap();
        let target = root.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        symlink(&target, directory.join("anisette-v4.json.lock")).unwrap();
        symlink(&target, directory.join(STATE_FILE_NAME)).unwrap();
        let store = StateStore::new(directory.join(STATE_FILE_NAME));
        assert!(store.lock().is_err());
        std::fs::remove_file(directory.join("anisette-v4.json.lock")).unwrap();
        let lock = store.lock().unwrap();
        assert!(store.read(&lock).is_err());

        let linked = root.path().join("linked");
        symlink(&directory, &linked).unwrap();
        let through_link = StateStore::new(linked.join(STATE_FILE_NAME));
        assert!(through_link.lock().is_err());
    }

    #[test]
    fn rejects_an_oversized_state_file() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::new(root.path().join(STATE_FILE_NAME));
        let lock = store.lock().unwrap();
        std::fs::write(store.path(), vec![b' '; MAX_STATE_SIZE + 1]).unwrap();
        assert!(store.read(&lock).is_err());
    }

    #[test]
    fn empty_state_file_reads_as_missing() {
        let root = tempfile::tempdir().unwrap();
        let store = StateStore::new(root.path().join(STATE_FILE_NAME));
        let lock = store.lock().unwrap();
        std::fs::write(store.path(), b"").unwrap();
        assert_eq!(store.read(&lock).unwrap(), None);
    }
}
