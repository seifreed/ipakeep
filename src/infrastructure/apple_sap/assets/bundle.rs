//! The pinned macOS framework bundle (ipatool `assets.Load`).
//!
//! Loads the seven Apple images from the local cache, or extracts them from
//! the remote restore image, verifying every file against its pinned digest.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use crate::infrastructure::observability::elapsed_ms;

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    apfs::{ApfsError, ApfsExtractor, extract_apfs_files},
    dyld::{DyldError, extract_dyld_image},
    http_range::{BlockingHttp, HttpRangeError, ReadAt},
    kernel::{
        KERNEL_CACHE_ARCHIVE_SIZE, KERNEL_CACHE_COMPRESSED_SIZE, KERNEL_CACHE_NAME, KernelError,
        extract_fair_play_kext,
    },
    remote::{
        APPLE_MEDIA_SERVICES_IMAGE, ARM64_CACHE_PATH, FRAMEWORK_IMAGE_PATHS, PinnedMember,
        RemoteError, RestoreImage,
    },
};

/// Cache folder name, tied to the pinned macOS build and layout version.
pub const CACHE_DIRECTORY_NAME: &str = "apple-assets-macos-27-26A434-arm64-v1";

const KERNEL_MEMBER: PinnedMember = PinnedMember {
    name: KERNEL_CACHE_NAME,
    compressed_size: KERNEL_CACHE_COMPRESSED_SIZE,
    uncompressed_size: KERNEL_CACHE_ARCHIVE_SIZE,
};

struct FileSpec {
    name: &'static str,
    size: usize,
    digest: &'static str,
}

const FILES: [FileSpec; 7] = [
    spec(
        "AppleMediaServices",
        14_813_888,
        "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4",
    ),
    spec(
        "commerce",
        2_735_088,
        "c4b2088dd39aeb353f59cb57597902e8317aec66ae7da0414b03c5f932771343",
    ),
    spec(
        "adid",
        3_047_808,
        "43419a206c28bc93ecb8884256088d18306a0a462350f83adbced8e60a94e390",
    ),
    spec(
        "CoreFP",
        30_764_976,
        "afbc123e688a822d980d5816cc2b52f69fde669d1dca92cf85627e1cbee587f6",
    ),
    spec(
        "CoreFP.icxs",
        7_365_344,
        "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
    ),
    spec(
        "fairplayd",
        17_389_744,
        "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784",
    ),
    spec(
        "FairPlayIOKit",
        2_132_320,
        "47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025",
    ),
];

const fn spec(name: &'static str, size: usize, digest: &'static str) -> FileSpec {
    FileSpec { name, size, digest }
}

/// The verified arm64e images the SAP, ADI and kbsync machines execute.
#[derive(Debug)]
pub struct Bundle {
    /// `AppleMediaServices`, exported from the arm64e shared cache.
    pub apple_media_services: Vec<u8>,
    /// The `commerce` daemon.
    pub commerce: Vec<u8>,
    /// The `adid` daemon.
    pub adid: Vec<u8>,
    /// `CoreFP`.
    pub core_fp: Vec<u8>,
    /// `CoreFP.icxs` (data, not a Mach-O).
    pub core_fp_icxs: Vec<u8>,
    /// The `fairplayd` daemon.
    pub fairplayd: Vec<u8>,
    /// The `FairPlayIOKit` kernel extension.
    pub fairplay_kext: Vec<u8>,
}

/// Failures while locating, extracting or verifying the bundle.
#[derive(Debug, Error)]
pub enum BundleError {
    /// No per-user cache directory exists on this platform.
    #[error("no user cache directory is available for the Apple SAP assets")]
    NoCacheDirectory,
    /// A cached or extracted file is missing or unreadable.
    #[error("{context} {path}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The file involved.
        path: PathBuf,
        /// Underlying failure.
        source: io::Error,
    },
    /// A file does not match its pinned size and SHA-256.
    #[error("Apple SAP asset {0} failed integrity verification")]
    Integrity(&'static str),
    /// The HTTP client could not be created.
    #[error(transparent)]
    Http(#[from] HttpRangeError),
    /// The restore image could not be opened or read.
    #[error(transparent)]
    Remote(#[from] RemoteError),
    /// The APFS file system could not be read.
    #[error(transparent)]
    Apfs(#[from] ApfsError),
    /// `AppleMediaServices` could not be exported from the shared cache.
    #[error(transparent)]
    Dyld(#[from] DyldError),
    /// `FairPlayIOKit` could not be exported from the kernel cache.
    #[error(transparent)]
    Kernel(#[from] KernelError),
}

impl BundleError {
    /// A stable, path-free category for structured log events.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoCacheDirectory => "no_cache_directory",
            Self::Io { .. } => "io",
            Self::Integrity(_) => "integrity",
            Self::Http(_) => "http",
            Self::Remote(_) => "remote_image",
            Self::Apfs(_) => "apfs",
            Self::Dyld(_) => "dyld",
            Self::Kernel(_) => "kernel",
        }
    }
}

static LOADED: Mutex<Option<Arc<Bundle>>> = Mutex::new(None);

/// Returns the bundle, loading it at most once per process.
///
/// This blocks (possibly for minutes on first use, while it streams the
/// restore image), so async callers should run it in `spawn_blocking`.
///
/// # Errors
/// Fails when the cache is unusable and the remote extraction fails.
pub fn load() -> Result<Arc<Bundle>, BundleError> {
    let mut loaded = LOADED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(bundle) = loaded.as_ref() {
        return Ok(Arc::clone(bundle));
    }
    let root = dirs::cache_dir().ok_or(BundleError::NoCacheDirectory)?;
    let bundle = Arc::new(load_or_extract(&root.join("ipakeep").join("sap"))?);
    *loaded = Some(Arc::clone(&bundle));
    Ok(bundle)
}

/// Reads the bundle under `root`, extracting it there first when missing or invalid.
///
/// # Errors
/// Fails when extraction or verification fails.
pub fn load_or_extract(root: &Path) -> Result<Bundle, BundleError> {
    let started = Instant::now();
    let directory = root.join(CACHE_DIRECTORY_NAME);
    match read_bundle(&directory) {
        Ok(bundle) => {
            log_cache_hit(started);
            return Ok(bundle);
        }
        Err(error) => log_cache_miss(&error),
    }
    let result = extract_and_install(root, &directory);
    match &result {
        Ok(_) => tracing::info!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "extract_assets",
            event_name = "apple_sap.assets.extracted",
            outcome = "success",
            duration_ms = elapsed_ms(started),
            "Apple SAP assets extracted and verified"
        ),
        Err(error) => tracing::error!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "extract_assets",
            event_name = "apple_sap.assets.extraction_failed",
            outcome = "failure",
            error_type = error.kind(),
            duration_ms = elapsed_ms(started),
            "Apple SAP asset extraction failed"
        ),
    }
    result
}

fn extract_and_install(root: &Path, directory: &Path) -> Result<Bundle, BundleError> {
    tracing::info!(
        service = "ipakeep",
        component = "apple_sap",
        operation = "extract_assets",
        event_name = "apple_sap.assets.extraction_started",
        cache_layout = CACHE_DIRECTORY_NAME,
        "extracting Apple SAP assets from the macOS restore image; this can take minutes"
    );
    let staging = root.join(format!(".staging-{}", std::process::id()));
    remove_directory(&staging)?;
    extract_remote(&staging)?;
    let bundle = read_bundle(&staging)?;
    remove_directory(directory)?;
    fs::rename(&staging, directory).map_err(|source| io_error("install", directory, source))?;
    Ok(bundle)
}

fn log_cache_hit(started: Instant) {
    tracing::debug!(
        service = "ipakeep",
        component = "apple_sap",
        operation = "load_assets",
        event_name = "apple_sap.assets.cache_hit",
        outcome = "hit",
        cache_layout = CACHE_DIRECTORY_NAME,
        duration_ms = elapsed_ms(started),
        "Apple SAP assets loaded from the verified cache"
    );
}

fn log_cache_miss(error: &BundleError) {
    let missing =
        matches!(error, BundleError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound);
    if missing {
        tracing::info!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "load_assets",
            event_name = "apple_sap.assets.cache_miss",
            outcome = "miss",
            cache_layout = CACHE_DIRECTORY_NAME,
            "Apple SAP assets are not cached yet"
        );
    } else {
        tracing::warn!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "load_assets",
            event_name = "apple_sap.assets.cache_invalid",
            outcome = "miss",
            error_type = error.kind(),
            cache_layout = CACHE_DIRECTORY_NAME,
            "cached Apple SAP assets are unusable; extracting them again"
        );
    }
}

/// Reads and verifies the seven pinned files in `directory`.
///
/// # Errors
/// Fails when a file is missing or does not match its pin.
pub fn read_bundle(directory: &Path) -> Result<Bundle, BundleError> {
    let [ams, commerce, adid, core_fp, icxs, fairplayd, kext] =
        FILES.each_ref().map(|file| read_verified(directory, file));
    Ok(Bundle {
        apple_media_services: ams?,
        commerce: commerce?,
        adid: adid?,
        core_fp: core_fp?,
        core_fp_icxs: icxs?,
        fairplayd: fairplayd?,
        fairplay_kext: kext?,
    })
}

fn read_verified(directory: &Path, file: &FileSpec) -> Result<Vec<u8>, BundleError> {
    let path = directory.join(file.name);
    let data = fs::read(&path).map_err(|source| io_error("read", &path, source))?;
    let digest = hex::encode(Sha256::digest(&data));
    if data.len() != file.size || digest != file.digest {
        tracing::warn!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "verify_assets",
            event_name = "apple_sap.assets.integrity_failed",
            outcome = "failure",
            asset = file.name,
            actual_bytes = data.len(),
            expected_bytes = file.size,
            "Apple SAP asset does not match its pinned size and SHA-256"
        );
        return Err(BundleError::Integrity(file.name));
    }
    Ok(data)
}

fn extract_remote(destination: &Path) -> Result<(), BundleError> {
    let restore = RestoreImage::open_pinned(Arc::new(BlockingHttp::new()?))?;
    let stage = Instant::now();
    extract_apfs_files(
        restore.open_file_system_image()?,
        &FRAMEWORK_IMAGE_PATHS,
        destination,
    )?;
    log_stage("framework_images", stage);
    let stage = Instant::now();
    let system = ApfsExtractor::open(restore.open_system_os_image()?)?;
    let opener = |suffix: &str| -> io::Result<Box<dyn ReadAt + '_>> {
        let file = system
            .open_file(&format!("{ARM64_CACHE_PATH}{suffix}"))
            .map_err(io::Error::other)?;
        Ok(Box::new(file))
    };
    let apple_media_services = extract_dyld_image(opener, APPLE_MEDIA_SERVICES_IMAGE)?;
    write_file(destination, "AppleMediaServices", &apple_media_services)?;
    log_stage("apple_media_services", stage);
    let stage = Instant::now();
    let kext = extract_fair_play_kext(&restore.read_member(&KERNEL_MEMBER)?)?;
    write_file(destination, "FairPlayIOKit", &kext)?;
    log_stage("fairplay_kext", stage);
    Ok(())
}

fn log_stage(stage: &'static str, started: Instant) {
    tracing::info!(
        service = "ipakeep",
        component = "apple_sap",
        operation = "extract_assets",
        event_name = "apple_sap.assets.extraction_stage",
        outcome = "success",
        stage,
        duration_ms = elapsed_ms(started),
        "Apple SAP asset extraction stage completed"
    );
}

fn write_file(directory: &Path, name: &str, data: &[u8]) -> Result<(), BundleError> {
    let path = directory.join(name);
    fs::write(&path, data).map_err(|source| io_error("write", &path, source))
}

fn remove_directory(path: &Path) -> Result<(), BundleError> {
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            Err(io_error("remove", path, error))
        }
        _ => Ok(()),
    }
}

fn io_error(context: &'static str, path: &Path, source: io::Error) -> BundleError {
    BundleError::Io {
        context,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;

    #[test]
    fn rejects_missing_and_tampered_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert!(matches!(
            read_bundle(directory.path()),
            Err(BundleError::Io { .. })
        ));
        for file in &FILES {
            fs::write(directory.path().join(file.name), vec![0; file.size]).expect("write");
        }
        let capture = LogCapture::default();
        let guard = capture.install();
        assert!(matches!(
            read_bundle(directory.path()),
            Err(BundleError::Integrity("AppleMediaServices"))
        ));
        drop(guard);
        let logs = capture.contents();
        assert!(logs.contains("apple_sap.assets.integrity_failed"), "{logs}");
        assert!(logs.contains("asset=\"AppleMediaServices\""));
        assert!(logs.contains("expected_bytes=14813888"));
        let root = directory.path().to_string_lossy().into_owned();
        assert!(!logs.contains(&root));
    }

    #[test]
    fn error_kinds_are_path_free() {
        let io = io_error("read", Path::new("/private/secret"), io::Error::other("x"));
        assert_eq!(io.kind(), "io");
        assert_eq!(BundleError::Integrity("adid").kind(), "integrity");
        assert_eq!(BundleError::NoCacheDirectory.kind(), "no_cache_directory");
    }

    #[test]
    #[ignore = "streams the multi-gigabyte macOS restore image from Apple"]
    fn extracts_pinned_bundle_from_apple() {
        let root = tempfile::tempdir().expect("temporary directory");
        let bundle = load_or_extract(root.path()).expect("extract bundle");
        assert_eq!(bundle.core_fp.len(), FILES[3].size);
        assert!(read_bundle(&root.path().join(CACHE_DIRECTORY_NAME)).is_ok());
    }
}
