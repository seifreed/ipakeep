//! Pinned macOS restore image (IPSW) opened as a remote ZIP archive.
//!
//! Ported from ipatool `internal/sap/assets/remote.go` (archive and member
//! access only; APFS, dyld and kernel extraction live in sibling modules).
//! The archive is never downloaded: its central directory and members are
//! read lazily through [`ReadAt`], so a stored member is itself a
//! random-access [`SectionReader`] over the remote file.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, MutexGuard};

use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

use super::aea::{AeaError, AeaReader};
use super::http_range::{BlockingHttp, HttpRangeError, ReadAt, RemoteFile, SectionReader};

/// Pinned macOS version.
pub const MACOS_VERSION: &str = "27.0.1";
/// Pinned macOS build.
pub const MACOS_BUILD: &str = "26A434";
/// URL of the pinned universal macOS restore image.
pub const MACOS_RESTORE_URL: &str = "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw";

/// Path of `AppleMediaServices` inside the arm64e shared cache.
pub const APPLE_MEDIA_SERVICES_IMAGE: &str =
    "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices";
/// Path of the arm64e dyld shared cache inside the `SystemOS` cryptex.
pub const ARM64_CACHE_PATH: &str = "/System/Library/dyld/dyld_shared_cache_arm64e";
/// Framework files extracted from the macOS file-system image.
pub const FRAMEWORK_IMAGE_PATHS: [&str; 5] = [
    "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid",
    "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
    "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd",
];

/// Decrypted size of the macOS file-system image.
pub const FILE_SYSTEM_IMAGE_SIZE: u64 = 14_189_330_432;
/// Decrypted size of the `SystemOS` cryptex image.
pub const SYSTEM_OS_IMAGE_SIZE: u64 = 2_879_389_696;

/// The encrypted macOS file-system image member.
pub const FILE_SYSTEM_MEMBER: PinnedMember = PinnedMember {
    name: "043-70867-640.dmg.aea",
    compressed_size: 11_274_289_152,
    uncompressed_size: 11_274_289_152,
};
/// The encrypted `SystemOS` cryptex member.
pub const SYSTEM_OS_MEMBER: PinnedMember = PinnedMember {
    name: "043-70701-651.dmg.aea",
    compressed_size: 2_415_919_104,
    uncompressed_size: 2_415_919_104,
};

/// A random-access window over one stored member of the remote archive.
pub type RemoteSection<R> = SectionReader<Arc<R>>;
/// Decrypted plaintext of an AEA member of the remote archive.
pub type EncryptedImage<R> = AeaReader<RemoteSection<R>>;

/// Errors produced while opening the restore image or its members.
#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    /// The remote file could not be opened.
    #[error("resolve macOS {MACOS_VERSION} ({MACOS_BUILD}) frameworks: {0}")]
    Http(#[from] HttpRangeError),
    /// The ZIP structure could not be read.
    #[error("read macOS {MACOS_VERSION} ({MACOS_BUILD}) restore image: {0}")]
    Zip(#[from] ZipError),
    /// A pinned member is absent.
    #[error("macOS {MACOS_VERSION} ({MACOS_BUILD}) restore image does not contain {0}")]
    MissingMember(&'static str),
    /// A pinned member has a different method or size.
    #[error(
        "macOS {MACOS_VERSION} ({MACOS_BUILD}) restore member {0} does not match the pinned image"
    )]
    MemberMismatch(&'static str),
    /// The data offset of a member could not be located.
    #[error("locate restore member {0}")]
    MissingDataOffset(&'static str),
    /// Reading a member failed.
    #[error("read restore member {name}: {source}")]
    Read {
        /// Member name.
        name: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A member decoded to an unexpected size.
    #[error("restore member {name} has size {actual}, expected {expected}")]
    MemberSize {
        /// Member name.
        name: &'static str,
        /// Decoded size.
        actual: u64,
        /// Pinned size.
        expected: u64,
    },
    /// Opening an encrypted member failed.
    #[error("open encrypted {name}: {source}")]
    Aea {
        /// Member name.
        name: &'static str,
        /// AEA failure.
        #[source]
        source: AeaError,
    },
    /// An encrypted member decrypts to an unexpected size.
    #[error("{name} has size {actual}, expected {expected}")]
    ImageSize {
        /// Member name.
        name: &'static str,
        /// Decrypted size.
        actual: u64,
        /// Pinned size.
        expected: u64,
    },
}

/// A pinned archive member: name plus exact compressed and decoded sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedMember {
    /// Member path inside the archive.
    pub name: &'static str,
    /// Size of the member data in the archive.
    pub compressed_size: u64,
    /// Size of the decoded member.
    pub uncompressed_size: u64,
}

impl PinnedMember {
    /// Stored when both sizes match, otherwise Deflate.
    pub fn expected_method(&self) -> CompressionMethod {
        if self.compressed_size == self.uncompressed_size {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        }
    }
}

/// `Read + Seek` adapter so the `zip` crate can parse a [`ReadAt`] source.
#[derive(Debug)]
struct ReadAtCursor<R> {
    source: Arc<R>,
    position: u64,
}

impl<R: ReadAt> Read for ReadAtCursor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read_at(buf, self.position)?;
        self.position += count as u64;
        Ok(count)
    }
}

impl<R: ReadAt> Seek for ReadAtCursor<R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.source.size().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek position"))?;
        Ok(self.position)
    }
}

/// A ZIP archive read lazily from a random-access source.
pub struct RestoreImage<R> {
    source: Arc<R>,
    archive: Mutex<ZipArchive<ReadAtCursor<R>>>,
}

impl RestoreImage<RemoteFile> {
    /// Opens the pinned macOS restore image over HTTP.
    ///
    /// # Errors
    /// Fails when the server lacks range support or the archive is malformed.
    pub fn open_pinned(http: Arc<BlockingHttp>) -> Result<Self, RemoteError> {
        Self::open_url(http, MACOS_RESTORE_URL)
    }

    /// Opens a restore image at `url` over HTTP.
    ///
    /// # Errors
    /// See [`RestoreImage::open_pinned`].
    pub fn open_url(http: Arc<BlockingHttp>, url: &str) -> Result<Self, RemoteError> {
        Self::new(RemoteFile::open(http, url)?)
    }

    /// Opens a pinned encrypted member, downloading its FCS key.
    ///
    /// # Errors
    /// Fails on member mismatches, AEA failures or an unexpected decrypted size.
    pub fn open_encrypted_image(
        &self,
        member: &PinnedMember,
        decrypted_size: u64,
    ) -> Result<EncryptedImage<RemoteFile>, RemoteError> {
        let section = self.member_section(member)?;
        let image =
            AeaReader::open(section, self.source.http()).map_err(|source| RemoteError::Aea {
                name: member.name,
                source,
            })?;
        check_image_size(member, &image, decrypted_size)?;
        Ok(image)
    }

    /// Opens the decrypted macOS file-system image.
    ///
    /// # Errors
    /// See [`RestoreImage::open_encrypted_image`].
    pub fn open_file_system_image(&self) -> Result<EncryptedImage<RemoteFile>, RemoteError> {
        self.open_encrypted_image(&FILE_SYSTEM_MEMBER, FILE_SYSTEM_IMAGE_SIZE)
    }

    /// Opens the decrypted `SystemOS` cryptex image.
    ///
    /// # Errors
    /// See [`RestoreImage::open_encrypted_image`].
    pub fn open_system_os_image(&self) -> Result<EncryptedImage<RemoteFile>, RemoteError> {
        self.open_encrypted_image(&SYSTEM_OS_MEMBER, SYSTEM_OS_IMAGE_SIZE)
    }
}

impl<R: ReadAt> RestoreImage<R> {
    /// Parses the ZIP central directory of `source`.
    ///
    /// # Errors
    /// Fails when the archive structure cannot be read.
    pub fn new(source: R) -> Result<Self, RemoteError> {
        let source = Arc::new(source);
        let cursor = ReadAtCursor {
            source: Arc::clone(&source),
            position: 0,
        };
        let archive = ZipArchive::new(cursor)?;
        Ok(Self {
            source,
            archive: Mutex::new(archive),
        })
    }

    /// The underlying random-access source.
    pub fn source(&self) -> &Arc<R> {
        &self.source
    }

    /// Number of archive entries.
    pub fn len(&self) -> usize {
        self.lock_archive().len()
    }

    /// Whether the archive has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Absolute offset and size of a pinned member's raw data.
    ///
    /// # Errors
    /// Fails when the member is absent or differs from its pin.
    pub fn member_data_range(&self, member: &PinnedMember) -> Result<(u64, u64), RemoteError> {
        let mut archive = self.lock_archive();
        let index = archive
            .index_for_name(member.name)
            .ok_or(RemoteError::MissingMember(member.name))?;
        let entry = archive.by_index_raw(index)?;
        if entry.compression() != member.expected_method()
            || entry.compressed_size() != member.compressed_size
            || entry.size() != member.uncompressed_size
        {
            return Err(RemoteError::MemberMismatch(member.name));
        }
        let offset = entry
            .data_start()
            .ok_or(RemoteError::MissingDataOffset(member.name))?;
        Ok((offset, entry.compressed_size()))
    }

    /// Random-access view of a pinned member's raw (for stored members,
    /// decoded) bytes.
    ///
    /// # Errors
    /// See [`RestoreImage::member_data_range`].
    pub fn member_section(&self, member: &PinnedMember) -> Result<RemoteSection<R>, RemoteError> {
        let (offset, size) = self.member_data_range(member)?;
        Ok(SectionReader::new(Arc::clone(&self.source), offset, size))
    }

    /// Reads and decodes a whole pinned member, verifying its CRC and size.
    ///
    /// # Errors
    /// Fails on mismatches, read or inflate errors, or a wrong decoded size.
    pub fn read_member(&self, member: &PinnedMember) -> Result<Vec<u8>, RemoteError> {
        self.member_data_range(member)?;
        let mut archive = self.lock_archive();
        let entry = archive.by_name(member.name)?;
        let mut data = Vec::new();
        entry
            .take(member.uncompressed_size.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(|source| RemoteError::Read {
                name: member.name,
                source,
            })?;
        if data.len() as u64 != member.uncompressed_size {
            return Err(RemoteError::MemberSize {
                name: member.name,
                actual: data.len() as u64,
                expected: member.uncompressed_size,
            });
        }
        Ok(data)
    }

    fn lock_archive(&self) -> MutexGuard<'_, ZipArchive<ReadAtCursor<R>>> {
        self.archive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn check_image_size<R: ReadAt>(
    member: &PinnedMember,
    image: &AeaReader<R>,
    expected: u64,
) -> Result<(), RemoteError> {
    if image.size() == expected {
        return Ok(());
    }
    Err(RemoteError::ImageSize {
        name: member.name,
        actual: image.size(),
        expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    const STORED: PinnedMember = PinnedMember {
        name: "image.dmg.aea",
        compressed_size: 4000,
        uncompressed_size: 4000,
    };

    fn pattern(size: usize, step: usize) -> Vec<u8> {
        (0..size)
            .map(|n| u8::try_from((n * step) % 251).unwrap())
            .collect()
    }

    fn archive() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let stored = pattern(4000, 7);
        let deflated = vec![b'k'; 10_000];
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let store = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let deflate = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        writer.start_file("kernelcache", deflate).unwrap();
        writer.write_all(&deflated).unwrap();
        writer.start_file(STORED.name, store).unwrap();
        writer.write_all(&stored).unwrap();
        (writer.finish().unwrap().into_inner(), stored, deflated)
    }

    fn deflated_member(image: &RestoreImage<Vec<u8>>) -> PinnedMember {
        let mut archive = image.lock_archive();
        let index = archive.index_for_name("kernelcache").unwrap();
        let compressed_size = archive.by_index_raw(index).unwrap().compressed_size();
        PinnedMember {
            name: "kernelcache",
            compressed_size,
            uncompressed_size: 10_000,
        }
    }

    #[test]
    fn exposes_stored_member_as_random_access_section() {
        let (zip, stored, _) = archive();
        let image = RestoreImage::new(zip).unwrap();
        assert_eq!(image.len(), 2);
        let section = image.member_section(&STORED).unwrap();
        assert_eq!(section.size(), 4000);
        let mut data = vec![0; 100];
        section.read_exact_at(&mut data, 1234).unwrap();
        assert_eq!(data, stored[1234..1334]);
        assert_eq!(image.read_member(&STORED).unwrap(), stored);
    }

    #[test]
    fn inflates_deflated_member() {
        let (zip, _, deflated) = archive();
        let image = RestoreImage::new(zip).unwrap();
        let member = deflated_member(&image);
        assert_eq!(member.expected_method(), CompressionMethod::Deflated);
        assert_eq!(image.read_member(&member).unwrap(), deflated);
    }

    #[test]
    fn rejects_members_that_differ_from_their_pin() {
        let (zip, _, _) = archive();
        let image = RestoreImage::new(zip).unwrap();
        let resized = PinnedMember {
            compressed_size: 4001,
            uncompressed_size: 4001,
            ..STORED
        };
        assert!(matches!(
            image.member_section(&resized),
            Err(RemoteError::MemberMismatch(_))
        ));
        let missing = PinnedMember {
            name: "absent",
            ..STORED
        };
        assert!(matches!(
            image.member_section(&missing),
            Err(RemoteError::MissingMember("absent"))
        ));
        let wrong_method = PinnedMember {
            uncompressed_size: 10_000,
            ..deflated_member(&image)
        };
        let stored_as_deflate = PinnedMember {
            compressed_size: wrong_method.uncompressed_size,
            ..wrong_method
        };
        assert!(matches!(
            image.member_section(&stored_as_deflate),
            Err(RemoteError::MemberMismatch(_))
        ));
    }

    #[test]
    fn opens_synthetic_aea_member_through_the_archive() {
        let aea = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apple_sap/A/synthetic.aea"
        ));
        let plain = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apple_sap/A/synthetic.out"
        ));
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let store = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("x.aea", store).unwrap();
        writer.write_all(aea).unwrap();
        let image = RestoreImage::new(writer.finish().unwrap().into_inner()).unwrap();
        let member = PinnedMember {
            name: "x.aea",
            compressed_size: aea.len() as u64,
            uncompressed_size: aea.len() as u64,
        };
        let pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apple_sap/A/synthetic_fcs_key.pem"
        ));
        let reader =
            AeaReader::open_with_fcs_key(image.member_section(&member).unwrap(), pem).unwrap();
        let mut output = vec![0; plain.len()];
        reader.read_exact_at(&mut output, 0).unwrap();
        assert_eq!(output, plain);
    }

    fn golden() -> serde_json::Value {
        serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apple_sap/A/real.json"
        )))
        .unwrap()
    }

    #[test]
    #[ignore = "downloads ranges of the 26 GB macOS 27.0.1 restore image and Apple's FCS key"]
    fn decrypts_pinned_system_os_cryptex_like_go() {
        let golden = golden();
        let http = Arc::new(BlockingHttp::new().unwrap());
        let image = RestoreImage::open_pinned(http).unwrap();
        assert_eq!(image.source().size(), golden["ipsw_size"].as_u64().unwrap());
        assert_eq!(image.len() as u64, golden["zip_entries"].as_u64().unwrap());
        for member in [FILE_SYSTEM_MEMBER, SYSTEM_OS_MEMBER] {
            let (offset, _) = image.member_data_range(&member).unwrap();
            let key = format!("{}.data_offset", member.name);
            assert_eq!(offset, golden[key.as_str()].as_u64().unwrap());
        }
        let system_os = image.open_system_os_image().unwrap();
        crate::infrastructure::apple_sap::assets::aea::tests::assert_real_reads(
            &system_os, &golden,
        );
        let file_system = image.open_file_system_image().unwrap();
        let mut header = [0; 4096];
        file_system.read_exact_at(&mut header, 0).unwrap();
    }

    /// Segment 2276 has a short FSE stream that upstream's Go decoder only
    /// accepts after `padLZFSEStreams`; `lzfse_rust` must decode it as is.
    #[test]
    #[ignore = "downloads one 1 MiB segment of the macOS 27.0.1 SystemOS cryptex"]
    fn decodes_system_os_segment_needing_go_lzfse_padding() {
        const SHORT_STREAM_SEGMENT: u64 = 2276;
        let http = Arc::new(BlockingHttp::new().unwrap());
        let image = RestoreImage::open_pinned(http).unwrap();
        let system_os = image.open_system_os_image().unwrap();
        let segment_size = u64::from(system_os.segment_size());
        let mut data = vec![0; usize::try_from(segment_size).unwrap()];
        system_os
            .read_exact_at(&mut data, SHORT_STREAM_SEGMENT * segment_size)
            .unwrap();
    }

    #[test]
    #[ignore = "downloads the 33 MB pinned kernel cache member of the macOS 27.0.1 restore image"]
    fn inflates_pinned_kernel_cache_member() {
        let kernel_cache = PinnedMember {
            name: "kernelcache.release.mac13j",
            compressed_size: 33_043_908,
            uncompressed_size: 33_096_787,
        };
        let http = Arc::new(BlockingHttp::new().unwrap());
        let image = RestoreImage::open_pinned(http).unwrap();
        let (offset, _) = image.member_data_range(&kernel_cache).unwrap();
        assert_eq!(
            offset,
            golden()["kernelcache.data_offset"].as_u64().unwrap()
        );
        assert_eq!(image.read_member(&kernel_cache).unwrap().len(), 33_096_787);
    }
}
