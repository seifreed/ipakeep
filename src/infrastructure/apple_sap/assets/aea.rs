//! Apple Encrypted Archive (AEA1, symmetric profile 1) random-access decryption.
//!
//! Ported from ipatool `internal/sap/assets/aea.go`.
//!
//! The symmetric key is HPKE-wrapped (`DHKEM(P-256, HKDF-SHA256)`,
//! `HKDF-SHA256`, `AES-256-GCM`, base mode) to an Apple-published FCS P-256
//! key named in the archive metadata. HPKE is implemented here on top of
//! `p256`, `hkdf` and `aes-gcm`. Clusters and segments are authenticated with
//! HMAC-SHA256, decrypted with AES-256-CTR, LZFSE-decoded and SHA-256 checked
//! lazily when [`ReadAt::read_at`] touches them.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::http_range::{BlockingHttp, HttpRangeError, ReadAt, clamp_len};

const AEA_MAGIC: &[u8; 4] = b"AEA1";
const AEA_SYMMETRIC_PROFILE: u32 = 1;
const AEA_PROFILE_MASK: u32 = 0x00ff_ffff;
const AEA_MAIN_KEY_INFO: &[u8] = b"AEA_AMK";
const AEA_ROOT_KEY_INFO: &[u8] = b"AEA_RHEK";
const AEA_CLUSTER_KEY_INFO: &[u8] = b"AEA_CK";
const AEA_CLUSTER_HEADER_KEY_INFO: &[u8] = b"AEA_CHEK";
const AEA_SEGMENT_KEY_INFO: &[u8] = b"AEA_SK";
const AEA_LZFSE_COMPRESSION: u8 = b'e';
const AEA_SHA256_CHECKSUM: u8 = 2;
const AEA_DECODED_SEGMENT_CACHE_COUNT: usize = 64;
const MAX_AEA_AUTH_DATA_SIZE: u32 = 1 << 20;
const MAX_FCS_KEY_SIZE: usize = 64 << 10;
const FCS_KEY: &str = "download Apple FCS key";

const AEA_HEADER_SIZE: usize = 12;
const MAC_SIZE: usize = 32;
const MAIN_SALT_SIZE: usize = 32;
const ROOT_DATA_SIZE: usize = 48;
const ENCRYPTED_ROOT_SIZE: usize = MAC_SIZE + ROOT_DATA_SIZE + MAC_SIZE;
const SEGMENT_HEADER_SIZE: usize = 8 + 32;
const HEADER_KEY_SIZE: usize = MAC_SIZE + 32 + 16;
const METADATA_LENGTH_SIZE: usize = 4;
const MIN_METADATA_RECORD_LENGTH: u32 = 5;

const FCS_KEY_URL_FIELD: &[u8] = b"com.apple.wkms.fcs-key-url";
const FCS_RESPONSE_FIELD: &[u8] = b"com.apple.wkms.fcs-response";
const FCS_KEY_SCHEME: &str = "https";
const FCS_KEY_HOST: &str = "wkms-public.apple.com";

const HPKE_VERSION_LABEL: &[u8] = b"HPKE-v1";
const HPKE_KEM_SUITE: &[u8] = b"KEM\x00\x10";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x02";
const HPKE_MODE_BASE: u8 = 0;
const HPKE_SECRET_SIZE: usize = 32;
const HPKE_KEY_SIZE: usize = 32;
const HPKE_NONCE_SIZE: usize = 12;
const P256_UNCOMPRESSED_POINT_SIZE: usize = 65;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Mac32 = [u8; MAC_SIZE];

/// Decoded AEA authentication-data records, keyed by raw field name.
pub type AeaMetadata = HashMap<Vec<u8>, Vec<u8>>;

/// Errors produced while opening or reading an AEA archive.
#[derive(Debug, thiserror::Error)]
pub enum AeaError {
    /// Reading the encrypted source failed.
    #[error("read {context}: {source}")]
    Io {
        /// What was being read.
        context: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The archive does not start with `AEA1`.
    #[error("invalid AEA magic {0:?}")]
    InvalidMagic([u8; 4]),
    /// The archive uses a profile other than 1.
    #[error("unsupported AEA profile {0}")]
    UnsupportedProfile(u32),
    /// The authentication data exceeds the 1 MiB bound.
    #[error("AEA authentication data is too large: {0}")]
    AuthDataTooLarge(u32),
    /// A metadata record length is out of bounds.
    #[error("invalid AEA metadata record length {0}")]
    InvalidMetadataRecordLength(u32),
    /// A metadata record lacks a NUL-terminated, non-empty key.
    #[error("invalid AEA metadata record")]
    InvalidMetadataRecord,
    /// A required metadata field is absent.
    #[error("AEA metadata does not contain {0}")]
    MissingMetadata(&'static str),
    /// The FCS key URL is not an `https://wkms-public.apple.com` URL.
    #[error("invalid Apple FCS key URL {0:?}")]
    InvalidKeyUrl(String),
    /// Downloading the FCS key failed.
    #[error("download Apple FCS key: {0}")]
    Http(#[from] HttpRangeError),
    /// The FCS key is not a PKCS#8 P-256 private key in PEM form.
    #[error("parse Apple FCS private key: {0}")]
    InvalidPrivateKey(String),
    /// The FCS response JSON or its base64 fields are malformed.
    #[error("parse AEA FCS response: {0}")]
    InvalidFcsResponse(String),
    /// HPKE decapsulation or decryption failed.
    #[error("unwrap AEA symmetric key: {0}")]
    Hpke(&'static str),
    /// HKDF could not produce the requested key length.
    #[error("expand AEA key: invalid length {0}")]
    KeyDerivation(usize),
    /// The root header MAC does not match.
    #[error("AEA root header failed authentication")]
    RootAuthentication,
    /// The declared output size is zero or too large.
    #[error("invalid AEA output size {0}")]
    InvalidOutputSize(u64),
    /// The declared encrypted size differs from the source size.
    #[error("AEA encrypted size is {actual}, expected {expected}")]
    EncryptedSizeMismatch {
        /// Size declared by the root header.
        actual: u64,
        /// Size of the encrypted source.
        expected: u64,
    },
    /// Segment size or segments per cluster is zero.
    #[error("AEA has an invalid segment layout")]
    InvalidSegmentLayout,
    /// The archive is not LZFSE-compressed with SHA-256 checksums.
    #[error("unsupported AEA encoding: compression {compression:?}, checksum {checksum}")]
    UnsupportedEncoding {
        /// Compression algorithm byte.
        compression: char,
        /// Checksum algorithm byte.
        checksum: u8,
    },
    /// A cluster header extends past the end of the source.
    #[error("AEA cluster header extends beyond the encrypted image")]
    ClusterOutOfBounds,
    /// A cluster header MAC does not match.
    #[error("AEA cluster {0} failed authentication")]
    ClusterAuthentication(u32),
    /// A segment header is inconsistent.
    #[error("AEA cluster {cluster} segment {segment} {reason}")]
    InvalidSegment {
        /// Cluster index.
        cluster: u32,
        /// Segment index inside the cluster.
        segment: u32,
        /// Description of the inconsistency.
        reason: &'static str,
    },
    /// A read touched a segment that was never indexed.
    #[error("AEA segment {0} is missing")]
    MissingSegment(u64),
    /// A segment MAC does not match.
    #[error("AEA cluster {cluster} segment {segment} failed authentication")]
    SegmentAuthentication {
        /// Cluster index.
        cluster: u32,
        /// Segment index inside the cluster.
        segment: u32,
    },
    /// LZFSE decoding failed or produced the wrong size.
    #[error("decompress AEA cluster {cluster} segment {segment}: {reason}")]
    Decompress {
        /// Cluster index.
        cluster: u32,
        /// Segment index inside the cluster.
        segment: u32,
        /// Decoder failure.
        reason: String,
    },
    /// The decoded segment does not match its SHA-256 checksum.
    #[error("AEA cluster {cluster} segment {segment} failed checksum verification")]
    Checksum {
        /// Cluster index.
        cluster: u32,
        /// Segment index inside the cluster.
        segment: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct Segment {
    input_offset: u64,
    output_offset: u64,
    compressed_size: u32,
    decompressed_size: u32,
    checksum: [u8; 32],
    mac: Mac32,
    cluster: u32,
    index: u32,
}

#[derive(Debug, Clone, Copy)]
struct RootHeader {
    file_size: u64,
    encrypted_size: u64,
    segment_size: u32,
    segments_per_cluster: u32,
    compression: u8,
    checksum: u8,
}

struct HeaderKey {
    mac: [u8; MAC_SIZE],
    key: [u8; 32],
    iv: [u8; 16],
}

#[derive(Debug, Default)]
struct SegmentCache {
    entries: HashMap<u64, Arc<Vec<u8>>>,
    order: VecDeque<u64>,
}

struct Prologue {
    profile_and_scrypt: u32,
    auth_data: Vec<u8>,
    metadata: AeaMetadata,
}

/// Lazily decrypted plaintext of an AEA1 profile-1 archive.
///
/// Opening authenticates the root header and every cluster header and
/// indexes all segments; segment payloads are only fetched, authenticated,
/// decrypted, decompressed and checksum-verified when read. The 64 most
/// recently decoded segments are cached.
#[derive(Debug)]
pub struct AeaReader<R> {
    source: R,
    size: u64,
    segment_size: u32,
    main_key: Vec<u8>,
    segments: Vec<Option<Segment>>,
    cache: Mutex<SegmentCache>,
}

impl<R: ReadAt> AeaReader<R> {
    /// Opens `source`, downloading the FCS key named by its metadata.
    ///
    /// # Errors
    /// Fails on malformed headers, key download or unwrap failures and
    /// authentication failures of the root or any cluster header.
    pub fn open(source: R, http: &BlockingHttp) -> Result<Self, AeaError> {
        let download = |url: &str| http.get_limited(url, MAX_FCS_KEY_SIZE, FCS_KEY);
        Self::open_downloading(source, download)
    }

    /// Opens `source`, fetching the FCS key PEM through `download` once its
    /// URL has been validated as Apple's WKMS host.
    ///
    /// # Errors
    /// See [`AeaReader::open`].
    pub fn open_downloading(
        source: R,
        download: impl FnOnce(&str) -> Result<Vec<u8>, HttpRangeError>,
    ) -> Result<Self, AeaError> {
        Self::open_keyed(source, |metadata| {
            let pem = download(fcs_key_url(metadata)?.as_str())?;
            unwrap_symmetric_key(&pem, metadata)
        })
    }

    /// Opens `source` with an already downloaded FCS private key PEM.
    ///
    /// # Errors
    /// See [`AeaReader::open`].
    pub fn open_with_fcs_key(source: R, pem: &[u8]) -> Result<Self, AeaError> {
        Self::open_keyed(source, |metadata| unwrap_symmetric_key(pem, metadata))
    }

    /// Opens `source` with its unwrapped symmetric key.
    ///
    /// # Errors
    /// See [`AeaReader::open`].
    pub fn open_with_symmetric_key(source: R, symmetric_key: &[u8]) -> Result<Self, AeaError> {
        Self::open_keyed(source, |_| Ok(symmetric_key.to_vec()))
    }

    /// Size of one decoded segment; reads aligned to it decode one segment.
    pub fn segment_size(&self) -> u32 {
        self.segment_size
    }

    fn open_keyed(
        source: R,
        resolve: impl FnOnce(&AeaMetadata) -> Result<Vec<u8>, AeaError>,
    ) -> Result<Self, AeaError> {
        let prologue = read_prologue(&source)?;
        let symmetric_key = resolve(&prologue.metadata)?;
        let salt_offset = (AEA_HEADER_SIZE + prologue.auth_data.len()) as u64;
        let main_salt: [u8; MAIN_SALT_SIZE] = read_array(&source, salt_offset, "AEA main salt")?;
        let main_info = indexed_info(AEA_MAIN_KEY_INFO, prologue.profile_and_scrypt);
        let key_len = symmetric_key.len();
        let main_key = derive_key(&symmetric_key, Some(&main_salt), &main_info, key_len)?;
        let root_offset = salt_offset + MAIN_SALT_SIZE as u64;
        let (root, first_cluster_mac) = read_root(&source, root_offset, &main_key, &prologue)?;
        let segment_count = root.file_size.div_ceil(u64::from(root.segment_size));
        let mut reader = Self {
            size: root.file_size,
            segment_size: root.segment_size,
            main_key,
            segments: vec![
                None;
                usize::try_from(segment_count)
                    .map_err(|_| AeaError::InvalidOutputSize(root.file_size))?
            ],
            cache: Mutex::new(SegmentCache::default()),
            source,
        };
        let cluster_offset = root_offset + ENCRYPTED_ROOT_SIZE as u64;
        reader.index_clusters(cluster_offset, first_cluster_mac, &root)?;
        Ok(reader)
    }

    fn index_clusters(
        &mut self,
        mut offset: u64,
        mut cluster_mac: Mac32,
        root: &RootHeader,
    ) -> Result<(), AeaError> {
        let per_cluster = u64::from(root.segments_per_cluster);
        let header_size = (SEGMENT_HEADER_SIZE + MAC_SIZE) as u64 * per_cluster + MAC_SIZE as u64;
        let mut output_size = 0;
        let mut cluster = 0_u32;
        while output_size < root.file_size {
            let location = (offset, header_size);
            let header = self.read_cluster_header(location, cluster, &cluster_mac, root)?;
            offset = self.index_segments(&header, offset + header_size, root, &mut output_size)?;
            cluster_mac = header.next_mac;
            cluster += 1;
        }
        Ok(())
    }

    fn read_cluster_header(
        &self,
        (offset, header_size): (u64, u64),
        cluster: u32,
        expected_mac: &Mac32,
        root: &RootHeader,
    ) -> Result<ClusterHeader, AeaError> {
        let source_size = self.source.size();
        if offset > source_size || header_size > source_size - offset {
            return Err(AeaError::ClusterOutOfBounds);
        }
        let header_len = usize::try_from(header_size).map_err(|_| AeaError::ClusterOutOfBounds)?;
        let mut data = read_vec(&self.source, offset, header_len, "AEA cluster header")?;
        let key = cluster_key(&self.main_key, cluster)?;
        let header_key = derive_header_key(&key, AEA_CLUSTER_HEADER_KEY_INFO)?;
        let encrypted_len = SEGMENT_HEADER_SIZE * root.segments_per_cluster as usize;
        let (encrypted, trailer) = data.split_at_mut(encrypted_len);
        if !verify_mac(&header_key.mac, encrypted, &[&trailer[..]], expected_mac) {
            return Err(AeaError::ClusterAuthentication(cluster));
        }
        apply_ctr(encrypted, &header_key);
        Ok(ClusterHeader::new(cluster, encrypted, trailer))
    }

    fn index_segments(
        &mut self,
        header: &ClusterHeader,
        mut data_offset: u64,
        root: &RootHeader,
        output_size: &mut u64,
    ) -> Result<u64, AeaError> {
        let source_size = self.source.size();
        for index in 0..root.segments_per_cluster {
            let available = source_size.saturating_sub(data_offset);
            if let Some(segment) = parse_segment(header, index, (data_offset, available), root)? {
                place_segment(&mut self.segments, segment, root)?;
                data_offset += u64::from(segment.compressed_size);
                *output_size += u64::from(segment.decompressed_size);
            }
        }
        Ok(data_offset)
    }

    fn lock_cache(&self) -> MutexGuard<'_, SegmentCache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn decode_segment(&self, slot: u64, segment: &Segment) -> Result<Arc<Vec<u8>>, AeaError> {
        let mut cache = self.lock_cache();
        if let Some(decoded) = cache.entries.get(&slot) {
            return Ok(Arc::clone(decoded));
        }
        let decoded = Arc::new(self.decode_uncached(segment)?);
        if cache.order.len() == AEA_DECODED_SEGMENT_CACHE_COUNT
            && let Some(evicted) = cache.order.pop_front()
        {
            cache.entries.remove(&evicted);
        }
        cache.entries.insert(slot, Arc::clone(&decoded));
        cache.order.push_back(slot);
        Ok(decoded)
    }

    fn decode_uncached(&self, segment: &Segment) -> Result<Vec<u8>, AeaError> {
        let length = segment.compressed_size as usize;
        let mut data = read_vec(&self.source, segment.input_offset, length, "AEA segment")?;
        let info = indexed_info(AEA_SEGMENT_KEY_INFO, segment.index);
        let key = derive_header_key(&cluster_key(&self.main_key, segment.cluster)?, &info)?;
        if !verify_mac(&key.mac, &data, &[], &segment.mac) {
            return Err(AeaError::SegmentAuthentication {
                cluster: segment.cluster,
                segment: segment.index,
            });
        }
        apply_ctr(&mut data, &key);
        let decoded = if segment.compressed_size == segment.decompressed_size {
            data
        } else {
            decompress_segment(&data, segment)?
        };
        if Sha256::digest(&decoded).as_slice() != segment.checksum {
            return Err(AeaError::Checksum {
                cluster: segment.cluster,
                segment: segment.index,
            });
        }
        Ok(decoded)
    }

    fn read_plain(&self, buf: &mut [u8], offset: u64) -> Result<(), AeaError> {
        let mut written = 0;
        while written < buf.len() {
            let position = offset + written as u64;
            let slot = position / u64::from(self.segment_size);
            let segment = usize::try_from(slot)
                .ok()
                .and_then(|slot| self.segments.get(slot).copied().flatten())
                .ok_or(AeaError::MissingSegment(slot))?;
            let decoded = self.decode_segment(slot, &segment)?;
            let inside = usize::try_from(position - segment.output_offset).unwrap_or(usize::MAX);
            let available = decoded.get(inside..).filter(|rest| !rest.is_empty());
            let available = available.ok_or(AeaError::MissingSegment(slot))?;
            let count = available.len().min(buf.len() - written);
            buf[written..written + count].copy_from_slice(&available[..count]);
            written += count;
        }
        Ok(())
    }
}

impl<R: ReadAt> ReadAt for AeaReader<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let wanted = clamp_len(buf.len(), self.size - offset);
        self.read_plain(&mut buf[..wanted], offset)
            .map_err(io::Error::other)?;
        Ok(wanted)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

struct ClusterHeader {
    index: u32,
    segment_headers: Vec<u8>,
    next_mac: Mac32,
    segment_macs: Vec<u8>,
}

impl ClusterHeader {
    fn new(index: u32, segment_headers: &[u8], trailer: &[u8]) -> Self {
        Self {
            index,
            segment_headers: segment_headers.to_vec(),
            next_mac: to_array(&trailer[..MAC_SIZE]),
            segment_macs: trailer[MAC_SIZE..].to_vec(),
        }
    }
}

/// Decodes segment `index` of a cluster whose payload starts at
/// `data_offset` with `available` encrypted bytes left; `None` marks an
/// unused slot.
fn parse_segment(
    header: &ClusterHeader,
    index: u32,
    (data_offset, available): (u64, u64),
    root: &RootHeader,
) -> Result<Option<Segment>, AeaError> {
    let fault = |reason| invalid_segment(header.index, index, reason);
    let start = index as usize * SEGMENT_HEADER_SIZE;
    let raw = &header.segment_headers[start..start + SEGMENT_HEADER_SIZE];
    let decompressed_size = le_u32(&raw[0..4]);
    let compressed_size = le_u32(&raw[4..8]);
    if decompressed_size == 0 {
        if compressed_size != 0 {
            return Err(fault("has compressed data without output"));
        }
        return Ok(None);
    }
    if decompressed_size > root.segment_size || compressed_size == 0 {
        return Err(fault("has invalid sizes"));
    }
    if u64::from(compressed_size) > available {
        return Err(fault("extends beyond the encrypted image"));
    }
    let mac_start = index as usize * MAC_SIZE;
    Ok(Some(Segment {
        input_offset: data_offset,
        output_offset: 0,
        compressed_size,
        decompressed_size,
        checksum: to_array(&raw[8..]),
        mac: to_array(&header.segment_macs[mac_start..mac_start + MAC_SIZE]),
        cluster: header.index,
        index,
    }))
}

/// Stores `segment` in its slot of the output index, rejecting slots outside
/// the declared output.
fn place_segment(
    segments: &mut [Option<Segment>],
    mut segment: Segment,
    root: &RootHeader,
) -> Result<(), AeaError> {
    let fault = |reason| invalid_segment(segment.cluster, segment.index, reason);
    let per_cluster = u64::from(root.segments_per_cluster);
    let global = u64::from(segment.cluster) * per_cluster + u64::from(segment.index);
    let slot = usize::try_from(global).ok();
    let slot = slot.and_then(|slot| segments.get_mut(slot));
    let slot = slot.ok_or_else(|| fault("is outside the declared output"))?;
    segment.output_offset = global * u64::from(root.segment_size);
    if segment.output_offset + u64::from(segment.decompressed_size) > root.file_size {
        return Err(fault("extends beyond the declared output"));
    }
    *slot = Some(segment);
    Ok(())
}

fn invalid_segment(cluster: u32, segment: u32, reason: &'static str) -> AeaError {
    AeaError::InvalidSegment {
        cluster,
        segment,
        reason,
    }
}

fn read_prologue(source: &impl ReadAt) -> Result<Prologue, AeaError> {
    let header: [u8; AEA_HEADER_SIZE] = read_array(source, 0, "AEA header")?;
    let magic: [u8; 4] = to_array(&header[..4]);
    if &magic != AEA_MAGIC {
        return Err(AeaError::InvalidMagic(magic));
    }
    let profile_and_scrypt = le_u32(&header[4..8]);
    if profile_and_scrypt & AEA_PROFILE_MASK != AEA_SYMMETRIC_PROFILE {
        return Err(AeaError::UnsupportedProfile(
            profile_and_scrypt & AEA_PROFILE_MASK,
        ));
    }
    let auth_length = le_u32(&header[8..12]);
    if auth_length > MAX_AEA_AUTH_DATA_SIZE {
        return Err(AeaError::AuthDataTooLarge(auth_length));
    }
    let auth_data = read_vec(
        source,
        AEA_HEADER_SIZE as u64,
        auth_length as usize,
        "AEA authentication data",
    )?;
    let metadata = parse_metadata(&auth_data)?;
    Ok(Prologue {
        profile_and_scrypt,
        auth_data,
        metadata,
    })
}

fn read_root(
    source: &impl ReadAt,
    offset: u64,
    main_key: &[u8],
    prologue: &Prologue,
) -> Result<(RootHeader, Mac32), AeaError> {
    let encrypted: [u8; ENCRYPTED_ROOT_SIZE] =
        read_array(source, offset, "encrypted AEA root header")?;
    let (mac, rest) = encrypted.split_at(MAC_SIZE);
    let (data, cluster_mac) = rest.split_at(ROOT_DATA_SIZE);
    let root_key = derive_header_key(main_key, AEA_ROOT_KEY_INFO)?;
    if !verify_mac(
        &root_key.mac,
        data,
        &[cluster_mac, &prologue.auth_data],
        mac,
    ) {
        return Err(AeaError::RootAuthentication);
    }
    let mut plain: [u8; ROOT_DATA_SIZE] = to_array(data);
    apply_ctr(&mut plain, &root_key);
    let root = RootHeader {
        file_size: le_u64(&plain[0..8]),
        encrypted_size: le_u64(&plain[8..16]),
        segment_size: le_u32(&plain[16..20]),
        segments_per_cluster: le_u32(&plain[20..24]),
        compression: plain[24],
        checksum: plain[25],
    };
    validate_root(&root, source.size())?;
    Ok((root, to_array(cluster_mac)))
}

fn validate_root(root: &RootHeader, source_size: u64) -> Result<(), AeaError> {
    if root.file_size == 0 || root.file_size > u64::MAX >> 1 {
        return Err(AeaError::InvalidOutputSize(root.file_size));
    }
    if root.encrypted_size != source_size {
        return Err(AeaError::EncryptedSizeMismatch {
            actual: root.encrypted_size,
            expected: source_size,
        });
    }
    if root.segment_size == 0 || root.segments_per_cluster == 0 {
        return Err(AeaError::InvalidSegmentLayout);
    }
    if root.compression != AEA_LZFSE_COMPRESSION || root.checksum != AEA_SHA256_CHECKSUM {
        return Err(AeaError::UnsupportedEncoding {
            compression: char::from(root.compression),
            checksum: root.checksum,
        });
    }
    Ok(())
}

/// Parses length-prefixed `key\0value` AEA authentication-data records.
///
/// # Errors
/// Rejects records whose length leaves the block or that lack a key.
pub fn parse_metadata(data: &[u8]) -> Result<AeaMetadata, AeaError> {
    let mut metadata = AeaMetadata::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some((length, body)) = rest.split_first_chunk::<METADATA_LENGTH_SIZE>() else {
            return Err(AeaError::InvalidMetadataRecordLength(0));
        };
        let length = u32::from_le_bytes(*length);
        let record_length = (length as usize).wrapping_sub(METADATA_LENGTH_SIZE);
        if length < MIN_METADATA_RECORD_LENGTH || record_length > body.len() {
            return Err(AeaError::InvalidMetadataRecordLength(length));
        }
        let (record, remaining) = body.split_at(record_length);
        let separator = record.iter().position(|&byte| byte == 0);
        let Some(separator) = separator.filter(|&separator| separator > 0) else {
            return Err(AeaError::InvalidMetadataRecord);
        };
        metadata.insert(
            record[..separator].to_vec(),
            record[separator + 1..].to_vec(),
        );
        rest = remaining;
    }
    Ok(metadata)
}

/// Returns the FCS key URL named by `metadata`.
///
/// # Errors
/// Fails when the URL is missing or not an `https` URL on Apple's WKMS host.
pub fn fcs_key_url(metadata: &AeaMetadata) -> Result<reqwest::Url, AeaError> {
    let raw = metadata
        .get(FCS_KEY_URL_FIELD)
        .ok_or(AeaError::MissingMetadata("an FCS key URL"))?;
    let text = String::from_utf8_lossy(raw).into_owned();
    match reqwest::Url::parse(&text) {
        Ok(url) if url.scheme() == FCS_KEY_SCHEME && url.host_str() == Some(FCS_KEY_HOST) => {
            Ok(url)
        }
        _ => Err(AeaError::InvalidKeyUrl(text)),
    }
}

#[derive(Deserialize)]
struct FcsResponse {
    #[serde(rename = "enc-request", default)]
    enc_request: String,
    #[serde(rename = "wrapped-key", default)]
    wrapped_key: String,
}

/// HPKE-unwraps the archive symmetric key with the FCS private key `pem`.
///
/// # Errors
/// Fails on a malformed key or FCS response, or when HPKE `Open` fails.
pub fn unwrap_symmetric_key(pem: &[u8], metadata: &AeaMetadata) -> Result<Vec<u8>, AeaError> {
    let pem =
        std::str::from_utf8(pem).map_err(|error| AeaError::InvalidPrivateKey(error.to_string()))?;
    let secret = SecretKey::from_pkcs8_pem(pem)
        .map_err(|error| AeaError::InvalidPrivateKey(error.to_string()))?;
    let response = metadata
        .get(FCS_RESPONSE_FIELD)
        .ok_or(AeaError::MissingMetadata("an FCS response"))?;
    let response: FcsResponse = serde_json::from_slice(response)
        .map_err(|error| AeaError::InvalidFcsResponse(error.to_string()))?;
    let encapsulation = decode_base64(&response.enc_request)?;
    let wrapped_key = decode_base64(&response.wrapped_key)?;
    hpke_open(&secret, &encapsulation, &wrapped_key)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, AeaError> {
    BASE64
        .decode(value)
        .map_err(|error| AeaError::InvalidFcsResponse(error.to_string()))
}

/// RFC 9180 base-mode single-shot `Open` with empty info and AAD.
fn hpke_open(
    secret: &SecretKey,
    encapsulation: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeaError> {
    let shared_secret = dhkem_decapsulate(secret, encapsulation)?;
    let psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", b"");
    let context = [&[HPKE_MODE_BASE][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(HPKE_SUITE, &shared_secret, b"secret", b"");
    let key = labeled_expand(HPKE_SUITE, &secret, b"key", &context, HPKE_KEY_SIZE)?;
    let nonce = labeled_expand(
        HPKE_SUITE,
        &secret,
        b"base_nonce",
        &context,
        HPKE_NONCE_SIZE,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AeaError::Hpke("invalid AEAD key"))?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext)
        .map_err(|_| AeaError::Hpke("message authentication failed"))
}

fn dhkem_decapsulate(secret: &SecretKey, encapsulation: &[u8]) -> Result<Vec<u8>, AeaError> {
    if encapsulation.len() != P256_UNCOMPRESSED_POINT_SIZE
        || encapsulation[0] != SEC1_UNCOMPRESSED_TAG
    {
        return Err(AeaError::Hpke("invalid encapsulated key"));
    }
    let ephemeral = PublicKey::from_sec1_bytes(encapsulation)
        .map_err(|_| AeaError::Hpke("invalid encapsulated key"))?;
    let shared = secret.diffie_hellman(&ephemeral);
    let recipient = secret.public_key().to_sec1_bytes();
    let kem_context = [encapsulation, &recipient].concat();
    let prk = labeled_extract(
        HPKE_KEM_SUITE,
        b"",
        b"eae_prk",
        shared.raw_secret_bytes().as_slice(),
    );
    labeled_expand(
        HPKE_KEM_SUITE,
        &prk,
        b"shared_secret",
        &kem_context,
        HPKE_SECRET_SIZE,
    )
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let labeled = [HPKE_VERSION_LABEL, suite, label, ikm].concat();
    Hkdf::<Sha256>::extract(Some(salt), &labeled).0.to_vec()
}

fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, AeaError> {
    let encoded_length = u16::try_from(length).map_err(|_| AeaError::KeyDerivation(length))?;
    let labeled = [
        &encoded_length.to_be_bytes()[..],
        HPKE_VERSION_LABEL,
        suite,
        label,
        info,
    ]
    .concat();
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| AeaError::KeyDerivation(length))?;
    let mut output = vec![0; length];
    hkdf.expand(&labeled, &mut output)
        .map_err(|_| AeaError::KeyDerivation(length))?;
    Ok(output)
}

fn derive_key(
    key: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, AeaError> {
    let mut output = vec![0; length];
    Hkdf::<Sha256>::new(salt, key)
        .expand(info, &mut output)
        .map_err(|_| AeaError::KeyDerivation(length))?;
    Ok(output)
}

fn derive_header_key(key: &[u8], info: &[u8]) -> Result<HeaderKey, AeaError> {
    let derived = derive_key(key, None, info, HEADER_KEY_SIZE)?;
    Ok(HeaderKey {
        mac: to_array(&derived[..MAC_SIZE]),
        key: to_array(&derived[MAC_SIZE..MAC_SIZE + 32]),
        iv: to_array(&derived[MAC_SIZE + 32..]),
    })
}

fn cluster_key(main_key: &[u8], cluster: u32) -> Result<Vec<u8>, AeaError> {
    derive_key(
        main_key,
        None,
        &indexed_info(AEA_CLUSTER_KEY_INFO, cluster),
        main_key.len(),
    )
}

fn indexed_info(label: &[u8], index: u32) -> Vec<u8> {
    [label, &index.to_le_bytes()].concat()
}

/// HMAC-SHA256 over `salt || data || le64(len(salt))`, compared in constant time.
fn verify_mac(key: &[u8], data: &[u8], salt: &[&[u8]], expected: &[u8]) -> bool {
    <HmacSha256 as Mac>::new_from_slice(key).is_ok_and(|mut mac| {
        let mut salt_length = 0_u64;
        for part in salt {
            mac.update(part);
            salt_length += part.len() as u64;
        }
        mac.update(data);
        mac.update(&salt_length.to_le_bytes());
        mac.verify_slice(expected).is_ok()
    })
}

fn apply_ctr(data: &mut [u8], key: &HeaderKey) {
    Aes256Ctr::new(&key.key.into(), &key.iv.into()).apply_keystream(data);
}

fn decompress_segment(compressed: &[u8], segment: &Segment) -> Result<Vec<u8>, AeaError> {
    let failure = |reason: String| AeaError::Decompress {
        cluster: segment.cluster,
        segment: segment.index,
        reason,
    };
    let mut decoded = Vec::with_capacity(segment.decompressed_size as usize);
    lzfse_rust::decode_bytes(compressed, &mut decoded)
        .map_err(|error| failure(error.to_string()))?;
    if decoded.len() != segment.decompressed_size as usize {
        return Err(failure(format!(
            "produced {} bytes, expected {}",
            decoded.len(),
            segment.decompressed_size
        )));
    }
    Ok(decoded)
}

fn read_vec(
    source: &impl ReadAt,
    offset: u64,
    length: usize,
    context: &'static str,
) -> Result<Vec<u8>, AeaError> {
    let mut data = vec![0; length];
    source
        .read_exact_at(&mut data, offset)
        .map_err(|source| AeaError::Io { context, source })?;
    Ok(data)
}

fn read_array<const N: usize>(
    source: &impl ReadAt,
    offset: u64,
    context: &'static str,
) -> Result<[u8; N], AeaError> {
    let mut data = [0; N];
    source
        .read_exact_at(&mut data, offset)
        .map_err(|source| AeaError::Io { context, source })?;
    Ok(data)
}

fn to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(&slice[..N]);
    array
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(to_array(bytes))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(to_array(bytes))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/apple_sap/A/",
                $name
            ))
        };
    }

    fn json(data: &[u8]) -> Value {
        serde_json::from_slice(data).unwrap()
    }

    fn hex_field(value: &Value, key: &str) -> Vec<u8> {
        hex::decode(value[key].as_str().unwrap()).unwrap()
    }

    fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn record(key: &str, value: &str) -> Vec<u8> {
        let body = [key.as_bytes(), &[0], value.as_bytes()].concat();
        let length = u32::try_from(body.len() + METADATA_LENGTH_SIZE).unwrap();
        [&length.to_le_bytes()[..], &body].concat()
    }

    #[test]
    fn parses_bounded_metadata_records() {
        let data = [record("first", "value"), record("second", "another")].concat();
        let metadata = parse_metadata(&data).unwrap();
        assert_eq!(metadata[&b"first".to_vec()], b"value");
        assert_eq!(metadata[&b"second".to_vec()], b"another");
    }

    #[test]
    fn rejects_metadata_record_outside_block() {
        let mut data = vec![0; 8];
        data[..4].copy_from_slice(&32_u32.to_le_bytes());
        assert!(matches!(
            parse_metadata(&data),
            Err(AeaError::InvalidMetadataRecordLength(32))
        ));
        assert!(matches!(
            parse_metadata(&record("", "value")),
            Err(AeaError::InvalidMetadataRecord)
        ));
    }

    fn synthetic() -> AeaReader<Vec<u8>> {
        AeaReader::open_with_fcs_key(
            fixture!("synthetic.aea").to_vec(),
            fixture!("synthetic_fcs_key.pem"),
        )
        .unwrap()
    }

    #[test]
    fn hpke_unwraps_go_sealed_key() {
        let golden = json(fixture!("synthetic.json"));
        let prologue = read_prologue(&fixture!("synthetic.aea").to_vec()).unwrap();
        let key =
            unwrap_symmetric_key(fixture!("synthetic_fcs_key.pem"), &prologue.metadata).unwrap();
        assert_eq!(key, hex_field(&golden, "symmetric_key"));
        let secret = SecretKey::from_pkcs8_pem(
            std::str::from_utf8(fixture!("synthetic_fcs_key.pem")).unwrap(),
        )
        .unwrap();
        let mut tampered = hex_field(&golden, "hpke_ct");
        tampered[0] ^= 1;
        assert!(matches!(
            hpke_open(&secret, &hex_field(&golden, "hpke_enc"), &tampered),
            Err(AeaError::Hpke(_))
        ));
    }

    #[test]
    fn decrypts_synthetic_archive_like_go() {
        let golden = json(fixture!("synthetic.json"));
        let reader = synthetic();
        assert_eq!(reader.main_key, hex_field(&golden, "main_key"));
        assert_eq!(reader.size(), golden["output_size"].as_u64().unwrap());
        assert_eq!(
            reader.segments.len() as u64,
            golden["segments"].as_u64().unwrap()
        );
        let mut output = vec![0; fixture!("synthetic.out").len() + 7];
        assert_eq!(
            reader.read_at(&mut output, 0).unwrap(),
            fixture!("synthetic.out").len()
        );
        assert_eq!(
            &output[..fixture!("synthetic.out").len()],
            fixture!("synthetic.out")
        );
        assert_eq!(
            sha256_hex(fixture!("synthetic.out")),
            golden["output_sha256"].as_str().unwrap()
        );
    }

    #[test]
    fn serves_random_access_reads_across_segments() {
        let reader = synthetic();
        let expected = fixture!("synthetic.out");
        for (offset, length) in [(4090_usize, 20_usize), (12_000, 5000), (19_470, 10)] {
            let mut data = vec![0; length];
            reader.read_exact_at(&mut data, offset as u64).unwrap();
            assert_eq!(data, expected[offset..offset + length]);
        }
        let mut tail = [0; 32];
        assert_eq!(
            reader
                .read_at(&mut tail, expected.len() as u64 - 4)
                .unwrap(),
            4
        );
        assert_eq!(reader.read_at(&mut tail, expected.len() as u64).unwrap(), 0);
    }

    #[test]
    fn rejects_tampered_root_cluster_and_segment() {
        let original = fixture!("synthetic.aea").to_vec();
        let pem = fixture!("synthetic_fcs_key.pem");
        let root_offset = original.len() - 1;
        let mut tampered = original.clone();
        tampered[root_offset] ^= 1;
        let reader = AeaReader::open_with_fcs_key(tampered, pem).unwrap();
        let mut data = vec![0; 32];
        let error = reader.read_at(&mut data, reader.size() - 32).unwrap_err();
        assert!(
            error.to_string().contains("failed authentication"),
            "{error}"
        );
        let salt_end = AEA_HEADER_SIZE + le_u32(&original[8..12]) as usize + MAIN_SALT_SIZE;
        for (offset, expected) in [
            (salt_end + MAC_SIZE, "root header"),
            (salt_end + ENCRYPTED_ROOT_SIZE, "cluster 0"),
        ] {
            let mut tampered = original.clone();
            tampered[offset] ^= 1;
            let error = AeaReader::open_with_fcs_key(tampered, pem).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_wrong_symmetric_key_and_magic() {
        let source = fixture!("synthetic.aea").to_vec();
        assert!(matches!(
            AeaReader::open_with_symmetric_key(source.clone(), &[0; 32]),
            Err(AeaError::RootAuthentication)
        ));
        let mut bad = source;
        bad[0] = b'X';
        assert!(matches!(
            AeaReader::open_with_symmetric_key(bad, &[0; 32]),
            Err(AeaError::InvalidMagic(_))
        ));
    }

    /// Offline replay of the byte ranges Go's reader touched in the real
    /// macOS 27.0.1 `SystemOS` cryptex (see `real.json`).
    struct SparseImage {
        ranges: Vec<(u64, Vec<u8>)>,
        size: u64,
    }

    impl SparseImage {
        fn load(data: &[u8], size: u64) -> Self {
            let mut ranges = Vec::new();
            let mut rest = data;
            while !rest.is_empty() {
                let offset = u64::from_le_bytes(rest[..8].try_into().unwrap());
                let length = u32::from_le_bytes(rest[8..12].try_into().unwrap()) as usize;
                ranges.push((offset, rest[12..12 + length].to_vec()));
                rest = &rest[12 + length..];
            }
            Self { ranges, size }
        }
    }

    impl ReadAt for SparseImage {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            let end = offset + buf.len() as u64;
            let (start, data) = self
                .ranges
                .iter()
                .find(|(start, data)| *start <= offset && end <= start + data.len() as u64)
                .ok_or_else(|| io::Error::other(format!("range {offset}-{end} not recorded")))?;
            let inside = usize::try_from(offset - start).unwrap();
            buf.copy_from_slice(&data[inside..inside + buf.len()]);
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            self.size
        }
    }

    #[test]
    fn decrypts_recorded_real_systemos_cryptex_like_go() {
        let golden = json(fixture!("real.json"));
        let image = SparseImage::load(
            fixture!("systemos_sparse.bin"),
            golden["source_size"].as_u64().unwrap(),
        );
        let prologue = read_prologue(&image).unwrap();
        let key = unwrap_symmetric_key(fixture!("wkms_fcs_key.pem"), &prologue.metadata).unwrap();
        assert_eq!(key, hex_field(&golden, "symmetric_key"));
        let reader = AeaReader::open_with_fcs_key(image, fixture!("wkms_fcs_key.pem")).unwrap();
        assert_eq!(reader.main_key, hex_field(&golden, "main_key"));
        assert_eq!(reader.size(), golden["output_size"].as_u64().unwrap());
        assert_eq!(
            u64::from(reader.segment_size()),
            golden["segment_size"].as_u64().unwrap()
        );
        assert_eq!(
            reader.segments.len() as u64,
            golden["segments"].as_u64().unwrap()
        );
        assert_real_reads(&reader, &golden);
    }

    pub(crate) fn assert_real_reads(reader: &impl ReadAt, golden: &Value) {
        let segment = golden["segment_size"].as_u64().unwrap();
        let mut first = vec![0; usize::try_from(segment).unwrap()];
        reader.read_exact_at(&mut first, 0).unwrap();
        assert_eq!(
            sha256_hex(&first),
            golden["segment0_plain_sha256"].as_str().unwrap()
        );
        let last = &golden["last_segment"];
        let mut tail = vec![0; usize::try_from(last["decompressed"].as_u64().unwrap()).unwrap()];
        reader
            .read_exact_at(&mut tail, last["output_offset"].as_u64().unwrap())
            .unwrap();
        assert_eq!(
            sha256_hex(&tail),
            golden["last_segment_plain_sha256"].as_str().unwrap()
        );
        let mut straddle = vec![0; 4096];
        reader.read_exact_at(&mut straddle, segment - 2048).unwrap();
        assert_eq!(
            sha256_hex(&straddle),
            golden["straddle_sha256"].as_str().unwrap()
        );
    }

    const TEST_SYMMETRIC_KEY: [u8; 32] = [0x42; 32];
    const TEST_MAIN_SALT: [u8; MAIN_SALT_SIZE] = [0x11; MAIN_SALT_SIZE];

    /// One segment as written: header sizes and checksum plus the bytes
    /// stored (before encryption) in the cluster's data area.
    #[derive(Clone)]
    struct SegmentSpec {
        decompressed: u32,
        compressed: u32,
        checksum: [u8; 32],
        stored: Vec<u8>,
    }

    fn stored_segment(plain: &[u8]) -> SegmentSpec {
        let size = u32::try_from(plain.len()).unwrap();
        SegmentSpec {
            decompressed: size,
            compressed: size,
            checksum: Sha256::digest(plain).into(),
            stored: plain.to_vec(),
        }
    }

    fn compressed_segment(plain: &[u8]) -> SegmentSpec {
        let mut stored = Vec::new();
        lzfse_rust::encode_bytes(plain, &mut stored).unwrap();
        SegmentSpec {
            compressed: u32::try_from(stored.len()).unwrap(),
            stored,
            ..stored_segment(plain)
        }
    }

    /// Encoder for synthetic AEA1 profile-1 archives (the inverse of
    /// [`AeaReader`]), with every header field overridable.
    struct ArchiveSpec {
        profile: u32,
        auth_data: Vec<u8>,
        file_size: u64,
        encrypted_size: Option<u64>,
        segment_size: u32,
        segments_per_cluster: u32,
        compression: u8,
        checksum: u8,
        clusters: Vec<Vec<SegmentSpec>>,
    }

    impl ArchiveSpec {
        fn new(segment_size: u32, segments_per_cluster: u32, plain: &[u8]) -> Self {
            let segments: Vec<SegmentSpec> = plain
                .chunks(segment_size as usize)
                .map(stored_segment)
                .collect();
            Self {
                profile: AEA_SYMMETRIC_PROFILE,
                auth_data: record("purpose", "test"),
                file_size: plain.len() as u64,
                encrypted_size: None,
                segment_size,
                segments_per_cluster,
                compression: AEA_LZFSE_COMPRESSION,
                checksum: AEA_SHA256_CHECKSUM,
                clusters: segments
                    .chunks(segments_per_cluster as usize)
                    .map(<[SegmentSpec]>::to_vec)
                    .collect(),
            }
        }

        fn main_key(&self) -> Vec<u8> {
            let info = indexed_info(AEA_MAIN_KEY_INFO, self.profile);
            derive_key(&TEST_SYMMETRIC_KEY, Some(&TEST_MAIN_SALT), &info, 32).unwrap()
        }

        fn cluster(&self, main_key: &[u8], index: u32, next_mac: Mac32) -> (Vec<u8>, Mac32) {
            let key = cluster_key(main_key, index).unwrap();
            let header_key = derive_header_key(&key, AEA_CLUSTER_HEADER_KEY_INFO).unwrap();
            let per_cluster = self.segments_per_cluster as usize;
            let mut headers = vec![0; SEGMENT_HEADER_SIZE * per_cluster];
            let mut trailer = next_mac.to_vec();
            trailer.resize(MAC_SIZE * (per_cluster + 1), 0);
            let mut data = Vec::new();
            for (slot, segment) in self.clusters[index as usize].iter().enumerate() {
                let info = indexed_info(AEA_SEGMENT_KEY_INFO, u32::try_from(slot).unwrap());
                let segment_key = derive_header_key(&key, &info).unwrap();
                let mut encrypted = segment.stored.clone();
                apply_ctr(&mut encrypted, &segment_key);
                let header = &mut headers[slot * SEGMENT_HEADER_SIZE..][..SEGMENT_HEADER_SIZE];
                header[..4].copy_from_slice(&segment.decompressed.to_le_bytes());
                header[4..8].copy_from_slice(&segment.compressed.to_le_bytes());
                header[8..].copy_from_slice(&segment.checksum);
                let mac = compute_mac(&segment_key.mac, &encrypted, &[]);
                trailer[MAC_SIZE * (slot + 1)..][..MAC_SIZE].copy_from_slice(&mac);
                data.extend(encrypted);
            }
            apply_ctr(&mut headers, &header_key);
            let mac = compute_mac(&header_key.mac, &headers, &[&trailer]);
            (([headers, trailer, data]).concat(), mac)
        }

        fn root(&self, main_key: &[u8], cluster_mac: Mac32, encrypted_size: u64) -> Vec<u8> {
            let root_key = derive_header_key(main_key, AEA_ROOT_KEY_INFO).unwrap();
            let mut data = [0u8; ROOT_DATA_SIZE];
            data[..8].copy_from_slice(&self.file_size.to_le_bytes());
            data[8..16].copy_from_slice(&encrypted_size.to_le_bytes());
            data[16..20].copy_from_slice(&self.segment_size.to_le_bytes());
            data[20..24].copy_from_slice(&self.segments_per_cluster.to_le_bytes());
            data[24] = self.compression;
            data[25] = self.checksum;
            apply_ctr(&mut data, &root_key);
            let mac = compute_mac(&root_key.mac, &data, &[&cluster_mac, &self.auth_data]);
            [&mac[..], &data, &cluster_mac].concat()
        }

        fn encode(&self) -> Vec<u8> {
            let main_key = self.main_key();
            let mut next_mac = [0u8; MAC_SIZE];
            let mut clusters = Vec::new();
            for index in (0..self.clusters.len()).rev() {
                let (bytes, mac) = self.cluster(&main_key, u32::try_from(index).unwrap(), next_mac);
                clusters.insert(0, bytes);
                next_mac = mac;
            }
            let mut prologue = AEA_MAGIC.to_vec();
            prologue.extend_from_slice(&self.profile.to_le_bytes());
            let auth_length = u32::try_from(self.auth_data.len()).unwrap();
            prologue.extend_from_slice(&auth_length.to_le_bytes());
            prologue.extend_from_slice(&self.auth_data);
            prologue.extend_from_slice(&TEST_MAIN_SALT);
            let clusters = clusters.concat();
            let total = (prologue.len() + ENCRYPTED_ROOT_SIZE + clusters.len()) as u64;
            let root = self.root(&main_key, next_mac, self.encrypted_size.unwrap_or(total));
            [prologue, root, clusters].concat()
        }

        fn open(&self) -> Result<AeaReader<Vec<u8>>, AeaError> {
            AeaReader::open_with_symmetric_key(self.encode(), &TEST_SYMMETRIC_KEY)
        }
    }

    fn compute_mac(key: &[u8], data: &[u8], salt: &[&[u8]]) -> Mac32 {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        for part in salt {
            mac.update(part);
        }
        mac.update(data);
        let salt_length: usize = salt.iter().map(|part| part.len()).sum();
        mac.update(&(salt_length as u64).to_le_bytes());
        mac.finalize().into_bytes().into()
    }

    fn pattern(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| (index * 7 % 251).to_le_bytes()[0])
            .collect()
    }

    fn read_all(reader: &AeaReader<Vec<u8>>) -> io::Result<Vec<u8>> {
        let mut output = vec![0; usize::try_from(reader.size()).unwrap()];
        reader.read_exact_at(&mut output, 0)?;
        Ok(output)
    }

    #[test]
    fn decodes_stored_and_compressed_segments_across_clusters() {
        let plain = pattern(100);
        let mut spec = ArchiveSpec::new(16, 3, &plain);
        spec.clusters[0][1] = compressed_segment(&plain[16..32]);
        let reader = spec.open().unwrap();
        assert_eq!(reader.segment_size(), 16);
        assert_eq!(read_all(&reader).unwrap(), plain);
    }

    #[test]
    fn evicts_least_recent_segments_beyond_the_cache_bound() {
        let plain = pattern(4 * (AEA_DECODED_SEGMENT_CACHE_COUNT + 2));
        let reader = ArchiveSpec::new(4, 8, &plain).open().unwrap();
        assert_eq!(read_all(&reader).unwrap(), plain);
        assert_eq!(read_all(&reader).unwrap(), plain);
        let cache = reader.lock_cache();
        assert_eq!(cache.entries.len(), AEA_DECODED_SEGMENT_CACHE_COUNT);
        assert_eq!(cache.order.len(), AEA_DECODED_SEGMENT_CACHE_COUNT);
    }

    fn open_error(spec: &ArchiveSpec) -> String {
        spec.open().unwrap_err().to_string()
    }

    #[test]
    fn rejects_invalid_root_headers() {
        let plain = pattern(32);
        let mut cases: Vec<(ArchiveSpec, &str)> = Vec::new();
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.file_size = 0;
        cases.push((spec, "invalid AEA output size 0"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.encrypted_size = Some(1);
        cases.push((spec, "AEA encrypted size is 1"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.segments_per_cluster = 0;
        spec.clusters.clear();
        cases.push((spec, "invalid segment layout"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.checksum = 1;
        cases.push((spec, "unsupported AEA encoding"));
        for (spec, expected) in cases {
            let error = open_error(&spec);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_unsupported_prologues() {
        let mut spec = ArchiveSpec::new(16, 2, &pattern(16));
        spec.profile = 2;
        assert!(matches!(spec.open(), Err(AeaError::UnsupportedProfile(2))));
        let mut oversized = ArchiveSpec::new(16, 2, &pattern(16)).encode();
        oversized[8..12].copy_from_slice(&(MAX_AEA_AUTH_DATA_SIZE + 1).to_le_bytes());
        assert!(matches!(
            AeaReader::open_with_symmetric_key(oversized, &TEST_SYMMETRIC_KEY),
            Err(AeaError::AuthDataTooLarge(_))
        ));
        assert!(matches!(
            parse_metadata(&[1, 2]),
            Err(AeaError::InvalidMetadataRecordLength(0))
        ));
    }

    #[test]
    fn rejects_clusters_missing_from_the_image() {
        let mut spec = ArchiveSpec::new(16, 2, &pattern(32));
        spec.clusters.clear();
        assert!(matches!(spec.open(), Err(AeaError::ClusterOutOfBounds)));
    }

    #[test]
    fn rejects_inconsistent_segment_headers() {
        let plain = pattern(32);
        let mut cases: Vec<(ArchiveSpec, &str)> = Vec::new();
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.clusters[0][0].decompressed = 0;
        cases.push((spec, "has compressed data without output"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.clusters[0][0].decompressed = 17;
        cases.push((spec, "has invalid sizes"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.clusters[0][1].compressed = 1000;
        cases.push((spec, "extends beyond the encrypted image"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.file_size = 24;
        cases.push((spec, "extends beyond the declared output"));
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.clusters[0][0] = stored_segment(&plain[..8]);
        spec.file_size = 16;
        cases.push((spec, "is outside the declared output"));
        for (spec, expected) in cases {
            let error = open_error(&spec);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn skips_empty_segment_slots() {
        let plain = pattern(16);
        let mut spec = ArchiveSpec::new(16, 2, &plain);
        spec.clusters[0].push(SegmentSpec {
            decompressed: 0,
            compressed: 0,
            checksum: [0; 32],
            stored: Vec::new(),
        });
        assert_eq!(read_all(&spec.open().unwrap()).unwrap(), plain);
    }

    fn read_error(spec: &ArchiveSpec) -> String {
        read_all(&spec.open().unwrap()).unwrap_err().to_string()
    }

    #[test]
    fn rejects_segments_failing_decoding_or_checksum() {
        let plain = pattern(16);
        let mut spec = ArchiveSpec::new(16, 1, &plain);
        spec.clusters[0][0].checksum[0] ^= 1;
        assert!(read_error(&spec).contains("failed checksum verification"));
        let mut spec = ArchiveSpec::new(16, 1, &plain);
        spec.clusters[0][0].stored = vec![0xee; 8];
        spec.clusters[0][0].compressed = 8;
        assert!(read_error(&spec).contains("decompress AEA cluster 0 segment 0"));
        let mut spec = ArchiveSpec::new(16, 1, &plain);
        spec.clusters[0][0] = compressed_segment(&plain[..12]);
        spec.clusters[0][0].decompressed = 16;
        assert!(read_error(&spec).contains("produced 12 bytes, expected 16"));
    }

    #[test]
    fn validates_fcs_key_urls() {
        let mut metadata = AeaMetadata::new();
        assert!(matches!(
            fcs_key_url(&metadata),
            Err(AeaError::MissingMetadata(_))
        ));
        for url in [
            "not a url",
            "http://wkms-public.apple.com/key",
            "https://example.com/key",
        ] {
            metadata.insert(FCS_KEY_URL_FIELD.to_vec(), url.as_bytes().to_vec());
            assert!(matches!(
                fcs_key_url(&metadata),
                Err(AeaError::InvalidKeyUrl(_))
            ));
        }
        let valid = "https://wkms-public.apple.com/fcs-keys/key";
        metadata.insert(FCS_KEY_URL_FIELD.to_vec(), valid.as_bytes().to_vec());
        assert_eq!(fcs_key_url(&metadata).unwrap().as_str(), valid);
    }

    #[test]
    fn downloads_the_fcs_key_named_by_the_archive() {
        let expected = fixture!("synthetic.out");
        let reader = AeaReader::open_downloading(fixture!("synthetic.aea").to_vec(), |url| {
            assert_eq!(url, "https://wkms-public.apple.com/fcs-keys/synthetic");
            Ok(fixture!("synthetic_fcs_key.pem").to_vec())
        })
        .unwrap();
        assert_eq!(read_all(&reader).unwrap(), expected);
        let failed = AeaReader::open_downloading(fixture!("synthetic.aea").to_vec(), |_| {
            Err(HttpRangeError::RuntimeUnavailable)
        });
        assert!(matches!(failed, Err(AeaError::Http(_))));
    }

    #[test]
    fn open_downloads_the_fcs_key_through_the_http_client() {
        let http = BlockingHttp::without_runtime();
        let opened = AeaReader::open(fixture!("synthetic.aea").to_vec(), &http);
        assert!(matches!(
            opened,
            Err(AeaError::Http(HttpRangeError::RuntimeUnavailable))
        ));
    }

    #[test]
    fn open_refuses_archives_without_an_fcs_key_url() {
        let http = BlockingHttp::new().unwrap();
        let source = ArchiveSpec::new(16, 1, &pattern(16)).encode();
        assert!(matches!(
            AeaReader::open(source, &http),
            Err(AeaError::MissingMetadata(_))
        ));
    }

    #[test]
    fn rejects_malformed_fcs_keys_and_responses() {
        let pem = fixture!("synthetic_fcs_key.pem");
        let metadata = |response: &str| {
            AeaMetadata::from([(FCS_RESPONSE_FIELD.to_vec(), response.as_bytes().to_vec())])
        };
        let valid = metadata(r#"{"enc-request":"","wrapped-key":""}"#);
        assert!(matches!(
            unwrap_symmetric_key(&[0xff, 0xfe], &valid),
            Err(AeaError::InvalidPrivateKey(_))
        ));
        assert!(matches!(
            unwrap_symmetric_key(b"not a pem", &valid),
            Err(AeaError::InvalidPrivateKey(_))
        ));
        assert!(matches!(
            unwrap_symmetric_key(pem, &AeaMetadata::new()),
            Err(AeaError::MissingMetadata(_))
        ));
        for response in ["{", r#"{"enc-request":"!!"}"#] {
            assert!(matches!(
                unwrap_symmetric_key(pem, &metadata(response)),
                Err(AeaError::InvalidFcsResponse(_))
            ));
        }
        let short = metadata(r#"{"enc-request":"BAAA","wrapped-key":""}"#);
        assert!(matches!(
            unwrap_symmetric_key(pem, &short),
            Err(AeaError::Hpke("invalid encapsulated key"))
        ));
        let off_curve = BASE64.encode([&[SEC1_UNCOMPRESSED_TAG][..], &[1; 64]].concat());
        let off_curve = metadata(&format!(r#"{{"enc-request":"{off_curve}"}}"#));
        assert!(matches!(
            unwrap_symmetric_key(pem, &off_curve),
            Err(AeaError::Hpke("invalid encapsulated key"))
        ));
    }

    /// One byte past the longest HKDF-SHA256 output (255 blocks of 32 bytes).
    const OVERLONG_KEY: usize = 255 * 32 + 1;

    #[test]
    fn rejects_key_lengths_hkdf_cannot_expand() {
        assert!(matches!(
            derive_key(b"key", None, b"info", OVERLONG_KEY),
            Err(AeaError::KeyDerivation(OVERLONG_KEY))
        ));
        assert!(matches!(
            labeled_expand(b"suite", &[0; 32], b"label", b"info", OVERLONG_KEY),
            Err(AeaError::KeyDerivation(OVERLONG_KEY))
        ));
    }

    #[test]
    fn short_sources_report_the_read_context() {
        let source = vec![0_u8; 4];
        assert!(matches!(
            read_vec(&source, 2, 4, "segment"),
            Err(AeaError::Io { context: "segment", source })
                if source.kind() == io::ErrorKind::UnexpectedEof
        ));
        assert!(matches!(
            read_array::<8>(&source, 0, "root header"),
            Err(AeaError::Io { context: "root header", source })
                if source.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn lzfse_decoder_accepts_short_entropy_streams() {
        let mut decoded = Vec::new();
        lzfse_rust::decode_bytes(fixture!("lzfse_short.bin"), &mut decoded).unwrap();
        assert_eq!(decoded, vec![0; 65536]);
    }
}
