//! Read-only APFS access for the sealed system volumes of macOS cryptexes.
//!
//! Ported from ipatool `internal/sap/assets/apfs.go` and the parts of
//! `github.com/majd/go-apfs` it relies on: container and checkpoint
//! superblocks, object maps, the (optionally sealed and hashed) file-system
//! B-tree, the file-extent tree, path resolution and decmpfs transparent
//! compression (LZVN, LZFSE and LZBITMAP resource forks).
//!
//! Only raw APFS containers are supported; the cryptex images used by the
//! pinned restore image are not wrapped in UDIF disk images.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::http_range::{ReadAt, SectionReader};
use super::lz;

/// APFS block size handled by this reader.
const BLOCK_SIZE: usize = 4096;
/// [`BLOCK_SIZE`] as a 64-bit byte count.
const BLOCK_SIZE_U64: u64 = 4096;
/// Size of `obj_phys_t`.
const OBJECT_HEADER_SIZE: usize = 32;
/// Size of `obj_phys_t` plus `btree_node_phys_t` without its data.
const NODE_HEADER_SIZE: usize = 56;
/// Size of the `btree_info_t` trailer of a root node.
const BTREE_INFO_SIZE: usize = 40;
/// Offset of the container magic inside block zero.
const CONTAINER_MAGIC_OFFSET: usize = 32;
/// Container superblock magic.
const CONTAINER_MAGIC: &[u8; 4] = b"NXSB";
/// Volume superblock magic.
const VOLUME_MAGIC: &[u8; 4] = b"APSB";
/// Mask selecting the object type from `o_type`.
const OBJECT_TYPE_MASK: u32 = 0x0000_ffff;
/// `OBJECT_TYPE_NX_SUPERBLOCK`.
const OBJECT_TYPE_CONTAINER: u32 = 0x01;
/// `OBJECT_TYPE_BTREE`.
const OBJECT_TYPE_BTREE: u32 = 0x02;
/// `OBJECT_TYPE_BTREE_NODE`.
const OBJECT_TYPE_BTREE_NODE: u32 = 0x03;
/// `OBJECT_TYPE_OMAP`.
const OBJECT_TYPE_OMAP: u32 = 0x0b;
/// `OBJECT_TYPE_FS`.
const OBJECT_TYPE_VOLUME: u32 = 0x0d;
/// `btree_node_phys_t` flag: root node.
const NODE_ROOT: u16 = 0x0001;
/// `btree_node_phys_t` flag: leaf node.
const NODE_LEAF: u16 = 0x0002;
/// `btree_node_phys_t` flag: fixed-size keys and values.
const NODE_FIXED_KV: u16 = 0x0004;
/// `btree_node_phys_t` flag: index values carry child hashes.
const NODE_HASHED: u16 = 0x0008;
/// `btree_node_phys_t` flag: node is stored without an object header.
const NODE_NO_HEADER: u16 = 0x0010;
/// Value offset marking a key without a value.
const NO_VALUE_OFFSET: u16 = 0xffff;
/// Deepest B-tree accepted before declaring the image malformed.
const MAXIMUM_TREE_DEPTH: usize = 32;
/// Object identifier of the root directory.
const ROOT_DIRECTORY_ID: u64 = 2;
/// Mask selecting the object identifier from `obj_id_and_type`.
const RECORD_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
/// Shift selecting the record type from `obj_id_and_type`.
const RECORD_TYPE_SHIFT: u32 = 60;
/// `APFS_TYPE_INODE`.
const RECORD_INODE: u8 = 3;
/// `APFS_TYPE_XATTR`.
const RECORD_XATTR: u8 = 4;
/// `APFS_TYPE_FILE_EXTENT`.
const RECORD_FILE_EXTENT: u8 = 8;
/// `APFS_TYPE_DIR_REC`.
const RECORD_DIRECTORY_ENTRY: u8 = 9;
/// Mask selecting the length from an extent's `len_and_flags`.
const EXTENT_LENGTH_MASK: u64 = 0x00ff_ffff_ffff_ffff;
/// Mask selecting the name length from a directory entry key.
const DIRECTORY_NAME_LENGTH_MASK: u32 = 0x0000_03ff;
/// Size of `j_inode_val_t` without extended fields.
const INODE_VALUE_SIZE: usize = 92;
/// `INO_EXT_TYPE_DSTREAM`.
const INODE_FIELD_DATA_STREAM: u8 = 8;
/// Extended fields are padded to this alignment.
const INODE_FIELD_ALIGNMENT: usize = 8;
/// `XATTR_DATA_EMBEDDED`.
const XATTR_EMBEDDED: u16 = 0x0002;
/// Extended attribute holding the decmpfs header.
const DECMPFS_XATTR: &str = "com.apple.decmpfs";
/// Extended attribute holding the compressed resource fork.
const RESOURCE_FORK_XATTR: &str = "com.apple.ResourceFork";
/// Size of the decmpfs on-disk header.
const DECMPFS_HEADER_SIZE: usize = 16;
/// decmpfs LZVN resource-fork compression.
const DECMPFS_LZVN: u32 = 8;
/// decmpfs LZFSE resource-fork compression.
const DECMPFS_LZFSE: u32 = 12;
/// decmpfs LZBITMAP resource-fork compression.
const DECMPFS_LZBITMAP: u32 = 14;
/// Uncompressed size of one decmpfs block.
const DECMPFS_BLOCK_SIZE: u64 = 64 << 10;
/// First byte of an LZVN block stored uncompressed.
const DECMPFS_LZVN_STORED: u8 = 0x06;
/// First byte of every compressed LZFSE block (`bvx`).
const DECMPFS_LZFSE_MAGIC: u8 = b'b';
/// First byte of an LZBITMAP block stored uncompressed.
const DECMPFS_LZBITMAP_STORED: u8 = 0xff;
/// Decompressed blocks kept per compressed file.
const DECMPFS_CACHE_BLOCKS: usize = 128;
/// Size of one decmpfs block-offset table entry.
const DECMPFS_OFFSET_SIZE: u64 = 4;
/// Bytes copied per read while extracting a file.
const EXTRACT_CHUNK_SIZE: usize = 1 << 20;
/// Universal binary magic.
const FAT_MAGIC: u32 = 0xcafe_babe;
/// Size of `fat_header`.
const FAT_HEADER_SIZE: u64 = 8;
/// Size of `fat_arch`.
const FAT_ARCH_SIZE: u64 = 20;
/// `CPU_TYPE_ARM64`.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_SUBTYPE_ARM64E`.
const CPU_SUBTYPE_ARM64E: u32 = 2;
/// Mask removing capability bits from a CPU subtype.
const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;
/// Extension of images that are copied without architecture thinning.
const UNTHINNED_EXTENSION: &str = "icxs";

/// Errors raised while reading an APFS container.
#[derive(Debug, Error)]
pub enum ApfsError {
    /// The underlying source failed.
    #[error("read Apple filesystem {context}: {source}")]
    Read {
        /// What was being read.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The image contains a malformed structure.
    #[error("malformed Apple filesystem: {0}")]
    Malformed(String),
    /// The image uses a feature this reader does not implement.
    #[error("unsupported Apple filesystem feature: {0}")]
    Unsupported(String),
    /// A path component does not exist.
    #[error("path component {0:?} was not found")]
    NotFound(String),
    /// A block failed its Fletcher-64 checksum.
    #[error("block {0:#x} failed checksum validation")]
    Checksum(u64),
    /// A sealed tree node failed SHA-256 verification.
    #[error("filesystem child {0:#x} failed SHA-256 verification")]
    Hash(u64),
    /// A compressed block could not be decoded.
    #[error("decode compressed block {block}: {source}")]
    Decompress {
        /// Index of the failing decmpfs block.
        block: u64,
        /// Decoder error.
        #[source]
        source: lz::LzError,
    },
    /// Writing an extracted file failed.
    #[error("write {path}: {source}")]
    Output {
        /// Destination path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

type Result<T> = std::result::Result<T, ApfsError>;

fn malformed(message: impl Into<String>) -> ApfsError {
    ApfsError::Malformed(message.into())
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| malformed(format!("structure truncated at offset {offset}")))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    field(bytes, offset).map(u16::from_le_bytes)
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    field(bytes, offset).map(u32::from_le_bytes)
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    field(bytes, offset).map(u64::from_le_bytes)
}

fn trimmed_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_matches('\0').to_owned()
}

fn to_usize(value: u64) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| malformed(format!("value {value} exceeds the address space")))
}

/// Fletcher-64 checksum used by every APFS object header.
fn fletcher64(block: &[u8]) -> u64 {
    const MODULUS: u64 = 0xffff_ffff;
    let (mut low, mut high) = (0u64, 0u64);
    for word in block[8..].as_chunks::<4>().0 {
        low = (low + u64::from(u32::from_le_bytes([word[0], word[1], word[2], word[3]]))) % MODULUS;
        high = (high + low) % MODULUS;
    }
    let check_low = MODULUS - ((low + high) % MODULUS);
    let check_high = MODULUS - ((low + check_low) % MODULUS);
    (check_high << 32) | check_low
}

fn object_type(block: &[u8]) -> Result<u32> {
    Ok(le_u32(block, 24)? & OBJECT_TYPE_MASK)
}

fn object_transaction(block: &[u8]) -> Result<u64> {
    le_u64(block, 16)
}

/// Sealed-volume tree nodes omit the object header entirely.
fn is_headerless_node(block: &[u8]) -> bool {
    block[..OBJECT_HEADER_SIZE].iter().all(|&byte| byte == 0)
        && u16::from_le_bytes([block[OBJECT_HEADER_SIZE], block[OBJECT_HEADER_SIZE + 1]])
            & NODE_NO_HEADER
            != 0
}

/// One decoded B-tree node block.
struct Node {
    block: Vec<u8>,
    flags: u16,
    count: usize,
    table_offset: usize,
    table_length: usize,
}

/// Raw key and optional value of one node entry.
struct Entry<'a> {
    key: &'a [u8],
    value: Option<&'a [u8]>,
}

impl Node {
    fn parse(block: Vec<u8>) -> Result<Self> {
        let header = OBJECT_HEADER_SIZE;
        let count = to_usize(u64::from(le_u32(&block, header + 4)?))?;
        Ok(Self {
            flags: le_u16(&block, header)?,
            count,
            table_offset: usize::from(le_u16(&block, header + 8)?),
            table_length: usize::from(le_u16(&block, header + 10)?),
            block,
        })
    }

    fn is_leaf(&self) -> bool {
        self.flags & NODE_LEAF != 0
    }

    fn is_hashed(&self) -> bool {
        self.flags & NODE_HASHED != 0
    }

    fn value_area_end(&self) -> usize {
        if self.flags & NODE_ROOT != 0 {
            BLOCK_SIZE - BTREE_INFO_SIZE
        } else {
            BLOCK_SIZE
        }
    }

    fn slice(&self, start: usize, length: usize) -> Result<&[u8]> {
        self.block
            .get(start..start + length)
            .ok_or_else(|| malformed("tree entry exceeds its node"))
    }

    fn key_start(&self, offset: u16) -> usize {
        NODE_HEADER_SIZE + self.table_length + usize::from(offset)
    }

    fn value_start(&self, offset: u16) -> Result<usize> {
        self.value_area_end()
            .checked_sub(usize::from(offset))
            .ok_or_else(|| malformed("tree value offset exceeds its node"))
    }

    /// Entry `index` of a node with variable-size keys and values.
    fn entry(&self, index: usize) -> Result<Entry<'_>> {
        let toc = NODE_HEADER_SIZE + self.table_offset + index * 8;
        let (key_offset, key_length) = (le_u16(&self.block, toc)?, le_u16(&self.block, toc + 2)?);
        let (value_offset, value_length) =
            (le_u16(&self.block, toc + 4)?, le_u16(&self.block, toc + 6)?);
        let key = self.slice(self.key_start(key_offset), usize::from(key_length))?;
        let value = if value_offset == NO_VALUE_OFFSET {
            None
        } else {
            Some(self.slice(self.value_start(value_offset)?, usize::from(value_length))?)
        };
        Ok(Entry { key, value })
    }

    /// Entry `index` of a node with fixed-size keys and values.
    fn fixed_entry(
        &self,
        index: usize,
        key_length: usize,
        value_length: usize,
    ) -> Result<Entry<'_>> {
        let toc = NODE_HEADER_SIZE + self.table_offset + index * 4;
        let (key_offset, value_offset) = (le_u16(&self.block, toc)?, le_u16(&self.block, toc + 2)?);
        let key = self.slice(self.key_start(key_offset), key_length)?;
        let value = if value_offset == NO_VALUE_OFFSET {
            None
        } else {
            Some(self.slice(self.value_start(value_offset)?, value_length)?)
        };
        Ok(Entry { key, value })
    }

    /// Entry `index` of an object-map or extent tree (16-byte keys).
    fn map_entry(&self, index: usize) -> Result<Entry<'_>> {
        const KEY_LENGTH: usize = 16;
        const LEAF_VALUE_LENGTH: usize = 16;
        const INDEX_VALUE_LENGTH: usize = 8;
        let value_length = if self.is_leaf() {
            LEAF_VALUE_LENGTH
        } else {
            INDEX_VALUE_LENGTH
        };
        if self.flags & NODE_FIXED_KV != 0 {
            self.fixed_entry(index, KEY_LENGTH, value_length)
        } else {
            self.entry(index)
        }
    }
}

/// One contiguous run of a file's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Extent {
    logical: u64,
    physical: u64,
    length: u64,
}

/// Value of an extended attribute.
enum XattrValue {
    Embedded(Vec<u8>),
    Stream { object_id: u64, size: u64 },
}

impl XattrValue {
    /// The data-stream object and size of a non-embedded attribute.
    fn stream(&self) -> Option<(u64, u64)> {
        match self {
            Self::Stream { object_id, size } => Some((*object_id, *size)),
            Self::Embedded(_) => None,
        }
    }
}

/// The file-system records the extractor understands.
enum Record {
    Inode { private_id: u64, size: u64 },
    Extent(Extent),
    Xattr { name: String, value: XattrValue },
    DirectoryEntry { name: String, file_id: u64 },
    Other,
}

fn parse_record(record_type: u8, key: &[u8], value: &[u8]) -> Result<Record> {
    match record_type {
        RECORD_INODE => parse_inode(value),
        RECORD_FILE_EXTENT => Ok(Record::Extent(Extent {
            logical: le_u64(key, 8)?,
            length: le_u64(value, 0)? & EXTENT_LENGTH_MASK,
            physical: le_u64(value, 8)?,
        })),
        RECORD_XATTR => parse_xattr(key, value),
        RECORD_DIRECTORY_ENTRY => {
            let length = (le_u32(key, 8)? & DIRECTORY_NAME_LENGTH_MASK) as usize;
            let name = key
                .get(12..12 + length)
                .ok_or_else(|| malformed("directory entry name is truncated"))?;
            Ok(Record::DirectoryEntry {
                name: trimmed_name(name),
                file_id: le_u64(value, 0)?,
            })
        }
        _ => Ok(Record::Other),
    }
}

fn parse_inode(value: &[u8]) -> Result<Record> {
    const PRIVATE_ID_OFFSET: usize = 8;
    const UNCOMPRESSED_SIZE_OFFSET: usize = 84;
    let private_id = le_u64(value, PRIVATE_ID_OFFSET)?;
    let mut size = le_u64(value, UNCOMPRESSED_SIZE_OFFSET)?;
    if value.len() != INODE_VALUE_SIZE
        && let Some(stream_size) = inode_stream_size(&value[INODE_VALUE_SIZE..])?
    {
        size = stream_size;
    }
    Ok(Record::Inode { private_id, size })
}

/// Size of the first `INO_EXT_TYPE_DSTREAM` extended field, if any.
fn inode_stream_size(blob: &[u8]) -> Result<Option<u64>> {
    const BLOB_HEADER_SIZE: usize = 4;
    const FIELD_HEADER_SIZE: usize = 4;
    let count = usize::from(le_u16(blob, 0)?);
    let mut data = BLOB_HEADER_SIZE + count * FIELD_HEADER_SIZE;
    for index in 0..count {
        let header = BLOB_HEADER_SIZE + index * FIELD_HEADER_SIZE;
        let kind = *blob
            .get(header)
            .ok_or_else(|| malformed("inode field header is truncated"))?;
        if kind == INODE_FIELD_DATA_STREAM {
            return le_u64(blob, data).map(Some);
        }
        let length = usize::from(le_u16(blob, header + 2)?);
        data += length.div_ceil(INODE_FIELD_ALIGNMENT) * INODE_FIELD_ALIGNMENT;
    }
    Ok(None)
}

fn parse_xattr(key: &[u8], value: &[u8]) -> Result<Record> {
    const STREAM_OBJECT_OFFSET: usize = 4;
    const STREAM_SIZE_OFFSET: usize = 12;
    let name_length = usize::from(le_u16(key, 8)?);
    let name = trimmed_name(
        key.get(10..10 + name_length)
            .ok_or_else(|| malformed("xattr name is truncated"))?,
    );
    let flags = le_u16(value, 0)?;
    let value = if flags & XATTR_EMBEDDED != 0 {
        let length = usize::from(le_u16(value, 2)?);
        let data = value
            .get(4..4 + length)
            .ok_or_else(|| malformed("xattr data is truncated"))?;
        XattrValue::Embedded(data.to_vec())
    } else {
        XattrValue::Stream {
            object_id: le_u64(value, STREAM_OBJECT_OFFSET)?,
            size: le_u64(value, STREAM_SIZE_OFFSET)?,
        }
    };
    Ok(Record::Xattr { name, value })
}

/// Block-level access to a raw APFS container.
struct Container<R> {
    device: R,
}

/// An opened APFS container and its first volume.
pub struct ApfsExtractor<R> {
    container: Container<R>,
    volume_omap: Node,
    filesystem_root: Node,
    root_tree_base: u64,
    transaction_id: u64,
    extent_tree: u64,
}

/// Locations read from the volume superblock.
struct VolumeInfo {
    xid: u64,
    omap: u64,
    root_tree: u64,
    extent_tree: u64,
}

impl<R: ReadAt> ApfsExtractor<R> {
    /// Opens the container at offset zero of `device` and mounts its first
    /// volume read-only.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is not a raw APFS container or any
    /// superblock, object map or tree root is unreadable or malformed.
    pub fn open(device: R) -> Result<Self> {
        let container = Container { device };
        container.check_container_magic()?;
        let volume = container.read_volume_info()?;
        let (transaction_id, volume_omap) = container.read_omap(volume.omap)?;
        let root = container.omap_lookup(&volume_omap, volume.root_tree, volume.xid)?;
        let filesystem_root = container.read_node(root)?;
        let extractor = Self {
            container,
            volume_omap,
            filesystem_root,
            root_tree_base: volume.root_tree,
            transaction_id,
            extent_tree: volume.extent_tree,
        };
        Ok(extractor)
    }
}

impl<R: ReadAt> Container<R> {
    fn check_container_magic(&self) -> Result<()> {
        let device = &self.device;
        let mut header = [0u8; CONTAINER_MAGIC_OFFSET + 4];
        if device.size() < header.len() as u64 {
            return Err(malformed(format!("image is too small: {}", device.size())));
        }
        device
            .read_exact_at(&mut header, 0)
            .map_err(|source| ApfsError::Read {
                context: "header".into(),
                source,
            })?;
        if &header[CONTAINER_MAGIC_OFFSET..] != CONTAINER_MAGIC {
            return Err(ApfsError::Unsupported(
                "image is not a raw APFS container (disk images are not supported)".into(),
            ));
        }
        Ok(())
    }

    fn read_block(&self, address: u64) -> Result<Vec<u8>> {
        let offset = address
            .checked_mul(BLOCK_SIZE_U64)
            .ok_or_else(|| malformed(format!("block address {address:#x} overflows")))?;
        let mut block = vec![0u8; BLOCK_SIZE];
        self.device
            .read_exact_at(&mut block, offset)
            .map_err(|source| ApfsError::Read {
                context: format!("block {address:#x}"),
                source,
            })?;
        Ok(block)
    }

    /// Reads a block and verifies its object checksum. Headerless sealed
    /// nodes are accepted as is; their integrity comes from the parent hash.
    fn read_object(&self, address: u64) -> Result<Vec<u8>> {
        let block = self.read_block(address)?;
        if is_headerless_node(&block) || fletcher64(&block) == le_u64(&block, 0)? {
            Ok(block)
        } else {
            Err(ApfsError::Checksum(address))
        }
    }

    fn read_typed_object(&self, address: u64, expected: u32, what: &str) -> Result<Vec<u8>> {
        let block = self.read_object(address)?;
        if object_type(&block)? == expected {
            Ok(block)
        } else {
            Err(malformed(format!("block {address:#x} is not a {what}")))
        }
    }

    fn read_node(&self, address: u64) -> Result<Node> {
        let block = self.read_object(address)?;
        let kind = object_type(&block)?;
        if is_headerless_node(&block) || kind == OBJECT_TYPE_BTREE || kind == OBJECT_TYPE_BTREE_NODE
        {
            Node::parse(block)
        } else {
            Err(malformed(format!("block {address:#x} is not a tree node")))
        }
    }

    /// Reads an object map and returns its transaction and tree root.
    fn read_omap(&self, address: u64) -> Result<(u64, Node)> {
        const TREE_OFFSET: usize = 48;
        let omap = self.read_typed_object(address, OBJECT_TYPE_OMAP, "object map")?;
        let tree = self.read_node(le_u64(&omap, TREE_OFFSET)?)?;
        Ok((object_transaction(&omap)?, tree))
    }

    fn read_volume_info(&self) -> Result<VolumeInfo> {
        const CONTAINER_OMAP_OFFSET: usize = 160;
        const FIRST_VOLUME_OFFSET: usize = 184;
        const VOLUME_OMAP_OFFSET: usize = 128;
        const VOLUME_ROOT_TREE_OFFSET: usize = 136;
        const VOLUME_EXTENT_TREE_OFFSET: usize = 1032;
        let container = self.latest_checkpoint()?;
        let (_, container_omap) = self.read_omap(le_u64(&container, CONTAINER_OMAP_OFFSET)?)?;
        let volume_id = le_u64(&container, FIRST_VOLUME_OFFSET)?;
        let checkpoint_xid = object_transaction(&container)?;
        let address = self.omap_lookup(&container_omap, volume_id, checkpoint_xid)?;
        let volume = self.read_typed_object(address, OBJECT_TYPE_VOLUME, "volume superblock")?;
        if field::<4>(&volume, CONTAINER_MAGIC_OFFSET)? != *VOLUME_MAGIC {
            return Err(malformed("volume superblock has an invalid magic"));
        }
        let xid = object_transaction(&volume)?;
        let omap = le_u64(&volume, VOLUME_OMAP_OFFSET)?;
        let root_tree = le_u64(&volume, VOLUME_ROOT_TREE_OFFSET)?;
        let extent_tree = le_u64(&volume, VOLUME_EXTENT_TREE_OFFSET)?;
        let info = VolumeInfo {
            xid,
            omap,
            root_tree,
            extent_tree,
        };
        Ok(info)
    }

    /// Returns the valid checkpoint superblock with the highest transaction.
    fn latest_checkpoint(&self) -> Result<Vec<u8>> {
        const BLOCK_SIZE_OFFSET: usize = 36;
        const DESCRIPTOR_BLOCKS_OFFSET: usize = 104;
        const DESCRIPTOR_BASE_OFFSET: usize = 112;
        const NON_CONTIGUOUS: u32 = 1 << 31;
        let (kind, what) = (OBJECT_TYPE_CONTAINER, "container superblock");
        let superblock = self.read_typed_object(0, kind, what)?;
        if u64::from(le_u32(&superblock, BLOCK_SIZE_OFFSET)?) != BLOCK_SIZE_U64 {
            return Err(ApfsError::Unsupported("non-4096-byte block size".into()));
        }
        let blocks = le_u32(&superblock, DESCRIPTOR_BLOCKS_OFFSET)?;
        if blocks & NON_CONTIGUOUS != 0 {
            return Err(ApfsError::Unsupported(
                "non-contiguous checkpoint descriptor area".into(),
            ));
        }
        let base = le_u64(&superblock, DESCRIPTOR_BASE_OFFSET)?;
        let mut latest: Option<Vec<u8>> = None;
        for index in 0..u64::from(blocks) {
            if let Some(candidate) = self.checkpoint_candidate(base + index)? {
                keep_newer_checkpoint(&mut latest, candidate)?;
            }
        }
        latest.ok_or_else(|| malformed("checkpoint area has no valid container superblock"))
    }

    /// Reads a checkpoint-area block, skipping blocks that are not valid
    /// container superblocks.
    fn checkpoint_candidate(&self, address: u64) -> Result<Option<Vec<u8>>> {
        match self.read_object(address) {
            Ok(block) if object_type(&block)? == OBJECT_TYPE_CONTAINER => Ok(Some(block)),
            Ok(_) | Err(ApfsError::Checksum(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Resolves a virtual object to its physical address (go-apfs
    /// `GetOMapEntry` semantics: newest version not after `max_xid`).
    fn omap_lookup(&self, root: &Node, object_id: u64, max_xid: u64) -> Result<u64> {
        let mut child: Option<Node> = None;
        for _ in 0..MAXIMUM_TREE_DEPTH {
            let node = child.as_ref().unwrap_or(root);
            let index = Self::omap_floor(node, object_id, max_xid)?;
            let entry = node.map_entry(index)?;
            let value = entry.value;
            let value = value.ok_or_else(|| malformed("object map entry has no value"))?;
            if node.is_leaf() {
                let (oid, xid) = (le_u64(entry.key, 0)?, le_u64(entry.key, 8)?);
                if oid != object_id || xid > max_xid {
                    let reason = format!("object {object_id:#x} is not in the object map");
                    return Err(malformed(reason));
                }
                return le_u64(value, 8);
            }
            child = Some(self.read_node(le_u64(value, 0)?)?);
        }
        Err(malformed("object map exceeds maximum depth"))
    }

    fn omap_floor(node: &Node, object_id: u64, max_xid: u64) -> Result<usize> {
        for index in 0..node.count {
            let key = node.map_entry(index)?.key;
            let (oid, xid) = (le_u64(key, 0)?, le_u64(key, 8)?);
            if oid > object_id || (oid == object_id && xid > max_xid) {
                return index.checked_sub(1).ok_or_else(|| {
                    malformed(format!("object {object_id:#x} is not in the object map"))
                });
            }
        }
        node.count
            .checked_sub(1)
            .ok_or_else(|| malformed("object map node is empty"))
    }
}

impl<R: ReadAt> ApfsExtractor<R> {
    /// Opens the file at `path` for random-access reads.
    ///
    /// # Errors
    ///
    /// Returns an error when the path does not resolve to a regular file or
    /// its extents or compression metadata are invalid or unsupported.
    pub fn open_file(&self, path: &str) -> Result<ApfsFile<'_, R>> {
        let file = FileRecords::collect(self.resolve_path(path)?)?;
        let missing_inode = || malformed("file has no inode record");
        let (private_id, size) = file.inode.ok_or_else(missing_inode)?;
        if let Some((method, output_size)) = file.compression {
            return self.open_compressed(method, output_size, file.resource);
        }
        let mut extents = file.extents;
        if extents.is_empty() && size != 0 {
            extents = self.data_extents(private_id)?;
        }
        let reader = ExtentReader::new(&self.container.device, extents, size)?;
        Ok(ApfsFile::Plain(reader))
    }

    fn open_compressed(
        &self,
        method: u32,
        output_size: u64,
        resource: Option<(u64, u64)>,
    ) -> Result<ApfsFile<'_, R>> {
        if ![DECMPFS_LZVN, DECMPFS_LZFSE, DECMPFS_LZBITMAP].contains(&method) {
            return Err(ApfsError::Unsupported(format!("compression type {method}")));
        }
        let resource = resource.ok_or_else(|| malformed("compressed file has no resource fork"));
        let (object_id, size) = resource?;
        let extents = self.data_extents(object_id)?;
        let source = ExtentReader::new(&self.container.device, extents, size)?;
        let reader = DecmpfsReader::new(source, output_size, method)?;
        Ok(ApfsFile::Compressed(reader))
    }

    fn resolve_path(&self, path: &str) -> Result<Vec<Record>> {
        let mut object_id = ROOT_DIRECTORY_ID;
        for component in path.trim_matches('/').split('/') {
            object_id = self
                .records_for(object_id)?
                .into_iter()
                .find_map(|record| match record {
                    Record::DirectoryEntry { name, file_id } if name == component => Some(file_id),
                    _ => None,
                })
                .ok_or_else(|| ApfsError::NotFound(component.to_owned()))?;
        }
        self.records_for(object_id)
    }

    fn records_for(&self, object_id: u64) -> Result<Vec<Record>> {
        let mut visited = HashSet::new();
        let mut records = Vec::new();
        let root = &self.filesystem_root;
        self.collect_records(root, object_id, &mut visited, 0, &mut records)?;
        Ok(records)
    }

    fn collect_records(
        &self,
        node: &Node,
        object_id: u64,
        visited: &mut HashSet<u64>,
        depth: usize,
        records: &mut Vec<Record>,
    ) -> Result<()> {
        if depth > MAXIMUM_TREE_DEPTH {
            return Err(malformed("filesystem tree exceeds maximum depth"));
        }
        for index in 0..node.count {
            let entry = node.entry(index)?;
            let header = le_u64(entry.key, 0)?;
            if node.is_leaf() {
                if header & RECORD_ID_MASK == object_id {
                    let record_type = (header >> RECORD_TYPE_SHIFT) as u8;
                    let value = entry.value.unwrap_or_default();
                    records.push(parse_record(record_type, entry.key, value)?);
                }
            } else if Self::child_may_contain(node, index, header & RECORD_ID_MASK, object_id)? {
                let (child, address) = self.filesystem_child(node, entry.value)?;
                if visited.insert(address) {
                    self.collect_records(&child, object_id, visited, depth + 1, records)?;
                }
            }
        }
        Ok(())
    }

    fn child_may_contain(node: &Node, index: usize, lower: u64, object_id: u64) -> Result<bool> {
        let upper = if index + 1 < node.count {
            le_u64(node.entry(index + 1)?.key, 0)? & RECORD_ID_MASK
        } else {
            u64::MAX
        };
        Ok(lower <= object_id && object_id <= upper)
    }

    fn filesystem_child(&self, node: &Node, value: Option<&[u8]>) -> Result<(Node, u64)> {
        const HASH_OFFSET: usize = 8;
        let value = value.ok_or_else(|| {
            malformed("sealed filesystem tree contains an invalid child reference")
        })?;
        let child_id = le_u64(value, 0)?;
        let (object_id, expected_hash) = if node.is_hashed() {
            let hash: [u8; 32] = field(value, HASH_OFFSET)?;
            (self.root_tree_base.wrapping_add(child_id), Some(hash))
        } else {
            (child_id, None)
        };
        let (container, xid) = (&self.container, self.transaction_id);
        let address = container.omap_lookup(&self.volume_omap, object_id, xid)?;
        if let Some(expected) = expected_hash {
            let digest: [u8; 32] = Sha256::digest(self.container.read_block(address)?).into();
            if digest != expected {
                return Err(ApfsError::Hash(object_id));
            }
        }
        Ok((self.container.read_node(address)?, address))
    }

    fn data_extents(&self, object_id: u64) -> Result<Vec<Extent>> {
        let mut extents = if self.extent_tree == 0 {
            self.records_for(object_id)?
                .into_iter()
                .filter_map(|record| match record {
                    Record::Extent(extent) => Some(extent),
                    _ => None,
                })
                .collect()
        } else {
            let root = self.container.read_node(self.extent_tree)?;
            let mut extents = Vec::new();
            self.collect_physical_extents(&root, object_id, &mut HashSet::new(), 0, &mut extents)?;
            extents
        };
        extents.sort_by_key(|extent| extent.logical);
        Ok(extents)
    }

    fn collect_physical_extents(
        &self,
        node: &Node,
        object_id: u64,
        visited: &mut HashSet<u64>,
        depth: usize,
        extents: &mut Vec<Extent>,
    ) -> Result<()> {
        if depth > MAXIMUM_TREE_DEPTH {
            return Err(malformed("physical extent tree exceeds maximum depth"));
        }
        for index in 0..node.count {
            let entry = node.map_entry(index)?;
            if node.is_leaf() {
                if le_u64(entry.key, 0)? == object_id {
                    extents.push(physical_extent(entry.key, entry.value)?);
                }
            } else {
                let address = Self::extent_child(node, index, &entry, object_id)?;
                if let Some(address) = address.filter(|address| visited.insert(*address)) {
                    let child = self.container.read_node(address)?;
                    self.collect_physical_extents(&child, object_id, visited, depth + 1, extents)?;
                }
            }
        }
        Ok(())
    }

    /// Physical address of an extent-tree index child that may hold
    /// `object_id`'s extents.
    fn extent_child(
        node: &Node,
        index: usize,
        entry: &Entry<'_>,
        object_id: u64,
    ) -> Result<Option<u64>> {
        let lower = le_u64(entry.key, 0)?;
        let upper = if index + 1 < node.count {
            le_u64(node.map_entry(index + 1)?.key, 0)?
        } else {
            u64::MAX
        };
        if object_id < lower || object_id > upper {
            return Ok(None);
        }
        let value = entry.value;
        let value = value.ok_or_else(|| malformed("extent index has no child"))?;
        le_u64(value, 0).map(Some)
    }

    /// Extracts `path` into `destination` under its base name. When `thin`
    /// is set and the file is a universal binary, only its arm64e slice is
    /// written.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened or decoded, it has no
    /// arm64e slice, or the output cannot be created or written.
    pub fn extract_file(&self, path: &str, destination: &Path, thin: bool) -> Result<()> {
        let file = self.open_file(path)?;
        let (offset, size) = if thin {
            arm64e_range(&file)?
        } else {
            (0, file.size())
        };
        let name = Path::new(path)
            .file_name()
            .ok_or_else(|| malformed(format!("path {path:?} has no file name")))?;
        write_output(
            &destination.join(name),
            &SectionReader::new(&file, offset, size),
        )
    }
}

fn physical_extent(key: &[u8], value: Option<&[u8]>) -> Result<Extent> {
    let value = value.unwrap_or(&[0u8; 16]);
    Ok(Extent {
        logical: le_u64(key, 8)?,
        length: le_u64(value, 0)? & EXTENT_LENGTH_MASK,
        physical: le_u64(value, 8)?,
    })
}

/// Returns the compression method and uncompressed size of a decmpfs header.
fn decmpfs_header(value: &XattrValue) -> Result<(u32, u64)> {
    let XattrValue::Embedded(data) = value else {
        return Err(ApfsError::Unsupported(
            "decmpfs header stored in a data stream".into(),
        ));
    };
    if data.len() < DECMPFS_HEADER_SIZE {
        return Err(malformed("decmpfs header is truncated"));
    }
    Ok((le_u32(data, 4)?, le_u64(data, 8)?))
}

fn create_output(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn output_error(path: &Path, source: io::Error) -> ApfsError {
    ApfsError::Output {
        path: path.to_path_buf(),
        source,
    }
}

/// Creates `path` exclusively and fills it from `source`; a partially
/// written file is removed, a pre-existing one is left untouched.
fn write_output(path: &Path, source: &impl ReadAt) -> Result<()> {
    let mut output = create_output(path).map_err(|error| output_error(path, error))?;
    let result = copy_output(&mut output, path, source);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn copy_output(output: &mut File, path: &Path, source: &impl ReadAt) -> Result<()> {
    let mut buffer = vec![0u8; EXTRACT_CHUNK_SIZE];
    let mut offset = 0u64;
    while offset < source.size() {
        let wanted = to_usize((source.size() - offset).min(EXTRACT_CHUNK_SIZE as u64))?;
        source
            .read_exact_at(&mut buffer[..wanted], offset)
            .map_err(|source| ApfsError::Read {
                context: format!("file data at {offset}"),
                source,
            })?;
        output
            .write_all(&buffer[..wanted])
            .map_err(|error| output_error(path, error))?;
        offset += wanted as u64;
    }
    output.sync_all().map_err(|error| output_error(path, error))
}

fn read_header(source: &impl ReadAt, buffer: &mut [u8], offset: u64) -> Result<()> {
    source
        .read_exact_at(buffer, offset)
        .map_err(|source| ApfsError::Read {
            context: "universal binary header".into(),
            source,
        })
}

/// Locates a thin image or the arm64e slice of a universal binary.
fn arm64e_range(source: &impl ReadAt) -> Result<(u64, u64)> {
    let size = source.size();
    let mut header = [0u8; 8];
    if size < 4 {
        return Ok((0, size));
    }
    read_header(source, &mut header[..4], 0)?;
    if u32::from_be_bytes([header[0], header[1], header[2], header[3]]) != FAT_MAGIC {
        return Ok((0, size));
    }
    if size < FAT_HEADER_SIZE {
        return Err(malformed("truncated universal binary header"));
    }
    read_header(source, &mut header[4..], 4)?;
    let count = u64::from(u32::from_be_bytes([
        header[4], header[5], header[6], header[7],
    ]));
    if count == 0 || count > (size - FAT_HEADER_SIZE) / FAT_ARCH_SIZE {
        return Err(malformed("invalid universal binary architecture count"));
    }
    find_arm64e_slice(source, count)
}

fn find_arm64e_slice(source: &impl ReadAt, count: u64) -> Result<(u64, u64)> {
    let size = source.size();
    for index in 0..count {
        let mut arch = [0u8; 20];
        read_header(source, &mut arch, FAT_HEADER_SIZE + index * FAT_ARCH_SIZE)?;
        let word =
            |at: usize| u32::from_be_bytes([arch[at], arch[at + 1], arch[at + 2], arch[at + 3]]);
        if word(0) != CPU_TYPE_ARM64 || word(4) & CPU_SUBTYPE_MASK != CPU_SUBTYPE_ARM64E {
            continue;
        }
        let (offset, length) = (u64::from(word(8)), u64::from(word(12)));
        let header_end = FAT_HEADER_SIZE + count * FAT_ARCH_SIZE;
        if length == 0 || offset < header_end || offset > size || length > size - offset {
            return Err(malformed(
                "arm64e slice exceeds input size or overlaps universal binary header",
            ));
        }
        return Ok((offset, length));
    }
    Err(malformed("universal binary has no arm64e slice"))
}

/// Extracts `paths` from the APFS container in `source` into `destination`.
///
/// Each file is written under its base name. Every file except `.icxs`
/// images is thinned to its arm64e slice.
///
/// # Errors
///
/// Returns an error when the container cannot be opened or any file cannot
/// be extracted; a partially written output file is removed.
pub fn extract_apfs_files<R: ReadAt>(source: R, paths: &[&str], destination: &Path) -> Result<()> {
    let extractor = ApfsExtractor::open(source)?;
    create_destination(destination)?;
    for path in paths {
        let thin = Path::new(path)
            .extension()
            .is_none_or(|extension| extension != UNTHINNED_EXTENSION);
        extractor.extract_file(path, destination, thin)?;
    }
    Ok(())
}

fn create_destination(destination: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(destination)
        .map_err(|source| ApfsError::Output {
            path: destination.to_path_buf(),
            source,
        })
}

/// A file opened from an APFS volume, readable at arbitrary offsets.
pub enum ApfsFile<'a, R> {
    /// Uncompressed data read straight from its extents.
    Plain(ExtentReader<'a, R>),
    /// decmpfs-compressed data decoded block by block.
    Compressed(DecmpfsReader<'a, R>),
}

impl<R: ReadAt> ReadAt for ApfsFile<'_, R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read_at(buf, offset),
            Self::Compressed(reader) => reader.read_at(buf, offset),
        }
    }

    fn size(&self) -> u64 {
        match self {
            Self::Plain(reader) => reader.size(),
            Self::Compressed(reader) => reader.size(),
        }
    }
}

/// Replaces `latest` with `candidate` unless `latest` has a newer transaction.
fn keep_newer_checkpoint(latest: &mut Option<Vec<u8>>, candidate: Vec<u8>) -> Result<()> {
    let newer = match latest {
        Some(current) => object_transaction(&candidate)? >= object_transaction(current)?,
        None => true,
    };
    if newer {
        *latest = Some(candidate);
    }
    Ok(())
}

/// The records of one file that opening it depends on.
#[derive(Default)]
struct FileRecords {
    inode: Option<(u64, u64)>,
    compression: Option<(u32, u64)>,
    resource: Option<(u64, u64)>,
    extents: Vec<Extent>,
}

impl FileRecords {
    fn collect(records: Vec<Record>) -> Result<Self> {
        let mut file = Self::default();
        for record in records {
            match record {
                Record::Inode { private_id, size } => file.inode = Some((private_id, size)),
                Record::Extent(extent) => file.extents.push(extent),
                Record::Xattr { name, value } if name == DECMPFS_XATTR => {
                    file.compression = Some(decmpfs_header(&value)?);
                }
                Record::Xattr { name, value } if name == RESOURCE_FORK_XATTR => {
                    file.resource = value.stream().or(file.resource);
                }
                _ => {}
            }
        }
        Ok(file)
    }
}

/// Reads a file's logical bytes from its physical extents.
pub struct ExtentReader<'a, R> {
    device: &'a R,
    extents: Vec<Extent>,
    size: u64,
}

impl<'a, R: ReadAt> ExtentReader<'a, R> {
    fn new(device: &'a R, mut extents: Vec<Extent>, size: u64) -> Result<Self> {
        if size > i64::MAX as u64 {
            return Err(too_large("file size", size));
        }
        extents.sort_by_key(|extent| extent.logical);
        let mut position = 0u64;
        for extent in &extents {
            if extent.length == 0
                || extent.logical != position
                || extent.physical > u64::MAX / BLOCK_SIZE_U64
            {
                return Err(malformed("file has invalid or sparse physical extents"));
            }
            let physical = extent.physical * BLOCK_SIZE_U64;
            if physical > device.size() || extent.length > device.size() - physical {
                return Err(malformed("file extent exceeds the Apple filesystem image"));
            }
            position = position
                .checked_add(extent.length)
                .ok_or_else(|| malformed("file extent length overflows"))?;
        }
        if position < size {
            let reason = format!("file extents cover {position} bytes, expected {size}");
            return Err(malformed(reason));
        }
        let reader = Self {
            device,
            extents,
            size,
        };
        Ok(reader)
    }
}

impl<R: ReadAt> ReadAt for ExtentReader<'_, R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut written = 0usize;
        let mut position = offset;
        while written < buf.len() && position < self.size {
            let extents = &self.extents;
            let index = extents.partition_point(|run| run.logical + run.length <= position);
            let extent = extents.get(index);
            let extent = extent.filter(|extent| position >= extent.logical);
            let extent = extent.ok_or(io::ErrorKind::UnexpectedEof)?;
            let available = (extent.logical + extent.length - position).min(self.size - position);
            let count = (buf.len() - written).min(usize::try_from(available).unwrap_or(usize::MAX));
            let physical = extent.physical * BLOCK_SIZE_U64 + position - extent.logical;
            self.device
                .read_exact_at(&mut buf[written..written + count], physical)?;
            written += count;
            position += count as u64;
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// Bounded FIFO cache of decompressed blocks.
#[derive(Default)]
struct BlockCache {
    blocks: HashMap<u64, Vec<u8>>,
    order: VecDeque<u64>,
}

/// Decodes a decmpfs resource fork (block-offset table plus compressed
/// 64 KiB blocks) on demand.
pub struct DecmpfsReader<'a, R> {
    source: ExtentReader<'a, R>,
    output_size: u64,
    method: u32,
    offsets: Vec<u64>,
    cache: Mutex<BlockCache>,
}

impl<'a, R: ReadAt> DecmpfsReader<'a, R> {
    fn new(source: ExtentReader<'a, R>, output_size: u64, method: u32) -> Result<Self> {
        if output_size > i64::MAX as u64 {
            return Err(too_large("compressed file size", output_size));
        }
        let source_size = source.size();
        if source_size < 2 * DECMPFS_OFFSET_SIZE {
            return Err(malformed("compressed resource fork is too small"));
        }
        let block_count = output_size.div_ceil(DECMPFS_BLOCK_SIZE);
        let table_size = (block_count + 1) * DECMPFS_OFFSET_SIZE;
        let mut first = [0u8; 4];
        read_resource(&source, &mut first, 0)?;
        let declared = u64::from(u32::from_le_bytes(first));
        if declared != table_size || declared > source_size {
            let reason = format!("compression index has size {declared}, expected {table_size}");
            return Err(malformed(reason));
        }
        let mut table = vec![0u8; to_usize(table_size)?];
        read_resource(&source, &mut table, 0)?;
        let offsets = block_offsets(&table);
        validate_block_offsets(&offsets, table_size, source_size)?;
        let reader = Self {
            source,
            output_size,
            method,
            offsets,
            cache: Mutex::new(BlockCache::default()),
        };
        Ok(reader)
    }

    fn block(&self, index: u64) -> io::Result<Vec<u8>> {
        let cache = self.cache.lock();
        let mut cache = cache.map_err(|_| io::Error::other("decmpfs cache lock poisoned"))?;
        if let Some(block) = cache.blocks.get(&index) {
            return Ok(block.clone());
        }
        let plain = self.decode_block(index).map_err(io::Error::other)?;
        if cache.order.len() == DECMPFS_CACHE_BLOCKS
            && let Some(oldest) = cache.order.pop_front()
        {
            cache.blocks.remove(&oldest);
        }
        cache.blocks.insert(index, plain.clone());
        cache.order.push_back(index);
        Ok(plain)
    }

    fn decode_block(&self, index: u64) -> Result<Vec<u8>> {
        let slot = to_usize(index)?;
        let range = self.offsets.get(slot..=slot + 1);
        let out_of_range = || malformed(format!("compressed block {index} is out of range"));
        let range = range.ok_or_else(out_of_range)?;
        let (start, end) = (range[0], range[1]);
        let mut compressed = vec![0u8; to_usize(end - start)?];
        read_resource(&self.source, &mut compressed, start)?;
        let expected = DECMPFS_BLOCK_SIZE.min(self.output_size - index * DECMPFS_BLOCK_SIZE);
        decode_decmpfs_block(&compressed, self.method, index, expected)
    }
}

/// Decompresses decmpfs block `index`, which must expand to `expected` bytes.
fn decode_decmpfs_block(
    compressed: &[u8],
    method: u32,
    index: u64,
    expected: u64,
) -> Result<Vec<u8>> {
    let plain = decompress_block(compressed, method, to_usize(expected)?).map_err(|source| {
        ApfsError::Decompress {
            block: index,
            source,
        }
    })?;
    if plain.len() as u64 != expected {
        return Err(malformed(format!(
            "decompressed block {index} has size {}, expected {expected}",
            plain.len()
        )));
    }
    Ok(plain)
}

/// Error for a size beyond what a signed 64-bit file offset can address.
fn too_large(what: &str, size: u64) -> ApfsError {
    malformed(format!("{what} {size} exceeds the supported maximum"))
}

fn read_resource<R: ReadAt>(
    source: &ExtentReader<'_, R>,
    buffer: &mut [u8],
    offset: u64,
) -> Result<()> {
    let read = source.read_exact_at(buffer, offset);
    read.map_err(|source| ApfsError::Read {
        context: "compressed resource fork".into(),
        source,
    })
}

/// Decodes the little-endian 32-bit entries of a decmpfs block-offset table.
fn block_offsets(table: &[u8]) -> Vec<u64> {
    let (entries, _) = table.as_chunks::<4>();
    entries
        .iter()
        .map(|entry| u64::from(u32::from_le_bytes(*entry)))
        .collect()
}

fn validate_block_offsets(offsets: &[u64], table_size: u64, source_size: u64) -> Result<()> {
    for (index, pair) in offsets.windows(2).enumerate() {
        let (start, end) = (pair[0], pair[1]);
        if start < table_size
            || end <= start
            || end > source_size
            || end - start > DECMPFS_BLOCK_SIZE + 1
        {
            return Err(malformed(format!(
                "compressed block {index} has invalid range {start}..{end}"
            )));
        }
    }
    match offsets.last() {
        Some(&last) if last == source_size => Ok(()),
        last => Err(malformed(format!(
            "compressed blocks end at {last:?}, expected {source_size}"
        ))),
    }
}

impl<R: ReadAt> ReadAt for DecmpfsReader<'_, R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let remaining = self.output_size.saturating_sub(offset);
        let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
        let wanted = buf.len().min(remaining);
        let mut written = 0usize;
        let mut position = offset;
        while written < wanted {
            let block = self.block(position / DECMPFS_BLOCK_SIZE)?;
            let within = usize::try_from(position % DECMPFS_BLOCK_SIZE).unwrap_or(usize::MAX);
            let count = (wanted - written).min(block.len().saturating_sub(within));
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf[written..written + count].copy_from_slice(&block[within..within + count]);
            written += count;
            position += count as u64;
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.output_size
    }
}

/// Decodes one decmpfs block, honouring each codec's stored-block marker.
fn decompress_block(
    compressed: &[u8],
    method: u32,
    maximum_size: usize,
) -> std::result::Result<Vec<u8>, lz::LzError> {
    let (&first, rest) = compressed.split_first().unwrap_or((&0, &[]));
    match method {
        DECMPFS_LZVN if first == DECMPFS_LZVN_STORED => Ok(rest.to_vec()),
        DECMPFS_LZVN => lz::decompress_lzvn(compressed, maximum_size),
        DECMPFS_LZFSE if first != DECMPFS_LZFSE_MAGIC => Ok(rest.to_vec()),
        DECMPFS_LZFSE => lz::decompress_lzfse(compressed),
        DECMPFS_LZBITMAP if first == DECMPFS_LZBITMAP_STORED => Ok(rest.to_vec()),
        _ => lz::decompress_lzbitmap(compressed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    const TEST_XID: u64 = 7;
    const STALE_XID: u64 = 5;
    const NEWER_XID: u64 = 9;
    const OLDER_XID: u64 = 2;
    const CHECKPOINT_BASE: u64 = 1;
    const CHECKPOINT_BLOCKS: u32 = 4;
    const STALE_CHECKPOINT: u64 = 1;
    const CHECKPOINT_MAP_BLOCK: u64 = 2;
    const LATEST_CHECKPOINT: u64 = 3;
    const CORRUPT_CHECKPOINT: u64 = 4;
    const CONTAINER_OMAP: u64 = 10;
    const CONTAINER_OMAP_TREE: u64 = 11;
    const VOLUME_BLOCK: u64 = 12;
    const VOLUME_OMAP: u64 = 13;
    const VOLUME_OMAP_TREE: u64 = 14;
    const FIRST_NODE_BLOCK: u64 = 20;
    const FIRST_DATA_BLOCK: u64 = 200;
    const VOLUME_OID: u64 = 1026;
    const FS_ROOT_OID: u64 = 1028;
    const FORK_OID_BIAS: u64 = 0x1000;
    const OBJECT_TYPE_CHECKPOINT_MAP: u32 = 0x0c;
    const RECORD_SIBLING_LINK: u8 = 5;
    const INODE_FIELD_NAME: u8 = 4;
    const XATTR_STREAM: u16 = 0x0001;
    const XATTR_STREAM_VALUE_SIZE: usize = 4 + 40;
    const DECMPFS_MAGIC: &[u8; 4] = b"fpmc";
    const DECMPFS_UNSUPPORTED: u32 = 4;
    const RECORDS_PER_LEAF: usize = 10;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const LZVN_LITERAL: u8 = 0xe0;
    const LZVN_MAX_LITERAL: usize = 271;
    const LZVN_LARGE_BIAS: usize = 16;
    const LZBITMAP_MAX_CHUNK: usize = 0x8000;
    const LZBITMAP_CHUNK_HEADER: usize = 6;
    const ROOT: u64 = ROOT_DIRECTORY_ID;

    fn put_u16(block: &mut [u8], at: usize, value: usize) {
        let value = u16::try_from(value).expect("u16 field");
        block[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(block: &mut [u8], at: usize, value: u32) {
        block[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(block: &mut [u8], at: usize, value: u64) {
        block[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn u32_of(value: usize) -> u32 {
        u32::try_from(value).expect("u32")
    }

    fn sealed(mut block: Vec<u8>) -> Vec<u8> {
        let checksum = fletcher64(&block);
        put_u64(&mut block, 0, checksum);
        block
    }

    fn object(oid: u64, xid: u64, kind: u32) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        put_u64(&mut block, 8, oid);
        put_u64(&mut block, 16, xid);
        put_u32(&mut block, 24, kind);
        block
    }

    fn container_superblock(xid: u64, omap: u64) -> Vec<u8> {
        let mut block = object(1, xid, OBJECT_TYPE_CONTAINER);
        block[32..36].copy_from_slice(CONTAINER_MAGIC);
        put_u32(&mut block, 36, u32_of(BLOCK_SIZE));
        put_u32(&mut block, 104, CHECKPOINT_BLOCKS);
        put_u64(&mut block, 112, CHECKPOINT_BASE);
        put_u64(&mut block, 160, omap);
        put_u64(&mut block, 184, VOLUME_OID);
        sealed(block)
    }

    fn volume_superblock(extent_tree: u64) -> Vec<u8> {
        let mut block = object(VOLUME_OID, TEST_XID, OBJECT_TYPE_VOLUME);
        block[32..36].copy_from_slice(VOLUME_MAGIC);
        put_u64(&mut block, 128, VOLUME_OMAP);
        put_u64(&mut block, 136, FS_ROOT_OID);
        put_u64(&mut block, 1032, extent_tree);
        sealed(block)
    }

    fn omap_object(address: u64, tree: u64) -> Vec<u8> {
        let mut block = object(address, TEST_XID, OBJECT_TYPE_OMAP);
        put_u64(&mut block, 48, tree);
        sealed(block)
    }

    type KeyValue = (Vec<u8>, Option<Vec<u8>>);

    /// One B-tree node before encoding.
    struct TreeNode {
        flags: u16,
        entries: Vec<KeyValue>,
    }

    impl TreeNode {
        fn new(flags: u16, entries: Vec<KeyValue>) -> Self {
            Self { flags, entries }
        }

        fn encode(&self, oid: u64) -> Vec<u8> {
            let fixed = self.flags & NODE_FIXED_KV != 0;
            let root = self.flags & NODE_ROOT != 0;
            let toc_size = if fixed { 4 } else { 8 };
            let kind = if root {
                OBJECT_TYPE_BTREE
            } else {
                OBJECT_TYPE_BTREE_NODE
            };
            let mut block = object(oid, TEST_XID, kind);
            put_u16(&mut block, 32, usize::from(self.flags));
            put_u16(&mut block, 34, usize::from(self.flags & NODE_LEAF == 0));
            put_u32(&mut block, 36, u32_of(self.entries.len()));
            let table_length = toc_size * self.entries.len();
            put_u16(&mut block, 42, table_length);
            let value_end = if root {
                BLOCK_SIZE - BTREE_INFO_SIZE
            } else {
                BLOCK_SIZE
            };
            let (mut key_offset, mut value_offset) = (0, 0);
            for (index, (key, value)) in self.entries.iter().enumerate() {
                let key_at = NODE_HEADER_SIZE + table_length + key_offset;
                block[key_at..key_at + key.len()].copy_from_slice(key);
                let value_field = value
                    .as_ref()
                    .map_or(usize::from(NO_VALUE_OFFSET), |value| {
                        value_offset += value.len();
                        block[value_end - value_offset..][..value.len()].copy_from_slice(value);
                        value_offset
                    });
                let toc = NODE_HEADER_SIZE + index * toc_size;
                put_u16(&mut block, toc, key_offset);
                if fixed {
                    put_u16(&mut block, toc + 2, value_field);
                } else {
                    put_u16(&mut block, toc + 2, key.len());
                    put_u16(&mut block, toc + 4, value_field);
                    put_u16(&mut block, toc + 6, value.as_ref().map_or(0, Vec::len));
                }
                key_offset += key.len();
            }
            sealed(block)
        }
    }

    fn headerless(mut block: Vec<u8>) -> Vec<u8> {
        block[..OBJECT_HEADER_SIZE].fill(0);
        block[OBJECT_HEADER_SIZE] |= u8::try_from(NODE_NO_HEADER).expect("flag");
        block
    }

    fn omap_key(oid: u64, xid: u64) -> Vec<u8> {
        [oid.to_le_bytes(), xid.to_le_bytes()].concat()
    }

    fn omap_value(address: u64) -> Vec<u8> {
        [[0u8; 8], address.to_le_bytes()].concat()
    }

    fn omap_leaf(entries: &[(u64, u64, u64)], flags: u16) -> TreeNode {
        let entries = entries
            .iter()
            .map(|&(oid, xid, address)| (omap_key(oid, xid), Some(omap_value(address))))
            .collect();
        TreeNode::new(flags | NODE_LEAF | NODE_FIXED_KV, entries)
    }

    /// A raw container image assembled block by block.
    #[derive(Default)]
    struct Image {
        blocks: BTreeMap<u64, Vec<u8>>,
    }

    impl Image {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (index, chunk) in bytes.chunks(BLOCK_SIZE).enumerate() {
                let mut block = chunk.to_vec();
                block.resize(BLOCK_SIZE, 0);
                self.blocks.insert(address + index as u64, block);
            }
        }

        fn edit(&mut self, address: u64, change: impl FnOnce(&mut Vec<u8>)) {
            let block = self.blocks.get_mut(&address).expect("block");
            change(block);
            let resealed = sealed(std::mem::take(block));
            *block = resealed;
        }

        fn bytes(&self) -> Vec<u8> {
            let end = self.blocks.keys().last().map_or(0, |last| last + 1);
            let mut image = vec![0u8; usize::try_from(end).expect("size") * BLOCK_SIZE];
            for (address, block) in &self.blocks {
                let start = usize::try_from(*address).expect("address") * BLOCK_SIZE;
                image[start..start + BLOCK_SIZE].copy_from_slice(block);
            }
            image
        }

        fn open(&self) -> Result<ApfsExtractor<Vec<u8>>> {
            ApfsExtractor::open(self.bytes())
        }

        /// Replaces the volume object map with a two-level tree mapping
        /// `entries` (`oid`, `xid`, `address`), stored from `first_block`.
        fn set_volume_omap(&mut self, mut entries: Vec<(u64, u64, u64)>, first_block: u64) {
            entries.sort_unstable();
            let half = entries.len().div_ceil(2);
            let mut index = Vec::new();
            for (slot, chunk) in entries.chunks(half).enumerate() {
                let address = first_block + slot as u64;
                self.put(address, &omap_leaf(chunk, 0).encode(address));
                let value = Some(address.to_le_bytes().to_vec());
                index.push((omap_key(chunk[0].0, chunk[0].1), value));
            }
            let root = TreeNode::new(NODE_ROOT | NODE_FIXED_KV, index);
            self.put(VOLUME_OMAP_TREE, &root.encode(VOLUME_OMAP_TREE));
        }
    }

    fn record_key(oid: u64, kind: u8) -> Vec<u8> {
        ((u64::from(kind) << RECORD_TYPE_SHIFT) | oid)
            .to_le_bytes()
            .to_vec()
    }

    fn named_key(oid: u64, kind: u8, name: &str, length_field: u32) -> Vec<u8> {
        let mut key = record_key(oid, kind);
        if kind == RECORD_XATTR {
            put_u16_vec(&mut key, usize::try_from(length_field).expect("length"));
        } else {
            key.extend_from_slice(&length_field.to_le_bytes());
        }
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        key
    }

    fn put_u16_vec(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&u16::try_from(value).expect("u16").to_le_bytes());
    }

    fn directory_record(parent: u64, name: &str, file_id: u64) -> (Vec<u8>, Vec<u8>) {
        let key = named_key(parent, RECORD_DIRECTORY_ENTRY, name, u32_of(name.len() + 1));
        let mut value = file_id.to_le_bytes().to_vec();
        value.resize(18, 0);
        (key, value)
    }

    fn inode_record(oid: u64, size: u64, stream: bool) -> (Vec<u8>, Vec<u8>) {
        let mut value = vec![0u8; INODE_VALUE_SIZE];
        put_u64(&mut value, 8, oid);
        put_u64(&mut value, 84, if stream { 0 } else { size });
        if stream {
            let name = b"file\0\0\0\0";
            let mut blob = Vec::new();
            for word in [2, 48, 0, 5, usize::from(INODE_FIELD_DATA_STREAM), 40] {
                put_u16_vec(&mut blob, word);
            }
            blob[4] = INODE_FIELD_NAME;
            blob[8] = INODE_FIELD_DATA_STREAM;
            blob.extend_from_slice(name);
            blob.extend_from_slice(&size.to_le_bytes());
            blob.resize(blob.len() + 32, 0);
            value.extend(blob);
        }
        (record_key(oid, RECORD_INODE), value)
    }

    fn extent_record(oid: u64, logical: u64, length: u64, physical: u64) -> (Vec<u8>, Vec<u8>) {
        let key = [
            record_key(oid, RECORD_FILE_EXTENT),
            logical.to_le_bytes().to_vec(),
        ]
        .concat();
        let value = [length, physical, 0].map(u64::to_le_bytes).concat();
        (key, value)
    }

    fn xattr_key(oid: u64, name: &str) -> Vec<u8> {
        named_key(oid, RECORD_XATTR, name, u32_of(name.len() + 1))
    }

    fn embedded_xattr(oid: u64, name: &str, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut value = Vec::new();
        put_u16_vec(&mut value, usize::from(XATTR_EMBEDDED));
        put_u16_vec(&mut value, data.len());
        value.extend_from_slice(data);
        (xattr_key(oid, name), value)
    }

    fn stream_xattr(oid: u64, name: &str, object_id: u64, size: u64) -> (Vec<u8>, Vec<u8>) {
        let mut value = vec![0u8; XATTR_STREAM_VALUE_SIZE];
        put_u16(&mut value, 0, usize::from(XATTR_STREAM));
        put_u16(&mut value, 2, XATTR_STREAM_VALUE_SIZE - 4);
        put_u64(&mut value, 4, object_id);
        put_u64(&mut value, 12, size);
        (xattr_key(oid, name), value)
    }

    fn decmpfs(method: u32, size: u64) -> Vec<u8> {
        let mut header = DECMPFS_MAGIC.to_vec();
        header.extend_from_slice(&method.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        header
    }

    fn resource_fork(blocks: &[Vec<u8>]) -> Vec<u8> {
        let table = (blocks.len() + 1) * 4;
        let mut fork = Vec::new();
        let mut offset = table;
        fork.extend_from_slice(&u32_of(offset).to_le_bytes());
        for block in blocks {
            offset += block.len();
            fork.extend_from_slice(&u32_of(offset).to_le_bytes());
        }
        for block in blocks {
            fork.extend_from_slice(block);
        }
        fork
    }

    fn lzvn_literals(plain: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();
        for chunk in plain.chunks(LZVN_MAX_LITERAL) {
            if chunk.len() < LZVN_LARGE_BIAS {
                stream.push(LZVN_LITERAL | u8::try_from(chunk.len()).expect("nibble"));
            } else {
                let operand = u8::try_from(chunk.len() - LZVN_LARGE_BIAS).expect("operand");
                stream.extend_from_slice(&[LZVN_LITERAL, operand]);
            }
            stream.extend_from_slice(chunk);
        }
        stream.push(DECMPFS_LZVN_STORED);
        stream
    }

    fn lzvn_zeros(count: usize) -> Vec<u8> {
        let mut stream = vec![0xe1, 0x00, 0x38, 0x01];
        let mut remaining = count - 11;
        while remaining > 0 {
            let chunk = remaining.clamp(LZVN_LARGE_BIAS, LZVN_MAX_LITERAL);
            let operand = u8::try_from(chunk - LZVN_LARGE_BIAS).expect("operand");
            stream.extend_from_slice(&[0xf0, operand]);
            remaining -= chunk;
        }
        stream.push(DECMPFS_LZVN_STORED);
        stream
    }

    fn lzbitmap_stored(plain: &[u8]) -> Vec<u8> {
        let mut stream = b"ZBM\x09".to_vec();
        for chunk in plain.chunks(LZBITMAP_MAX_CHUNK) {
            let length = (chunk.len() + LZBITMAP_CHUNK_HEADER).to_le_bytes();
            stream.extend_from_slice(&length[..3]);
            stream.extend_from_slice(&chunk.len().to_le_bytes()[..3]);
            stream.extend_from_slice(chunk);
        }
        stream.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
        stream
    }

    fn lzfse(plain: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();
        lzfse_rust::encode_bytes(plain, &mut stream).expect("encode");
        stream
    }

    fn pattern(length: usize, seed: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index * 31 + seed) % 251).to_le_bytes()[0])
            .collect()
    }

    fn universal_binary() -> Vec<u8> {
        let mut data = vec![0u8; 8200];
        data[..8].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]);
        let arches = [
            [CPU_TYPE_X86_64, 3, 4096, 8, 12],
            [CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 8192, 8, 14],
        ];
        for (index, arch) in arches.iter().enumerate() {
            for (field, word) in arch.iter().enumerate() {
                let at = 8 + index * 20 + field * 4;
                data[at..at + 4].copy_from_slice(&word.to_be_bytes());
            }
        }
        data[4096..4104].copy_from_slice(b"x86slice");
        data[8192..8200].copy_from_slice(b"arm64e!!");
        data
    }

    /// The file-system records and data of one synthetic volume.
    struct Volume {
        records: Vec<(Vec<u8>, Vec<u8>)>,
        data: Vec<(u64, Vec<u8>)>,
        physical: Vec<KeyValue>,
        next_block: u64,
        hashed: bool,
    }

    impl Volume {
        fn new() -> Self {
            Self {
                records: Vec::new(),
                data: Vec::new(),
                physical: Vec::new(),
                next_block: FIRST_DATA_BLOCK,
                hashed: false,
            }
        }

        fn store(&mut self, bytes: &[u8]) -> u64 {
            let block = self.next_block;
            self.next_block += (bytes.len() as u64).div_ceil(BLOCK_SIZE_U64).max(1);
            self.data.push((block, bytes.to_vec()));
            block
        }

        fn link(&mut self, parent: u64, name: &str, oid: u64) {
            self.records.push(directory_record(parent, name, oid));
        }

        fn directory(&mut self, parent: u64, name: &str, oid: u64) {
            self.link(parent, name, oid);
            self.records.push(inode_record(oid, 0, false));
        }

        fn plain(&mut self, parent: u64, name: &str, oid: u64, bytes: &[u8]) {
            self.link(parent, name, oid);
            self.records
                .push(inode_record(oid, bytes.len() as u64, true));
            if !bytes.is_empty() {
                let block = self.store(bytes);
                self.records
                    .push(extent_record(oid, 0, bytes.len() as u64, block));
            }
        }

        fn compressed(&mut self, parent: u64, name: &str, oid: u64, method: u32, size: u64) {
            self.link(parent, name, oid);
            self.records.push(inode_record(oid, 0, false));
            let header = decmpfs(method, size);
            self.records
                .push(embedded_xattr(oid, DECMPFS_XATTR, &header));
        }

        fn fork(&mut self, oid: u64, fork: &[u8]) {
            let fork_oid = oid + FORK_OID_BIAS;
            let size = fork.len() as u64;
            self.records
                .push(stream_xattr(oid, RESOURCE_FORK_XATTR, fork_oid, size));
            let block = self.store(fork);
            self.records.push(extent_record(fork_oid, 0, size, block));
        }

        fn compressed_file(
            &mut self,
            name: &str,
            oid: u64,
            method: u32,
            size: usize,
            blocks: &[Vec<u8>],
        ) {
            self.compressed(ROOT, name, oid, method, size as u64);
            self.fork(oid, &resource_fork(blocks));
        }

        fn sorted_records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
            let mut records = self.records.clone();
            records.sort_by_key(|(key, _)| {
                let header = u64::from_le_bytes(key[..8].try_into().expect("header"));
                (
                    header & RECORD_ID_MASK,
                    header >> RECORD_TYPE_SHIFT,
                    key.clone(),
                )
            });
            records
        }

        fn image(&self) -> Image {
            let mut image = Image::default();
            image.put(0, &container_superblock(1, CONTAINER_OMAP));
            image.put(STALE_CHECKPOINT, &container_superblock(STALE_XID, 0));
            let map = sealed(object(
                CHECKPOINT_MAP_BLOCK,
                TEST_XID,
                OBJECT_TYPE_CHECKPOINT_MAP,
            ));
            image.put(CHECKPOINT_MAP_BLOCK, &map);
            let latest = container_superblock(TEST_XID, CONTAINER_OMAP);
            image.put(LATEST_CHECKPOINT, &latest);
            image.put(CORRUPT_CHECKPOINT, &vec![0xaa; BLOCK_SIZE]);
            image.put(
                CONTAINER_OMAP,
                &omap_object(CONTAINER_OMAP, CONTAINER_OMAP_TREE),
            );
            let container_tree = omap_leaf(&[(VOLUME_OID, TEST_XID, VOLUME_BLOCK)], NODE_ROOT);
            image.put(
                CONTAINER_OMAP_TREE,
                &container_tree.encode(CONTAINER_OMAP_TREE),
            );
            image.put(VOLUME_OMAP, &omap_object(VOLUME_OMAP, VOLUME_OMAP_TREE));
            for (block, bytes) in &self.data {
                image.put(*block, bytes);
            }
            let mut next = FIRST_NODE_BLOCK;
            let omap = self.put_filesystem(&mut image, &mut next);
            image.set_volume_omap(omap, next);
            let extent_tree = self.put_extent_tree(&mut image, next + 2);
            image.put(VOLUME_BLOCK, &volume_superblock(extent_tree));
            image
        }

        /// Writes the file-system tree and returns its object-map entries.
        fn put_filesystem(&self, image: &mut Image, next: &mut u64) -> Vec<(u64, u64, u64)> {
            let root_block = *next;
            let mut omap = vec![
                (FS_ROOT_OID, OLDER_XID, 0),
                (FS_ROOT_OID, STALE_XID, root_block),
                (FS_ROOT_OID, NEWER_XID, 0),
            ];
            let mut index = Vec::new();
            for (slot, chunk) in self.sorted_records().chunks(RECORDS_PER_LEAF).enumerate() {
                *next += 1;
                let child = slot as u64 + 1;
                let entries = chunk
                    .iter()
                    .map(|(k, v)| (k.clone(), Some(v.clone())))
                    .collect();
                let mut leaf = TreeNode::new(NODE_LEAF, entries).encode(FS_ROOT_OID + child);
                let mut value = child.to_le_bytes().to_vec();
                if self.hashed {
                    leaf = headerless(leaf);
                    value.extend_from_slice(&Sha256::digest(&leaf));
                } else {
                    value = (FS_ROOT_OID + child).to_le_bytes().to_vec();
                }
                image.put(*next, &leaf);
                omap.push((FS_ROOT_OID + child, TEST_XID, *next));
                index.push((chunk[0].0.clone(), Some(value)));
            }
            let flags = NODE_ROOT | if self.hashed { NODE_HASHED } else { 0 };
            image.put(root_block, &TreeNode::new(flags, index).encode(FS_ROOT_OID));
            *next += 1;
            omap
        }

        fn put_extent_tree(&self, image: &mut Image, first_block: u64) -> u64 {
            if self.physical.is_empty() {
                return 0;
            }
            let mut physical = self.physical.clone();
            physical.sort_by_key(|(key, _)| (le_u64(key, 0).ok(), le_u64(key, 8).ok()));
            let half = physical.len().div_ceil(2);
            let mut index = Vec::new();
            for (slot, chunk) in physical.chunks(half).enumerate() {
                let address = first_block + 1 + slot as u64;
                image.put(
                    address,
                    &TreeNode::new(NODE_LEAF, chunk.to_vec()).encode(address),
                );
                index.push((chunk[0].0.clone(), Some(address.to_le_bytes().to_vec())));
            }
            image.put(
                first_block,
                &TreeNode::new(NODE_ROOT, index).encode(first_block),
            );
            first_block
        }
    }

    const LZVN_PLAIN: usize = 65_536 + 100;
    const LZFSE_PLAIN: usize = 70_000;
    const LZBITMAP_PLAIN: usize = 40_000;
    const BIG_BLOCKS: usize = DECMPFS_CACHE_BLOCKS + 1;
    const BLOCK: usize = 65_536;

    fn standard_volume() -> Volume {
        let mut volume = Volume::new();
        volume.plain(ROOT, "plain.txt", 16, b"hello apfs");
        volume
            .records
            .push((record_key(16, RECORD_SIBLING_LINK), vec![0; 10]));
        volume.link(ROOT, "..", 16);
        volume.directory(ROOT, "dir", 17);
        volume.plain(17, "nested.icxs", 18, &universal_binary());
        volume.plain(ROOT, "fat", 19, &universal_binary());
        volume.plain(ROOT, "empty", 25, &[]);
        let lzvn = pattern(LZVN_PLAIN, 1);
        let lzvn_blocks = [
            [&[DECMPFS_LZVN_STORED][..], &lzvn[..BLOCK]].concat(),
            lzvn_literals(&lzvn[BLOCK..]),
        ];
        volume.compressed_file("lzvn", 20, DECMPFS_LZVN, LZVN_PLAIN, &lzvn_blocks);
        let lzfse_plain = pattern(LZFSE_PLAIN, 2);
        let lzfse_blocks = [
            lzfse(&lzfse_plain[..BLOCK]),
            [&[0xcc][..], &lzfse_plain[BLOCK..]].concat(),
        ];
        volume.compressed_file("lzfse", 21, DECMPFS_LZFSE, LZFSE_PLAIN, &lzfse_blocks);
        let bitmap = pattern(LZBITMAP_PLAIN, 3);
        let bitmap_blocks = [lzbitmap_stored(&bitmap)];
        volume.compressed_file(
            "lzbitmap",
            22,
            DECMPFS_LZBITMAP,
            LZBITMAP_PLAIN,
            &bitmap_blocks,
        );
        let big_blocks = vec![lzvn_zeros(BLOCK); BIG_BLOCKS];
        volume.compressed_file("big", 23, DECMPFS_LZVN, BIG_BLOCKS * BLOCK, &big_blocks);
        add_broken_files(&mut volume);
        volume
    }

    fn add_broken_files(volume: &mut Volume) {
        volume.link(ROOT, "no-inode", 30);
        volume.compressed(ROOT, "bad-method", 31, DECMPFS_UNSUPPORTED, 4);
        volume.compressed(ROOT, "no-fork", 32, DECMPFS_LZVN, 4);
        volume.link(ROOT, "stream-header", 33);
        volume.records.push(inode_record(33, 0, false));
        volume
            .records
            .push(stream_xattr(33, DECMPFS_XATTR, 0x9999, 16));
        volume.link(ROOT, "short-header", 34);
        volume.records.push(inode_record(34, 0, false));
        volume
            .records
            .push(embedded_xattr(34, DECMPFS_XATTR, &[0; 8]));
        let stored = [vec![DECMPFS_LZVN_STORED], vec![0; BLOCK]].concat();
        let corrupt = [stored, vec![0xe3, 1]];
        volume.compressed_file("corrupt", 35, DECMPFS_LZVN, BLOCK + 2, &corrupt);
        volume.compressed_file("short-block", 36, DECMPFS_LZVN, 4, &[vec![0x06, 1]]);
        volume.compressed(ROOT, "bad-index", 37, DECMPFS_LZVN, 4);
        volume.fork(37, &[12, 0, 0, 0, 12, 0, 0, 0, 0x06, 1, 2, 3, 4]);
        volume.compressed(ROOT, "embedded-fork", 47, DECMPFS_LZVN, 4);
        let embedded = embedded_xattr(47, RESOURCE_FORK_XATTR, &[0; 8]);
        volume.records.push(embedded);
        volume.compressed(ROOT, "tiny-fork", 38, DECMPFS_LZVN, 4);
        volume.fork(38, &[8, 0, 0, 0]);
        volume.plain(ROOT, "sparse", 39, &[]);
        let inode = inode_record(39, 100, false);
        volume.records.retain(|(key, _)| *key != inode.0);
        volume.records.push(inode);
        volume.plain(ROOT, "fat-header", 40, &[0xca, 0xfe, 0xba, 0xbe, 0]);
        volume.plain(ROOT, "fat-count", 41, &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]);
        add_malformed_records(volume);
    }

    fn add_malformed_records(volume: &mut Volume) {
        volume.link(ROOT, "bad-fields", 42);
        let (key, mut value) = inode_record(42, 0, false);
        value.extend_from_slice(&[3, 0, 0, 0]);
        volume.records.push((key, value));
        volume.directory(ROOT, "broken", 43);
        let mut name = directory_record(43, "x", 44).0;
        name.truncate(name.len() - 2);
        volume.records.push((name, 44u64.to_le_bytes().to_vec()));
        volume.link(ROOT, "bad-xattr-name", 45);
        volume.records.push(inode_record(45, 0, false));
        let (mut key, value) = embedded_xattr(45, "n", b"x");
        key.truncate(key.len() - 1);
        volume.records.push((key, value));
        volume.link(ROOT, "bad-xattr-data", 46);
        volume.records.push(inode_record(46, 0, false));
        let (key, mut value) = embedded_xattr(46, "n", b"xyz");
        value.truncate(value.len() - 1);
        volume.records.push((key, value));
    }

    fn standard_image() -> Image {
        standard_volume().image()
    }

    fn open_standard() -> ApfsExtractor<Vec<u8>> {
        standard_image().open().expect("open synthetic container")
    }

    fn read_file<R: ReadAt>(extractor: &ApfsExtractor<R>, path: &str) -> Result<Vec<u8>> {
        let file = extractor.open_file(path)?;
        let mut data = vec![0u8; usize::try_from(file.size()).expect("size")];
        file.read_exact_at(&mut data, 0)
            .map_err(|source| ApfsError::Read {
                context: path.to_owned(),
                source,
            })?;
        Ok(data)
    }

    fn scratch_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ipakeep-apfs-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn reads_plain_and_compressed_files_from_synthetic_container() {
        let extractor = open_standard();
        assert_eq!(
            read_file(&extractor, "/plain.txt").expect("plain"),
            b"hello apfs"
        );
        assert_eq!(
            read_file(&extractor, "dir/nested.icxs").expect("nested"),
            universal_binary()
        );
        assert_eq!(
            read_file(&extractor, "/lzvn").expect("lzvn"),
            pattern(LZVN_PLAIN, 1)
        );
        assert_eq!(
            read_file(&extractor, "/lzfse").expect("lzfse"),
            pattern(LZFSE_PLAIN, 2)
        );
        assert_eq!(
            read_file(&extractor, "/lzbitmap").expect("lzbitmap"),
            pattern(LZBITMAP_PLAIN, 3)
        );
        assert_eq!(
            read_file(&extractor, "/empty").expect("empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn extracts_files_thinning_all_but_icxs_images() {
        let image = standard_image().bytes();
        let destination = scratch_directory("extract");
        let paths = ["/plain.txt", "/dir/nested.icxs", "/fat", "/lzfse", "/empty"];
        extract_apfs_files(image, &paths, &destination).expect("extract");
        let read = |name: &str| fs::read(destination.join(name)).expect("output");
        assert_eq!(read("plain.txt"), b"hello apfs");
        assert_eq!(read("nested.icxs"), universal_binary());
        assert_eq!(read("fat"), b"arm64e!!");
        assert_eq!(read("lzfse"), pattern(LZFSE_PLAIN, 2));
        assert_eq!(read("empty"), Vec::<u8>::new());
        fs::remove_dir_all(&destination).expect("cleanup");
    }

    #[test]
    fn extraction_keeps_existing_outputs_and_removes_partial_ones() {
        let extractor = open_standard();
        let destination = scratch_directory("partial");
        create_destination(&destination).expect("destination");
        fs::write(destination.join("plain.txt"), b"keep").expect("seed");
        let existing = extractor.extract_file("/plain.txt", &destination, false);
        assert!(matches!(existing, Err(ApfsError::Output { .. })));
        assert_eq!(
            fs::read(destination.join("plain.txt")).expect("kept"),
            b"keep"
        );
        let corrupt = extractor.extract_file("/corrupt", &destination, true);
        assert!(
            matches!(corrupt, Err(ApfsError::Read { .. })),
            "{corrupt:?}"
        );
        assert!(!destination.join("corrupt").exists());
        let nameless = extractor.extract_file("/..", &destination, false);
        assert!(matches!(nameless, Err(ApfsError::Malformed(_))));
        fs::remove_dir_all(&destination).expect("cleanup");
    }

    #[test]
    fn extraction_reports_unusable_destinations() {
        let blocker = scratch_directory("blocker");
        fs::write(&blocker, b"file").expect("blocker");
        let result = extract_apfs_files(standard_image().bytes(), &["/plain.txt"], &blocker);
        assert!(matches!(result, Err(ApfsError::Output { .. })));
        fs::remove_file(&blocker).expect("cleanup");
    }

    #[test]
    fn decoded_blocks_are_cached_with_a_bounded_size() {
        let extractor = open_standard();
        let ApfsFile::Compressed(reader) = extractor.open_file("/big").expect("big") else {
            panic!("big is compressed");
        };
        let mut chunk = vec![1u8; BLOCK];
        for index in 0..BIG_BLOCKS as u64 {
            reader
                .read_exact_at(&mut chunk, index * BLOCK as u64)
                .expect("read");
            assert!(chunk.iter().all(|&byte| byte == 0));
        }
        reader.read_exact_at(&mut chunk[..8], 0).expect("cached");
        let cache = reader.cache.lock().expect("cache");
        assert_eq!(cache.blocks.len(), DECMPFS_CACHE_BLOCKS);
        assert_eq!(cache.order.len(), DECMPFS_CACHE_BLOCKS);
    }

    fn file_error(path: &str) -> String {
        match read_file(&open_standard(), path) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("{path} unexpectedly decoded"),
        }
    }

    #[test]
    fn rejects_files_with_unusable_metadata() {
        let cases = [
            ("/missing", "path component \"missing\" was not found"),
            ("/no-inode", "file has no inode record"),
            ("/bad-method", "compression type 4"),
            ("/no-fork", "compressed file has no resource fork"),
            ("/embedded-fork", "compressed file has no resource fork"),
            ("/stream-header", "decmpfs header stored in a data stream"),
            ("/short-header", "decmpfs header is truncated"),
            (
                "/short-block",
                "decompressed block 0 has size 1, expected 4",
            ),
            ("/bad-index", "compression index has size 12, expected 8"),
            ("/tiny-fork", "compressed resource fork is too small"),
            ("/sparse", "file extents cover 0 bytes, expected 100"),
            ("/bad-fields", "inode field header is truncated"),
            ("/broken/x", "directory entry name is truncated"),
            ("/bad-xattr-name", "xattr name is truncated"),
            ("/bad-xattr-data", "xattr data is truncated"),
            ("/corrupt", "decode compressed block 1"),
        ];
        for (path, expected) in cases {
            let error = file_error(path);
            assert!(error.contains(expected), "{path}: {error}");
        }
    }

    #[test]
    fn arm64e_range_rejects_malformed_universal_headers() {
        let extractor = open_standard();
        for path in ["/fat-header", "/fat-count"] {
            let file = extractor.open_file(path).expect("open");
            assert!(matches!(arm64e_range(&file), Err(ApfsError::Malformed(_))));
        }
        let corrupt = extractor.open_file("/corrupt").expect("open");
        assert!(matches!(arm64e_range(&corrupt), Ok((0, _))));
        let short = extractor.open_file("/short-block").expect("open");
        assert!(matches!(arm64e_range(&short), Err(ApfsError::Read { .. })));
    }

    fn open_error(image: &Image) -> ApfsError {
        match image.open() {
            Err(error) => error,
            Ok(_) => panic!("container unexpectedly opened"),
        }
    }

    fn assert_open_error(image: &Image, expected: &str) {
        let error = open_error(image).to_string();
        assert!(error.contains(expected), "{error}");
    }

    #[test]
    fn rejects_unusable_container_superblocks() {
        assert_open_error(&Image::default(), "image is too small");
        let mut image = standard_image();
        image.edit(0, |block| put_u32(block, 36, 8192));
        assert_open_error(&image, "non-4096-byte block size");
        let mut image = standard_image();
        image.edit(0, |block| put_u32(block, 104, CHECKPOINT_BLOCKS | 1 << 31));
        assert_open_error(&image, "non-contiguous checkpoint descriptor area");
        let mut image = standard_image();
        image.edit(0, |block| {
            put_u64(block, 112, CHECKPOINT_MAP_BLOCK);
            put_u32(block, 104, 1);
        });
        assert_open_error(&image, "checkpoint area has no valid container superblock");
        let mut image = standard_image();
        image.edit(0, |block| put_u64(block, 112, 1 << 40));
        assert!(matches!(open_error(&image), ApfsError::Read { .. }));
        let mut image = standard_image();
        image.edit(0, |block| put_u32(block, 24, OBJECT_TYPE_OMAP));
        assert_open_error(&image, "is not a container superblock");
    }

    #[test]
    fn rejects_unusable_volume_superblocks_and_object_maps() {
        let mut image = standard_image();
        image.edit(VOLUME_BLOCK, |block| block[32] = b'X');
        assert_open_error(&image, "volume superblock has an invalid magic");
        let mut image = standard_image();
        image.blocks.get_mut(&VOLUME_BLOCK).expect("volume")[100] ^= 1;
        assert!(matches!(
            open_error(&image),
            ApfsError::Checksum(VOLUME_BLOCK)
        ));
        let mut image = standard_image();
        image.edit(LATEST_CHECKPOINT, |block| put_u64(block, 160, VOLUME_BLOCK));
        assert_open_error(&image, "is not a object map");
        let mut image = standard_image();
        image.edit(CONTAINER_OMAP, |block| put_u64(block, 48, VOLUME_BLOCK));
        assert_open_error(&image, "is not a tree node");
    }

    fn with_container_omap(node: &TreeNode) -> Image {
        let mut image = standard_image();
        image.put(CONTAINER_OMAP_TREE, &node.encode(CONTAINER_OMAP_TREE));
        image
    }

    #[test]
    fn object_map_lookups_reject_missing_or_malformed_entries() {
        let missing = "is not in the object map";
        let above = omap_leaf(&[(VOLUME_OID + 1, TEST_XID, VOLUME_BLOCK)], NODE_ROOT);
        assert_open_error(&with_container_omap(&above), missing);
        let below = omap_leaf(&[(VOLUME_OID - 1, TEST_XID, VOLUME_BLOCK)], NODE_ROOT);
        assert_open_error(&with_container_omap(&below), missing);
        let empty = TreeNode::new(NODE_ROOT | NODE_LEAF | NODE_FIXED_KV, Vec::new());
        assert_open_error(&with_container_omap(&empty), "object map node is empty");
        let valueless = TreeNode::new(
            NODE_ROOT | NODE_LEAF | NODE_FIXED_KV,
            vec![(omap_key(VOLUME_OID, TEST_XID), None)],
        );
        assert_open_error(
            &with_container_omap(&valueless),
            "object map entry has no value",
        );
        let looping = TreeNode::new(
            NODE_ROOT | NODE_FIXED_KV,
            vec![(
                omap_key(0, 0),
                Some(CONTAINER_OMAP_TREE.to_le_bytes().to_vec()),
            )],
        );
        assert_open_error(
            &with_container_omap(&looping),
            "object map exceeds maximum depth",
        );
        let overflowing = omap_leaf(&[(VOLUME_OID, TEST_XID, u64::MAX)], NODE_ROOT);
        assert_open_error(&with_container_omap(&overflowing), "overflows");
    }

    fn hashed_volume() -> Volume {
        let mut volume = Volume::new();
        volume.hashed = true;
        for index in 0..3u64 {
            let name = format!("file{index}");
            volume.plain(ROOT, &name, 16 + index, name.as_bytes());
        }
        volume
    }

    #[test]
    fn reads_sealed_volumes_with_hashed_headerless_nodes() {
        let extractor = hashed_volume().image().open().expect("open sealed");
        for index in 0..3 {
            let name = format!("file{index}");
            assert_eq!(read_file(&extractor, &name).expect("read"), name.as_bytes());
        }
    }

    #[test]
    fn sealed_volumes_reject_tampered_children() {
        let mut image = hashed_volume().image();
        let leaf = image.blocks.get_mut(&(FIRST_NODE_BLOCK + 1)).expect("leaf");
        leaf[BLOCK_SIZE - 1] ^= 1;
        let extractor = image.open().expect("open sealed");
        let error = read_file(&extractor, "file0").expect_err("tampered");
        assert!(matches!(error, ApfsError::Hash(oid) if oid == FS_ROOT_OID + 1));
    }

    #[test]
    fn filesystem_tree_rejects_valueless_children_and_deep_chains() {
        let mut image = standard_image();
        let root_block = FIRST_NODE_BLOCK;
        let key = record_key(0, 0);
        let root = TreeNode::new(NODE_ROOT, vec![(key, None)]);
        image.put(root_block, &root.encode(FS_ROOT_OID));
        let extractor = image.open().expect("open");
        let error = read_file(&extractor, "plain.txt").expect_err("valueless");
        assert!(
            error.to_string().contains("invalid child reference"),
            "{error}"
        );

        let mut image = standard_image();
        let chain = MAXIMUM_TREE_DEPTH as u64 + 2;
        let mut omap = Vec::new();
        for level in 0..chain {
            let (oid, block) = (FS_ROOT_OID + level, 3000 + level);
            let child = (oid + 1).to_le_bytes().to_vec();
            let flags = if level == 0 { NODE_ROOT } else { 0 };
            let node = TreeNode::new(flags, vec![(record_key(0, 0), Some(child))]);
            image.put(block, &node.encode(oid));
            omap.push((oid, TEST_XID, block));
        }
        image.set_volume_omap(omap, 4000);
        let extractor = image.open().expect("open");
        let error = read_file(&extractor, "plain.txt").expect_err("deep");
        assert!(
            error
                .to_string()
                .contains("filesystem tree exceeds maximum depth")
        );
    }

    fn physical_key(oid: u64, logical: u64) -> Vec<u8> {
        omap_key(oid, logical)
    }

    fn physical_value(length: u64, block: u64) -> Vec<u8> {
        [length, block].map(u64::to_le_bytes).concat()
    }

    fn extent_tree_volume() -> Volume {
        let mut volume = Volume::new();
        volume.link(ROOT, "split", 16);
        let split_size = BLOCK_SIZE_U64 + 100;
        volume.records.push(inode_record(16, split_size, true));
        volume.link(ROOT, "valueless", 17);
        volume.records.push(inode_record(17, 10, true));
        let one = volume.store(&pattern(BLOCK_SIZE, 4));
        let two = volume.store(&pattern(100, 5));
        volume.physical = vec![
            (physical_key(9, 0), Some(physical_value(1, one))),
            (
                physical_key(16, BLOCK_SIZE_U64),
                Some(physical_value(100, two)),
            ),
            (
                physical_key(16, 0),
                Some(physical_value(BLOCK_SIZE_U64, one)),
            ),
            (physical_key(17, 0), None),
            (physical_key(30, 0), Some(physical_value(1, one))),
        ];
        volume
    }

    #[test]
    fn reads_extents_from_the_physical_extent_tree() {
        let extractor = extent_tree_volume().image().open().expect("open");
        let expected = [pattern(BLOCK_SIZE, 4), pattern(100, 5)].concat();
        assert_eq!(read_file(&extractor, "split").expect("split"), expected);
        let error = read_file(&extractor, "valueless").expect_err("valueless");
        assert!(error.to_string().contains("invalid or sparse"), "{error}");
    }

    fn extent_tree_error(root: &TreeNode, extra: &[(u64, Vec<u8>)]) -> String {
        let mut image = extent_tree_volume().image();
        let address = 5000;
        image.put(address, &root.encode(address));
        for (block, bytes) in extra {
            image.put(*block, bytes);
        }
        image.edit(VOLUME_BLOCK, |block| put_u64(block, 1032, address));
        let extractor = image.open().expect("open");
        read_file(&extractor, "split")
            .expect_err("extent tree")
            .to_string()
    }

    #[test]
    fn physical_extent_tree_rejects_valueless_children_and_deep_chains() {
        let valueless = TreeNode::new(NODE_ROOT, vec![(physical_key(0, 0), None)]);
        let error = extent_tree_error(&valueless, &[]);
        assert!(error.contains("extent index has no child"), "{error}");
        let mut chain = Vec::new();
        for level in 1..=MAXIMUM_TREE_DEPTH as u64 + 2 {
            let child = Some((5000 + level + 1).to_le_bytes().to_vec());
            let node = TreeNode::new(0, vec![(physical_key(0, 0), child)]);
            chain.push((5000 + level, node.encode(5000 + level)));
        }
        let root = TreeNode::new(
            NODE_ROOT,
            vec![(physical_key(0, 0), Some(5001u64.to_le_bytes().to_vec()))],
        );
        let error = extent_tree_error(&root, &chain);
        assert!(
            error.contains("physical extent tree exceeds maximum depth"),
            "{error}"
        );
    }

    /// A device of `u64::MAX` zero bytes.
    struct Endless;

    impl ReadAt for Endless {
        fn read_at(&self, buf: &mut [u8], _offset: u64) -> io::Result<usize> {
            buf.fill(0);
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            u64::MAX
        }
    }

    /// A device whose reads always fail.
    struct Failing;

    impl ReadAt for Failing {
        fn read_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<usize> {
            Err(io::Error::other("device failure"))
        }

        fn size(&self) -> u64 {
            BLOCK_SIZE_U64
        }
    }

    #[test]
    fn device_read_failures_are_reported() {
        assert!(matches!(
            ApfsExtractor::open(Failing),
            Err(ApfsError::Read { .. })
        ));
        let source = ExtentReader::new(&Failing, vec![extent(0, 0, 16)], 16).expect("source");
        let error = DecmpfsReader::new(source, 4, DECMPFS_LZVN)
            .err()
            .expect("failing fork");
        assert!(
            error.to_string().contains("compressed resource fork"),
            "{error}"
        );
    }

    fn extent(logical: u64, physical: u64, length: u64) -> Extent {
        Extent {
            logical,
            physical,
            length,
        }
    }

    #[test]
    fn extent_reader_validates_extents_against_the_device() {
        let half = 1u64 << 63;
        let overflowing = vec![extent(0, 0, half), extent(half, 0, half)];
        let error = ExtentReader::new(&Endless, overflowing, 1)
            .err()
            .expect("overflow");
        assert!(error.to_string().contains("length overflows"));
        let huge_block = vec![extent(0, u64::MAX / BLOCK_SIZE_U64 + 1, 1)];
        assert!(ExtentReader::new(&Endless, huge_block, 1).is_err());
        assert!(ExtentReader::new(&Endless, Vec::new(), u64::MAX).is_err());
        let device = vec![0u8; BLOCK_SIZE];
        let beyond = vec![extent(0, 1, 1)];
        let error = ExtentReader::new(&device, beyond, 1).err().expect("beyond");
        assert!(
            error
                .to_string()
                .contains("exceeds the Apple filesystem image")
        );
        let unchecked = ExtentReader {
            device: &device,
            extents: Vec::new(),
            size: 4,
        };
        let mut buffer = [0u8; 4];
        let error = unchecked.read_at(&mut buffer, 0).expect_err("uncovered");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decmpfs_reader_guards_its_block_table_and_cache() {
        let fork = resource_fork(&[vec![DECMPFS_LZVN_STORED, 7, 7]]);
        let mut device = fork.clone();
        device.resize(BLOCK_SIZE, 0);
        let extents = vec![extent(0, 0, fork.len() as u64)];
        let source = ExtentReader::new(&device, extents, fork.len() as u64).expect("source");
        let oversized = ExtentReader::new(&device, Vec::new(), 0).expect("empty source");
        assert!(DecmpfsReader::new(oversized, u64::MAX, DECMPFS_LZVN).is_err());
        let reader = DecmpfsReader::new(source, 2, DECMPFS_LZVN).expect("reader");
        assert!(matches!(
            reader.decode_block(1),
            Err(ApfsError::Malformed(_))
        ));
        let mut data = [0u8; 2];
        reader.read_exact_at(&mut data, 0).expect("read");
        assert_eq!(data, [7, 7]);
        reader
            .cache
            .lock()
            .expect("cache")
            .blocks
            .insert(0, vec![7]);
        let error = reader
            .read_at(&mut data, 0)
            .expect_err("short cached block");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = reader.cache.lock();
                    panic!("poison the decmpfs cache");
                })
                .join()
        });
        assert!(poisoned.is_err());
        assert!(reader.read_at(&mut data, 0).is_err());
    }

    #[test]
    fn decompresses_codec_blocks_by_method() {
        let plain = pattern(300, 6);
        let lzvn = decompress_block(&lzvn_literals(&plain), DECMPFS_LZVN, 300).expect("lzvn");
        assert_eq!(lzvn, plain);
        let lzfse = decompress_block(&lzfse(&plain), DECMPFS_LZFSE, 300).expect("lzfse");
        assert_eq!(lzfse, plain);
        let bitmap = decompress_block(&lzbitmap_stored(&plain), DECMPFS_LZBITMAP, 300);
        assert_eq!(bitmap.expect("lzbitmap"), plain);
        assert_eq!(
            decompress_block(&[], DECMPFS_LZVN, 0).expect("empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn parses_other_record_types_as_ignored() {
        assert!(matches!(
            parse_record(RECORD_SIBLING_LINK, &[0; 8], &[]),
            Ok(Record::Other)
        ));
    }

    const REPLAY_MAGIC: &[u8; 8] = b"APFSREC1";
    const REPLAY_ENV: &str = "IPAKEEP_APFS_REPLAY";
    const REPLAY_NAME: &str = "ipakeep/test-fixtures/apfs-filesystem-26A434.apfsrec";
    const FRAMEWORKS: [(&str, &str); 5] = [
        (
            "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid",
            "43419a206c28bc93ecb8884256088d18306a0a462350f83adbced8e60a94e390",
        ),
        (
            "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
            "c4b2088dd39aeb353f59cb57597902e8317aec66ae7da0414b03c5f932771343",
        ),
        (
            "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
            "afbc123e688a822d980d5816cc2b52f69fde669d1dca92cf85627e1cbee587f6",
        ),
        (
            "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
            "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
        ),
        (
            "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd",
            "1e58d37e9602dd0ca5e24b14762063b6c310248b4d3a94272771d815e4ea1784",
        ),
    ];

    /// Sparse image holding only the byte ranges upstream ipatool read
    /// while extracting the pinned frameworks.
    struct Replay {
        size: u64,
        spans: Vec<(u64, Vec<u8>)>,
    }

    impl Replay {
        fn load(path: &Path) -> Self {
            let raw = fs::read(path).expect("read replay fixture");
            assert_eq!(&raw[..8], REPLAY_MAGIC);
            let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().expect("word"));
            let (size, count) = (word(8), word(16));
            let mut spans = Vec::new();
            let mut at = 24;
            for _ in 0..count {
                let (offset, length) = (word(at), usize::try_from(word(at + 8)).expect("length"));
                spans.push((offset, raw[at + 16..at + 16 + length].to_vec()));
                at += 16 + length;
            }
            Self { size, spans }
        }
    }

    impl ReadAt for Replay {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            let index = self.spans.partition_point(|(start, _)| *start <= offset);
            let (start, data) = index
                .checked_sub(1)
                .map(|slot| &self.spans[slot])
                .ok_or_else(|| io::Error::other(format!("offset {offset} was not recorded")))?;
            let within = usize::try_from(offset - start).expect("within");
            let available = data.get(within..).unwrap_or_default();
            if available.len() < buf.len() {
                return Err(io::Error::other(format!(
                    "range {offset}+{} was not recorded",
                    buf.len()
                )));
            }
            buf.copy_from_slice(&available[..buf.len()]);
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            self.size
        }
    }

    fn replay_path() -> PathBuf {
        std::env::var_os(REPLAY_ENV)
            .map(PathBuf::from)
            .or_else(|| dirs::cache_dir().map(|cache| cache.join(REPLAY_NAME)))
            .expect("replay fixture path")
    }

    #[test]
    #[ignore = "needs the recorded macOS 26A434 filesystem cryptex reads (IPAKEEP_APFS_REPLAY or ~/Library/Caches/ipakeep/test-fixtures)"]
    fn extracts_pinned_frameworks_from_recorded_cryptex() {
        let replay = Replay::load(&replay_path());
        let destination = std::env::temp_dir().join(format!("ipakeep-apfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&destination);
        let paths: Vec<&str> = FRAMEWORKS.iter().map(|(path, _)| *path).collect();
        extract_apfs_files(&replay, &paths, &destination).expect("extract");
        for (path, digest) in FRAMEWORKS {
            let name = Path::new(path).file_name().expect("name");
            let data = fs::read(destination.join(name)).expect("read output");
            assert_eq!(hex::encode(Sha256::digest(&data)), digest, "{path}");
        }
        fs::remove_dir_all(&destination).expect("cleanup");
    }

    fn fat_binary(cpu: u32, subtype: u32, offset: u32, length: u32, total: usize) -> Vec<u8> {
        let mut data = vec![0u8; total];
        data[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&1u32.to_be_bytes());
        for (index, word) in [cpu, subtype, offset, length].into_iter().enumerate() {
            data[8 + index * 4..12 + index * 4].copy_from_slice(&word.to_be_bytes());
        }
        data
    }

    #[test]
    fn arm64e_range_selects_slice_or_whole_thin_image() {
        let fat = fat_binary(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E | 0x8000_0000, 64, 32, 96);
        assert_eq!(arm64e_range(&fat).expect("fat"), (64, 32));
        let thin = vec![0xcf, 0xfa, 0xed, 0xfe, 0, 0];
        assert_eq!(arm64e_range(&thin).expect("thin"), (0, 6));
        let arm64 = fat_binary(CPU_TYPE_ARM64, 0, 64, 32, 96);
        assert!(arm64e_range(&arm64).is_err());
        let overflowing = fat_binary(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, 64, 64, 96);
        assert!(arm64e_range(&overflowing).is_err());
    }

    #[test]
    fn stored_blocks_skip_their_marker_byte() {
        assert_eq!(
            decompress_block(&[0x06, 1, 2], DECMPFS_LZVN, 2).expect("lzvn"),
            vec![1, 2]
        );
        assert_eq!(
            decompress_block(&[0xcc, 3], DECMPFS_LZFSE, 1).expect("lzfse"),
            vec![3]
        );
        assert_eq!(
            decompress_block(&[0xff, 4], DECMPFS_LZBITMAP, 1).expect("lzbitmap"),
            vec![4]
        );
    }

    #[test]
    fn inode_stream_size_honours_field_alignment() {
        let mut blob = vec![2, 0, 0, 0, 1, 0, 3, 0, INODE_FIELD_DATA_STREAM, 0, 40, 0];
        blob.extend_from_slice(&[0xaa; 8]);
        blob.extend_from_slice(&1234u64.to_le_bytes());
        assert_eq!(inode_stream_size(&blob).expect("parse"), Some(1234));
        assert_eq!(inode_stream_size(&[0, 0, 0, 0]).expect("empty"), None);
    }

    #[test]
    fn block_offsets_must_be_contiguous_and_end_at_fork_size() {
        assert!(validate_block_offsets(&[8, 20], 8, 20).is_ok());
        assert!(validate_block_offsets(&[8, 20], 8, 21).is_err());
        assert!(validate_block_offsets(&[4, 20], 8, 20).is_err());
        assert!(validate_block_offsets(&[8, 8], 8, 8).is_err());
    }

    #[test]
    fn fletcher64_matches_apfs_reference() {
        let mut block = vec![0u8; BLOCK_SIZE];
        block[8..12].copy_from_slice(&1u32.to_le_bytes());
        block[12..16].copy_from_slice(&2u32.to_le_bytes());
        let checksum = fletcher64(&block);
        block[..8].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(checksum, 0x0bf8_ffff_f404);
    }

    #[test]
    fn extent_reader_rejects_sparse_extents() {
        let device = vec![0u8; BLOCK_SIZE * 4];
        let gap = vec![Extent {
            logical: 4096,
            physical: 0,
            length: 4096,
        }];
        assert!(ExtentReader::new(&device, gap, 4096).is_err());
        let extents = vec![Extent {
            logical: 0,
            physical: 1,
            length: 4096,
        }];
        let reader = ExtentReader::new(&device, extents, 100).expect("reader");
        let mut buffer = [1u8; 200];
        assert_eq!(reader.read_at(&mut buffer, 0).expect("read"), 100);
    }

    #[test]
    fn open_rejects_non_container_images() {
        let image = vec![0u8; BLOCK_SIZE];
        assert!(matches!(
            ApfsExtractor::open(image),
            Err(ApfsError::Unsupported(_))
        ));
    }
}
