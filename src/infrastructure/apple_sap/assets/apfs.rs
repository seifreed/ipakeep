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
    for word in block[8..].chunks_exact(4) {
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
        Ok(Self {
            container,
            volume_omap,
            filesystem_root,
            root_tree_base: volume.root_tree,
            transaction_id,
            extent_tree: volume.extent_tree,
        })
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
        let address =
            self.omap_lookup(&container_omap, volume_id, object_transaction(&container)?)?;
        let volume = self.read_typed_object(address, OBJECT_TYPE_VOLUME, "volume superblock")?;
        if field::<4>(&volume, CONTAINER_MAGIC_OFFSET)? != *VOLUME_MAGIC {
            return Err(malformed("volume superblock has an invalid magic"));
        }
        Ok(VolumeInfo {
            xid: object_transaction(&volume)?,
            omap: le_u64(&volume, VOLUME_OMAP_OFFSET)?,
            root_tree: le_u64(&volume, VOLUME_ROOT_TREE_OFFSET)?,
            extent_tree: le_u64(&volume, VOLUME_EXTENT_TREE_OFFSET)?,
        })
    }

    /// Returns the valid checkpoint superblock with the highest transaction.
    fn latest_checkpoint(&self) -> Result<Vec<u8>> {
        const BLOCK_SIZE_OFFSET: usize = 36;
        const DESCRIPTOR_BLOCKS_OFFSET: usize = 104;
        const DESCRIPTOR_BASE_OFFSET: usize = 112;
        const NON_CONTIGUOUS: u32 = 1 << 31;
        let superblock =
            self.read_typed_object(0, OBJECT_TYPE_CONTAINER, "container superblock")?;
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
            let candidate = match self.read_object(base + index) {
                Ok(block) if object_type(&block)? == OBJECT_TYPE_CONTAINER => block,
                Ok(_) | Err(ApfsError::Checksum(_)) => continue,
                Err(err) => return Err(err),
            };
            let newer = match &latest {
                Some(current) => object_transaction(&candidate)? >= object_transaction(current)?,
                None => true,
            };
            if newer {
                latest = Some(candidate);
            }
        }
        latest.ok_or_else(|| malformed("checkpoint area has no valid container superblock"))
    }

    /// Resolves a virtual object to its physical address (go-apfs
    /// `GetOMapEntry` semantics: newest version not after `max_xid`).
    fn omap_lookup(&self, root: &Node, object_id: u64, max_xid: u64) -> Result<u64> {
        let mut child: Option<Node> = None;
        for _ in 0..MAXIMUM_TREE_DEPTH {
            let node = child.as_ref().unwrap_or(root);
            let index = Self::omap_floor(node, object_id, max_xid)?;
            let entry = node.map_entry(index)?;
            let value = entry
                .value
                .ok_or_else(|| malformed("object map entry has no value"))?;
            if node.is_leaf() {
                let (oid, xid) = (le_u64(entry.key, 0)?, le_u64(entry.key, 8)?);
                if oid != object_id || xid > max_xid {
                    return Err(malformed(format!(
                        "object {object_id:#x} is not in the object map"
                    )));
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
        let records = self.resolve_path(path)?;
        let mut inode = None;
        let mut compression = None;
        let mut resource = None;
        let mut extents = Vec::new();
        for record in records {
            match record {
                Record::Inode { private_id, size } => inode = Some((private_id, size)),
                Record::Extent(extent) => extents.push(extent),
                Record::Xattr { name, value } if name == DECMPFS_XATTR => {
                    compression = Some(decmpfs_header(&value)?);
                }
                Record::Xattr {
                    name,
                    value: XattrValue::Stream { object_id, size },
                } if name == RESOURCE_FORK_XATTR => resource = Some((object_id, size)),
                _ => {}
            }
        }
        let (private_id, size) = inode.ok_or_else(|| malformed("file has no inode record"))?;
        if let Some((method, output_size)) = compression {
            return self.open_compressed(method, output_size, resource);
        }
        if extents.is_empty() && size != 0 {
            extents = self.data_extents(private_id)?;
        }
        Ok(ApfsFile::Plain(ExtentReader::new(
            &self.container.device,
            extents,
            size,
        )?))
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
        let (object_id, size) =
            resource.ok_or_else(|| malformed("compressed file has no resource fork"))?;
        let extents = self.data_extents(object_id)?;
        let source = ExtentReader::new(&self.container.device, extents, size)?;
        Ok(ApfsFile::Compressed(DecmpfsReader::new(
            source,
            output_size,
            method,
        )?))
    }

    fn resolve_path(&self, path: &str) -> Result<Vec<Record>> {
        let mut object_id = ROOT_DIRECTORY_ID;
        for name in path.trim_matches('/').split('/') {
            object_id = self
                .records_for(object_id)?
                .into_iter()
                .find_map(|record| match record {
                    Record::DirectoryEntry {
                        name: entry,
                        file_id,
                    } if entry == name => Some(file_id),
                    _ => None,
                })
                .ok_or_else(|| ApfsError::NotFound(name.to_owned()))?;
        }
        self.records_for(object_id)
    }

    fn records_for(&self, object_id: u64) -> Result<Vec<Record>> {
        let mut visited = HashSet::new();
        let mut records = Vec::new();
        self.collect_records(
            &self.filesystem_root,
            object_id,
            &mut visited,
            0,
            &mut records,
        )?;
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
                    records.push(parse_record(
                        record_type,
                        entry.key,
                        entry.value.unwrap_or_default(),
                    )?);
                }
                continue;
            }
            if !Self::child_may_contain(node, index, header & RECORD_ID_MASK, object_id)? {
                continue;
            }
            let (child, address) = self.filesystem_child(node, entry.value)?;
            if visited.insert(address) {
                self.collect_records(&child, object_id, visited, depth + 1, records)?;
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
        let address =
            self.container
                .omap_lookup(&self.volume_omap, object_id, self.transaction_id)?;
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
                continue;
            }
            let Some(address) = Self::extent_child(node, index, &entry, object_id)? else {
                continue;
            };
            if visited.insert(address) {
                let child = self.container.read_node(address)?;
                self.collect_physical_extents(&child, object_id, visited, depth + 1, extents)?;
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
        let value = entry
            .value
            .ok_or_else(|| malformed("extent index has no child"))?;
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
        let output_path = destination.join(name);
        let result = write_output(&output_path, &SectionReader::new(&file, offset, size));
        if result.is_err() {
            let _ = fs::remove_file(&output_path);
        }
        result
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

fn write_output(path: &Path, source: &impl ReadAt) -> Result<()> {
    let output_error = |source| ApfsError::Output {
        path: path.to_path_buf(),
        source,
    };
    let mut output = create_output(path).map_err(output_error)?;
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
        output.write_all(&buffer[..wanted]).map_err(output_error)?;
        offset += wanted as u64;
    }
    output.sync_all().map_err(output_error)
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

/// Reads a file's logical bytes from its physical extents.
pub struct ExtentReader<'a, R> {
    device: &'a R,
    extents: Vec<Extent>,
    size: u64,
}

impl<'a, R: ReadAt> ExtentReader<'a, R> {
    fn new(device: &'a R, mut extents: Vec<Extent>, size: u64) -> Result<Self> {
        if size > i64::MAX as u64 {
            return Err(malformed(format!(
                "file size {size} exceeds the supported maximum"
            )));
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
            return Err(malformed(format!(
                "file extents cover {position} bytes, expected {size}"
            )));
        }
        Ok(Self {
            device,
            extents,
            size,
        })
    }
}

impl<R: ReadAt> ReadAt for ExtentReader<'_, R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut written = 0usize;
        let mut position = offset;
        while written < buf.len() && position < self.size {
            let index = self
                .extents
                .partition_point(|extent| extent.logical + extent.length <= position);
            let Some(extent) = self
                .extents
                .get(index)
                .filter(|extent| position >= extent.logical)
            else {
                return Err(io::ErrorKind::UnexpectedEof.into());
            };
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
            return Err(malformed(format!(
                "compressed file size {output_size} exceeds the supported maximum"
            )));
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
            return Err(malformed(format!(
                "compression index has size {declared}, expected {table_size}"
            )));
        }
        let mut table = vec![0u8; to_usize(table_size)?];
        read_resource(&source, &mut table, 0)?;
        let offsets: Vec<u64> = table
            .chunks_exact(4)
            .map(|entry| u64::from(u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]])))
            .collect();
        validate_block_offsets(&offsets, table_size, source_size)?;
        Ok(Self {
            source,
            output_size,
            method,
            offsets,
            cache: Mutex::new(BlockCache::default()),
        })
    }

    fn block(&self, index: u64) -> io::Result<Vec<u8>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("decmpfs cache lock poisoned"))?;
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
        let (Some(&start), Some(&end)) = (self.offsets.get(slot), self.offsets.get(slot + 1))
        else {
            return Err(malformed(format!(
                "compressed block {index} is out of range"
            )));
        };
        let mut compressed = vec![0u8; to_usize(end - start)?];
        read_resource(&self.source, &mut compressed, start)?;
        let expected = DECMPFS_BLOCK_SIZE.min(self.output_size - index * DECMPFS_BLOCK_SIZE);
        let plain =
            decompress_block(&compressed, self.method, to_usize(expected)?).map_err(|source| {
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
}

fn read_resource<R: ReadAt>(
    source: &ExtentReader<'_, R>,
    buffer: &mut [u8],
    offset: u64,
) -> Result<()> {
    source
        .read_exact_at(buffer, offset)
        .map_err(|source| ApfsError::Read {
            context: "compressed resource fork".into(),
            source,
        })
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
        let wanted = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
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
