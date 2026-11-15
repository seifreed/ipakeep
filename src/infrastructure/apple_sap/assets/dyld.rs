//! Ported from ipatool `internal/sap/assets/dyld.go`.
//!
//! Reads the arm64e dyld shared cache (primary file plus subcaches) through
//! positional readers, decodes slide info v5 and exports one cached image as a
//! standalone thin Mach-O, byte-identical to ipatool's go-macho export.

pub mod export;

use std::io;

use thiserror::Error;

use self::export::{ExportError, ImageMemory, MachImage, le_u32, le_u64};
use super::dyld_symbols::restore_image_symbols;
use super::http_range::ReadAt;

/// Install name of the framework ipatool extracts from the shared cache.
pub const APPLE_MEDIA_SERVICES_IMAGE: &str =
    "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices";
/// Path of the primary arm64e shared-cache file inside the `SystemOS` cryptex.
pub const ARM64E_CACHE_PATH: &str = "/System/Library/dyld/dyld_shared_cache_arm64e";

const HEADER_SIZE: usize = 568;
const MAPPING_SIZE: usize = 56;
const IMAGE_INFO_SIZE: usize = 32;
const SUBCACHE_ENTRY_SIZE: usize = 56;
const MAXIMUM_MAPPINGS: u64 = 64;
const MAXIMUM_IMAGES: u64 = 100_000;
const MAXIMUM_SUBCACHES: u64 = 128;
const MAXIMUM_PATH_LENGTH: u64 = 4096;
const SLIDE_INFO_5_SIZE: usize = 24;
const SLIDE_VERSION_5: u32 = 5;
const MAXIMUM_LOAD_COMMANDS_SIZE: u64 = 16 << 20;
const MAXIMUM_SLIDE_CHAIN_POINTERS: usize = 1 << 16;
const SEGMENT_COMMAND_MINIMUM: u64 = 72;
const CACHE_MAGIC: &[u8] = b"dyld_v1  arm64e";
const MAGIC_FIELD: std::ops::Range<usize> = 0..16;
const UUID_FIELD: std::ops::Range<usize> = 88..104;
const MAPPING_OFFSET_FIELD: usize = 312;
const MAPPING_COUNT_FIELD: usize = 316;
const SUBCACHE_OFFSET_FIELD: usize = 392;
const SUBCACHE_COUNT_FIELD: usize = 396;
const IMAGES_OFFSET_FIELD: usize = 448;
const IMAGES_COUNT_FIELD: usize = 452;
const SUBCACHE_SUFFIX_FIELD: std::ops::Range<usize> = 24..56;
const IMAGE_PATH_OFFSET_FIELD: usize = 24;
const NO_REBASE_PAGE: u16 = 0xffff;
const POINTER_SIZE: u64 = 8;
const POINTER_BYTES: usize = 8;
const CACHE_PAGE_BYTES: usize = 4096;
const SLIDE_TARGET_BITS: u32 = 34;
const SLIDE_HIGH8_SHIFT: u32 = 56;
const SLIDE_HIGH8_MASK: u64 = 0xff;
const SLIDE_AUTH_BIT: u32 = 63;
const SLIDE_NEXT_SHIFT: u32 = 52;
const SLIDE_NEXT_MASK: u64 = 0x7ff;
const LINKEDIT_SEGMENT: &[u8] = b"__LINKEDIT";
/// Size of the unslid pages returned by [`DyldCache::page`].
pub const CACHE_PAGE_SIZE: u64 = 4096;

/// Failures while reading the shared cache or exporting an image from it.
#[derive(Debug, Error)]
pub enum DyldError {
    /// A cache member could not be opened or read.
    #[error("{context}: {source}")]
    Io {
        /// What was being read.
        context: &'static str,
        /// Underlying failure.
        source: io::Error,
    },
    /// The cache structure is malformed.
    #[error("invalid shared cache: {0}")]
    Format(&'static str),
    /// The cache is not an arm64e v1 cache.
    #[error("unsupported shared-cache format {0:?}")]
    UnsupportedFormat(String),
    /// A mapping uses a slide-info version other than 5.
    #[error("unsupported shared-cache slide version {0}")]
    UnsupportedSlideVersion(u32),
    /// A subcache's UUID does not match the primary's table.
    #[error("shared-cache member {0} has an unexpected UUID")]
    SubcacheUuid(String),
    /// The requested image is not in the cache.
    #[error("image {0} was not found")]
    ImageNotFound(String),
    /// An address is not backed by any mapping.
    #[error("address {0:#x} is outside the shared cache")]
    AddressOutsideCache(u64),
    /// The image could not be exported.
    #[error("export image: {0}")]
    Export(#[from] ExportError),
}

/// Opens one shared-cache member by suffix (`""` is the primary file).
pub trait CacheOpener<'src> {
    /// Opens the member named `ARM64E_CACHE_PATH + suffix`.
    ///
    /// # Errors
    /// Returns the underlying I/O failure.
    fn open(&mut self, suffix: &str) -> io::Result<Box<dyn ReadAt + 'src>>;
}

impl<'src, F> CacheOpener<'src> for F
where
    F: FnMut(&str) -> io::Result<Box<dyn ReadAt + 'src>>,
{
    fn open(&mut self, suffix: &str) -> io::Result<Box<dyn ReadAt + 'src>> {
        self(suffix)
    }
}

/// One `dyld_cache_mapping_and_slide_info` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// Index of the member file holding the mapping.
    pub member: usize,
    /// Unslid virtual address.
    pub address: u64,
    /// Mapping size.
    pub size: u64,
    /// Offset in the member file.
    pub file_offset: u64,
    /// Slide info offset in the member file.
    pub slide_info_offset: u64,
    /// Slide info size.
    pub slide_info_size: u64,
}

impl Mapping {
    fn contains(&self, address: u64) -> bool {
        self.address <= address && address - self.address < self.size
    }

    fn file_offset_of(&self, address: u64) -> u64 {
        self.file_offset + (address - self.address)
    }
}

struct Member<'src> {
    source: Box<dyn ReadAt + 'src>,
    uuid: [u8; 16],
    mappings: Vec<Mapping>,
}

impl Member<'_> {
    fn read(&self, buf: &mut [u8], offset: u64, context: &'static str) -> Result<(), DyldError> {
        self.source
            .read_exact_at(buf, offset)
            .map_err(|source| DyldError::Io { context, source })
    }

    fn size(&self) -> u64 {
        self.source.size()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlideInfo5 {
    page_size: u32,
    page_starts_count: u32,
    value_add: u64,
}

impl SlideInfo5 {
    fn decode(&self, pointer: u64) -> u64 {
        if pointer == 0 {
            return 0;
        }
        let mut target = pointer & ((1u64 << SLIDE_TARGET_BITS) - 1);
        if pointer >> SLIDE_AUTH_BIT == 0 {
            target |= ((pointer >> SLIDE_TARGET_BITS) & SLIDE_HIGH8_MASK) << SLIDE_HIGH8_SHIFT;
        }
        self.value_add.wrapping_add(target)
    }
}

/// A rebased pointer location and its unslid target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rebase {
    /// Location of the pointer.
    pub address: u64,
    /// Decoded unslid target.
    pub target: u64,
}

/// A cached image located by install name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedImage {
    member: usize,
    /// Unslid load address.
    pub address: u64,
    offset: u64,
}

/// An opened arm64e shared cache.
pub struct DyldCache<'src> {
    members: Vec<Member<'src>>,
    slide: SlideInfo5,
}

impl std::fmt::Debug for DyldCache<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DyldCache")
            .field("members", &self.members.len())
            .field("slide", &self.slide)
            .finish_non_exhaustive()
    }
}

/// Exports `image_path` from the shared cache served by `opener`
/// (ipatool `extractDyldImageFromFiles`).
///
/// # Errors
/// Fails when the cache is malformed or the image cannot be exported.
pub fn extract_dyld_image<'src>(
    opener: impl CacheOpener<'src>,
    image_path: &str,
) -> Result<Vec<u8>, DyldError> {
    DyldCache::open(opener)?.export_image(image_path)
}

impl<'src> DyldCache<'src> {
    /// Opens the primary member and every subcache it lists.
    ///
    /// # Errors
    /// Fails on malformed headers, UUID mismatches or missing slide info.
    pub fn open(mut opener: impl CacheOpener<'src>) -> Result<Self, DyldError> {
        let (primary, header) = open_member(&mut opener, "")?;
        let entries = subcache_entries(&primary, &header)?;
        let mut members = vec![primary];
        for (suffix, uuid) in entries {
            let (mut member, _) = open_member(&mut opener, &suffix)?;
            if member.uuid != uuid {
                return Err(DyldError::SubcacheUuid(suffix));
            }
            let index = members.len();
            member
                .mappings
                .iter_mut()
                .for_each(|mapping| mapping.member = index);
            members.push(member);
        }
        let slide = common_slide_info(&members)?;
        Ok(Self { members, slide })
    }

    /// Every mapping, in member then table order.
    pub fn mappings(&self) -> impl Iterator<Item = &Mapping> {
        self.members
            .iter()
            .flat_map(|member| member.mappings.iter())
    }

    /// The mapping holding `address`.
    ///
    /// # Errors
    /// Fails when no mapping contains the address.
    pub fn mapping_for_address(&self, address: u64) -> Result<&Mapping, DyldError> {
        self.mappings()
            .find(|mapping| mapping.contains(address))
            .ok_or(DyldError::AddressOutsideCache(address))
    }

    /// The unslid start and length of the range covered by all mappings.
    pub fn address_range(&self) -> (u64, u64) {
        let start = self
            .mappings()
            .map(|mapping| mapping.address)
            .min()
            .unwrap_or(u64::MAX);
        let end = self
            .mappings()
            .map(|mapping| mapping.address.wrapping_add(mapping.size))
            .max()
            .unwrap_or(0);
        (start, end.wrapping_sub(start))
    }

    /// Reports whether `[address, address + size)` lies inside one mapping.
    pub fn contains(&self, address: u64, size: u64) -> bool {
        self.mappings().any(|mapping| {
            address >= mapping.address
                && address - mapping.address <= mapping.size
                && size <= mapping.size - (address - mapping.address)
        })
    }

    /// Exports one image as a standalone Mach-O with slid pointers resolved.
    ///
    /// # Errors
    /// Fails when the image is missing or cannot be exported.
    pub fn export_image(&self, image_path: &str) -> Result<Vec<u8>, DyldError> {
        let image = self.image(image_path)?;
        let linkedit = self
            .mapping_for_address(self.linkedit_address(&image)?)?
            .member;
        let mut macho = self.parse_image(&image)?;
        restore_image_symbols(self, &image, linkedit, &mut macho)?;
        let memory = CacheMemory {
            cache: self,
            linkedit_member: linkedit,
        };
        let mut exported = export::export_in_cache_image(macho, &memory, &[])?;
        self.apply_slide(&mut exported)?;
        Ok(exported)
    }

    /// Locates an image by install name.
    ///
    /// # Errors
    /// Fails on a malformed image table or when the image is absent.
    pub fn image(&self, path: &str) -> Result<CachedImage, DyldError> {
        let table = self.image_table()?;
        for entry in table.chunks_exact(IMAGE_INFO_SIZE) {
            let (name, address) = self.image_entry(entry)?;
            if name == path.as_bytes() {
                let mapping = self.mapping_for_address(address)?;
                return Ok(CachedImage {
                    member: mapping.member,
                    address,
                    offset: mapping.file_offset_of(address),
                });
            }
        }
        Err(DyldError::ImageNotFound(path.to_owned()))
    }

    /// Every image install name with its unslid load address.
    ///
    /// # Errors
    /// Fails on a malformed image table.
    pub fn images(&self) -> Result<Vec<(String, u64)>, DyldError> {
        let table = self.image_table()?;
        table
            .chunks_exact(IMAGE_INFO_SIZE)
            .map(|entry| {
                let (name, address) = self.image_entry(entry)?;
                Ok((String::from_utf8_lossy(&name).into_owned(), address))
            })
            .collect()
    }

    fn image_entry(&self, entry: &[u8]) -> Result<(Vec<u8>, u64), DyldError> {
        let primary = &self.members[0];
        let address = le_u64(entry, 0).ok_or(DyldError::Format("truncated image entry"))?;
        let path_offset = header_u32(entry, IMAGE_PATH_OFFSET_FIELD)?;
        Ok((read_cstring(primary, primary.size(), path_offset)?, address))
    }

    fn image_table(&self) -> Result<Vec<u8>, DyldError> {
        let primary = &self.members[0];
        let mut header = vec![0; HEADER_SIZE];
        primary.read(&mut header, 0, "read shared-cache header")?;
        let offset = header_u32(&header, IMAGES_OFFSET_FIELD)?;
        let count = header_u32(&header, IMAGES_COUNT_FIELD)?;
        if count == 0
            || count > MAXIMUM_IMAGES
            || !valid_range(primary.size(), offset, count * IMAGE_INFO_SIZE as u64)
        {
            return Err(DyldError::Format("shared cache has an invalid image table"));
        }
        let mut table = vec![0; to_usize(count * IMAGE_INFO_SIZE as u64)?];
        primary.read(&mut table, offset, "read shared-cache image table")?;
        Ok(table)
    }

    /// Reads unslid bytes at a virtual address, crossing mappings as needed.
    ///
    /// # Errors
    /// Fails when part of the range is unmapped or unreadable.
    pub fn read_at_addr(&self, buf: &mut [u8], mut address: u64) -> Result<(), DyldError> {
        let mut written = 0;
        while written < buf.len() {
            let mapping = self.mapping_for_address(address)?;
            let available = mapping.address + mapping.size - address;
            let remaining = u64::try_from(buf.len() - written).unwrap_or(u64::MAX);
            let count = to_usize(available.min(remaining))?;
            let member = &self.members[mapping.member];
            member.read(
                &mut buf[written..written + count],
                mapping.file_offset_of(address),
                "read shared-cache data",
            )?;
            written += count;
            address += count as u64;
        }
        Ok(())
    }

    /// Returns one unslid 4 KiB page with its slide-info pointers decoded
    /// (ipatool `StoreCache.Page`, without its per-page cache).
    ///
    /// # Errors
    /// Fails on an unaligned or unmapped address.
    pub fn page(&self, address: u64) -> Result<Vec<u8>, DyldError> {
        if !address.is_multiple_of(CACHE_PAGE_SIZE) {
            return Err(DyldError::Format("unaligned Store page"));
        }
        let mapping = *self.mapping_for_address(address)?;
        let mut data = vec![0; CACHE_PAGE_BYTES];
        self.read_at_addr(&mut data, address)?;
        if mapping.slide_info_size == 0 {
            return Ok(data);
        }
        let page_size = u64::from(self.slide_info(&mapping)?.page_size);
        let index = (address - mapping.address) / page_size;
        for rebase in self.rebases(&mapping, index, index + 1)? {
            if rebase.address >= address
                && rebase.address + POINTER_SIZE <= address + CACHE_PAGE_SIZE
            {
                let start = to_usize(rebase.address - address)?;
                data[start..start + POINTER_BYTES].copy_from_slice(&rebase.target.to_le_bytes());
            }
        }
        Ok(data)
    }

    /// Decodes a raw cache pointer (ipatool `slidePointer`).
    pub fn slide_pointer(&self, pointer: u64) -> u64 {
        if pointer == 0 || self.mapping_for_address(pointer).is_ok() {
            return pointer;
        }
        self.slide.decode(pointer)
    }

    pub(crate) fn read_member(
        &self,
        member: usize,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<(), DyldError> {
        let member = self
            .members
            .get(member)
            .ok_or(DyldError::Format("unknown shared-cache member"))?;
        member.read(buf, offset, "read shared-cache member")
    }

    pub(crate) fn member_size(&self, member: usize) -> u64 {
        self.members.get(member).map_or(0, Member::size)
    }

    pub(crate) fn read_cstring(
        &self,
        member: usize,
        size: u64,
        offset: u64,
    ) -> Result<Vec<u8>, DyldError> {
        let source = self
            .members
            .get(member)
            .ok_or(DyldError::Format("unknown shared-cache member"))?;
        read_cstring(source, size, offset)
    }

    /// Reads the image's header and raw load commands.
    pub(crate) fn image_commands(
        &self,
        image: &CachedImage,
    ) -> Result<(Vec<u8>, Vec<u8>), DyldError> {
        let mut header = vec![0; export::MACH_HEADER_64_SIZE];
        self.read_member(image.member, &mut header, image.offset)?;
        let size =
            u64::from(le_u32(&header, 20).ok_or(DyldError::Format("truncated Mach-O header"))?);
        if size > MAXIMUM_LOAD_COMMANDS_SIZE {
            return Err(DyldError::Format("invalid image load command size"));
        }
        let mut commands = vec![0; to_usize(size)?];
        self.read_member(
            image.member,
            &mut commands,
            image.offset + export::MACH_HEADER_64_SIZE as u64,
        )?;
        Ok((header, commands))
    }

    fn parse_image(&self, image: &CachedImage) -> Result<MachImage, DyldError> {
        let (header, commands) = self.image_commands(image)?;
        Ok(MachImage::parse(
            &header,
            &commands,
            &[export::LC_SYMTAB, export::LC_DYSYMTAB],
        )?)
    }

    /// The `__LINKEDIT` vmaddr of an image (ipatool `dyldImage.linkeditAddress`).
    pub(crate) fn linkedit_address(&self, image: &CachedImage) -> Result<u64, DyldError> {
        let mut header = vec![0; export::MACH_HEADER_64_SIZE];
        self.read_member(image.member, &mut header, image.offset)?;
        if le_u32(&header, 0) != Some(export::MH_MAGIC_64) {
            return Err(DyldError::Format("image has an invalid Mach-O magic"));
        }
        let count = header_u32(&header, 16)?;
        let size = header_u32(&header, 20)?;
        let start = image.offset + export::MACH_HEADER_64_SIZE as u64;
        if size > MAXIMUM_LOAD_COMMANDS_SIZE
            || !valid_range(self.member_size(image.member), start, size)
        {
            return Err(DyldError::Format("image has invalid load commands"));
        }
        let mut commands = vec![0; to_usize(size)?];
        self.read_member(image.member, &mut commands, start)?;
        find_linkedit(&commands, count)
    }

    fn slide_info(&self, mapping: &Mapping) -> Result<SlideInfo5, DyldError> {
        read_slide_info(&self.members[mapping.member], mapping)
    }

    /// Decodes the slide chains of `[start_page, end_page)` of a mapping.
    ///
    /// # Errors
    /// Fails on malformed slide information.
    pub fn rebases(
        &self,
        mapping: &Mapping,
        start_page: u64,
        end_page: u64,
    ) -> Result<Vec<Rebase>, DyldError> {
        let member = &self.members[mapping.member];
        slide_version(member, mapping)?;
        let slide = read_slide_info(member, mapping)?;
        let starts = read_page_starts(member, mapping, slide.page_starts_count)?;
        let page_count = starts.len() as u64;
        let end_page = if end_page == 0 || end_page > page_count {
            page_count
        } else {
            end_page
        };
        if start_page > end_page {
            return Err(DyldError::Format("invalid shared-cache slide page range"));
        }
        let mut rebases = Vec::new();
        for page in start_page..end_page {
            let start = starts[to_usize(page)?];
            if start != NO_REBASE_PAGE {
                walk_slide_chain(member, mapping, &slide, page, start, &mut rebases)?;
            }
        }
        Ok(rebases)
    }

    fn apply_slide(&self, exported: &mut Vec<u8>) -> Result<(), DyldError> {
        let segments = exported_segments(exported)?;
        for segment in &segments {
            let mapping = *self.mapping_for_address(segment.address)?;
            if mapping.slide_info_offset == 0 {
                continue;
            }
            let page_size = u64::from(self.slide_info(&mapping)?.page_size);
            let start = (segment.address - mapping.address) / page_size;
            let end =
                (segment.address + segment.memory_size - mapping.address + page_size) / page_size;
            for rebase in self.rebases(&mapping, start, end)? {
                if let Some(offset) = file_offset_for(&segments, rebase.address) {
                    write_pointer(exported, offset, rebase.target)?;
                }
            }
        }
        Ok(())
    }
}

struct CacheMemory<'a> {
    cache: &'a DyldCache<'a>,
    linkedit_member: usize,
}

impl ImageMemory for CacheMemory<'_> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), ExportError> {
        self.cache
            .read_member(self.linkedit_member, buf, offset)
            .map_err(|error| export_read_error(&error))
    }

    fn read_at_addr(&self, buf: &mut [u8], address: u64) -> Result<(), ExportError> {
        self.cache
            .read_at_addr(buf, address)
            .map_err(|error| export_read_error(&error))
    }
}

fn export_read_error(error: &DyldError) -> ExportError {
    ExportError::Read {
        context: "shared-cache image data",
        source: io::Error::other(error.to_string()),
    }
}

fn open_member<'src>(
    opener: &mut impl CacheOpener<'src>,
    suffix: &str,
) -> Result<(Member<'src>, Vec<u8>), DyldError> {
    let source = opener.open(suffix).map_err(|source| DyldError::Io {
        context: "open shared-cache member",
        source,
    })?;
    if source.size() < HEADER_SIZE as u64 {
        return Err(DyldError::Format("shared-cache member is too small"));
    }
    let mut header = vec![0; HEADER_SIZE];
    source
        .read_exact_at(&mut header, 0)
        .map_err(|source| DyldError::Io {
            context: "read shared-cache header",
            source,
        })?;
    let magic = trim_trailing_nul(&header[MAGIC_FIELD]);
    if magic != CACHE_MAGIC {
        return Err(DyldError::UnsupportedFormat(
            String::from_utf8_lossy(magic).into_owned(),
        ));
    }
    let mut member = Member {
        source,
        uuid: [0; 16],
        mappings: Vec::new(),
    };
    member.uuid.copy_from_slice(&header[UUID_FIELD]);
    member.mappings = read_mappings(&member, &header)?;
    Ok((member, header))
}

fn read_mappings(member: &Member, header: &[u8]) -> Result<Vec<Mapping>, DyldError> {
    let offset = header_u32(header, MAPPING_OFFSET_FIELD)?;
    let count = header_u32(header, MAPPING_COUNT_FIELD)?;
    let size = member.size();
    if count == 0
        || count > MAXIMUM_MAPPINGS
        || !valid_range(size, offset, count * MAPPING_SIZE as u64)
    {
        return Err(DyldError::Format(
            "shared-cache member has an invalid mapping table",
        ));
    }
    let mut table = vec![0; to_usize(count * MAPPING_SIZE as u64)?];
    member.read(&mut table, offset, "read shared-cache mappings")?;
    table
        .chunks_exact(MAPPING_SIZE)
        .map(|entry| parse_mapping(entry, size))
        .collect()
}

fn parse_mapping(entry: &[u8], member_size: u64) -> Result<Mapping, DyldError> {
    let field =
        |index: usize| le_u64(entry, index * 8).ok_or(DyldError::Format("truncated mapping"));
    let mapping = Mapping {
        member: 0,
        address: field(0)?,
        size: field(1)?,
        file_offset: field(2)?,
        slide_info_offset: field(3)?,
        slide_info_size: field(4)?,
    };
    let overflows = mapping.address.checked_add(mapping.size).is_none();
    let slide_invalid = mapping.slide_info_size != 0
        && !valid_range(
            member_size,
            mapping.slide_info_offset,
            mapping.slide_info_size,
        );
    if mapping.size == 0
        || overflows
        || !valid_range(member_size, mapping.file_offset, mapping.size)
        || slide_invalid
    {
        return Err(DyldError::Format(
            "shared-cache member has an invalid mapping",
        ));
    }
    Ok(mapping)
}

fn subcache_entries(primary: &Member, header: &[u8]) -> Result<Vec<(String, [u8; 16])>, DyldError> {
    let offset = header_u32(header, SUBCACHE_OFFSET_FIELD)?;
    let count = header_u32(header, SUBCACHE_COUNT_FIELD)?;
    let table_size = count * SUBCACHE_ENTRY_SIZE as u64;
    if count > MAXIMUM_SUBCACHES || (count > 0 && !valid_range(primary.size(), offset, table_size))
    {
        return Err(DyldError::Format(
            "shared cache has an invalid subcache table",
        ));
    }
    let mut table = vec![0; to_usize(table_size)?];
    if !table.is_empty() {
        primary.read(&mut table, offset, "read shared-cache subcache table")?;
    }
    table
        .chunks_exact(SUBCACHE_ENTRY_SIZE)
        .map(parse_subcache_entry)
        .collect()
}

fn parse_subcache_entry(entry: &[u8]) -> Result<(String, [u8; 16]), DyldError> {
    let invalid = DyldError::Format("shared cache has an invalid subcache suffix");
    let suffix = trim_trailing_nul(&entry[SUBCACHE_SUFFIX_FIELD]);
    if suffix.is_empty() || suffix.iter().any(|&byte| byte == b'/' || byte == b'\\') {
        return Err(invalid);
    }
    let suffix = String::from_utf8(suffix.to_vec()).map_err(|_| invalid)?;
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&entry[..16]);
    Ok((suffix, uuid))
}

fn common_slide_info(members: &[Member]) -> Result<SlideInfo5, DyldError> {
    let mut common: Option<SlideInfo5> = None;
    for member in members {
        for mapping in member
            .mappings
            .iter()
            .filter(|mapping| mapping.slide_info_size != 0)
        {
            slide_version(member, mapping)?;
            let slide = read_slide_info(member, mapping)?;
            match common {
                None => common = Some(slide),
                Some(existing)
                    if existing.page_size != slide.page_size
                        || existing.value_add != slide.value_add =>
                {
                    return Err(DyldError::Format(
                        "shared-cache members use incompatible slide information",
                    ));
                }
                Some(_) => {}
            }
        }
    }
    common.ok_or(DyldError::Format("shared cache has no slide information"))
}

fn slide_version(member: &Member, mapping: &Mapping) -> Result<(), DyldError> {
    if mapping.slide_info_size < 4 {
        return Err(DyldError::Format(
            "shared cache has truncated slide information",
        ));
    }
    let mut version = [0; 4];
    member.read(
        &mut version,
        mapping.slide_info_offset,
        "read shared-cache slide version",
    )?;
    match u32::from_le_bytes(version) {
        SLIDE_VERSION_5 => Ok(()),
        other => Err(DyldError::UnsupportedSlideVersion(other)),
    }
}

fn read_slide_info(member: &Member, mapping: &Mapping) -> Result<SlideInfo5, DyldError> {
    if mapping.slide_info_size < SLIDE_INFO_5_SIZE as u64 {
        return Err(DyldError::Format(
            "shared cache has truncated slide information",
        ));
    }
    let mut data = [0; SLIDE_INFO_5_SIZE];
    member.read(
        &mut data,
        mapping.slide_info_offset,
        "read shared-cache slide information",
    )?;
    let version = field_u32(&data, 0)?;
    if version != SLIDE_VERSION_5 {
        return Err(DyldError::UnsupportedSlideVersion(version));
    }
    let slide = SlideInfo5 {
        page_size: field_u32(&data, 4)?,
        page_starts_count: field_u32(&data, 8)?,
        value_add: le_u64(&data, 16).ok_or(DyldError::Format("truncated slide information"))?,
    };
    let table_end = SLIDE_INFO_5_SIZE as u64 + u64::from(slide.page_starts_count) * 2;
    if slide.page_size == 0 || table_end > mapping.slide_info_size {
        return Err(DyldError::Format(
            "shared cache has invalid slide information",
        ));
    }
    Ok(slide)
}

fn read_page_starts(member: &Member, mapping: &Mapping, count: u32) -> Result<Vec<u16>, DyldError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let mut data = vec![0; count as usize * 2];
    let offset = mapping.slide_info_offset + SLIDE_INFO_5_SIZE as u64;
    member.read(&mut data, offset, "read shared-cache slide table")?;
    Ok(data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn walk_slide_chain(
    member: &Member,
    mapping: &Mapping,
    slide: &SlideInfo5,
    page: u64,
    start: u16,
    rebases: &mut Vec<Rebase>,
) -> Result<(), DyldError> {
    let page_size = u64::from(slide.page_size);
    let page_offset = mapping.file_offset + page * page_size;
    let page_address = mapping.address + page * page_size;
    let mut offset = u64::from(start);
    for count in 0..MAXIMUM_SLIDE_CHAIN_POINTERS {
        if offset + POINTER_SIZE > page_size {
            return Err(DyldError::Format(
                "shared-cache slide chain leaves its page",
            ));
        }
        let mut data = [0; POINTER_BYTES];
        member.read(
            &mut data,
            page_offset + offset,
            "read shared-cache slide pointer",
        )?;
        let pointer = u64::from_le_bytes(data);
        rebases.push(Rebase {
            address: page_address + offset,
            target: slide.decode(pointer),
        });
        let next = (pointer >> SLIDE_NEXT_SHIFT) & SLIDE_NEXT_MASK;
        if next == 0 {
            return Ok(());
        }
        offset += next * POINTER_SIZE;
        if count == MAXIMUM_SLIDE_CHAIN_POINTERS - 1 {
            return Err(DyldError::Format("shared-cache slide chain is too long"));
        }
    }
    Ok(())
}

fn find_linkedit(commands: &[u8], count: u64) -> Result<u64, DyldError> {
    let mut offset = 0usize;
    for _ in 0..count {
        let size = le_u32(commands, offset + 4)
            .ok_or(DyldError::Format("image load commands are truncated"))?;
        let size = size as usize;
        if size < 8 || offset + size > commands.len() {
            return Err(DyldError::Format("image has an invalid load command"));
        }
        let command = &commands[offset..offset + size];
        if le_u32(command, 0) == Some(export::LC_SEGMENT_64)
            && size as u64 >= SEGMENT_COMMAND_MINIMUM
            && trim_trailing_nul(&command[8..24]) == LINKEDIT_SEGMENT
        {
            return le_u64(command, 24).ok_or(DyldError::Format("truncated segment command"));
        }
        offset += size;
    }
    Err(DyldError::Format("image has no __LINKEDIT segment"))
}

#[derive(Debug, Clone, Copy)]
struct ExportedSegment {
    address: u64,
    memory_size: u64,
    file_offset: u64,
}

fn exported_segments(image: &[u8]) -> Result<Vec<ExportedSegment>, DyldError> {
    let header = &image
        .get(..export::MACH_HEADER_64_SIZE)
        .ok_or(DyldError::Format("exported image is truncated"))?;
    let size = header_u32(header, 20)?;
    let commands = image
        .get(export::MACH_HEADER_64_SIZE..export::MACH_HEADER_64_SIZE + to_usize(size)?)
        .ok_or(DyldError::Format("exported image is truncated"))?;
    let parsed = MachImage::parse(header, commands, &[])?;
    Ok(parsed
        .segments()
        .map(|segment| ExportedSegment {
            address: segment.address,
            memory_size: segment.memory_size,
            file_offset: segment.file_offset,
        })
        .collect())
}

fn file_offset_for(segments: &[ExportedSegment], address: u64) -> Option<u64> {
    segments
        .iter()
        .find(|segment| {
            segment.address <= address && address - segment.address < segment.memory_size
        })
        .map(|segment| address - segment.address + segment.file_offset)
}

fn write_pointer(image: &mut Vec<u8>, offset: u64, value: u64) -> Result<(), DyldError> {
    let start = to_usize(offset)?;
    let end = start + POINTER_BYTES;
    if image.len() < end {
        image.resize(end, 0);
    }
    image[start..end].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_cstring(member: &Member, size: u64, offset: u64) -> Result<Vec<u8>, DyldError> {
    if !valid_range(size, offset, 1) {
        return Err(DyldError::Format(
            "shared cache contains an invalid string offset",
        ));
    }
    let limit = MAXIMUM_PATH_LENGTH.min(size - offset);
    let mut data = vec![0; to_usize(limit)?];
    member.read(&mut data, offset, "read shared-cache string")?;
    match data.iter().position(|&byte| byte == 0) {
        Some(end) => {
            data.truncate(end);
            Ok(data)
        }
        None => Err(DyldError::Format("shared-cache string is not terminated")),
    }
}

/// Go's `validDyldRange`: `[offset, offset + length)` fits in `size`.
pub(crate) fn valid_range(size: u64, offset: u64, length: u64) -> bool {
    offset <= size && length <= size - offset
}

fn trim_trailing_nul(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |index| index + 1);
    &data[..end]
}

fn field_u32(data: &[u8], offset: usize) -> Result<u32, DyldError> {
    le_u32(data, offset).ok_or(DyldError::Format("truncated header"))
}

fn header_u32(data: &[u8], offset: usize) -> Result<u64, DyldError> {
    le_u32(data, offset)
        .map(u64::from)
        .ok_or(DyldError::Format("truncated header"))
}

pub(crate) fn to_usize(value: u64) -> Result<usize, DyldError> {
    usize::try_from(value).map_err(|_| DyldError::Format("size exceeds address space"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    use super::*;

    const APPLE_MEDIA_SERVICES_SHA256: &str =
        "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4";
    const SPARSE_MAGIC: &[u8] = b"DYLDSPR1";

    /// Replays the exact byte ranges ipatool read from each cache member.
    struct SparseMember {
        size: u64,
        ranges: Vec<(u64, Vec<u8>)>,
    }

    impl ReadAt for SparseMember {
        fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let end = offset + buf.len() as u64;
            let (start, data) = self
                .ranges
                .iter()
                .find(|(start, data)| *start <= offset && end <= start + data.len() as u64)
                .ok_or_else(|| {
                    io::Error::other(format!("unrecorded read {offset:#x}+{:#x}", buf.len()))
                })?;
            let from = usize::try_from(offset - start).expect("offset fits");
            buf.copy_from_slice(&data[from..from + buf.len()]);
            Ok(buf.len())
        }

        fn size(&self) -> u64 {
            self.size
        }
    }

    fn fixture_directory() -> PathBuf {
        std::env::var_os("IPAKEEP_APPLE_SAP_FIXTURES").map_or_else(
            || {
                dirs::cache_dir()
                    .unwrap_or_default()
                    .join("ipakeep")
                    .join("apple_sap_fixtures")
            },
            PathBuf::from,
        )
    }

    fn take<'a>(data: &mut &'a [u8], count: usize) -> &'a [u8] {
        let (head, tail) = data.split_at(count);
        *data = tail;
        head
    }

    fn take_u64(data: &mut &[u8], count: usize) -> u64 {
        take(data, count)
            .iter()
            .rev()
            .fold(0, |value, &byte| (value << 8) | u64::from(byte))
    }

    fn load_sparse_fixture() -> HashMap<String, Arc<SparseMember>> {
        let bytes =
            std::fs::read(fixture_directory().join("dyld_sparse.bin")).expect("read dyld fixture");
        let mut data = bytes.as_slice();
        assert_eq!(take(&mut data, SPARSE_MAGIC.len()), SPARSE_MAGIC);
        let members = take_u64(&mut data, 4);
        let mut out = HashMap::new();
        for _ in 0..members {
            let length = usize::try_from(take_u64(&mut data, 2)).expect("length");
            let suffix = String::from_utf8(take(&mut data, length).to_vec()).expect("suffix");
            let size = take_u64(&mut data, 8);
            let count = take_u64(&mut data, 4);
            let ranges = (0..count)
                .map(|_| {
                    let offset = take_u64(&mut data, 8);
                    let length = usize::try_from(take_u64(&mut data, 4)).expect("length");
                    (offset, take(&mut data, length).to_vec())
                })
                .collect();
            out.insert(suffix, Arc::new(SparseMember { size, ranges }));
        }
        out
    }

    fn mapping(address: u64, size: u64) -> Mapping {
        Mapping {
            member: 0,
            address,
            size,
            file_offset: 0,
            slide_info_offset: 0,
            slide_info_size: 0,
        }
    }

    #[test]
    fn slide_v5_decodes_plain_and_authenticated_pointers() {
        let slide = SlideInfo5 {
            page_size: 0x4000,
            page_starts_count: 0,
            value_add: 0x1_8000_0000,
        };
        assert_eq!(slide.decode(0), 0);
        let plain = (0x12u64 << SLIDE_TARGET_BITS) | 0x1234;
        assert_eq!(
            slide.decode(plain),
            0x1_8000_0000 + ((0x12u64 << 56) | 0x1234)
        );
        let authenticated = (1u64 << 63) | (0x12u64 << SLIDE_TARGET_BITS) | 0x1234;
        assert_eq!(slide.decode(authenticated), 0x1_8000_1234);
    }

    #[test]
    fn mapping_contains_is_half_open() {
        let mapping = mapping(0x1000, 0x100);
        assert!(mapping.contains(0x1000));
        assert!(mapping.contains(0x10ff));
        assert!(!mapping.contains(0x1100));
        assert!(!mapping.contains(0xfff));
    }

    #[test]
    fn subcache_suffix_validation() {
        let mut entry = vec![0u8; SUBCACHE_ENTRY_SIZE];
        entry[24..27].copy_from_slice(b".01");
        assert_eq!(parse_subcache_entry(&entry).expect("suffix").0, ".01");
        entry[24..27].copy_from_slice(b"../");
        assert!(parse_subcache_entry(&entry).is_err());
        entry[24..27].fill(0);
        assert!(parse_subcache_entry(&entry).is_err());
    }

    #[test]
    fn valid_range_rejects_overflow() {
        assert!(valid_range(10, 0, 10));
        assert!(!valid_range(10, 11, 0));
        assert!(!valid_range(10, 5, u64::MAX));
    }

    #[test]
    #[ignore = "needs the recorded shared-cache fixture in IPAKEEP_APPLE_SAP_FIXTURES"]
    fn exports_apple_media_services_byte_identical_to_ipatool() {
        let members = load_sparse_fixture();
        let opener = |suffix: &str| -> io::Result<Box<dyn ReadAt>> {
            let member = members
                .get(suffix)
                .ok_or_else(|| io::Error::other(format!("missing member {suffix}")))?;
            Ok(Box::new(Arc::clone(member)))
        };
        let exported = extract_dyld_image(opener, APPLE_MEDIA_SERVICES_IMAGE)
            .expect("export AppleMediaServices");
        assert_eq!(exported.len(), 14_813_888);
        assert_eq!(
            hex::encode(Sha256::digest(&exported)),
            APPLE_MEDIA_SERVICES_SHA256
        );
    }
}
