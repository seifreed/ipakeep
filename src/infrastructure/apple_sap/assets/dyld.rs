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
            .map_err(io_error(context))
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
        let linkedit_address = self.linkedit_address(&image)?;
        let linkedit = self.mapping_for_address(linkedit_address)?.member;
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
        for entry in table.as_chunks::<IMAGE_INFO_SIZE>().0 {
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
            .as_chunks::<IMAGE_INFO_SIZE>()
            .0
            .iter()
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

fn io_error(context: &'static str) -> impl FnOnce(io::Error) -> DyldError {
    move |source| DyldError::Io { context, source }
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
    let source = opener
        .open(suffix)
        .map_err(io_error("open shared-cache member"))?;
    if source.size() < HEADER_SIZE as u64 {
        return Err(DyldError::Format("shared-cache member is too small"));
    }
    let mut header = vec![0; HEADER_SIZE];
    source
        .read_exact_at(&mut header, 0)
        .map_err(io_error("read shared-cache header"))?;
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
        .as_chunks::<MAPPING_SIZE>()
        .0
        .iter()
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
        .as_chunks::<SUBCACHE_ENTRY_SIZE>()
        .0
        .iter()
        .map(parse_subcache_entry)
        .collect()
}

fn parse_subcache_entry(
    entry: &[u8; SUBCACHE_ENTRY_SIZE],
) -> Result<(String, [u8; 16]), DyldError> {
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
        .as_chunks::<2>()
        .0
        .iter()
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
    for _ in 0..MAXIMUM_SLIDE_CHAIN_POINTERS {
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
    }
    Err(DyldError::Format("shared-cache slide chain is too long"))
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
pub(crate) mod fixtures {
    //! Synthetic arm64e shared caches: a primary member holding `__TEXT` and a
    //! slid `__DATA`, plus one subcache holding the image's `__LINKEDIT`.

    use std::io;

    use super::export::fixtures::{
        ARM64, DEFINED, FUNCTION_STARTS_COMMAND, ID_DYLIB, IN_CACHE, INDIRECT, LOCAL,
        LOCAL_INDIRECT, SectionSpec, SegmentSpec, UNDEFINED, dylib_command, dysymtab_command,
        dysymtab_fields, linkedit_command, macho, nlist, segment_command, string_table,
        symtab_command, words,
    };
    use super::export::le_u32;
    use super::{
        CACHE_MAGIC, DyldCache, DyldError, IMAGE_PATH_OFFSET_FIELD, IMAGES_COUNT_FIELD,
        IMAGES_OFFSET_FIELD, MAPPING_COUNT_FIELD, MAPPING_OFFSET_FIELD, MAPPING_SIZE, ReadAt,
        SLIDE_VERSION_5, SUBCACHE_COUNT_FIELD, SUBCACHE_OFFSET_FIELD, SUBCACHE_SUFFIX_FIELD,
        UUID_FIELD,
    };

    pub(crate) const IMAGE_PATH: &str = "/usr/lib/libsynthetic.dylib";
    pub(crate) const OTHER_IMAGE_PATH: &str = "/usr/lib/libother.dylib";
    pub(crate) const SUBCACHE_SUFFIX: &str = ".01";
    pub(crate) const LINKEDIT_MEMBER: usize = 1;
    pub(crate) const TEXT_ADDRESS: u64 = 0x1_0000;
    pub(crate) const DATA_ADDRESS: u64 = 0x1_4000;
    pub(crate) const LINKEDIT_ADDRESS: u64 = 0x1_8000;
    pub(crate) const REGION: u64 = 0x4000;
    pub(crate) const PRIMARY_UUID: [u8; 16] = [0x11; 16];
    pub(crate) const SUBCACHE_UUID: [u8; 16] = [0x22; 16];
    pub(crate) const MAPPING_TABLE: usize = 0x240;
    pub(crate) const SUBCACHE_TABLE: usize = 0x300;
    pub(crate) const IMAGE_TABLE: usize = 0x340;
    pub(crate) const IMAGE_PATHS: usize = 0x380;
    pub(crate) const SLIDE_INFO: usize = 0x400;
    pub(crate) const SLIDE_INFO_SIZE: u64 = 32;
    pub(crate) const SLIDE_PAGE_SIZE: u32 = 0x1000;
    pub(crate) const TEXT_FILE: usize = 0x4000;
    pub(crate) const DATA_FILE: usize = 0x8000;
    pub(crate) const PRIMARY_SIZE: usize = 0xc000;
    pub(crate) const LINKEDIT_FILE: usize = 0x1000;
    pub(crate) const SUBCACHE_SIZE: usize = 0x5000;
    pub(crate) const SYMBOLS: u32 = 0x1000;
    pub(crate) const STRINGS: u32 = 0x1100;
    pub(crate) const STRING_SIZE: u32 = 0x40;
    pub(crate) const INDIRECT_TABLE: u32 = 0x1200;
    pub(crate) const FUNCTION_STARTS: u32 = 0x1300;
    pub(crate) const SYMBOL_COUNT: u32 = 5;
    pub(crate) const INDIRECT_ENTRIES: [u32; 2] = [3, LOCAL_INDIRECT];
    pub(crate) const FUNCTION_START_BYTES: [u8; 8] = [9; 8];
    pub(crate) const TEXT_SECTION: usize = 0x400;
    pub(crate) const TEXT_FILL: u8 = 0xc3;
    pub(crate) const PLAIN_TARGET: u64 = TEXT_ADDRESS + 0x400;
    pub(crate) const AUTH_TARGET: u64 = TEXT_ADDRESS + 0x410;
    pub(crate) const NEXT_POINTER: u64 = 1 << 52;
    pub(crate) const AUTH_BIT: u64 = 1 << 63;
    pub(crate) const NO_REBASE: u16 = 0xffff;
    const OTHER_PATH_OFFSET: usize = IMAGE_PATHS;
    const IMAGE_PATH_OFFSET: usize = IMAGE_PATHS + 0x40;
    const IMAGE_ENTRY_SIZE: usize = 32;

    /// The two member files of a synthetic cache.
    pub(crate) struct CacheFixture {
        pub primary: Vec<u8>,
        pub subcache: Vec<u8>,
    }

    pub(crate) fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn put_usize(buffer: &mut [u8], offset: usize, value: usize) {
        put_u32(
            buffer,
            offset,
            u32::try_from(value).expect("fixture offset"),
        );
    }

    fn offset_u64(value: usize) -> u64 {
        u64::try_from(value).expect("fixture offset")
    }

    /// Writes `[address, size, file offset, slide offset, slide size]`.
    pub(crate) fn set_mapping(buffer: &mut [u8], index: usize, fields: [u64; 5]) {
        let start = MAPPING_TABLE + index * MAPPING_SIZE;
        for (field, value) in fields.into_iter().enumerate() {
            put_u64(buffer, start + field * 8, value);
        }
    }

    /// Writes a version 5 slide-info header and its page starts.
    pub(crate) fn set_slide_info(buffer: &mut [u8], offset: usize, starts: &[u16], value_add: u64) {
        let count = u32::try_from(starts.len()).expect("page count");
        buffer[offset..offset + 12].copy_from_slice(&words(&[
            SLIDE_VERSION_5,
            SLIDE_PAGE_SIZE,
            count,
        ]));
        put_u64(buffer, offset + 16, value_add);
        for (index, start) in starts.iter().enumerate() {
            let at = offset + 24 + index * 2;
            buffer[at..at + 2].copy_from_slice(&start.to_le_bytes());
        }
    }

    fn write_member_header(buffer: &mut [u8], uuid: [u8; 16], mappings: usize) {
        buffer[..CACHE_MAGIC.len()].copy_from_slice(CACHE_MAGIC);
        buffer[UUID_FIELD].copy_from_slice(&uuid);
        put_usize(buffer, MAPPING_OFFSET_FIELD, MAPPING_TABLE);
        put_usize(buffer, MAPPING_COUNT_FIELD, mappings);
    }

    fn place(buffer: &mut [u8], offset: u32, bytes: &[u8]) {
        let start = offset as usize;
        buffer[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn segment(name: &[u8], address: u64, file: usize, sections: &[SectionSpec<'_>]) -> Vec<u8> {
        segment_command(&SegmentSpec {
            name,
            address,
            memory_size: REGION,
            file_offset: offset_u64(file),
            file_size: REGION,
            sections,
        })
    }

    /// The default image's load commands.
    pub(crate) fn image_commands() -> Vec<Vec<u8>> {
        let text_offset = u32::try_from(TEXT_FILE + TEXT_SECTION).expect("offset");
        let data_offset = u32::try_from(DATA_FILE).expect("offset");
        vec![
            segment(
                b"__TEXT",
                TEXT_ADDRESS,
                TEXT_FILE,
                &[SectionSpec {
                    name: b"__text",
                    segment: b"__TEXT",
                    address: TEXT_ADDRESS + offset_u64(TEXT_SECTION),
                    size: 0x20,
                    offset: text_offset,
                }],
            ),
            segment(
                b"__DATA",
                DATA_ADDRESS,
                DATA_FILE,
                &[SectionSpec {
                    name: b"__data",
                    segment: b"__DATA",
                    address: DATA_ADDRESS,
                    size: 0x10,
                    offset: data_offset,
                }],
            ),
            segment(b"__LINKEDIT", LINKEDIT_ADDRESS, LINKEDIT_FILE, &[]),
            dylib_command(ID_DYLIB, IMAGE_PATH.as_bytes(), None),
            symtab_command(SYMBOLS, SYMBOL_COUNT, STRINGS, STRING_SIZE),
            dysymtab_command(dysymtab_fields([2, 2, 1], INDIRECT_TABLE, 2)),
            linkedit_command(FUNCTION_STARTS_COMMAND, FUNCTION_STARTS, 8),
        ]
    }

    /// `commands` with every `command` replaced by `replacement` (or dropped).
    pub(crate) fn replace_command(
        commands: Vec<Vec<u8>>,
        command: u32,
        replacement: Option<&[u8]>,
    ) -> Vec<Vec<u8>> {
        commands
            .into_iter()
            .filter_map(|raw| match le_u32(&raw, 0) {
                Some(id) if id == command => replacement.map(<[u8]>::to_vec),
                _ => Some(raw),
            })
            .collect()
    }

    impl CacheFixture {
        pub(crate) fn new() -> Self {
            Self::with_commands(&image_commands())
        }

        pub(crate) fn with_commands(commands: &[Vec<u8>]) -> Self {
            let mut fixture = Self {
                primary: vec![0; PRIMARY_SIZE],
                subcache: vec![0; SUBCACHE_SIZE],
            };
            fixture.write_primary_tables();
            fixture.write_image(commands);
            fixture.write_subcache();
            fixture
        }

        pub(crate) fn opener<'a>(
            &'a self,
        ) -> impl FnMut(&str) -> io::Result<Box<dyn ReadAt + 'a>> + 'a {
            move |suffix: &str| -> io::Result<Box<dyn ReadAt + 'a>> {
                match suffix {
                    "" => Ok(Box::new(&self.primary)),
                    SUBCACHE_SUFFIX => Ok(Box::new(&self.subcache)),
                    _ => Err(io::Error::new(io::ErrorKind::NotFound, suffix.to_owned())),
                }
            }
        }

        pub(crate) fn open(&self) -> Result<DyldCache<'_>, DyldError> {
            DyldCache::open(self.opener())
        }

        fn write_primary_tables(&mut self) {
            let primary = &mut self.primary;
            write_member_header(primary, PRIMARY_UUID, 2);
            put_usize(primary, SUBCACHE_OFFSET_FIELD, SUBCACHE_TABLE);
            put_u32(primary, SUBCACHE_COUNT_FIELD, 1);
            put_usize(primary, IMAGES_OFFSET_FIELD, IMAGE_TABLE);
            put_u32(primary, IMAGES_COUNT_FIELD, 2);
            set_mapping(
                primary,
                0,
                [TEXT_ADDRESS, REGION, offset_u64(TEXT_FILE), 0, 0],
            );
            let slide = offset_u64(SLIDE_INFO);
            let data = offset_u64(DATA_FILE);
            set_mapping(
                primary,
                1,
                [DATA_ADDRESS, REGION, data, slide, SLIDE_INFO_SIZE],
            );
            set_slide_info(
                primary,
                SLIDE_INFO,
                &[0, NO_REBASE, NO_REBASE, NO_REBASE],
                0,
            );
            primary[SUBCACHE_TABLE..SUBCACHE_TABLE + 16].copy_from_slice(&SUBCACHE_UUID);
            let suffix = SUBCACHE_TABLE + SUBCACHE_SUFFIX_FIELD.start;
            primary[suffix..suffix + SUBCACHE_SUFFIX.len()]
                .copy_from_slice(SUBCACHE_SUFFIX.as_bytes());
            for (index, (path, offset)) in [
                (OTHER_IMAGE_PATH, OTHER_PATH_OFFSET),
                (IMAGE_PATH, IMAGE_PATH_OFFSET),
            ]
            .into_iter()
            .enumerate()
            {
                let entry = IMAGE_TABLE + index * IMAGE_ENTRY_SIZE;
                put_u64(primary, entry, TEXT_ADDRESS);
                put_usize(primary, entry + IMAGE_PATH_OFFSET_FIELD, offset);
                primary[offset..offset + path.len()].copy_from_slice(path.as_bytes());
            }
        }

        fn write_image(&mut self, commands: &[Vec<u8>]) {
            let image = macho(ARM64, IN_CACHE, commands);
            self.primary[TEXT_FILE..TEXT_FILE + image.len()].copy_from_slice(&image);
            let region = usize::try_from(REGION).expect("region");
            self.primary[TEXT_FILE + TEXT_SECTION..TEXT_FILE + region].fill(TEXT_FILL);
            put_u64(&mut self.primary, DATA_FILE, PLAIN_TARGET | NEXT_POINTER);
            put_u64(&mut self.primary, DATA_FILE + 8, AUTH_BIT | AUTH_TARGET);
        }

        fn write_subcache(&mut self) {
            let subcache = &mut self.subcache;
            write_member_header(subcache, SUBCACHE_UUID, 1);
            let linkedit = offset_u64(LINKEDIT_FILE);
            set_mapping(subcache, 0, [LINKEDIT_ADDRESS, REGION, linkedit, 0, 0]);
            let (strings, names) =
                string_table(&[b"_local", b"_exported", b"_indirect", b"_target", b"_undef"]);
            let symbols = [
                nlist(names[0], LOCAL, 1, TEXT_ADDRESS),
                nlist(names[1], DEFINED, 1, PLAIN_TARGET),
                nlist(names[2], INDIRECT, 0, u64::from(names[3])),
                nlist(names[4], UNDEFINED, 0, 0),
                nlist(STRING_SIZE, LOCAL, 1, AUTH_TARGET),
            ]
            .concat();
            place(subcache, SYMBOLS, &symbols);
            place(subcache, STRINGS, &strings);
            place(subcache, INDIRECT_TABLE, &words(&INDIRECT_ENTRIES));
            place(subcache, FUNCTION_STARTS, &FUNCTION_START_BYTES);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    use sha2::{Digest, Sha256};

    use super::export::fixtures::{ARM64, IN_CACHE, macho, raw_command, words};
    use super::fixtures::{
        AUTH_BIT, AUTH_TARGET, CacheFixture, DATA_ADDRESS, DATA_FILE, FUNCTION_START_BYTES,
        IMAGE_PATH, IMAGE_TABLE, LINKEDIT_ADDRESS, LINKEDIT_FILE, LINKEDIT_MEMBER, NEXT_POINTER,
        NO_REBASE, OTHER_IMAGE_PATH, PLAIN_TARGET, PRIMARY_SIZE, REGION, SLIDE_INFO,
        SLIDE_INFO_SIZE, SLIDE_PAGE_SIZE, SUBCACHE_SUFFIX, SUBCACHE_TABLE, TEXT_ADDRESS, TEXT_FILE,
        TEXT_FILL, TEXT_SECTION, image_commands, put_u32, put_u64, set_mapping, set_slide_info,
    };
    use super::*;

    const LC_UUID: u32 = 0x1b;

    type FixtureEdit = (fn(&mut CacheFixture), &'static str);
    const LC_LOAD_DYLIB: u32 = 0xc;
    const EXPORTED_DATA: usize = 0x4000;
    const EXPORTED_LINKEDIT: usize = 0x8000;
    const SUBCACHE_SLIDE_INFO: usize = 0x400;
    const SUBCACHE_SUFFIX_START: usize = SUBCACHE_TABLE + SUBCACHE_SUFFIX_FIELD.start;
    const OVERSIZED_COMMANDS: u32 = 0x0100_0001;
    const UNMAPPED_ADDRESS: u64 = 0x9_0000;

    fn patched(edit: impl FnOnce(&mut CacheFixture)) -> CacheFixture {
        let mut fixture = CacheFixture::new();
        edit(&mut fixture);
        fixture
    }

    fn open_error(fixture: &CacheFixture) -> DyldError {
        fixture.open().expect_err("open must fail")
    }

    fn assert_format(error: &DyldError, expected: &str) {
        match error {
            DyldError::Format(message) => assert_eq!(*message, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }

    fn u64_of(value: usize) -> u64 {
        u64::try_from(value).expect("fits in u64")
    }

    fn u32_of(value: usize) -> u32 {
        u32::try_from(value).expect("fits in u32")
    }

    fn data_mapping(slide_offset: u64, slide_size: u64) -> [u64; 5] {
        [
            DATA_ADDRESS,
            REGION,
            u64_of(DATA_FILE),
            slide_offset,
            slide_size,
        ]
    }

    fn with_subcache_slide(value_add: u64) -> CacheFixture {
        patched(|fixture| {
            set_slide_info(
                &mut fixture.subcache,
                SUBCACHE_SLIDE_INFO,
                &[NO_REBASE],
                value_add,
            );
            let fields = [
                LINKEDIT_ADDRESS,
                REGION,
                u64_of(LINKEDIT_FILE),
                u64_of(SUBCACHE_SLIDE_INFO),
                SLIDE_INFO_SIZE,
            ];
            set_mapping(&mut fixture.subcache, 0, fields);
        })
    }

    fn bare_member(data: Vec<u8>) -> Member<'static> {
        Member {
            source: Box::new(data),
            uuid: [0; 16],
            mappings: Vec::new(),
        }
    }

    struct Unreadable;

    impl ReadAt for Unreadable {
        fn read_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<usize> {
            Err(io::Error::other("unreadable"))
        }

        fn size(&self) -> u64 {
            u64_of(HEADER_SIZE)
        }
    }

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
        let mut entry = [0u8; SUBCACHE_ENTRY_SIZE];
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

    #[test]
    fn opens_primary_and_subcache_members() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        let members: Vec<(usize, u64)> = cache
            .mappings()
            .map(|mapping| (mapping.member, mapping.address))
            .collect();
        assert_eq!(
            members,
            [
                (0, TEXT_ADDRESS),
                (0, DATA_ADDRESS),
                (LINKEDIT_MEMBER, LINKEDIT_ADDRESS)
            ]
        );
        assert_eq!(cache.address_range(), (TEXT_ADDRESS, 3 * REGION));
        assert!(cache.contains(DATA_ADDRESS, REGION));
        assert!(!cache.contains(DATA_ADDRESS + 8, REGION));
        assert!(!cache.contains(0x100, 1));
        assert!(format!("{cache:?}").contains("members: 2"));
        assert_eq!(
            cache.member_size(LINKEDIT_MEMBER),
            u64_of(fixture.subcache.len())
        );
    }

    #[test]
    fn locates_images_by_install_name() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        assert_eq!(
            cache.images().expect("images"),
            [
                (OTHER_IMAGE_PATH.to_owned(), TEXT_ADDRESS),
                (IMAGE_PATH.to_owned(), TEXT_ADDRESS)
            ]
        );
        let image = cache.image(IMAGE_PATH).expect("image");
        assert_eq!(
            (image.member, image.address, image.offset),
            (0, TEXT_ADDRESS, u64_of(TEXT_FILE))
        );
        assert!(matches!(
            cache.image("/usr/lib/missing.dylib"),
            Err(DyldError::ImageNotFound(path)) if path == "/usr/lib/missing.dylib"
        ));
    }

    #[test]
    fn validates_image_table_and_entries() {
        let empty = patched(|fixture| put_u32(&mut fixture.primary, IMAGES_COUNT_FIELD, 0));
        let error = empty.open().expect("open").images().expect_err("no images");
        assert_format(&error, "shared cache has an invalid image table");
        let dangling = patched(|fixture| {
            let entry = IMAGE_TABLE + IMAGE_PATH_OFFSET_FIELD;
            put_u32(&mut fixture.primary, entry, u32_of(PRIMARY_SIZE));
        });
        let error = dangling.open().expect("open").images().expect_err("path");
        assert_format(&error, "shared cache contains an invalid string offset");
        let unmapped =
            patched(|fixture| put_u64(&mut fixture.primary, IMAGE_TABLE, UNMAPPED_ADDRESS));
        assert!(matches!(
            unmapped.open().expect("open").image(OTHER_IMAGE_PATH),
            Err(DyldError::AddressOutsideCache(UNMAPPED_ADDRESS))
        ));
    }

    #[test]
    fn reads_virtual_ranges_across_mappings() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        let mut buf = [0; 16];
        cache
            .read_at_addr(&mut buf, DATA_ADDRESS - 8)
            .expect("read across mappings");
        assert_eq!(buf[..8], [TEXT_FILL; 8]);
        assert_eq!(buf[8..], (PLAIN_TARGET | NEXT_POINTER).to_le_bytes());
        assert!(matches!(
            cache.read_at_addr(&mut buf, LINKEDIT_ADDRESS + REGION - 8),
            Err(DyldError::AddressOutsideCache(_))
        ));
        assert!(matches!(
            cache.mapping_for_address(0),
            Err(DyldError::AddressOutsideCache(0))
        ));
    }

    #[test]
    fn pages_resolve_slide_chains() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        let data = cache.page(DATA_ADDRESS).expect("data page");
        assert_eq!(data[..8], PLAIN_TARGET.to_le_bytes());
        assert_eq!(data[8..16], AUTH_TARGET.to_le_bytes());
        let text = cache.page(TEXT_ADDRESS).expect("text page");
        assert_eq!(
            text,
            fixture.primary[TEXT_FILE..TEXT_FILE + CACHE_PAGE_BYTES]
        );
        let error = cache.page(TEXT_ADDRESS + 8).expect_err("unaligned");
        assert_format(&error, "unaligned Store page");
        let mapping = *cache.mapping_for_address(DATA_ADDRESS).expect("mapping");
        assert_eq!(
            cache.rebases(&mapping, 0, 0).expect("rebases"),
            [
                Rebase {
                    address: DATA_ADDRESS,
                    target: PLAIN_TARGET
                },
                Rebase {
                    address: DATA_ADDRESS + 8,
                    target: AUTH_TARGET
                }
            ]
        );
        let error = cache.rebases(&mapping, 2, 1).expect_err("page range");
        assert_format(&error, "invalid shared-cache slide page range");
    }

    #[test]
    fn empty_page_tables_leave_pages_unslid() {
        let fixture = patched(|fixture| put_u32(&mut fixture.primary, SLIDE_INFO + 8, 0));
        let cache = fixture.open().expect("open cache");
        let mapping = *cache.mapping_for_address(DATA_ADDRESS).expect("mapping");
        assert_eq!(
            cache.rebases(&mapping, 0, 0).expect("rebases"),
            Vec::<Rebase>::new()
        );
        let page = cache.page(DATA_ADDRESS).expect("page");
        assert_eq!(page[..8], (PLAIN_TARGET | NEXT_POINTER).to_le_bytes());
    }

    #[test]
    fn slide_pointer_only_decodes_values_outside_the_cache() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        assert_eq!(cache.slide_pointer(0), 0);
        assert_eq!(cache.slide_pointer(DATA_ADDRESS), DATA_ADDRESS);
        assert_eq!(cache.slide_pointer(AUTH_BIT | AUTH_TARGET), AUTH_TARGET);
    }

    #[test]
    fn exports_image_with_slid_pointers_and_symbols() {
        let fixture = CacheFixture::new();
        let out = extract_dyld_image(fixture.opener(), IMAGE_PATH).expect("export");
        let header = export::MachHeader::parse(&out).expect("header");
        assert!(!header.in_cache());
        let end = export::MACH_HEADER_64_SIZE + header.commands_size as usize;
        let image = MachImage::parse(
            &out[..export::MACH_HEADER_64_SIZE],
            &out[export::MACH_HEADER_64_SIZE..end],
            &[],
        )
        .expect("parse export");
        let layout: Vec<(u64, u64)> = image
            .segments()
            .map(|segment| (segment.address, segment.file_offset))
            .collect();
        let (data, linkedit) = (u64_of(EXPORTED_DATA), u64_of(EXPORTED_LINKEDIT));
        assert_eq!(
            layout,
            [
                (TEXT_ADDRESS, 0),
                (DATA_ADDRESS, data),
                (LINKEDIT_ADDRESS, linkedit)
            ]
        );
        assert_eq!(
            out[EXPORTED_DATA..EXPORTED_DATA + 8],
            PLAIN_TARGET.to_le_bytes()
        );
        assert_eq!(
            out[EXPORTED_DATA + 8..EXPORTED_DATA + 16],
            AUTH_TARGET.to_le_bytes()
        );
        let text_end = TEXT_SECTION + CACHE_PAGE_BYTES / 2;
        assert!(
            out[TEXT_SECTION..text_end]
                .iter()
                .all(|byte| *byte == TEXT_FILL)
        );
        assert_eq!(
            out[EXPORTED_LINKEDIT..EXPORTED_LINKEDIT + 8],
            FUNCTION_START_BYTES
        );
        assert_eq!(image.symtab().map(|symtab| symtab.symbol_count), Some(5));
        let fields = image.dysymtab().expect("dysymtab").fields;
        assert_eq!(fields[..6], [0, 2, 2, 2, 4, 1]);
        let strings: &[u8] = b"\0_local\0\0_exported\0_indirect\0_undef\0";
        assert!(out.windows(strings.len()).any(|window| window == strings));
        let again = fixture.open().expect("open").export_image(IMAGE_PATH);
        assert_eq!(out, again.expect("export again"));
    }

    #[test]
    fn subcache_slide_info_must_agree_with_primary() {
        let compatible = with_subcache_slide(0);
        let out = extract_dyld_image(compatible.opener(), IMAGE_PATH).expect("export");
        assert_eq!(
            out[EXPORTED_DATA..EXPORTED_DATA + 8],
            PLAIN_TARGET.to_le_bytes()
        );
        assert_format(
            &open_error(&with_subcache_slide(1)),
            "shared-cache members use incompatible slide information",
        );
    }

    #[test]
    fn open_reports_member_io_failures() {
        let failing = |suffix: &str| -> io::Result<Box<dyn ReadAt>> {
            Err(io::Error::other(suffix.to_owned()))
        };
        assert!(matches!(
            DyldCache::open(failing),
            Err(DyldError::Io {
                context: "open shared-cache member",
                ..
            })
        ));
        let unreadable = |_: &str| -> io::Result<Box<dyn ReadAt>> { Ok(Box::new(Unreadable)) };
        assert!(matches!(
            DyldCache::open(unreadable),
            Err(DyldError::Io {
                context: "read shared-cache header",
                ..
            })
        ));
        let missing = patched(|fixture| fixture.primary[SUBCACHE_SUFFIX_START + 2] = b'2');
        assert!(matches!(open_error(&missing), DyldError::Io { .. }));
    }

    #[test]
    fn open_rejects_truncated_or_foreign_members() {
        let short = patched(|fixture| fixture.primary.truncate(HEADER_SIZE - 1));
        assert_format(&open_error(&short), "shared-cache member is too small");
        let foreign = patched(|fixture| fixture.primary[..4].copy_from_slice(b"dyl0"));
        assert!(matches!(
            open_error(&foreign),
            DyldError::UnsupportedFormat(magic) if magic.starts_with("dyl0")
        ));
    }

    #[test]
    fn open_validates_mapping_tables() {
        const TABLE: &str = "shared-cache member has an invalid mapping table";
        const MAPPING: &str = "shared-cache member has an invalid mapping";
        let cases: [FixtureEdit; 7] = [
            (|f| put_u32(&mut f.primary, MAPPING_COUNT_FIELD, 0), TABLE),
            (|f| put_u32(&mut f.primary, MAPPING_COUNT_FIELD, 65), TABLE),
            (
                |f| put_u32(&mut f.primary, MAPPING_OFFSET_FIELD, u32_of(PRIMARY_SIZE)),
                TABLE,
            ),
            (
                |f| {
                    set_mapping(
                        &mut f.primary,
                        0,
                        [TEXT_ADDRESS, 0, u64_of(TEXT_FILE), 0, 0],
                    );
                },
                MAPPING,
            ),
            (
                |f| {
                    set_mapping(
                        &mut f.primary,
                        0,
                        [u64::MAX, REGION, u64_of(TEXT_FILE), 0, 0],
                    );
                },
                MAPPING,
            ),
            (
                |f| {
                    let fields = [TEXT_ADDRESS, REGION, u64_of(PRIMARY_SIZE), 0, 0];
                    set_mapping(&mut f.primary, 0, fields);
                },
                MAPPING,
            ),
            (
                |f| {
                    let fields = data_mapping(u64_of(PRIMARY_SIZE), SLIDE_INFO_SIZE);
                    set_mapping(&mut f.primary, 1, fields);
                },
                MAPPING,
            ),
        ];
        for (edit, message) in cases {
            assert_format(&open_error(&patched(edit)), message);
        }
    }

    #[test]
    fn open_validates_subcache_table() {
        const TABLE: &str = "shared cache has an invalid subcache table";
        const SUFFIX: &str = "shared cache has an invalid subcache suffix";
        let cases: [FixtureEdit; 5] = [
            (
                |f| put_u32(&mut f.primary, SUBCACHE_COUNT_FIELD, 129),
                TABLE,
            ),
            (
                |f| put_u32(&mut f.primary, SUBCACHE_OFFSET_FIELD, u32_of(PRIMARY_SIZE)),
                TABLE,
            ),
            (
                |f| f.primary[SUBCACHE_SUFFIX_START..SUBCACHE_SUFFIX_START + 3].fill(0),
                SUFFIX,
            ),
            (
                |f| {
                    let suffix = SUBCACHE_SUFFIX_START..SUBCACHE_SUFFIX_START + 3;
                    f.primary[suffix].copy_from_slice(b"/01");
                },
                SUFFIX,
            ),
            (|f| f.primary[SUBCACHE_SUFFIX_START] = 0xff, SUFFIX),
        ];
        for (edit, message) in cases {
            assert_format(&open_error(&patched(edit)), message);
        }
        let mismatched = patched(|fixture| fixture.subcache[UUID_FIELD].fill(0x33));
        assert!(matches!(
            open_error(&mismatched),
            DyldError::SubcacheUuid(suffix) if suffix == SUBCACHE_SUFFIX
        ));
    }

    #[test]
    fn open_validates_slide_information() {
        const TRUNCATED: &str = "shared cache has truncated slide information";
        const INVALID: &str = "shared cache has invalid slide information";
        let cases: [FixtureEdit; 5] = [
            (
                |f| set_mapping(&mut f.primary, 1, data_mapping(0, 0)),
                "shared cache has no slide information",
            ),
            (
                |f| set_mapping(&mut f.primary, 1, data_mapping(u64_of(SLIDE_INFO), 2)),
                TRUNCATED,
            ),
            (
                |f| set_mapping(&mut f.primary, 1, data_mapping(u64_of(SLIDE_INFO), 8)),
                TRUNCATED,
            ),
            (|f| put_u32(&mut f.primary, SLIDE_INFO + 4, 0), INVALID),
            (|f| put_u32(&mut f.primary, SLIDE_INFO + 8, 100), INVALID),
        ];
        for (edit, message) in cases {
            assert_format(&open_error(&patched(edit)), message);
        }
        let version = patched(|fixture| put_u32(&mut fixture.primary, SLIDE_INFO, 4));
        assert!(matches!(
            open_error(&version),
            DyldError::UnsupportedSlideVersion(4)
        ));
    }

    #[test]
    fn slide_info_reader_rejects_other_versions() {
        let member = bare_member(words(&[4, SLIDE_PAGE_SIZE, 0, 0, 0, 0]));
        let mapping = Mapping {
            slide_info_size: u64_of(SLIDE_INFO_5_SIZE),
            ..mapping(0, REGION)
        };
        assert!(matches!(
            read_slide_info(&member, &mapping),
            Err(DyldError::UnsupportedSlideVersion(4))
        ));
    }

    #[test]
    fn slide_chains_must_stay_in_their_page_and_terminate() {
        let pointers = MAXIMUM_SLIDE_CHAIN_POINTERS;
        let page_size = u32_of(pointers * POINTER_BYTES);
        let member = bare_member(NEXT_POINTER.to_le_bytes().repeat(pointers));
        let mapping = mapping(DATA_ADDRESS, u64::from(page_size));
        let slide = SlideInfo5 {
            page_size,
            page_starts_count: 1,
            value_add: 0,
        };
        let mut rebases = Vec::new();
        let error = walk_slide_chain(&member, &mapping, &slide, 0, 0, &mut rebases)
            .expect_err("runaway chain");
        assert_format(&error, "shared-cache slide chain is too long");
        assert_eq!(rebases.len(), pointers);
        let small = SlideInfo5 {
            page_size: SLIDE_PAGE_SIZE,
            ..slide
        };
        let last_slot = u16::try_from(SLIDE_PAGE_SIZE - 4).expect("page offset");
        let error = walk_slide_chain(&member, &mapping, &small, 0, last_slot, &mut Vec::new())
            .expect_err("chain leaves page");
        assert_format(&error, "shared-cache slide chain leaves its page");
    }

    #[test]
    fn member_accessors_validate_indices_and_strings() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        let error = cache.read_member(9, &mut [0; 4], 0).expect_err("member");
        assert_format(&error, "unknown shared-cache member");
        let error = cache.read_cstring(9, 1, 0).expect_err("member");
        assert_format(&error, "unknown shared-cache member");
        assert_eq!(cache.member_size(9), 0);
        let magic = u64_of(CACHE_MAGIC.len());
        let error = cache.read_cstring(0, magic, 0).expect_err("unterminated");
        assert_format(&error, "shared-cache string is not terminated");
        let error = cache.read_cstring(0, 4, 5).expect_err("offset");
        assert_format(&error, "shared cache contains an invalid string offset");
        let memory = CacheMemory {
            cache: &cache,
            linkedit_member: 9,
        };
        assert!(matches!(
            memory.read_at(&mut [0; 4], 0),
            Err(ExportError::Read { .. })
        ));
        assert!(matches!(
            memory.read_at_addr(&mut [0; 4], 0),
            Err(ExportError::Read { .. })
        ));
    }

    #[test]
    fn image_headers_and_load_commands_are_validated() {
        let bad_magic = patched(|fixture| put_u32(&mut fixture.primary, TEXT_FILE, 0));
        let error = bad_magic.open().expect("open").export_image(IMAGE_PATH);
        assert_format(
            &error.expect_err("magic"),
            "image has an invalid Mach-O magic",
        );
        let oversized = patched(|fixture| {
            put_u32(&mut fixture.primary, TEXT_FILE + 20, OVERSIZED_COMMANDS);
        });
        let cache = oversized.open().expect("open");
        let error = cache.export_image(IMAGE_PATH).expect_err("size");
        assert_format(&error, "image has invalid load commands");
        let image = cache.image(IMAGE_PATH).expect("image");
        let error = cache.image_commands(&image).expect_err("size");
        assert_format(&error, "invalid image load command size");
        let headless = CacheFixture::with_commands(&image_commands()[..2]);
        let error = headless.open().expect("open").export_image(IMAGE_PATH);
        assert_format(
            &error.expect_err("linkedit"),
            "image has no __LINKEDIT segment",
        );
        let malformed = [image_commands(), vec![words(&[LC_LOAD_DYLIB, 8])]].concat();
        let malformed = CacheFixture::with_commands(&malformed);
        assert!(matches!(
            malformed.open().expect("open").export_image(IMAGE_PATH),
            Err(DyldError::Export(ExportError::Format(_)))
        ));
    }

    #[test]
    fn export_requires_a_mapped_linkedit_segment() {
        let mut commands = image_commands();
        commands[2][24..32].copy_from_slice(&UNMAPPED_ADDRESS.to_le_bytes());
        let fixture = CacheFixture::with_commands(&commands);
        assert!(matches!(
            fixture.open().expect("open").export_image(IMAGE_PATH),
            Err(DyldError::AddressOutsideCache(UNMAPPED_ADDRESS))
        ));
    }

    #[test]
    fn find_linkedit_walks_well_formed_commands() {
        let commands = [raw_command(LC_UUID, &[0; 16]), image_commands()[2].clone()].concat();
        assert_eq!(
            find_linkedit(&commands, 2).expect("linkedit"),
            LINKEDIT_ADDRESS
        );
        let error = find_linkedit(&commands[..24], 2).expect_err("truncated");
        assert_format(&error, "image load commands are truncated");
        let error = find_linkedit(&words(&[LC_UUID, 4]), 1).expect_err("size");
        assert_format(&error, "image has an invalid load command");
        let error = find_linkedit(&commands, 1).expect_err("absent");
        assert_format(&error, "image has no __LINKEDIT segment");
    }

    #[test]
    fn exported_segment_helpers_validate_and_place_pointers() {
        let error = exported_segments(&[0; 8]).expect_err("short header");
        assert_format(&error, "exported image is truncated");
        let mut header = macho(ARM64, IN_CACHE, &[]);
        put_u32(&mut header, 20, 64);
        let error = exported_segments(&header).expect_err("short commands");
        assert_format(&error, "exported image is truncated");
        let segments = [ExportedSegment {
            address: 0x1000,
            memory_size: 0x10,
            file_offset: 0x40,
        }];
        assert_eq!(file_offset_for(&segments, 0x1008), Some(0x48));
        assert_eq!(file_offset_for(&segments, 0x1010), None);
        let mut image = vec![0; 4];
        write_pointer(&mut image, 8, 0x0102).expect("write pointer");
        assert_eq!(image.len(), 16);
        assert_eq!(image[8..], 0x0102u64.to_le_bytes());
    }
}
