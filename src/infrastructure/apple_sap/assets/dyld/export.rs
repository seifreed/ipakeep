//! Standalone export of an in-cache Mach-O image.
//!
//! A byte-exact port of the subset of `github.com/blacktop/go-macho`
//! (`File.Export`, `optimizeLoadCommands`, `optimizeLinkedit` and the load
//! command writers) that ipatool uses to rebuild `AppleMediaServices` from the
//! dyld shared cache and `FairPlayIOKit` from the kernel collection.

use thiserror::Error;

mod trie;

/// 64-bit little-endian Mach-O magic.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// Size of a 64-bit Mach-O header.
pub const MACH_HEADER_64_SIZE: usize = 32;
/// Segment load command.
pub const LC_SEGMENT_64: u32 = 0x19;
/// Symbol table load command.
pub const LC_SYMTAB: u32 = 0x2;
/// Dynamic symbol table load command.
pub const LC_DYSYMTAB: u32 = 0xb;
/// Kernel collection fileset entry.
pub const LC_FILESET_ENTRY: u32 = 0x8000_0035;

const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DATA_IN_CODE: u32 = 0x29;
const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const LC_ATOM_INFO: u32 = 0x36;
const LC_FUNCTION_VARIANTS: u32 = 0x37;
const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
const LC_LAZY_LOAD_DYLIB_INFO: u32 = 0x3a;

const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
const CPU_SUBTYPE_ARM_V7K: u32 = 12;
const MH_KEXT_BUNDLE: u32 = 0xb;
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;
const PAGE_SIZE_16K: u64 = 0x4000;
const PAGE_SIZE_4K: u64 = 0x1000;
const POINTER_SIZE: usize = 8;
const SEGMENT_COMMAND_SIZE: usize = 72;
const SECTION_SIZE: usize = 80;
const LINKEDIT_DATA_SIZE: u32 = 16;
const DYLIB_COMMAND_SIZE: usize = 24;
const DYLIB_USE_COMMAND_SIZE: u32 = 28;
const DYLIB_USE_MARKER: u32 = 0x1a74_1800;
const DYSYMTAB_FIELDS: usize = 18;
const NLIST_64_SIZE: usize = 16;
const NAME_FIELD_SIZE: usize = 16;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_INDR: u8 = 0x0a;
const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const REDACTED_SYMBOL: &[u8] = b"<redacted>";
const TEXT_SEGMENT: &[u8] = b"__TEXT";
const LINKEDIT_SEGMENT: &[u8] = b"__LINKEDIT";

/// Failures while parsing or exporting an image.
#[derive(Debug, Error)]
pub enum ExportError {
    /// The image bytes could not be read from their container.
    #[error("read {context}: {source}")]
    Read {
        /// What was being read.
        context: &'static str,
        /// Underlying failure.
        source: std::io::Error,
    },
    /// The Mach-O structure is malformed.
    #[error("invalid Mach-O: {0}")]
    Format(&'static str),
    /// The image uses a feature this exporter does not reproduce.
    #[error("unsupported Mach-O feature: {0}")]
    Unsupported(&'static str),
    /// A file offset is outside every exported segment.
    #[error("failed to remap offset {0:#x}")]
    Remap(u64),
}

/// Random-access view of the container an image lives in.
pub trait ImageMemory {
    /// Reads bytes at a container file offset (go-macho's `cr.ReadAt`).
    ///
    /// # Errors
    /// Fails when the range is not fully readable.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), ExportError>;

    /// Reads bytes at an unslid virtual address (go-macho's `cr.ReadAtAddr`).
    ///
    /// # Errors
    /// Fails when the range is not fully mapped.
    fn read_at_addr(&self, buf: &mut [u8], address: u64) -> Result<(), ExportError>;
}

/// The fixed 64-bit Mach-O header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachHeader {
    /// Magic number.
    pub magic: u32,
    /// CPU type.
    pub cpu: u32,
    /// CPU subtype.
    pub sub_cpu: u32,
    /// File type.
    pub file_type: u32,
    /// Number of load commands.
    pub command_count: u32,
    /// Size of all load commands.
    pub commands_size: u32,
    /// Header flags.
    pub flags: u32,
    /// Reserved word.
    pub reserved: u32,
}

impl MachHeader {
    /// Decodes a 64-bit little-endian header.
    ///
    /// # Errors
    /// Fails on short input or a non-`MH_MAGIC_64` magic.
    pub fn parse(data: &[u8]) -> Result<Self, ExportError> {
        let words = u32_array::<8>(data, 0).ok_or(ExportError::Format("truncated header"))?;
        if words[0] != MH_MAGIC_64 {
            return Err(ExportError::Format("not a 64-bit Mach-O"));
        }
        Ok(Self {
            magic: words[0],
            cpu: words[1],
            sub_cpu: words[2],
            file_type: words[3],
            command_count: words[4],
            commands_size: words[5],
            flags: words[6],
            reserved: words[7],
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        for word in [
            self.magic,
            self.cpu,
            self.sub_cpu,
            self.file_type,
            self.command_count,
            self.commands_size,
            self.flags,
            self.reserved,
        ] {
            put_u32(out, word);
        }
    }

    fn page_size(&self) -> u64 {
        let sixteen_k = match self.cpu {
            CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => true,
            CPU_TYPE_ARM => self.file_type == MH_KEXT_BUNDLE && self.sub_cpu == CPU_SUBTYPE_ARM_V7K,
            _ => false,
        };
        if sixteen_k {
            PAGE_SIZE_16K
        } else {
            PAGE_SIZE_4K
        }
    }

    /// Reports whether the image is still marked as living inside a cache.
    pub fn in_cache(&self) -> bool {
        self.flags & MH_DYLIB_IN_CACHE != 0
    }
}

/// One section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    name: [u8; NAME_FIELD_SIZE],
    segment: [u8; NAME_FIELD_SIZE],
    address: u64,
    size: u64,
    offset: u32,
    words: [u32; 7],
}

/// A segment command with its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    length: u32,
    name: [u8; NAME_FIELD_SIZE],
    /// Virtual address.
    pub address: u64,
    /// Virtual size.
    pub memory_size: u64,
    /// File offset.
    pub file_offset: u64,
    /// File size.
    pub file_size: u64,
    protections: [u32; 2],
    section_count: u32,
    flags: u32,
    sections: Vec<Section>,
}

impl Segment {
    /// The segment name without trailing NULs.
    pub fn name(&self) -> &[u8] {
        cstring(&self.name)
    }
}

/// `LC_SYMTAB` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymtabCommand {
    /// Raw command length.
    pub length: u32,
    /// Symbol table offset.
    pub symbol_offset: u32,
    /// Number of symbols.
    pub symbol_count: u32,
    /// String table offset.
    pub string_offset: u32,
    /// String table size.
    pub string_size: u32,
}

/// `LC_DYSYMTAB` fields, in on-disk order after `cmd`/`cmdsize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DysymtabCommand {
    /// Raw command length.
    pub length: u32,
    /// `ilocalsym` .. `nlocrel`.
    pub fields: [u32; DYSYMTAB_FIELDS],
}

const DYSYM_ILOCAL: usize = 0;
const DYSYM_IUNDEF: usize = 4;
const DYSYM_NUNDEF: usize = 5;
const DYSYM_INDIRECT_OFFSET: usize = 12;
const DYSYM_INDIRECT_COUNT: usize = 13;
const DYSYM_EXTREL: usize = 14;

impl DysymtabCommand {
    /// Index of the first undefined symbol.
    pub fn undefined_index(&self) -> u32 {
        self.fields[DYSYM_IUNDEF]
    }

    /// Number of undefined symbols.
    pub fn undefined_count(&self) -> u32 {
        self.fields[DYSYM_NUNDEF]
    }

    /// Indirect symbol table offset.
    pub fn indirect_offset(&self) -> u32 {
        self.fields[DYSYM_INDIRECT_OFFSET]
    }

    /// Number of indirect symbols.
    pub fn indirect_count(&self) -> u32 {
        self.fields[DYSYM_INDIRECT_COUNT]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DylibCommand {
    command: u32,
    length: u32,
    name_offset: u32,
    timestamp: u32,
    versions: [u32; 2],
    use_flags: Option<u32>,
    name: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkEditCommand {
    command: u32,
    length: u32,
    offset: u32,
    size: u32,
}

/// A parsed load command, re-serialised the way go-macho writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadCommand {
    /// `LC_SEGMENT_64`.
    Segment(Segment),
    /// `LC_SYMTAB`.
    Symtab(SymtabCommand),
    /// `LC_DYSYMTAB`.
    Dysymtab(DysymtabCommand),
    /// Dylib identity or dependency.
    Dylib(DylibCommandBox),
    /// `linkedit_data_command`-shaped commands.
    LinkEdit(LinkEditBox),
    /// Commands written back verbatim.
    Raw(Vec<u8>),
}

/// Opaque dylib command payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibCommandBox(DylibCommand);

/// Opaque `linkedit_data_command` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEditBox(LinkEditCommand);

impl LoadCommand {
    /// The command identifier.
    pub fn command(&self) -> u32 {
        match self {
            Self::Segment(_) => LC_SEGMENT_64,
            Self::Symtab(_) => LC_SYMTAB,
            Self::Dysymtab(_) => LC_DYSYMTAB,
            Self::Dylib(dylib) => dylib.0.command,
            Self::LinkEdit(link) => link.0.command,
            Self::Raw(bytes) => le_u32(bytes, 0).unwrap_or_default(),
        }
    }
}

/// A symbol table entry with its resolved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name bytes (no terminator).
    pub name: Vec<u8>,
    /// `n_type`.
    pub kind: u8,
    /// `n_sect`.
    pub section: u8,
    /// `n_desc`.
    pub description: u16,
    /// `n_value`.
    pub value: u64,
}

impl Symbol {
    /// `N_EXT` is set.
    pub fn is_external(&self) -> bool {
        self.kind & N_EXT != 0
    }

    /// The type bits are `N_UNDF`.
    pub fn is_undefined(&self) -> bool {
        self.kind & N_TYPE == 0
    }

    /// The type bits are `N_INDR`.
    pub fn is_indirect(&self) -> bool {
        self.kind & N_TYPE == N_INDR
    }
}

/// A Mach-O image as go-macho models it for export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachImage {
    /// File header.
    pub header: MachHeader,
    /// Load commands in file order.
    pub loads: Vec<LoadCommand>,
    /// Symbols referenced by `LC_SYMTAB`.
    pub symbols: Vec<Symbol>,
    /// Indirect symbol table referenced by `LC_DYSYMTAB`.
    pub indirect_symbols: Vec<u32>,
}

impl MachImage {
    /// Parses the header and load commands, skipping `excluding` commands.
    ///
    /// # Errors
    /// Fails on malformed load commands.
    pub fn parse(header: &[u8], commands: &[u8], excluding: &[u32]) -> Result<Self, ExportError> {
        let header = MachHeader::parse(header)?;
        let loads = parse_load_commands(&header, commands, excluding)?;
        Ok(Self {
            header,
            loads,
            symbols: Vec::new(),
            indirect_symbols: Vec::new(),
        })
    }

    /// Segment commands in load order.
    pub fn segments(&self) -> impl Iterator<Item = &Segment> {
        self.loads.iter().filter_map(|load| match load {
            LoadCommand::Segment(segment) => Some(segment),
            _ => None,
        })
    }

    /// The first segment with the given name.
    pub fn segment(&self, name: &[u8]) -> Option<&Segment> {
        self.segments().find(|segment| segment.name() == name)
    }

    /// The image's `LC_DYSYMTAB`, if present.
    pub fn dysymtab(&self) -> Option<DysymtabCommand> {
        self.loads.iter().find_map(|load| match load {
            LoadCommand::Dysymtab(dysymtab) => Some(*dysymtab),
            _ => None,
        })
    }

    /// The image's `LC_SYMTAB`, if present.
    pub fn symtab(&self) -> Option<SymtabCommand> {
        self.loads.iter().find_map(|load| match load {
            LoadCommand::Symtab(symtab) => Some(*symtab),
            _ => None,
        })
    }

    fn segment_mut(&mut self, name: &[u8]) -> Option<&mut Segment> {
        self.loads.iter_mut().find_map(|load| match load {
            LoadCommand::Segment(segment) if segment.name() == name => Some(segment),
            _ => None,
        })
    }

    fn first_link_edit_mut(&mut self, command: u32) -> Option<&mut LinkEditCommand> {
        self.loads.iter_mut().find_map(|load| match load {
            LoadCommand::LinkEdit(link) if link.0.command == command => Some(&mut link.0),
            _ => None,
        })
    }

    fn first_link_edit(&self, command: u32) -> Option<LinkEditCommand> {
        self.loads.iter().find_map(|load| match load {
            LoadCommand::LinkEdit(link) if link.0.command == command => Some(link.0),
            _ => None,
        })
    }

    fn has_command(&self, command: u32) -> bool {
        self.loads.iter().any(|load| load.command() == command)
    }

    fn base_address(&self) -> u64 {
        self.segment(TEXT_SEGMENT)
            .map_or(0, |segment| segment.address)
    }
}

fn parse_load_commands(
    header: &MachHeader,
    mut data: &[u8],
    excluding: &[u32],
) -> Result<Vec<LoadCommand>, ExportError> {
    let mut loads = Vec::new();
    for _ in 0..header.command_count {
        let (Some(command), Some(size)) = (le_u32(data, 0), le_u32(data, 4)) else {
            return Err(ExportError::Format("command block too small"));
        };
        let size = to_usize(size)?;
        if size < 8 || size > data.len() {
            return Err(ExportError::Format("invalid command block size"));
        }
        let (raw, rest) = data.split_at(size);
        data = rest;
        if !excluding.contains(&command) {
            loads.push(parse_load_command(command, raw)?);
        }
    }
    Ok(loads)
}

fn parse_load_command(command: u32, raw: &[u8]) -> Result<LoadCommand, ExportError> {
    Ok(match command {
        LC_SEGMENT_64 => LoadCommand::Segment(parse_segment(raw)?),
        LC_SYMTAB => LoadCommand::Symtab(parse_symtab_command(raw)?),
        LC_DYSYMTAB => LoadCommand::Dysymtab(parse_dysymtab_command(raw)?),
        LC_ID_DYLIB | LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
        | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => {
            LoadCommand::Dylib(DylibCommandBox(parse_dylib(raw)?))
        }
        LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_ATOM_INFO
        | LC_FUNCTION_VARIANTS
        | LC_FUNCTION_VARIANT_FIXUPS
        | LC_LAZY_LOAD_DYLIB_INFO => LoadCommand::LinkEdit(LinkEditBox(parse_link_edit(raw)?)),
        _ => LoadCommand::Raw(raw.to_vec()),
    })
}

fn parse_segment(raw: &[u8]) -> Result<Segment, ExportError> {
    const TRUNCATED: ExportError = ExportError::Format("truncated LC_SEGMENT_64");
    let words = u64_array::<4>(raw, 24).ok_or(TRUNCATED)?;
    let tail = u32_array::<4>(raw, 56).ok_or(TRUNCATED)?;
    let mut segment = Segment {
        length: le_u32(raw, 4).ok_or(TRUNCATED)?,
        name: name_field(raw, 8).ok_or(TRUNCATED)?,
        address: words[0],
        memory_size: words[1],
        file_offset: words[2],
        file_size: words[3],
        protections: [tail[0], tail[1]],
        section_count: tail[2],
        flags: tail[3],
        sections: Vec::new(),
    };
    for index in 0..to_usize(segment.section_count)? {
        let start = SEGMENT_COMMAND_SIZE + index * SECTION_SIZE;
        let section = raw
            .get(start..start + SECTION_SIZE)
            .ok_or(ExportError::Format("truncated section"))?;
        segment.sections.push(parse_section(section)?);
    }
    Ok(segment)
}

fn parse_section(raw: &[u8]) -> Result<Section, ExportError> {
    const TRUNCATED: ExportError = ExportError::Format("truncated section");
    let addresses = u64_array::<2>(raw, 32).ok_or(TRUNCATED)?;
    let words = u32_array::<8>(raw, 48).ok_or(TRUNCATED)?;
    Ok(Section {
        name: name_field(raw, 0).ok_or(TRUNCATED)?,
        segment: name_field(raw, NAME_FIELD_SIZE).ok_or(TRUNCATED)?,
        address: addresses[0],
        size: addresses[1],
        offset: words[0],
        words: [
            words[1], words[2], words[3], words[4], words[5], words[6], words[7],
        ],
    })
}

fn parse_symtab_command(raw: &[u8]) -> Result<SymtabCommand, ExportError> {
    let words = u32_array::<6>(raw, 0).ok_or(ExportError::Format("truncated LC_SYMTAB"))?;
    Ok(SymtabCommand {
        length: words[1],
        symbol_offset: words[2],
        symbol_count: words[3],
        string_offset: words[4],
        string_size: words[5],
    })
}

/// Decodes an `LC_DYSYMTAB` command.
///
/// # Errors
/// Fails on a truncated command.
pub fn parse_dysymtab_command(raw: &[u8]) -> Result<DysymtabCommand, ExportError> {
    let length = le_u32(raw, 4).ok_or(ExportError::Format("truncated LC_DYSYMTAB"))?;
    let fields =
        u32_array::<DYSYMTAB_FIELDS>(raw, 8).ok_or(ExportError::Format("truncated LC_DYSYMTAB"))?;
    Ok(DysymtabCommand { length, fields })
}

/// Decodes an `LC_SYMTAB` command.
///
/// # Errors
/// Fails on a truncated command.
pub fn parse_symtab(raw: &[u8]) -> Result<SymtabCommand, ExportError> {
    parse_symtab_command(raw)
}

fn parse_dylib(raw: &[u8]) -> Result<DylibCommand, ExportError> {
    let words = u32_array::<6>(raw, 0).ok_or(ExportError::Format("truncated dylib command"))?;
    let name_start = to_usize(words[2])?;
    let name = raw.get(name_start..).ok_or(ExportError::Format(
        "invalid name in dynamic library command",
    ))?;
    if name.is_empty() {
        return Err(ExportError::Format(
            "invalid name in dynamic library command",
        ));
    }
    let uses = words[2] == DYLIB_USE_COMMAND_SIZE && words[3] == DYLIB_USE_MARKER;
    let reads_flags = matches!(
        words[0],
        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB
    );
    let use_flags = match (uses, reads_flags) {
        (false, _) => None,
        (true, true) => Some(
            le_u32(raw, DYLIB_COMMAND_SIZE)
                .ok_or(ExportError::Format("truncated dylib use command"))?,
        ),
        (true, false) => Some(0),
    };
    Ok(DylibCommand {
        command: words[0],
        length: words[1],
        name_offset: words[2],
        timestamp: words[3],
        versions: [words[4], words[5]],
        use_flags,
        name: cstring(name).to_vec(),
    })
}

fn parse_link_edit(raw: &[u8]) -> Result<LinkEditCommand, ExportError> {
    let words =
        u32_array::<4>(raw, 0).ok_or(ExportError::Format("truncated linkedit data command"))?;
    Ok(LinkEditCommand {
        command: words[0],
        length: words[1],
        offset: words[2],
        size: words[3],
    })
}

/// Reads the indirect symbol table of `LC_DYSYMTAB` (go-macho `NewFile`).
///
/// # Errors
/// Fails when the table cannot be read or the undefined range exceeds the
/// symbol table.
pub fn read_indirect_symbols(
    dysymtab: &DysymtabCommand,
    symbol_count: usize,
    memory: &dyn ImageMemory,
) -> Result<Vec<u32>, ExportError> {
    let undefined_end =
        u64::from(dysymtab.undefined_index()) + u64::from(dysymtab.undefined_count());
    if undefined_end > symbol_count as u64 {
        return Err(ExportError::Format(
            "undefined symbols exceed the symbol table",
        ));
    }
    let mut data = vec![0; to_usize(dysymtab.indirect_count())? * 4];
    memory.read_at(&mut data, u64::from(dysymtab.indirect_offset()))?;
    Ok(data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect())
}

/// Reads a symbol table the way go-macho's `parseSymtab` does.
///
/// # Errors
/// Fails when the symbol or string table cannot be read.
pub fn read_symbols(
    symtab: &SymtabCommand,
    memory: &dyn ImageMemory,
) -> Result<Vec<Symbol>, ExportError> {
    let mut strings = vec![0; to_usize(symtab.string_size)?];
    memory.read_at(&mut strings, u64::from(symtab.string_offset))?;
    let mut entries = vec![0; to_usize(symtab.symbol_count)? * NLIST_64_SIZE];
    memory.read_at(&mut entries, u64::from(symtab.symbol_offset))?;
    entries
        .as_chunks::<NLIST_64_SIZE>()
        .0
        .iter()
        .map(|entry| {
            let nlist = Nlist::parse(entry)?;
            let name = strings
                .get(to_usize(nlist.string_index)?..)
                .map(go_symbol_name)
                .unwrap_or_default();
            Ok(nlist.into_symbol(name))
        })
        .collect()
}

/// A decoded `nlist_64`.
#[derive(Debug, Clone, Copy)]
pub struct Nlist {
    /// String table index.
    pub string_index: u32,
    /// `n_type`.
    pub kind: u8,
    /// `n_sect`.
    pub section: u8,
    /// `n_desc`.
    pub description: u16,
    /// `n_value`.
    pub value: u64,
}

impl Nlist {
    /// Decodes one 16-byte entry.
    ///
    /// # Errors
    /// Fails on short input.
    pub fn parse(entry: &[u8]) -> Result<Self, ExportError> {
        const TRUNCATED: ExportError = ExportError::Format("truncated nlist");
        Ok(Self {
            string_index: le_u32(entry, 0).ok_or(TRUNCATED)?,
            kind: *entry.get(4).ok_or(TRUNCATED)?,
            section: *entry.get(5).ok_or(TRUNCATED)?,
            description: le_u16(entry, 6).ok_or(TRUNCATED)?,
            value: le_u64(entry, 8).ok_or(TRUNCATED)?,
        })
    }

    /// Attaches a name to the entry.
    pub fn into_symbol(self, name: Vec<u8>) -> Symbol {
        Symbol {
            name,
            kind: self.kind,
            section: self.section,
            description: self.description,
            value: self.value,
        }
    }
}

/// go-macho's symbol-name normalisation: strip `_` from names containing `.`.
pub fn go_symbol_name(data: &[u8]) -> Vec<u8> {
    let name = cstring(data);
    match name.split_first() {
        Some((b'_', rest)) if name.contains(&b'.') => rest.to_vec(),
        _ => name.to_vec(),
    }
}

/// Returns `data` up to its first NUL.
pub fn cstring(data: &[u8]) -> &[u8] {
    data.iter()
        .position(|&byte| byte == 0)
        .map_or(data, |end| &data[..end])
}

#[derive(Debug, Clone)]
struct SegmentMapping {
    name: Vec<u8>,
    old_start: u64,
    old_end: u64,
    new_start: u64,
    new_end: u64,
    original_memory_size: u64,
    original_file_size: u64,
}

struct SegmentMap(Vec<SegmentMapping>);

impl SegmentMap {
    fn new(image: &MachImage, page_size: u64) -> Self {
        let mut next = 0;
        let mut entries: Vec<SegmentMapping> = image
            .segments()
            .map(|segment| {
                let size = page_align(segment.file_size, page_size);
                let entry = SegmentMapping {
                    name: segment.name().to_vec(),
                    old_start: segment.file_offset,
                    old_end: segment.file_offset.wrapping_add(segment.file_size),
                    new_start: next,
                    new_end: next.wrapping_add(size),
                    original_memory_size: segment.memory_size,
                    original_file_size: segment.file_size,
                };
                next = next.wrapping_add(size);
                entry
            })
            .collect();
        entries.sort_by_key(|entry| entry.old_start);
        Self(entries)
    }

    fn resize_linkedit(&mut self, size: u64) {
        if let Some(entry) = self
            .0
            .iter_mut()
            .find(|entry| entry.name == LINKEDIT_SEGMENT)
        {
            entry.new_end = entry.new_start.wrapping_add(size);
            entry.original_file_size = size;
        }
    }

    fn lookup(&self, name: &[u8]) -> Option<&SegmentMapping> {
        self.0.iter().find(|entry| entry.name == name)
    }

    fn remap(&self, offset: u64) -> Result<u64, ExportError> {
        self.0
            .iter()
            .find(|entry| entry.old_start <= offset && offset <= entry.old_end)
            .map(|entry| entry.new_start.wrapping_add(offset - entry.old_start))
            .ok_or(ExportError::Remap(offset))
    }
}

/// Exports an in-cache image as a standalone thin Mach-O (go-macho `Export`).
///
/// `extra_symbols` are go-macho's `locals`: symbols placed before the image's
/// own symbol table entries.
///
/// # Errors
/// Fails when the image is malformed, not marked in-cache, or uses a feature
/// this port does not reproduce.
pub fn export_in_cache_image(
    mut image: MachImage,
    memory: &dyn ImageMemory,
    extra_symbols: &[Symbol],
) -> Result<Vec<u8>, ExportError> {
    if !image.header.in_cache() {
        return Err(ExportError::Unsupported("image is not marked as in-cache"));
    }
    let page_size = image.header.page_size();
    let mut segment_map = SegmentMap::new(&image, page_size);
    let text_relative = text_first_section_offset(&image)?;
    optimize_load_commands(&mut image, &segment_map)?;
    let linkedit = optimize_linkedit(&mut image, memory, extra_symbols, page_size)?;
    segment_map.resize_linkedit(linkedit.len() as u64);
    strip_cache_state(&mut image);
    let mut out = Vec::new();
    image.header.write(&mut out);
    write_load_commands(&image, &mut out)?;
    let layout = SegmentWriter {
        memory,
        segment_map: &segment_map,
        text_relative,
        end_of_loads: out.len() as u64,
    };
    for segment in image.segments() {
        layout.write(segment, &linkedit, &mut out)?;
    }
    Ok(out)
}

fn text_first_section_offset(image: &MachImage) -> Result<u64, ExportError> {
    let Some(text) = image.segment(TEXT_SEGMENT) else {
        return Ok(0);
    };
    match text.sections.iter().find(|section| section.offset != 0) {
        Some(section) if section.address < text.address => {
            Err(ExportError::Format("__TEXT section precedes its segment"))
        }
        Some(section) => Ok(section.address - text.address),
        None => Ok(0),
    }
}

fn optimize_load_commands(
    image: &mut MachImage,
    segment_map: &SegmentMap,
) -> Result<(), ExportError> {
    for load in &mut image.loads {
        match load {
            LoadCommand::Segment(segment) => remap_segment(segment, segment_map)?,
            LoadCommand::LinkEdit(link)
                if matches!(
                    link.0.command,
                    LC_DYLIB_CODE_SIGN_DRS | LC_LINKER_OPTIMIZATION_HINT
                ) =>
            {
                link.0.offset = low32(segment_map.remap(u64::from(link.0.offset))?);
            }
            LoadCommand::Raw(raw) => remap_raw_command(raw, segment_map)?,
            _ => {}
        }
    }
    Ok(())
}

fn remap_segment(segment: &mut Segment, segment_map: &SegmentMap) -> Result<(), ExportError> {
    let entry = segment_map
        .lookup(segment.name())
        .ok_or(ExportError::Remap(segment.file_offset))?;
    let size = entry.new_end.wrapping_sub(entry.new_start);
    segment.file_offset = entry.new_start;
    segment.file_size = size;
    segment.memory_size = if entry.original_memory_size > entry.original_file_size {
        size.wrapping_add(entry.original_memory_size - entry.original_file_size)
    } else {
        size
    };
    for section in &mut segment.sections {
        if section.offset != 0 {
            let relative = section.address.wrapping_sub(segment.address);
            section.offset = low32(segment.file_offset.wrapping_add(relative));
        }
    }
    Ok(())
}

fn remap_raw_command(raw: &mut [u8], segment_map: &SegmentMap) -> Result<(), ExportError> {
    const CRYPT_OFFSET: usize = 8;
    match le_u32(raw, 0) {
        Some(LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64) => {
            let offset = le_u32(raw, CRYPT_OFFSET)
                .ok_or(ExportError::Format("truncated encryption info"))?;
            let remapped = low32(segment_map.remap(u64::from(offset))?);
            raw[CRYPT_OFFSET..CRYPT_OFFSET + 4].copy_from_slice(&remapped.to_le_bytes());
            Ok(())
        }
        Some(LC_FILESET_ENTRY) => Err(ExportError::Unsupported(
            "fileset entry inside an exported image",
        )),
        _ => Ok(()),
    }
}

fn strip_cache_state(image: &mut MachImage) {
    image.header.flags &= !MH_DYLIB_IN_CACHE;
    if let Some(index) = image
        .loads
        .iter()
        .position(|load| load.command() == LC_DYLD_CHAINED_FIXUPS)
    {
        image.loads.remove(index);
        image.header.command_count = image.header.command_count.wrapping_sub(1);
        image.header.commands_size = image.header.commands_size.wrapping_sub(LINKEDIT_DATA_SIZE);
    }
}

struct LinkeditBuilder<'a> {
    memory: &'a dyn ImageMemory,
    base: u32,
    data: Vec<u8>,
}

impl LinkeditBuilder<'_> {
    fn copy(&mut self, offset: u32, size: u32) -> Result<u32, ExportError> {
        let mut chunk = vec![0; to_usize(size)?];
        self.memory.read_at(&mut chunk, u64::from(offset))?;
        let new_offset = self.base.wrapping_add(low32_usize(self.data.len()));
        self.data.extend_from_slice(&chunk);
        self.pad();
        Ok(new_offset)
    }

    fn pad(&mut self) {
        let remainder = self.data.len() % POINTER_SIZE;
        if remainder != 0 {
            self.data
                .resize(self.data.len() + POINTER_SIZE - remainder, 0);
        }
    }

    fn relocate(&mut self, image: &mut MachImage, command: u32) -> Result<(), ExportError> {
        if let Some(link) = image.first_link_edit(command) {
            let offset = self.copy(link.offset, link.size)?;
            if let Some(target) = image.first_link_edit_mut(command) {
                target.offset = offset;
            }
        }
        Ok(())
    }
}

fn optimize_linkedit(
    image: &mut MachImage,
    memory: &dyn ImageMemory,
    extra_symbols: &[Symbol],
    page_size: u64,
) -> Result<Vec<u8>, ExportError> {
    let base = linkedit_base(image)?;
    let exports = read_exports(image, memory)?;
    let mut builder = LinkeditBuilder {
        memory,
        base: low32(base),
        data: Vec::new(),
    };
    for command in [
        LC_DYLD_EXPORTS_TRIE,
        LC_DATA_IN_CODE,
        LC_FUNCTION_STARTS,
        LC_FUNCTION_VARIANTS,
        LC_FUNCTION_VARIANT_FIXUPS,
    ] {
        builder.relocate(image, command)?;
    }
    let tables = SymbolTables::build(image, extra_symbols, &exports);
    let layout = tables.write(&mut builder, image, extra_symbols.len());
    update_symbol_commands(image, &layout);
    let size = builder.data.len() as u64;
    if let Some(linkedit) = image.segment_mut(LINKEDIT_SEGMENT) {
        linkedit.file_size = size;
        linkedit.memory_size = page_align(size, page_size);
    }
    Ok(builder.data)
}

fn linkedit_base(image: &MachImage) -> Result<u64, ExportError> {
    let base = image
        .segment(LINKEDIT_SEGMENT)
        .ok_or(ExportError::Format("unable to find __LINKEDIT segment"))?
        .file_offset;
    if !image.has_command(LC_DYSYMTAB) {
        return Err(ExportError::Format("binary has no LC_DYSYMTAB"));
    }
    if image.has_command(LC_DYLD_INFO) || image.has_command(LC_DYLD_INFO_ONLY) {
        return Err(ExportError::Unsupported(
            "LC_DYLD_INFO in an in-cache image",
        ));
    }
    Ok(base)
}

fn read_exports(
    image: &MachImage,
    memory: &dyn ImageMemory,
) -> Result<Vec<trie::TrieExport>, ExportError> {
    let Some(link) = image.first_link_edit(LC_DYLD_EXPORTS_TRIE) else {
        return Ok(Vec::new());
    };
    if link.size == 0 {
        return Ok(Vec::new());
    }
    let mut data = vec![0; to_usize(link.size)?];
    memory.read_at(&mut data, u64::from(link.offset))?;
    trie::parse_exports(&data, image.base_address())
}

struct SymbolEntry {
    symbol: Symbol,
    name: Vec<u8>,
}

struct SymbolTables {
    locals: Vec<SymbolEntry>,
    defined: Vec<SymbolEntry>,
    undefined: Vec<SymbolEntry>,
}

struct SymbolLayout {
    symbol_offset: u32,
    indirect_offset: u32,
    string_offset: u32,
    string_size: u32,
    counts: [u32; 3],
    indirect_count: u32,
}

const RE_EXPORT_KIND: u8 = N_INDR | N_EXT;

impl SymbolTables {
    fn build(image: &MachImage, extra_symbols: &[Symbol], exports: &[trie::TrieExport]) -> Self {
        let mut tables = Self {
            locals: Vec::new(),
            defined: Vec::new(),
            undefined: Vec::new(),
        };
        for symbol in extra_symbols {
            tables.push(symbol.clone(), symbol.name.clone());
        }
        if image.symtab().is_some() {
            for symbol in image
                .symbols
                .iter()
                .filter(|symbol| symbol.name != REDACTED_SYMBOL)
            {
                tables.push(symbol.clone(), symbol.name.clone());
            }
        }
        for export in exports.iter().filter(|export| export.is_listed_in_symtab()) {
            let symbol = Symbol {
                name: export.name.clone(),
                kind: RE_EXPORT_KIND,
                section: 0,
                description: 0,
                value: export.address,
            };
            let mut name = export.name.clone();
            name.push(0);
            name.extend_from_slice(&export.re_export);
            tables.defined.push(SymbolEntry { symbol, name });
        }
        tables
    }

    fn push(&mut self, symbol: Symbol, name: Vec<u8>) {
        let entry = SymbolEntry { symbol, name };
        if !entry.symbol.is_external() {
            self.locals.push(entry);
        } else if entry.symbol.is_undefined() {
            self.undefined.push(entry);
        } else {
            self.defined.push(entry);
        }
    }

    fn write_nlists(&self, out: &mut Vec<u8>) -> Vec<u8> {
        let mut strings = vec![0u8];
        let entries = self
            .locals
            .iter()
            .chain(&self.defined)
            .chain(&self.undefined);
        for entry in entries {
            write_nlist(out, low32_usize(strings.len()), &entry.symbol);
            strings.extend_from_slice(&entry.name);
            strings.push(0);
        }
        strings
    }

    fn write(
        &self,
        builder: &mut LinkeditBuilder<'_>,
        image: &mut MachImage,
        shift: usize,
    ) -> SymbolLayout {
        let symbol_offset = low32_usize(builder.data.len());
        let mut strings = self.write_nlists(&mut builder.data);
        builder.pad();
        let indirect_offset = low32_usize(builder.data.len());
        shift_indirect_symbols(&mut image.indirect_symbols, shift);
        for index in &image.indirect_symbols {
            put_u32(&mut builder.data, *index);
        }
        builder.pad();
        let string_offset = low32_usize(builder.data.len());
        strings.resize(strings.len().next_multiple_of(POINTER_SIZE), 0);
        builder.data.extend_from_slice(&strings);
        SymbolLayout {
            symbol_offset: builder.base.wrapping_add(symbol_offset),
            indirect_offset: builder.base.wrapping_add(indirect_offset),
            string_offset: builder.base.wrapping_add(string_offset),
            string_size: low32_usize(strings.len()),
            counts: [
                low32_usize(self.locals.len()),
                low32_usize(self.defined.len()),
                low32_usize(self.undefined.len()),
            ],
            indirect_count: low32_usize(image.indirect_symbols.len()),
        }
    }
}

fn shift_indirect_symbols(indirect: &mut [u32], shift: usize) {
    if shift == 0 {
        return;
    }
    for index in indirect
        .iter_mut()
        .filter(|index| **index & INDIRECT_SYMBOL_LOCAL == 0)
    {
        *index = index.wrapping_add(low32_usize(shift));
    }
}

fn write_nlist(out: &mut Vec<u8>, string_index: u32, symbol: &Symbol) {
    put_u32(out, string_index);
    out.push(symbol.kind);
    out.push(symbol.section);
    out.extend_from_slice(&symbol.description.to_le_bytes());
    out.extend_from_slice(&symbol.value.to_le_bytes());
}

fn update_symbol_commands(image: &mut MachImage, layout: &SymbolLayout) {
    let [locals, defined, undefined] = layout.counts;
    let mut symbol_offset = None;
    for load in &mut image.loads {
        if let LoadCommand::Symtab(symtab) = load {
            symtab.symbol_count = locals.wrapping_add(defined).wrapping_add(undefined);
            symtab.symbol_offset = layout.symbol_offset;
            symtab.string_offset = layout.string_offset;
            symtab.string_size = layout.string_size;
            symbol_offset = Some(layout.symbol_offset);
            break;
        }
    }
    if let (Some(offset), Some(data_in_code)) =
        (symbol_offset, image.first_link_edit_mut(LC_DATA_IN_CODE))
        && data_in_code.size == 0
    {
        data_in_code.offset = offset;
    }
    if let Some(LoadCommand::Dysymtab(dysymtab)) = image
        .loads
        .iter_mut()
        .find(|load| load.command() == LC_DYSYMTAB)
    {
        let fields = &mut dysymtab.fields;
        fields[DYSYM_ILOCAL..DYSYM_ILOCAL + 6].copy_from_slice(&[
            0,
            locals,
            locals,
            defined,
            locals.wrapping_add(defined),
            undefined,
        ]);
        fields[DYSYM_EXTREL..DYSYM_EXTREL + 4].copy_from_slice(&[0, 0, 0, 0]);
        fields[DYSYM_INDIRECT_COUNT] = layout.indirect_count;
        fields[DYSYM_INDIRECT_OFFSET] = layout.indirect_offset;
    }
}

fn write_load_commands(image: &MachImage, out: &mut Vec<u8>) -> Result<(), ExportError> {
    for load in &image.loads {
        match load {
            LoadCommand::Segment(segment) => write_segment(image, segment, out)?,
            LoadCommand::Symtab(symtab) => {
                for word in [
                    LC_SYMTAB,
                    symtab.length,
                    symtab.symbol_offset,
                    symtab.symbol_count,
                    symtab.string_offset,
                    symtab.string_size,
                ] {
                    put_u32(out, word);
                }
            }
            LoadCommand::Dysymtab(dysymtab) => {
                put_u32(out, LC_DYSYMTAB);
                put_u32(out, dysymtab.length);
                dysymtab
                    .fields
                    .iter()
                    .for_each(|field| put_u32(out, *field));
            }
            LoadCommand::Dylib(dylib) => write_dylib(&dylib.0, out)?,
            LoadCommand::LinkEdit(link) => {
                for word in [link.0.command, link.0.length, link.0.offset, link.0.size] {
                    put_u32(out, word);
                }
            }
            LoadCommand::Raw(raw) => out.extend_from_slice(raw),
        }
    }
    Ok(())
}

fn write_segment(
    image: &MachImage,
    segment: &Segment,
    out: &mut Vec<u8>,
) -> Result<(), ExportError> {
    put_u32(out, LC_SEGMENT_64);
    put_u32(out, segment.length);
    out.extend_from_slice(&segment.name);
    for value in [
        segment.address,
        segment.memory_size,
        segment.file_offset,
        segment.file_size,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for word in [
        segment.protections[0],
        segment.protections[1],
        segment.section_count,
        segment.flags,
    ] {
        put_u32(out, word);
    }
    for section in &segment.sections {
        let canonical = image
            .segments()
            .flat_map(|candidate| candidate.sections.iter())
            .find(|candidate| {
                candidate.segment == section.segment && candidate.name == section.name
            })
            .ok_or(ExportError::Format("section disappeared"))?;
        write_section(canonical, out);
    }
    Ok(())
}

fn write_section(section: &Section, out: &mut Vec<u8>) {
    out.extend_from_slice(&section.name);
    out.extend_from_slice(&section.segment);
    out.extend_from_slice(&section.address.to_le_bytes());
    out.extend_from_slice(&section.size.to_le_bytes());
    put_u32(out, section.offset);
    section.words.iter().for_each(|word| put_u32(out, *word));
}

fn write_dylib(dylib: &DylibCommand, out: &mut Vec<u8>) -> Result<(), ExportError> {
    let start = out.len();
    for word in [
        dylib.command,
        dylib.length,
        dylib.name_offset,
        dylib.timestamp,
        dylib.versions[0],
        dylib.versions[1],
    ] {
        put_u32(out, word);
    }
    if let Some(flags) = dylib.use_flags {
        put_u32(out, flags);
    }
    out.extend_from_slice(&dylib.name);
    out.push(0);
    let length = to_usize(dylib.length)?;
    let written = out.len() - start;
    if length < written {
        return Err(ExportError::Format(
            "dylib command is smaller than its contents",
        ));
    }
    out.resize(start + length, 0);
    Ok(())
}

struct SegmentWriter<'a> {
    memory: &'a dyn ImageMemory,
    segment_map: &'a SegmentMap,
    text_relative: u64,
    end_of_loads: u64,
}

impl SegmentWriter<'_> {
    fn write(
        &self,
        segment: &Segment,
        linkedit: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), ExportError> {
        let entry = self
            .segment_map
            .lookup(segment.name())
            .ok_or(ExportError::Remap(segment.file_offset))?;
        if segment.file_size > 0 {
            pad_to(out, entry.new_start)?;
            match segment.name() {
                TEXT_SEGMENT => self.write_text(segment, entry, out)?,
                LINKEDIT_SEGMENT => out.extend_from_slice(linkedit),
                _ => out.extend_from_slice(&self.read_segment(segment, entry)?),
            }
        }
        pad_to(out, entry.new_end)
    }

    fn read_segment(
        &self,
        segment: &Segment,
        entry: &SegmentMapping,
    ) -> Result<Vec<u8>, ExportError> {
        let mut data = vec![0; to_usize_u64(entry.original_file_size)?];
        self.memory.read_at_addr(&mut data, segment.address)?;
        Ok(data)
    }

    fn write_text(
        &self,
        segment: &Segment,
        entry: &SegmentMapping,
        out: &mut Vec<u8>,
    ) -> Result<(), ExportError> {
        let data = self.read_segment(segment, entry)?;
        let start = self.text_relative.max(self.end_of_loads);
        if start > data.len() as u64 {
            return Err(ExportError::Format(
                "__TEXT data start exceeds segment data length",
            ));
        }
        out.resize(out.len() + to_usize_u64(start - self.end_of_loads)?, 0);
        out.extend_from_slice(&data[to_usize_u64(start)?..]);
        Ok(())
    }
}

fn pad_to(out: &mut Vec<u8>, end: u64) -> Result<(), ExportError> {
    let end = to_usize_u64(end)?;
    if out.len() < end {
        out.resize(end, 0);
    }
    Ok(())
}

fn page_align(value: u64, align: u64) -> u64 {
    match value % align {
        0 => value,
        remainder => value.wrapping_add(align - remainder),
    }
}

fn to_usize(value: u32) -> Result<usize, ExportError> {
    usize::try_from(value).map_err(|_| ExportError::Format("value exceeds address space"))
}

fn to_usize_u64(value: u64) -> Result<usize, ExportError> {
    usize::try_from(value).map_err(|_| ExportError::Format("value exceeds address space"))
}

/// Go's `uint32(x)`: keeps the low 32 bits.
pub fn low32(value: u64) -> u32 {
    u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX)
}

fn low32_usize(value: usize) -> u32 {
    low32(u64::try_from(value).unwrap_or(u64::MAX))
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn name_field(data: &[u8], offset: usize) -> Option<[u8; NAME_FIELD_SIZE]> {
    let raw = data.get(offset..offset.checked_add(NAME_FIELD_SIZE)?)?;
    let mut field = [0; NAME_FIELD_SIZE];
    let name = cstring(raw);
    field[..name.len()].copy_from_slice(name);
    Some(field)
}

/// Little-endian `u16` at `offset`.
pub fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

/// Little-endian `u32` at `offset`.
pub fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Little-endian `u64` at `offset`.
pub fn le_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn u32_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u32; N]> {
    let mut words = [0; N];
    for (index, word) in words.iter_mut().enumerate() {
        *word = le_u32(data, offset + index * 4)?;
    }
    Some(words)
}

fn u64_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u64; N]> {
    let mut words = [0; N];
    for (index, word) in words.iter_mut().enumerate() {
        *word = le_u64(data, offset + index * 8)?;
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_symbol_name_strips_underscore_only_for_dotted_names() {
        assert_eq!(go_symbol_name(b"_main\0junk"), b"_main");
        assert_eq!(go_symbol_name(b"_a.b\0"), b"a.b");
        assert_eq!(go_symbol_name(b"x.y"), b"x.y");
    }

    #[test]
    fn page_align_rounds_up() {
        assert_eq!(page_align(0, PAGE_SIZE_16K), 0);
        assert_eq!(page_align(1, PAGE_SIZE_16K), PAGE_SIZE_16K);
        assert_eq!(page_align(PAGE_SIZE_16K, PAGE_SIZE_16K), PAGE_SIZE_16K);
    }

    #[test]
    fn dylib_round_trips_with_padding() {
        let mut raw = Vec::new();
        for word in [LC_LOAD_DYLIB, 40, 24, 2, 0x10000, 0x10000] {
            put_u32(&mut raw, word);
        }
        raw.extend_from_slice(b"/usr/lib/libz\0");
        raw.resize(40, 0);
        let parsed = parse_dylib(&raw).expect("parse dylib");
        let mut out = Vec::new();
        write_dylib(&parsed, &mut out).expect("write dylib");
        assert_eq!(out, raw);
    }

    #[test]
    fn indirect_shift_skips_local_entries() {
        let mut indirect = vec![1, INDIRECT_SYMBOL_LOCAL, 7];
        shift_indirect_symbols(&mut indirect, 2);
        assert_eq!(indirect, vec![3, INDIRECT_SYMBOL_LOCAL, 9]);
    }
}
