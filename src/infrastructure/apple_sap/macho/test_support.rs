//! Synthetic arm64e Mach-O images for unit tests.
//!
//! [`MachOBuilder`] lays out a 64-bit header, `LC_SEGMENT_64` commands (with
//! sections) and arbitrary extra load commands, then writes payload bytes at
//! chosen file offsets. The helpers below encode the linkedit structures the
//! parsers consume: `nlist_64` tables, export tries and chained-fixup blobs.

pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub(crate) const CPU_SUBTYPE_ARM64E: u32 = 2;
pub(crate) const LC_SEGMENT_64: u32 = 0x19;
pub(crate) const LC_SYMTAB: u32 = 0x2;
pub(crate) const LC_DYLD_INFO: u32 = 0x22;
pub(crate) const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub(crate) const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
pub(crate) const PURE_INSTRUCTIONS: u32 = 0x8000_0400;
pub(crate) const PROT_RX: u32 = 5;
pub(crate) const PROT_RW: u32 = 3;

/// Preferred base of the standard image.
pub(crate) const BASE: u64 = 0x1_0000_0000;
/// File offset of the `__text` section of the standard image.
pub(crate) const TEXT_SECTION: usize = 0x800;
/// File offset of `__DATA` in the standard image.
pub(crate) const DATA_AT: usize = 0x1000;
/// File offset of `__LINKEDIT` in the standard image.
pub(crate) const LINKEDIT_AT: usize = 0x2000;
/// Total size of the standard image.
pub(crate) const IMAGE_SIZE: usize = 0x3000;
/// `pacibsp`, rewritten to `nop`.
pub(crate) const PACIBSP: u32 = 0xd503_237f;
/// `retab`, rewritten to `ret`.
pub(crate) const RETAB: u32 = 0xd65f_0fff;
pub(crate) const NOP: u32 = 0xd503_201f;
pub(crate) const RET: u32 = 0xd65f_03c0;

const HEADER_SIZE: usize = 32;
const SEGMENT_COMMAND_SIZE: usize = 72;
const SECTION_SIZE: usize = 80;
const NAME_SIZE: usize = 16;

pub(crate) fn u32_of(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn fixed_name(name: &str) -> [u8; NAME_SIZE] {
    let mut raw = [0u8; NAME_SIZE];
    raw[..name.len()].copy_from_slice(name.as_bytes());
    raw
}

#[derive(Debug, Clone)]
struct SectionSpec {
    name: String,
    address: u64,
    size: u64,
    offset: u32,
    flags: u32,
}

#[derive(Debug, Clone)]
struct SegmentSpec {
    name: String,
    fields: [u64; 4],
    protection: u32,
    sections: Vec<SectionSpec>,
}

impl SegmentSpec {
    fn encode(&self) -> Vec<u8> {
        let size = SEGMENT_COMMAND_SIZE + self.sections.len() * SECTION_SIZE;
        let mut command = Vec::with_capacity(size);
        command.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        command.extend_from_slice(&u32_of(size).to_le_bytes());
        command.extend_from_slice(&fixed_name(&self.name));
        for value in self.fields {
            command.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            self.protection,
            self.protection,
            u32_of(self.sections.len()),
            0,
        ] {
            command.extend_from_slice(&value.to_le_bytes());
        }
        for section in &self.sections {
            command.extend_from_slice(&fixed_name(&section.name));
            command.extend_from_slice(&fixed_name(&self.name));
            command.extend_from_slice(&section.address.to_le_bytes());
            command.extend_from_slice(&section.size.to_le_bytes());
            for value in [section.offset, 0, 0, 0, section.flags, 0, 0, 0] {
                command.extend_from_slice(&value.to_le_bytes());
            }
        }
        command
    }
}

/// Builds thin arm64 Mach-O images byte by byte.
#[derive(Debug, Clone, Default)]
pub(crate) struct MachOBuilder {
    segments: Vec<SegmentSpec>,
    commands: Vec<Vec<u8>>,
    writes: Vec<(usize, Vec<u8>)>,
    file_size: usize,
}

impl MachOBuilder {
    pub(crate) fn new(file_size: usize) -> Self {
        Self {
            file_size,
            ..Self::default()
        }
    }

    /// Standard image: `__PAGEZERO`, `__TEXT` (with an instruction section
    /// holding `pacibsp; retab`), `__DATA` and `__LINKEDIT`.
    pub(crate) fn standard() -> Self {
        Self::new(IMAGE_SIZE)
            .segment("__PAGEZERO", 0, BASE, 0, 0)
            .segment("__TEXT", BASE, 0x1000, 0, 0x1000)
            .section(
                "__text",
                BASE + 0x800,
                8,
                u32_of(TEXT_SECTION),
                PURE_INSTRUCTIONS,
            )
            .section("__const", BASE + 0x900, 8, 0x900, 0)
            .segment("__DATA", BASE + 0x1000, 0x1000, 0x1000, 0x1000)
            .segment("__LINKEDIT", BASE + 0x2000, 0x1000, 0x2000, 0x1000)
            .word(TEXT_SECTION, PACIBSP)
            .word(TEXT_SECTION + 4, RETAB)
    }

    pub(crate) fn segment(
        mut self,
        name: &str,
        address: u64,
        size: u64,
        file_offset: u64,
        file_size: u64,
    ) -> Self {
        let protection = if name == "__TEXT" { PROT_RX } else { PROT_RW };
        self.segments.push(SegmentSpec {
            name: name.to_owned(),
            fields: [address, size, file_offset, file_size],
            protection,
            sections: Vec::new(),
        });
        self
    }

    /// Adds a section to the most recently added segment.
    pub(crate) fn section(
        mut self,
        name: &str,
        address: u64,
        size: u64,
        offset: u32,
        flags: u32,
    ) -> Self {
        if let Some(segment) = self.segments.last_mut() {
            segment.sections.push(SectionSpec {
                name: name.to_owned(),
                address,
                size,
                offset,
                flags,
            });
        }
        self
    }

    /// Appends a load command whose body (after `cmd`/`cmdsize`) is `fields`.
    pub(crate) fn command(mut self, command: u32, fields: &[u32]) -> Self {
        let mut raw = Vec::new();
        raw.extend_from_slice(&command.to_le_bytes());
        raw.extend_from_slice(&u32_of(8 + fields.len() * 4).to_le_bytes());
        for field in fields {
            raw.extend_from_slice(&field.to_le_bytes());
        }
        self.commands.push(raw);
        self
    }

    pub(crate) fn symtab(self, symbols: usize, count: usize, strings: usize, size: usize) -> Self {
        let fields = [symbols, count, strings, size].map(u32_of);
        self.command(LC_SYMTAB, &fields)
    }

    /// `LC_DYLD_INFO(_ONLY)` with `(offset, size)` for rebase, bind, weak,
    /// lazy and export streams.
    pub(crate) fn dyld_info(self, command: u32, ranges: [(usize, usize); 5]) -> Self {
        let fields: Vec<u32> = ranges
            .iter()
            .flat_map(|&(offset, size)| [u32_of(offset), u32_of(size)])
            .collect();
        self.command(command, &fields)
    }

    pub(crate) fn chained_fixups(self, offset: usize, size: usize) -> Self {
        self.command(LC_DYLD_CHAINED_FIXUPS, &[u32_of(offset), u32_of(size)])
    }

    pub(crate) fn bytes(mut self, offset: usize, bytes: &[u8]) -> Self {
        self.writes.push((offset, bytes.to_vec()));
        self
    }

    pub(crate) fn word(self, offset: usize, value: u32) -> Self {
        self.bytes(offset, &value.to_le_bytes())
    }

    pub(crate) fn pointer(self, offset: usize, value: u64) -> Self {
        self.bytes(offset, &value.to_le_bytes())
    }

    pub(crate) fn build(self) -> Vec<u8> {
        let mut commands: Vec<Vec<u8>> = self.segments.iter().map(SegmentSpec::encode).collect();
        commands.extend(self.commands);
        let total: usize = commands.iter().map(Vec::len).sum();
        let mut data = Vec::with_capacity(self.file_size);
        for value in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64E,
            6,
            u32_of(commands.len()),
            u32_of(total),
            0,
            0,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        debug_assert_eq!(data.len(), HEADER_SIZE);
        for command in commands {
            data.extend_from_slice(&command);
        }
        data.resize(self.file_size.max(data.len()), 0);
        for (offset, bytes) in self.writes {
            let end = offset + bytes.len();
            if data.len() < end {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(&bytes);
        }
        data
    }
}

/// Encodes `(name, n_type, n_value)` entries as an `nlist_64` table plus a
/// string pool. Returns `(table, strings)`.
pub(crate) fn symbol_table(entries: &[(&str, u8, u64)]) -> (Vec<u8>, Vec<u8>) {
    let mut strings = vec![0u8];
    let mut table = Vec::new();
    for &(name, kind, value) in entries {
        table.extend_from_slice(&u32_of(strings.len()).to_le_bytes());
        table.extend_from_slice(&[kind, 1, 0, 0]);
        table.extend_from_slice(&value.to_le_bytes());
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    (table, strings)
}

/// A one-level export trie: the root has one child edge per `(name, offset)`.
pub(crate) fn export_trie(entries: &[(&str, u8)]) -> Vec<u8> {
    let mut root = vec![0u8, u8::try_from(entries.len()).unwrap_or(u8::MAX)];
    let edges: usize = entries.iter().map(|(name, _)| name.len() + 2).sum();
    let mut child = root.len() + edges;
    let mut nodes = Vec::new();
    for &(name, offset) in entries {
        root.extend_from_slice(name.as_bytes());
        root.push(0);
        root.push(u8::try_from(child).unwrap_or(u8::MAX));
        let node = [2u8, 0, offset, 0];
        child += node.len();
        nodes.extend_from_slice(&node);
    }
    root.extend_from_slice(&nodes);
    root
}

/// Starts of one segment inside a chained-fixup payload.
#[derive(Debug, Clone)]
pub(crate) struct ChainStarts {
    pub(crate) page_size: u16,
    pub(crate) pointer_format: u16,
    pub(crate) segment_offset: u64,
    pub(crate) page_starts: Vec<u16>,
}

impl ChainStarts {
    pub(crate) fn single(pointer_format: u16, page_start: u16) -> Self {
        Self {
            page_size: 0x1000,
            pointer_format,
            segment_offset: 0,
            page_starts: vec![page_start],
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let size = 22 + self.page_starts.len() * 2;
        out.extend_from_slice(&u32_of(size).to_le_bytes());
        out.extend_from_slice(&self.page_size.to_le_bytes());
        out.extend_from_slice(&self.pointer_format.to_le_bytes());
        out.extend_from_slice(&self.segment_offset.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let count = u16::try_from(self.page_starts.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for start in &self.page_starts {
            out.extend_from_slice(&start.to_le_bytes());
        }
        out
    }
}

/// Imports encoding of a chained-fixup payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportFormat {
    Plain,
    Addend,
    Addend64,
    Unknown,
}

impl ImportFormat {
    fn code(self) -> u32 {
        match self {
            Self::Plain => 1,
            Self::Addend => 2,
            Self::Addend64 => 3,
            Self::Unknown => 9,
        }
    }

    fn encode(self, name_offset: u32, addend: i64) -> Vec<u8> {
        match self {
            Self::Plain | Self::Unknown => ((name_offset << 9) | 1).to_le_bytes().to_vec(),
            Self::Addend => {
                let mut out = ((name_offset << 9) | 1).to_le_bytes().to_vec();
                let addend = i32::try_from(addend).unwrap_or_default();
                out.extend_from_slice(&addend.to_le_bytes());
                out
            }
            Self::Addend64 => {
                let mut out = ((u64::from(name_offset) << 32) | 1).to_le_bytes().to_vec();
                out.extend_from_slice(&addend.to_le_bytes());
                out
            }
        }
    }
}

/// Encodes an `LC_DYLD_CHAINED_FIXUPS` payload. `None` segments have no starts.
pub(crate) fn chained_payload(
    segments: &[Option<ChainStarts>],
    imports_format: ImportFormat,
    imports: &[(&str, i64)],
) -> Vec<u8> {
    const HEADER: usize = 28;
    let mut starts = u32_of(segments.len()).to_le_bytes().to_vec();
    let table_end = 4 + segments.len() * 4;
    let mut bodies = Vec::new();
    for segment in segments {
        let info = segment.as_ref().map_or(0, |segment| {
            let at = table_end + bodies.len();
            bodies.extend_from_slice(&segment.encode());
            at
        });
        starts.extend_from_slice(&u32_of(info).to_le_bytes());
    }
    starts.extend_from_slice(&bodies);
    let mut records = Vec::new();
    let mut pool = Vec::new();
    for &(name, addend) in imports {
        records.extend_from_slice(&imports_format.encode(u32_of(pool.len()), addend));
        pool.extend_from_slice(name.as_bytes());
        pool.push(0);
    }
    let imports_offset = HEADER + starts.len();
    let symbols_offset = imports_offset + records.len();
    let mut payload = Vec::new();
    for value in [
        0,
        u32_of(HEADER),
        u32_of(imports_offset),
        u32_of(symbols_offset),
        u32_of(imports.len()),
        imports_format.code(),
        0,
    ] {
        payload.extend_from_slice(&value.to_le_bytes());
    }
    payload.extend_from_slice(&starts);
    payload.extend_from_slice(&records);
    payload.extend_from_slice(&pool);
    payload
}
