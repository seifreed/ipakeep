//! Ported from ipatool `internal/sap/assets/kernel.go`.
//!
//! Decodes the pinned IM4P kernel collection (DER container, LZFSE payload),
//! resolves `FairPlayIOKit`'s imports against every other fileset entry and
//! exports the kext as a standalone Mach-O, byte-identical to ipatool.

use std::collections::HashMap;

use thiserror::Error;

use super::dyld::export::{
    self, ExportError, ImageMemory, LC_FILESET_ENTRY, MachHeader, MachImage, Symbol, cstring,
    le_u32, le_u64,
};

/// Restore-image member holding the kernel collection.
pub const KERNEL_CACHE_NAME: &str = "kernelcache.release.mac13j";
/// Pinned compressed size of the kernel collection zip member.
pub const KERNEL_CACHE_COMPRESSED_SIZE: u64 = 33_043_908;
/// Pinned uncompressed size of the kernel collection zip member (the IM4P).
pub const KERNEL_CACHE_ARCHIVE_SIZE: u64 = 33_096_787;
/// Fileset entry exported by [`extract_fair_play_kext`].
pub const FAIR_PLAY_KEXT_IDENTIFIER: &str = "com.apple.driver.FairPlayIOKit";

const KERNEL_CACHE_ARCHIVE_BYTES: usize = 33_096_787;
const KERNEL_CACHE_PAYLOAD_SIZE: usize = 33_096_384;
const KERNEL_CACHE_IMAGE_SIZE: usize = 124_354_560;
const MAXIMUM_KERNEL_CACHE_SYMBOLS: usize = 1 << 20;
const MH_FILESET: u32 = 0xc;
const N_ABS_EXTERNAL: u8 = 0x02 | 0x01;
const DER_TAG_SEQUENCE: u8 = 16;
const DER_TAG_OCTET_STRING: u8 = 4;
const DER_TAG_IA5_STRING: u8 = 22;
const DER_CONSTRUCTED: u8 = 0x20;
const DER_TAG_NUMBER_MASK: u8 = 0x1f;
const DER_LONG_LENGTH: u8 = 0x80;
const DER_LENGTH_COUNT_MASK: u8 = 0x7f;
const IM4P_FIELD_COUNT: usize = 4;
const FILESET_ENTRY_ID_FIELD: usize = 24;
const FILESET_FILE_OFFSET_FIELD: usize = 16;

/// Failures while decoding the kernel collection or exporting the kext.
#[derive(Debug, Error)]
pub enum KernelError {
    /// A pinned size does not match.
    #[error("pinned kernel {what} has size {actual}, expected {expected}")]
    Size {
        /// Which artefact.
        what: &'static str,
        /// Observed size.
        actual: usize,
        /// Pinned size.
        expected: usize,
    },
    /// The IM4P container is malformed.
    #[error("invalid IM4P kernel payload: {0}")]
    Im4p(&'static str),
    /// LZFSE decompression failed.
    #[error("decompress pinned kernel collection: {0}")]
    Lzfse(String),
    /// The kernel collection is not a usable fileset.
    #[error("pinned kernel collection: {0}")]
    Collection(&'static str),
    /// The pinned kernel symbol table exceeds the limit.
    #[error("pinned kernel symbol table exceeds the limit")]
    TooManySymbols,
    /// Mach-O parsing or export failed.
    #[error("export FairPlayIOKit from pinned kernel collection: {0}")]
    Export(#[from] ExportError),
}

/// Exports `FairPlayIOKit` from the raw `kernelcache.release.mac13j` member
/// (ipatool `extractFairPlayKext` after the zip entry has been read).
///
/// # Errors
/// Fails when any pinned size differs or the collection cannot be exported.
pub fn extract_fair_play_kext(kernel_cache: &[u8]) -> Result<Vec<u8>, KernelError> {
    check_size("collection", kernel_cache.len(), KERNEL_CACHE_ARCHIVE_BYTES)?;
    let payload = im4p_payload(kernel_cache)?;
    check_size("payload", payload.len(), KERNEL_CACHE_PAYLOAD_SIZE)?;
    let mut image = Vec::with_capacity(KERNEL_CACHE_IMAGE_SIZE);
    lzfse_rust::decode_bytes(payload, &mut image)
        .map_err(|error| KernelError::Lzfse(error.to_string()))?;
    check_size("image", image.len(), KERNEL_CACHE_IMAGE_SIZE)?;
    export_fileset_entry(&image, FAIR_PLAY_KEXT_IDENTIFIER)
}

/// Exports one fileset entry, resolving its undefined symbols against the
/// external definitions of every entry in the collection.
///
/// # Errors
/// Fails when the collection is not a fileset or the entry cannot be exported.
pub fn export_fileset_entry(collection: &[u8], identifier: &str) -> Result<Vec<u8>, KernelError> {
    let fileset = Fileset::parse(collection)?;
    let memory = CollectionMemory {
        data: collection,
        segments: &fileset.segments,
    };
    let definitions = fileset.external_definitions(&memory)?;
    let member = fileset
        .member(identifier, &memory)?
        .ok_or(KernelError::Collection(
            "fileset does not contain the requested entry",
        ))?;
    let resolved = resolve_imports(&member.symbols, &definitions);
    Ok(export::export_in_cache_image(member, &memory, &resolved)?)
}

fn check_size(what: &'static str, actual: usize, expected: usize) -> Result<(), KernelError> {
    if actual == expected {
        Ok(())
    } else {
        Err(KernelError::Size {
            what,
            actual,
            expected,
        })
    }
}

fn resolve_imports(symbols: &[Symbol], definitions: &HashMap<Vec<u8>, Symbol>) -> Vec<Symbol> {
    symbols
        .iter()
        .filter(|symbol| symbol.is_undefined() && !symbol.name.is_empty())
        .filter_map(|symbol| {
            definitions.get(&symbol.name).map(|target| Symbol {
                name: symbol.name.clone(),
                kind: N_ABS_EXTERNAL,
                section: 0,
                description: symbol.description,
                value: target.value,
            })
        })
        .collect()
}

struct FilesetEntry {
    identifier: Vec<u8>,
    file_offset: u64,
}

struct CollectionSegment {
    address: u64,
    memory_size: u64,
    file_offset: u64,
}

struct Fileset {
    entries: Vec<FilesetEntry>,
    segments: Vec<CollectionSegment>,
}

impl Fileset {
    fn parse(collection: &[u8]) -> Result<Self, KernelError> {
        let (header, commands) = header_and_commands(collection, 0)?;
        let parsed = MachImage::parse(header, commands, &[])?;
        if parsed.header.file_type != MH_FILESET {
            return Err(KernelError::Collection("not a fileset"));
        }
        let segments = parsed
            .segments()
            .map(|segment| CollectionSegment {
                address: segment.address,
                memory_size: segment.memory_size,
                file_offset: segment.file_offset,
            })
            .collect();
        let entries = fileset_entries(&parsed)?;
        Ok(Self { entries, segments })
    }

    fn external_definitions(
        &self,
        memory: &CollectionMemory<'_>,
    ) -> Result<HashMap<Vec<u8>, Symbol>, KernelError> {
        let mut definitions = HashMap::new();
        for entry in &self.entries {
            let Ok(Some(member)) = self.member_bytes(&entry.identifier, memory) else {
                continue;
            };
            if member.symtab().is_none() {
                continue;
            }
            for symbol in member.symbols {
                if symbol.is_external() && !symbol.is_undefined() && symbol.value != 0 {
                    definitions.insert(symbol.name.clone(), symbol);
                    if definitions.len() > MAXIMUM_KERNEL_CACHE_SYMBOLS {
                        return Err(KernelError::TooManySymbols);
                    }
                }
            }
        }
        Ok(definitions)
    }

    fn member(
        &self,
        identifier: &str,
        memory: &CollectionMemory<'_>,
    ) -> Result<Option<MachImage>, KernelError> {
        self.member_bytes(identifier.as_bytes(), memory)
    }

    /// go-macho `GetFileSetFileByName`: case-insensitive equality or suffix.
    fn member_bytes(
        &self,
        identifier: &[u8],
        memory: &CollectionMemory<'_>,
    ) -> Result<Option<MachImage>, KernelError> {
        let wanted = identifier.to_ascii_lowercase();
        let Some(entry) = self.entries.iter().find(|entry| {
            let candidate = entry.identifier.to_ascii_lowercase();
            candidate == wanted || candidate.ends_with(&wanted)
        }) else {
            return Ok(None);
        };
        let (header, commands) = header_and_commands(memory.data, entry.file_offset)?;
        let mut image = MachImage::parse(header, commands, &[])?;
        if let Some(symtab) = image.symtab() {
            image.symbols = export::read_symbols(&symtab, memory)?;
        }
        if let Some(dysymtab) = image.dysymtab() {
            if image.symtab().is_none() {
                return Err(KernelError::Collection(
                    "dynamic symbol table seen before any symbol table",
                ));
            }
            image.indirect_symbols =
                export::read_indirect_symbols(&dysymtab, image.symbols.len(), memory)?;
        }
        Ok(Some(image))
    }
}

fn fileset_entries(collection: &MachImage) -> Result<Vec<FilesetEntry>, KernelError> {
    collection
        .loads
        .iter()
        .filter_map(|load| match load {
            export::LoadCommand::Raw(raw) if le_u32(raw, 0) == Some(LC_FILESET_ENTRY) => Some(raw),
            _ => None,
        })
        .map(|raw| {
            let invalid = KernelError::Collection("invalid fileset entry");
            let file_offset = le_u64(raw, FILESET_FILE_OFFSET_FIELD)
                .ok_or(KernelError::Collection("invalid fileset entry"))?;
            let name_offset = le_u32(raw, FILESET_ENTRY_ID_FIELD)
                .ok_or(KernelError::Collection("invalid fileset entry"))?;
            let name = raw
                .get(name_offset as usize..)
                .filter(|name| !name.is_empty())
                .ok_or(invalid)?;
            Ok(FilesetEntry {
                identifier: cstring(name).to_vec(),
                file_offset,
            })
        })
        .collect()
}

fn header_and_commands(data: &[u8], offset: u64) -> Result<(&[u8], &[u8]), KernelError> {
    let image = usize::try_from(offset)
        .ok()
        .and_then(|start| data.get(start..))
        .ok_or_else(truncated_mach_o)?;
    let header = image
        .get(..export::MACH_HEADER_64_SIZE)
        .ok_or_else(truncated_mach_o)?;
    let size = MachHeader::parse(header)?.commands_size as usize;
    let commands = image[export::MACH_HEADER_64_SIZE..]
        .get(..size)
        .ok_or_else(truncated_mach_o)?;
    Ok((header, commands))
}

fn truncated_mach_o() -> KernelError {
    KernelError::Collection("truncated Mach-O")
}

struct CollectionMemory<'a> {
    data: &'a [u8],
    segments: &'a [CollectionSegment],
}

impl CollectionMemory<'_> {
    fn copy(&self, buf: &mut [u8], offset: u64) -> Result<(), ExportError> {
        let source = usize::try_from(offset)
            .ok()
            .and_then(|start| self.data.get(start..)?.get(..buf.len()))
            .ok_or(ExportError::Format(
                "read past the end of the kernel collection",
            ))?;
        buf.copy_from_slice(source);
        Ok(())
    }
}

impl ImageMemory for CollectionMemory<'_> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), ExportError> {
        self.copy(buf, offset)
    }

    fn read_at_addr(&self, buf: &mut [u8], address: u64) -> Result<(), ExportError> {
        let segment = self
            .segments
            .iter()
            .find(|segment| {
                segment.address <= address && address - segment.address < segment.memory_size
            })
            .ok_or(ExportError::Format(
                "address is not within any collection segment",
            ))?;
        self.copy(buf, address - segment.address + segment.file_offset)
    }
}

/// Returns the payload OCTET STRING of an IM4P `krnl` container.
///
/// # Errors
/// Fails when the DER structure or its identifiers do not match.
pub fn im4p_payload(data: &[u8]) -> Result<&[u8], KernelError> {
    let (container, rest) = der_element(data)?;
    if !rest.is_empty() || container.tag != DER_TAG_SEQUENCE || !container.constructed {
        return Err(KernelError::Im4p("invalid IM4P container"));
    }
    let mut contents = container.contents;
    let mut fields = Vec::with_capacity(IM4P_FIELD_COUNT);
    while !contents.is_empty() && fields.len() < IM4P_FIELD_COUNT {
        let (field, rest) = der_element(contents)?;
        fields.push(field);
        contents = rest;
    }
    match fields.as_slice() {
        [magic, kind, _, payload]
            if magic.is_ia5(b"IM4P")
                && kind.is_ia5(b"krnl")
                && payload.tag == DER_TAG_OCTET_STRING =>
        {
            Ok(payload.contents)
        }
        _ => Err(KernelError::Im4p("unexpected IM4P fields")),
    }
}

struct DerElement<'a> {
    tag: u8,
    constructed: bool,
    contents: &'a [u8],
}

impl DerElement<'_> {
    fn is_ia5(&self, expected: &[u8]) -> bool {
        self.tag == DER_TAG_IA5_STRING && self.contents == expected
    }
}

fn der_element(data: &[u8]) -> Result<(DerElement<'_>, &[u8]), KernelError> {
    let truncated = KernelError::Im4p("truncated DER element");
    let (&identifier, rest) = data
        .split_first()
        .ok_or(KernelError::Im4p("truncated DER element"))?;
    if identifier & DER_TAG_NUMBER_MASK == DER_TAG_NUMBER_MASK {
        return Err(KernelError::Im4p("unsupported DER tag"));
    }
    let (length, rest) = der_length(rest)?;
    if rest.len() < length {
        return Err(truncated);
    }
    let (contents, rest) = rest.split_at(length);
    let element = DerElement {
        tag: identifier & DER_TAG_NUMBER_MASK,
        constructed: identifier & DER_CONSTRUCTED != 0,
        contents,
    };
    Ok((element, rest))
}

fn der_length(data: &[u8]) -> Result<(usize, &[u8]), KernelError> {
    let (&first, rest) = data
        .split_first()
        .ok_or(KernelError::Im4p("truncated DER length"))?;
    if first & DER_LONG_LENGTH == 0 {
        return Ok((usize::from(first), rest));
    }
    let count = usize::from(first & DER_LENGTH_COUNT_MASK);
    if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count || rest[0] == 0 {
        return Err(KernelError::Im4p("invalid DER length"));
    }
    let length = rest[..count]
        .iter()
        .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
    if length < usize::from(DER_LONG_LENGTH) {
        return Err(KernelError::Im4p("non-minimal DER length"));
    }
    Ok((length, &rest[count..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der_header(tag: u8, length: usize) -> Vec<u8> {
        let mut out = vec![tag];
        if length < usize::from(DER_LONG_LENGTH) {
            out.push(u8::try_from(length).expect("short length"));
        } else {
            let bytes = length.to_be_bytes();
            let first = bytes.iter().position(|&byte| byte != 0).expect("non-zero");
            out.push(DER_LONG_LENGTH | u8::try_from(bytes.len() - first).expect("count"));
            out.extend_from_slice(&bytes[first..]);
        }
        out
    }

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        [der_header(tag, contents.len()), contents.to_vec()].concat()
    }

    /// Everything of an IM4P container except its payload bytes.
    fn im4p_prefix(kind: &[u8], description: &[u8], payload_length: usize) -> Vec<u8> {
        let mut fields = der(DER_TAG_IA5_STRING, b"IM4P");
        fields.extend(der(DER_TAG_IA5_STRING, kind));
        fields.extend(der(DER_TAG_IA5_STRING, description));
        fields.extend(der_header(DER_TAG_OCTET_STRING, payload_length));
        let total = fields.len() + payload_length;
        [
            der_header(DER_TAG_SEQUENCE | DER_CONSTRUCTED, total),
            fields,
        ]
        .concat()
    }

    fn im4p(kind: &[u8], payload: &[u8]) -> Vec<u8> {
        [im4p_prefix(kind, b"desc", payload.len()), payload.to_vec()].concat()
    }

    #[test]
    fn im4p_payload_returns_octet_string() {
        let payload = vec![0xab; 300];
        let container = im4p(b"krnl", &payload);
        assert_eq!(
            im4p_payload(&container).expect("payload"),
            payload.as_slice()
        );
    }

    #[test]
    fn im4p_payload_rejects_other_kinds_and_trailing_bytes() {
        assert!(im4p_payload(&im4p(b"rkrn", b"x")).is_err());
        let mut container = im4p(b"krnl", b"x");
        container.push(0);
        assert!(im4p_payload(&container).is_err());
    }

    #[test]
    fn der_length_rejects_non_minimal_encodings() {
        assert!(der_length(&[0x81, 0x10]).is_err());
        assert!(der_length(&[0x82, 0x00, 0x90]).is_err());
        assert_eq!(
            der_length(&[0x81, 0x90]).map(|(length, _)| length).ok(),
            Some(0x90)
        );
    }

    #[test]
    fn resolve_imports_marks_matches_absolute_external() {
        let undefined = Symbol {
            name: b"_f".to_vec(),
            kind: 0x01,
            section: 0,
            description: 7,
            value: 0,
        };
        let defined = Symbol {
            name: b"_f".to_vec(),
            kind: 0x0f,
            section: 1,
            description: 0,
            value: 0x1234,
        };
        let definitions = HashMap::from([(b"_f".to_vec(), defined)]);
        let resolved = resolve_imports(&[undefined], &definitions);
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            (resolved[0].kind, resolved[0].description, resolved[0].value),
            (N_ABS_EXTERNAL, 7, 0x1234)
        );
    }

    const COLLECTION_BASE: u64 = 0x1_0000_0000;
    const COLLECTION_SEGMENT_SIZE: usize = 0x4000;
    const KERNEL_OFFSET: usize = 0x1000;
    const KEXT_OFFSET: usize = 0x2000;
    const EMPTY_OFFSET: u64 = 0x3800;
    const KEXT_TEXT_SIZE: usize = 0x1000;
    const KEXT_LINKEDIT_SIZE: usize = 0x200;
    const SYMBOLS_AT: usize = 0x200;
    const STRINGS_AT: usize = 0x300;
    const INDIRECT_AT: usize = 0x1c0;
    const KERNEL_FUNCTION: u64 = 0xabc0;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const CPU_SUBTYPE_ARM64E: u32 = 2;
    const MH_EXECUTE: u32 = 2;
    const MH_KEXT_BUNDLE: u32 = 0xb;
    const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;
    const SEGMENT_COMMAND_SIZE: u32 = 72;
    const SYMTAB_COMMAND_SIZE: u32 = 24;
    const DYSYMTAB_COMMAND_SIZE: u32 = 80;
    const FILESET_ENTRY_HEADER: usize = 32;
    const N_SECT_EXTERNAL: u8 = 0x0f;
    const N_SECT_LOCAL: u8 = 0x0e;
    const N_UNDEFINED_EXTERNAL: u8 = 0x01;

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn u32_of(value: usize) -> u32 {
        u32::try_from(value).expect("fits in u32")
    }

    fn segment(name: &str, address: u64, offset: usize, size: usize) -> Vec<u8> {
        let mut out = words(&[export::LC_SEGMENT_64, SEGMENT_COMMAND_SIZE]);
        let mut field = [0u8; 16];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend_from_slice(&field);
        for value in [address, size as u64, offset as u64, size as u64] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.extend(words(&[7, 7, 0, 0]));
        out
    }

    fn symtab(symbols: usize, count: usize, strings: usize, size: usize) -> Vec<u8> {
        words(&[
            export::LC_SYMTAB,
            SYMTAB_COMMAND_SIZE,
            u32_of(symbols),
            u32_of(count),
            u32_of(strings),
            u32_of(size),
        ])
    }

    fn dysymtab(undefined: [u32; 2], indirect: [usize; 2]) -> Vec<u8> {
        let mut fields = [0u32; 20];
        fields[..2].copy_from_slice(&[export::LC_DYSYMTAB, DYSYMTAB_COMMAND_SIZE]);
        fields[6..8].copy_from_slice(&undefined);
        fields[14..16].copy_from_slice(&[u32_of(indirect[0]), u32_of(indirect[1])]);
        words(&fields)
    }

    fn fileset_entry(offset: u64, name: &str) -> Vec<u8> {
        let size = (FILESET_ENTRY_HEADER + name.len() + 1).next_multiple_of(8);
        let mut out = words(&[LC_FILESET_ENTRY, u32_of(size)]);
        out.extend_from_slice(&COLLECTION_BASE.wrapping_add(offset).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend(words(&[u32_of(FILESET_ENTRY_HEADER), 0]));
        out.extend_from_slice(name.as_bytes());
        out.resize(size, 0);
        out
    }

    fn mach_header(file_type: u32, flags: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let size: usize = commands.iter().map(Vec::len).sum();
        let mut out = words(&[
            export::MH_MAGIC_64,
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64E,
            file_type,
            u32_of(commands.len()),
            u32_of(size),
            flags,
            0,
        ]);
        for command in commands {
            out.extend_from_slice(command);
        }
        out
    }

    fn symbol_table(symbols: &[(&str, u8, u64)]) -> (Vec<u8>, Vec<u8>) {
        let mut nlists = Vec::new();
        let mut strings = vec![0u8];
        for (name, kind, value) in symbols {
            nlists.extend_from_slice(&u32_of(strings.len()).to_le_bytes());
            nlists.extend_from_slice(&[*kind, 0, 0, 0]);
            nlists.extend_from_slice(&value.to_le_bytes());
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        (nlists, strings)
    }

    fn place(image: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
        if image.len() < offset + bytes.len() {
            image.resize(offset + bytes.len(), 0);
        }
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// One fileset member: its identifier, Mach-O header and commands, and
    /// the tables its commands point at.
    struct Member {
        identifier: &'static str,
        offset: u64,
        file_type: u32,
        flags: u32,
        commands: Vec<Vec<u8>>,
        tables: Vec<(usize, Vec<u8>)>,
    }

    fn kernel_member() -> Member {
        let (nlists, strings) = symbol_table(&[
            ("_kernel_function", N_SECT_EXTERNAL, KERNEL_FUNCTION),
            ("_kernel_local", N_SECT_LOCAL, 0x10),
            ("_kernel_import", N_UNDEFINED_EXTERNAL, 0),
            ("_kernel_zero", N_SECT_EXTERNAL, 0),
        ]);
        let (symbols, names) = (KERNEL_OFFSET + SYMBOLS_AT, KERNEL_OFFSET + STRINGS_AT);
        Member {
            identifier: "com.apple.kernel",
            offset: KERNEL_OFFSET as u64,
            file_type: MH_EXECUTE,
            flags: 0,
            commands: vec![
                symtab(symbols, 4, names, strings.len()),
                dysymtab([2, 1], [0, 0]),
            ],
            tables: vec![(symbols, nlists), (names, strings)],
        }
    }

    fn kext_member() -> Member {
        let linkedit = KEXT_OFFSET + KEXT_TEXT_SIZE;
        let text_address = COLLECTION_BASE + KEXT_OFFSET as u64;
        let (nlists, strings) = symbol_table(&[
            ("_fp_local", N_SECT_LOCAL, text_address + 0x100),
            ("_kernel_function", N_UNDEFINED_EXTERNAL, 0),
            ("_missing_import", N_UNDEFINED_EXTERNAL, 0),
        ]);
        let (names, indirect) = (linkedit + 0x100, linkedit + INDIRECT_AT);
        Member {
            identifier: FAIR_PLAY_KEXT_IDENTIFIER,
            offset: KEXT_OFFSET as u64,
            file_type: MH_KEXT_BUNDLE,
            flags: MH_DYLIB_IN_CACHE,
            commands: vec![
                segment("__TEXT", text_address, KEXT_OFFSET, KEXT_TEXT_SIZE),
                segment(
                    "__LINKEDIT",
                    text_address + KEXT_TEXT_SIZE as u64,
                    linkedit,
                    KEXT_LINKEDIT_SIZE,
                ),
                symtab(linkedit, 3, names, strings.len()),
                dysymtab([1, 2], [indirect, 1]),
            ],
            tables: vec![
                (linkedit, nlists),
                (names, strings),
                (indirect, words(&[1])),
            ],
        }
    }

    fn empty_member(identifier: &'static str, offset: u64) -> Member {
        Member {
            identifier,
            offset,
            file_type: MH_EXECUTE,
            flags: 0,
            commands: Vec::new(),
            tables: Vec::new(),
        }
    }

    fn default_members() -> Vec<Member> {
        vec![
            empty_member("com.apple.unreadable", u64::MAX),
            empty_member("com.apple.empty", EMPTY_OFFSET),
            kernel_member(),
            kext_member(),
        ]
    }

    fn collection_of(file_type: u32, members: &[Member]) -> Vec<u8> {
        let mut commands = vec![segment("__KC", COLLECTION_BASE, 0, COLLECTION_SEGMENT_SIZE)];
        commands.extend(
            members
                .iter()
                .map(|member| fileset_entry(member.offset, member.identifier)),
        );
        let mut image = mach_header(file_type, 0, &commands);
        image.resize(COLLECTION_SEGMENT_SIZE, 0);
        for member in members.iter().filter(|member| member.offset != u64::MAX) {
            let offset = usize::try_from(member.offset).expect("member offset");
            let header = mach_header(member.file_type, member.flags, &member.commands);
            place(&mut image, offset, &header);
            for (at, table) in &member.tables {
                place(&mut image, *at, table);
            }
        }
        image
    }

    fn collection() -> Vec<u8> {
        collection_of(MH_FILESET, &default_members())
    }

    fn export_error(collection: &[u8], identifier: &str) -> String {
        match export_fileset_entry(collection, identifier) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("exporting {identifier} unexpectedly succeeded"),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn exports_kext_with_imports_resolved_against_other_entries() {
        let exported = export_fileset_entry(&collection(), "FAIRPLAYIOKIT").expect("export");
        let header = MachHeader::parse(&exported).expect("header");
        assert_eq!(header.file_type, MH_KEXT_BUNDLE);
        assert!(!header.in_cache());
        let resolved = [
            &[N_ABS_EXTERNAL, 0, 0, 0][..],
            &KERNEL_FUNCTION.to_le_bytes(),
        ]
        .concat();
        assert!(contains(&exported, &resolved));
        assert!(contains(&exported, b"_kernel_function\0"));
        assert!(contains(&exported, b"_missing_import\0"));
    }

    #[test]
    fn rejects_collections_that_are_not_filesets_or_lack_the_entry() {
        let executable = collection_of(MH_EXECUTE, &default_members());
        assert!(export_error(&executable, FAIR_PLAY_KEXT_IDENTIFIER).contains("not a fileset"));
        assert!(export_error(&collection(), "com.apple.absent").contains("does not contain"));
        assert!(export_error(&collection(), "com.apple.unreadable").contains("truncated Mach-O"));
        assert!(export_error(&[0; 8], FAIR_PLAY_KEXT_IDENTIFIER).contains("truncated Mach-O"));
    }

    #[test]
    fn rejects_truncated_member_commands_and_tables() {
        let mut truncated = collection();
        let commands_size = KEXT_OFFSET + 20;
        truncated[commands_size..commands_size + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(export_error(&truncated, FAIR_PLAY_KEXT_IDENTIFIER).contains("truncated Mach-O"));
        let mut kext = kext_member();
        kext.commands[2] = symtab(0x10_0000, 3, 0, 0);
        let unreadable = collection_of(MH_FILESET, &[kernel_member(), kext]);
        assert!(export_error(&unreadable, FAIR_PLAY_KEXT_IDENTIFIER).contains("read past the end"));
    }

    #[test]
    fn rejects_dynamic_symbol_table_without_symbol_table() {
        let mut kext = kext_member();
        kext.commands.remove(2);
        let image = collection_of(MH_FILESET, &[kernel_member(), kext]);
        assert!(
            export_error(&image, FAIR_PLAY_KEXT_IDENTIFIER)
                .contains("dynamic symbol table seen before any symbol table")
        );
    }

    #[test]
    fn rejects_kext_segments_outside_the_collection() {
        let mut kext = kext_member();
        kext.commands[0] = segment("__TEXT", 0x10, KEXT_OFFSET, KEXT_TEXT_SIZE);
        let image = collection_of(MH_FILESET, &[kernel_member(), kext]);
        assert!(
            export_error(&image, FAIR_PLAY_KEXT_IDENTIFIER)
                .contains("not within any collection segment")
        );
    }

    #[test]
    fn rejects_malformed_fileset_entries() {
        let valid = fileset_entry(KEXT_OFFSET as u64, FAIR_PLAY_KEXT_IDENTIFIER);
        let mut beyond = valid.clone();
        beyond[24..28].copy_from_slice(&u32_of(valid.len()).to_le_bytes());
        for mut entry in [valid[..16].to_vec(), valid[..24].to_vec(), beyond] {
            let length = u32_of(entry.len());
            entry[4..8].copy_from_slice(&length.to_le_bytes());
            let image = mach_header(MH_FILESET, 0, &[entry]);
            assert!(
                export_error(&image, FAIR_PLAY_KEXT_IDENTIFIER).contains("invalid fileset entry")
            );
        }
    }

    #[test]
    fn rejects_symbol_tables_over_the_limit() {
        let count = MAXIMUM_KERNEL_CACHE_SYMBOLS + 1;
        let names: Vec<String> = (0..count).map(|index| format!("_s{index}")).collect();
        let symbols: Vec<(&str, u8, u64)> = names
            .iter()
            .map(|name| (name.as_str(), N_SECT_EXTERNAL, KERNEL_FUNCTION))
            .collect();
        let (nlists, strings) = symbol_table(&symbols);
        let at_symbols = COLLECTION_SEGMENT_SIZE;
        let at_strings = at_symbols + nlists.len();
        let mut kernel = kernel_member();
        kernel.commands = vec![symtab(at_symbols, count, at_strings, strings.len())];
        let mut image = collection_of(MH_FILESET, &[kernel, kext_member()]);
        place(&mut image, at_symbols, &nlists);
        place(&mut image, at_strings, &strings);
        assert!(matches!(
            export_fileset_entry(&image, FAIR_PLAY_KEXT_IDENTIFIER),
            Err(KernelError::TooManySymbols)
        ));
    }

    #[test]
    fn der_parser_rejects_malformed_elements() {
        let malformed: [&[u8]; 6] = [
            &[],
            &[0x1f, 0x00],
            &[DER_TAG_OCTET_STRING, 0x05, 0x01],
            &[DER_TAG_OCTET_STRING],
            &[DER_TAG_OCTET_STRING, 0x80],
            &[DER_TAG_OCTET_STRING, 0x82, 0x01],
        ];
        for data in malformed {
            assert!(matches!(der_element(data), Err(KernelError::Im4p(_))));
        }
        assert!(im4p_payload(&der(DER_TAG_OCTET_STRING, b"x")).is_err());
    }

    const LZFSE_RAW_BLOCK: &[u8; 4] = b"bvx-";
    const LZFSE_LZVN_BLOCK: &[u8; 4] = b"bvxn";
    const LZFSE_END_OF_STREAM: &[u8; 4] = b"bvx$";
    const LZFSE_RAW_HEADER: usize = 8;
    const LZFSE_LZVN_HEADER: usize = 12;
    const LZVN_BUDGET: usize = 1_000_000;
    const LZVN_SEED: [u8; 4] = [0xe1, 0x00, 0x38, 0x01];
    const LZVN_SEED_OUTPUT: usize = 11;
    const LZVN_LARGE_MATCH: u8 = 0xf0;
    const LZVN_MAX_MATCH: usize = 271;
    const LZVN_LARGE_MATCH_BIAS: usize = 16;
    const LZVN_NOP: u8 = 0x0e;
    const LZVN_TRAILER: [u8; 8] = [0x06, 0, 0, 0, 0, 0, 0, 0];

    /// LZVN opcodes producing `count` zero bytes, NOP-padded to `size`.
    fn zero_lzvn(count: usize, size: usize) -> Vec<u8> {
        let mut ops = LZVN_SEED.to_vec();
        let mut remaining = count - LZVN_SEED_OUTPUT;
        while remaining >= LZVN_LARGE_MATCH_BIAS {
            let chunk = remaining.min(LZVN_MAX_MATCH);
            let operand = u8::try_from(chunk - LZVN_LARGE_MATCH_BIAS).expect("operand");
            ops.extend_from_slice(&[LZVN_LARGE_MATCH, operand]);
            remaining -= chunk;
        }
        if remaining > 0 {
            ops.push(LZVN_LARGE_MATCH | u8::try_from(remaining).expect("nibble"));
        }
        assert!(
            ops.len() + LZVN_TRAILER.len() <= size,
            "LZVN budget is too small"
        );
        ops.resize(size - LZVN_TRAILER.len(), LZVN_NOP);
        ops.extend_from_slice(&LZVN_TRAILER);
        ops
    }

    /// An LZFSE stream of exactly `payload_size` bytes that decodes to
    /// `prefix` followed by zeros up to `image_size` bytes.
    fn lzfse_image(prefix: &[u8], image_size: usize, payload_size: usize) -> Vec<u8> {
        let headers = LZFSE_RAW_HEADER + LZFSE_LZVN_HEADER + LZFSE_END_OF_STREAM.len();
        let raw_size = payload_size - headers - LZVN_BUDGET;
        let mut out = LZFSE_RAW_BLOCK.to_vec();
        out.extend_from_slice(&u32_of(raw_size).to_le_bytes());
        out.extend_from_slice(prefix);
        out.resize(LZFSE_RAW_HEADER + raw_size, 0);
        out.extend_from_slice(LZFSE_LZVN_BLOCK);
        out.extend(words(&[u32_of(image_size - raw_size), u32_of(LZVN_BUDGET)]));
        out.extend(zero_lzvn(image_size - raw_size, LZVN_BUDGET));
        out.extend_from_slice(LZFSE_END_OF_STREAM);
        out
    }

    /// A pinned-size IM4P archive around `payload`, padding the description
    /// so the whole archive has the pinned length.
    fn pinned_archive(payload: &[u8]) -> Vec<u8> {
        let overhead = KERNEL_CACHE_ARCHIVE_BYTES - payload.len();
        let prefix = (0..overhead)
            .map(|length| im4p_prefix(b"krnl", &vec![b'd'; length], payload.len()))
            .find(|prefix| prefix.len() == overhead)
            .expect("description length");
        [prefix, payload.to_vec()].concat()
    }

    #[test]
    fn extracts_kext_from_pinned_size_compressed_collection() {
        let payload = lzfse_image(
            &collection(),
            KERNEL_CACHE_IMAGE_SIZE,
            KERNEL_CACHE_PAYLOAD_SIZE,
        );
        assert_eq!(payload.len(), KERNEL_CACHE_PAYLOAD_SIZE);
        let exported = extract_fair_play_kext(&pinned_archive(&payload)).expect("extract");
        let expected =
            export_fileset_entry(&collection(), FAIR_PLAY_KEXT_IDENTIFIER).expect("export");
        assert_eq!(exported, expected);
    }

    fn size_error(archive: &[u8]) -> &'static str {
        match extract_fair_play_kext(archive) {
            Err(KernelError::Size { what, .. }) => what,
            other => panic!("expected a size error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_kernel_caches_with_unpinned_sizes() {
        assert_eq!(size_error(&[0; 16]), "collection");
        let short_payload = vec![0; KERNEL_CACHE_PAYLOAD_SIZE - 1];
        assert_eq!(size_error(&pinned_archive(&short_payload)), "payload");
        let raw_size = KERNEL_CACHE_PAYLOAD_SIZE - LZFSE_RAW_HEADER - LZFSE_END_OF_STREAM.len();
        let mut raw = LZFSE_RAW_BLOCK.to_vec();
        raw.extend_from_slice(&u32_of(raw_size).to_le_bytes());
        raw.resize(LZFSE_RAW_HEADER + raw_size, 0);
        raw.extend_from_slice(LZFSE_END_OF_STREAM);
        assert_eq!(size_error(&pinned_archive(&raw)), "image");
    }

    #[test]
    fn rejects_kernel_caches_with_corrupt_containers() {
        let garbage = vec![0x5a; KERNEL_CACHE_PAYLOAD_SIZE];
        assert!(matches!(
            extract_fair_play_kext(&pinned_archive(&garbage)),
            Err(KernelError::Lzfse(_))
        ));
        assert!(matches!(
            extract_fair_play_kext(&vec![0; KERNEL_CACHE_ARCHIVE_BYTES]),
            Err(KernelError::Im4p(_))
        ));
    }
}

#[cfg(test)]
mod golden_tests {
    use sha2::{Digest, Sha256};

    use super::*;

    const FAIR_PLAY_KEXT_SHA256: &str =
        "47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025";

    #[test]
    #[ignore = "needs kernelcache.im4p in IPAKEEP_APPLE_SAP_FIXTURES"]
    fn exports_fair_play_kext_byte_identical_to_ipatool() {
        let directory = std::env::var_os("IPAKEEP_APPLE_SAP_FIXTURES").map_or_else(
            || {
                dirs::cache_dir()
                    .unwrap_or_default()
                    .join("ipakeep")
                    .join("apple_sap_fixtures")
            },
            std::path::PathBuf::from,
        );
        let kernel_cache =
            std::fs::read(directory.join("kernelcache.im4p")).expect("read kernel fixture");
        let exported = extract_fair_play_kext(&kernel_cache).expect("export FairPlayIOKit");

        assert_eq!(exported.len(), 2_132_320);
        assert_eq!(
            hex::encode(Sha256::digest(&exported)),
            FAIR_PLAY_KEXT_SHA256
        );
    }
}
