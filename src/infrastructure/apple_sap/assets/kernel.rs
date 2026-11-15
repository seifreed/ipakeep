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
        let offset = usize::try_from(entry.file_offset)
            .map_err(|_| KernelError::Collection("entry offset overflows"))?;
        let (header, commands) = header_and_commands(memory.data, offset)?;
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

fn header_and_commands(data: &[u8], offset: usize) -> Result<(&[u8], &[u8]), KernelError> {
    let truncated = KernelError::Collection("truncated Mach-O");
    let header_end = offset
        .checked_add(export::MACH_HEADER_64_SIZE)
        .ok_or(KernelError::Collection("truncated Mach-O"))?;
    let header = data
        .get(offset..header_end)
        .ok_or(KernelError::Collection("truncated Mach-O"))?;
    let size = MachHeader::parse(header)?.commands_size as usize;
    let commands = data.get(header_end..header_end + size).ok_or(truncated)?;
    Ok((header, commands))
}

struct CollectionMemory<'a> {
    data: &'a [u8],
    segments: &'a [CollectionSegment],
}

impl CollectionMemory<'_> {
    fn copy(&self, buf: &mut [u8], offset: u64) -> Result<(), ExportError> {
        let start = usize::try_from(offset).map_err(|_| ExportError::Format("offset overflows"))?;
        let source = start
            .checked_add(buf.len())
            .and_then(|end| self.data.get(start..end))
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

    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() < 0x80 {
            out.push(u8::try_from(contents.len()).expect("short length"));
        } else {
            let length = u16::try_from(contents.len()).expect("two-byte length");
            out.push(0x82);
            out.extend_from_slice(&length.to_be_bytes());
        }
        out.extend_from_slice(contents);
        out
    }

    fn im4p(kind: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut fields = der(DER_TAG_IA5_STRING, b"IM4P");
        fields.extend(der(DER_TAG_IA5_STRING, kind));
        fields.extend(der(DER_TAG_IA5_STRING, b"desc"));
        fields.extend(der(DER_TAG_OCTET_STRING, payload));
        der(DER_TAG_SEQUENCE | DER_CONSTRUCTED, &fields)
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
