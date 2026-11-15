//! Versioned on-disk cache of immutable image preparations.
//!
//! An entry holds what is independent of the guest: instruction patches,
//! decoded fixups and the symbol table. Entries are keyed by the SHA-256 of
//! the thin image and carry a trailing SHA-256 so corrupt files are ignored.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::pac::InstructionPatch;
use super::relocation::Relocation;
use super::symbols::Symbol;

const MAGIC: &[u8; 8] = b"IPKMACHO";
/// Bump whenever the encoding or the preparation semantics change.
const FORMAT_VERSION: u32 = 1;
const DIGEST_SIZE: usize = 32;
const TAG_REBASE: u8 = 0;
const TAG_BIND: u8 = 1;
const CACHE_SUBDIRECTORY: &str = "ipakeep/sap/macho";
const ENTRY_EXTENSION: &str = "prep";

/// The cacheable result of preparing an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Preparation {
    pub(crate) has_symtab: bool,
    pub(crate) symbols: Vec<Symbol>,
    pub(crate) patches: Vec<InstructionPatch>,
    pub(crate) relocations: Vec<Relocation>,
}

/// Directory of cached preparations, one file per image digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationCache {
    directory: PathBuf,
}

impl PreparationCache {
    /// Uses `directory` for cache entries (created on first store).
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// `<user cache dir>/ipakeep/sap/macho`, when the platform has one.
    pub fn default_location() -> Option<Self> {
        dirs::cache_dir().map(|root| Self::new(root.join(CACHE_SUBDIRECTORY)))
    }

    /// Cache directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn entry_path(&self, key: &[u8; DIGEST_SIZE]) -> PathBuf {
        self.directory.join(format!(
            "v{FORMAT_VERSION}-{}.{ENTRY_EXTENSION}",
            hex::encode(key)
        ))
    }

    /// Returns the cached preparation for `key`, ignoring missing or corrupt entries.
    pub(crate) fn load(&self, key: &[u8; DIGEST_SIZE]) -> Option<Preparation> {
        let bytes = fs::read(self.entry_path(key)).ok()?;
        let decoded = decode(&bytes, key);
        if decoded.is_none() {
            tracing::debug!(path = %self.entry_path(key).display(), "ignoring corrupt Mach-O preparation cache entry");
        }
        decoded
    }

    /// Stores `preparation` atomically; failures only disable caching.
    pub(crate) fn store(&self, key: &[u8; DIGEST_SIZE], preparation: &Preparation) {
        if let Err(error) = self.try_store(key, preparation) {
            tracing::debug!(%error, "cannot write Mach-O preparation cache entry");
        }
    }

    fn try_store(&self, key: &[u8; DIGEST_SIZE], preparation: &Preparation) -> io::Result<()> {
        fs::create_dir_all(&self.directory)?;
        let path = self.entry_path(key);
        let temporary =
            path.with_extension(format!("{ENTRY_EXTENSION}.{}.tmp", std::process::id()));
        fs::write(&temporary, encode(key, preparation))?;
        fs::rename(&temporary, &path).inspect_err(|_| {
            let _ = fs::remove_file(&temporary);
        })
    }
}

struct Encoder(Vec<u8>);

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn len(&mut self, value: usize) {
        self.u64(value as u64);
    }
    fn string(&mut self, value: &str) {
        self.len(value.len());
        self.0.extend_from_slice(value.as_bytes());
    }
}

fn encode(key: &[u8; DIGEST_SIZE], preparation: &Preparation) -> Vec<u8> {
    let mut out = Encoder(Vec::new());
    out.0.extend_from_slice(MAGIC);
    out.u32(FORMAT_VERSION);
    out.0.extend_from_slice(key);
    out.u8(u8::from(preparation.has_symtab));
    out.len(preparation.symbols.len());
    for symbol in &preparation.symbols {
        encode_symbol(&mut out, symbol);
    }
    out.len(preparation.patches.len());
    for patch in &preparation.patches {
        out.u64(patch.offset);
        out.u32(patch.value);
    }
    out.len(preparation.relocations.len());
    for relocation in &preparation.relocations {
        encode_relocation(&mut out, relocation);
    }
    let digest: [u8; DIGEST_SIZE] = Sha256::digest(&out.0).into();
    out.0.extend_from_slice(&digest);
    out.0
}

fn encode_symbol(out: &mut Encoder, symbol: &Symbol) {
    out.string(&symbol.name);
    out.string(&symbol.indirect_name);
    out.u8(symbol.kind);
    out.u8(symbol.section);
    out.u16(symbol.description);
    out.u64(symbol.value);
}

fn encode_relocation(out: &mut Encoder, relocation: &Relocation) {
    match relocation {
        Relocation::Rebase { offset, target } => {
            out.u8(TAG_REBASE);
            out.u64(*offset);
            out.u64(*target);
        }
        Relocation::Bind {
            offset,
            symbol,
            addend,
        } => {
            out.u8(TAG_BIND);
            out.u64(*offset);
            out.u64(addend.cast_unsigned());
            out.string(symbol);
        }
    }
}

struct Decoder<'a> {
    data: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if count > self.data.len() {
            return None;
        }
        let (head, tail) = self.data.split_at(count);
        self.data = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    /// A count bounded by the remaining input, so corrupt files cannot force huge allocations.
    fn len(&mut self) -> Option<usize> {
        usize::try_from(self.u64()?)
            .ok()
            .filter(|&count| count <= self.data.len())
    }
    fn string(&mut self) -> Option<String> {
        let length = self.len()?;
        String::from_utf8(self.take(length)?.to_vec()).ok()
    }
}

fn decode(bytes: &[u8], key: &[u8; DIGEST_SIZE]) -> Option<Preparation> {
    let body_length = bytes.len().checked_sub(DIGEST_SIZE)?;
    let (body, digest) = bytes.split_at(body_length);
    if Sha256::digest(body).as_slice() != digest {
        return None;
    }
    let mut input = Decoder { data: body };
    (input.take(MAGIC.len())? == MAGIC).then_some(())?;
    (input.u32()? == FORMAT_VERSION).then_some(())?;
    (input.take(DIGEST_SIZE)? == key).then_some(())?;
    let has_symtab = input.u8()? != 0;
    let symbols = (0..input.len()?)
        .map(|_| decode_symbol(&mut input))
        .collect::<Option<_>>()?;
    let patches = (0..input.len()?)
        .map(|_| {
            Some(InstructionPatch {
                offset: input.u64()?,
                value: input.u32()?,
            })
        })
        .collect::<Option<_>>()?;
    let relocations = (0..input.len()?)
        .map(|_| decode_relocation(&mut input))
        .collect::<Option<_>>()?;
    input.data.is_empty().then_some(Preparation {
        has_symtab,
        symbols,
        patches,
        relocations,
    })
}

fn decode_symbol(input: &mut Decoder<'_>) -> Option<Symbol> {
    Some(Symbol {
        name: input.string()?,
        indirect_name: input.string()?,
        kind: input.u8()?,
        section: input.u8()?,
        description: input.u16()?,
        value: input.u64()?,
    })
}

fn decode_relocation(input: &mut Decoder<'_>) -> Option<Relocation> {
    match input.u8()? {
        TAG_REBASE => Some(Relocation::Rebase {
            offset: input.u64()?,
            target: input.u64()?,
        }),
        TAG_BIND => Some(Relocation::Bind {
            offset: input.u64()?,
            addend: input.u64()?.cast_signed(),
            symbol: input.string()?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Preparation {
        Preparation {
            has_symtab: true,
            symbols: vec![Symbol {
                name: "_main".to_owned(),
                indirect_name: String::new(),
                kind: 0x0f,
                section: 1,
                description: 0,
                value: 0x1_0000_4000,
            }],
            patches: vec![InstructionPatch {
                offset: 0x40,
                value: 0xd503_201f,
            }],
            relocations: vec![
                Relocation::Rebase {
                    offset: 0x100,
                    target: 0x40,
                },
                Relocation::Bind {
                    offset: 0x108,
                    symbol: "_free".to_owned(),
                    addend: -8,
                },
            ],
        }
    }

    #[test]
    fn encoding_round_trips() {
        let key = [7u8; DIGEST_SIZE];
        assert_eq!(decode(&encode(&key, &sample()), &key), Some(sample()));
    }

    #[test]
    fn rejects_wrong_key_and_corruption() {
        let key = [7u8; DIGEST_SIZE];
        let mut bytes = encode(&key, &sample());
        assert_eq!(decode(&bytes, &[8u8; DIGEST_SIZE]), None);
        bytes[20] ^= 1;
        assert_eq!(decode(&bytes, &key), None);
    }

    #[test]
    fn store_then_load_from_directory() {
        let directory =
            std::env::temp_dir().join(format!("ipakeep-macho-cache-{}", std::process::id()));
        let cache = PreparationCache::new(&directory);
        let key = [9u8; DIGEST_SIZE];
        assert_eq!(cache.load(&key), None);
        cache.store(&key, &sample());
        assert_eq!(cache.load(&key), Some(sample()));
        let _ = fs::remove_dir_all(&directory);
    }
}
