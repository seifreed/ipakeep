//! Ported from ipatool `internal/sap/assets/dyld_symbols.go`.
//!
//! Restores an image's `LC_SYMTAB`/`LC_DYSYMTAB` without loading the
//! cache-wide string table: only this image's nlists and the strings they
//! reference are read.

use super::dyld::export::{
    self, LoadCommand, MachImage, Nlist, Symbol, SymtabCommand, go_symbol_name, le_u32,
    parse_dysymtab_command, parse_symtab,
};
use super::dyld::{CachedImage, DyldCache, DyldError, to_usize, valid_range};

const MAXIMUM_SYMBOLS: u32 = 4 << 20;
const MAXIMUM_INDIRECT_SYMBOLS: u32 = 4 << 20;
const NLIST_SIZE: u64 = 16;
const INDIRECT_ENTRY_SIZE: u64 = 4;
const NLIST_ENTRY_BYTES: usize = 16;
const INDIRECT_ENTRY_BYTES: usize = 4;
const LOAD_COMMAND_HEADER_SIZE: usize = 8;

/// Inserts the image's symbol tables into `macho`, which was parsed with
/// `LC_SYMTAB` and `LC_DYSYMTAB` excluded (ipatool `dyldCache.imageSymbols`).
///
/// # Errors
/// Fails when the tables are malformed or the load command order changed.
pub fn restore_image_symbols(
    cache: &DyldCache<'_>,
    image: &CachedImage,
    linkedit_member: usize,
    macho: &mut MachImage,
) -> Result<(), DyldError> {
    let (_, commands) = cache.image_commands(image)?;
    cache.linkedit_address(image)?;
    let reader = SymbolReader {
        cache,
        member: linkedit_member,
    };
    let mut existing = std::mem::take(&mut macho.loads).into_iter();
    let mut loads = Vec::new();
    let mut offset = 0;
    while offset < commands.len() {
        let raw = next_command(&commands, offset)?;
        offset += raw.len();
        match le_u32(raw, 0) {
            Some(export::LC_SYMTAB) => {
                let (symtab, symbols) = reader.symbols(raw)?;
                macho.symbols = symbols;
                loads.push(LoadCommand::Symtab(symtab));
            }
            Some(export::LC_DYSYMTAB) => {
                let symbol_count = loads
                    .iter()
                    .any(|load| matches!(load, LoadCommand::Symtab(_)))
                    .then_some(macho.symbols.len());
                let (dysymtab, indirect) = reader.dynamic_symbols(raw, symbol_count)?;
                macho.indirect_symbols = indirect;
                loads.push(LoadCommand::Dysymtab(dysymtab));
            }
            command => loads.push(matching_load(existing.next(), command)?),
        }
    }
    macho.loads = loads;
    Ok(())
}

fn next_command(commands: &[u8], offset: usize) -> Result<&[u8], DyldError> {
    if commands.len() - offset < LOAD_COMMAND_HEADER_SIZE {
        return Err(DyldError::Format("truncated image command"));
    }
    let length =
        le_u32(commands, offset + 4).ok_or(DyldError::Format("truncated image command"))? as usize;
    if length < LOAD_COMMAND_HEADER_SIZE || length > commands.len() - offset {
        return Err(DyldError::Format("invalid image command size"));
    }
    Ok(&commands[offset..offset + length])
}

fn matching_load(
    load: Option<LoadCommand>,
    command: Option<u32>,
) -> Result<LoadCommand, DyldError> {
    match load {
        Some(load) if Some(load.command()) == command => Ok(load),
        _ => Err(DyldError::Format("image load command order changed")),
    }
}

struct SymbolReader<'a> {
    cache: &'a DyldCache<'a>,
    member: usize,
}

impl SymbolReader<'_> {
    fn symbols(&self, raw: &[u8]) -> Result<(SymtabCommand, Vec<Symbol>), DyldError> {
        let symtab = parse_symtab(raw)?;
        let size = self.cache.member_size(self.member);
        let table_size = u64::from(symtab.symbol_count) * NLIST_SIZE;
        if symtab.symbol_count > MAXIMUM_SYMBOLS
            || !valid_range(size, u64::from(symtab.symbol_offset), table_size)
            || !valid_range(
                size,
                u64::from(symtab.string_offset),
                u64::from(symtab.string_size),
            )
        {
            return Err(DyldError::Format("invalid image symbol table"));
        }
        let mut encoded = vec![0; to_usize(table_size)?];
        self.cache
            .read_member(self.member, &mut encoded, u64::from(symtab.symbol_offset))?;
        let symbols = encoded
            .as_chunks::<NLIST_ENTRY_BYTES>()
            .0
            .iter()
            .map(|entry| self.symbol(&symtab, entry))
            .collect::<Result<_, _>>()?;
        Ok((symtab, symbols))
    }

    fn symbol(&self, symtab: &SymtabCommand, entry: &[u8]) -> Result<Symbol, DyldError> {
        let nlist = Nlist::parse(entry)?;
        let name = self.name(symtab, u64::from(nlist.string_index))?;
        let symbol = nlist.into_symbol(name);
        if symbol.is_indirect() {
            self.name(symtab, symbol.value)?;
        }
        Ok(symbol)
    }

    fn name(&self, symtab: &SymtabCommand, offset: u64) -> Result<Vec<u8>, DyldError> {
        if offset >= u64::from(symtab.string_size) {
            return Ok(Vec::new());
        }
        let start = u64::from(symtab.string_offset);
        let name = self.cache.read_cstring(
            self.member,
            start + u64::from(symtab.string_size),
            start + offset,
        )?;
        Ok(go_symbol_name(&name))
    }

    fn dynamic_symbols(
        &self,
        raw: &[u8],
        symbol_count: Option<usize>,
    ) -> Result<(export::DysymtabCommand, Vec<u32>), DyldError> {
        let dysymtab = parse_dysymtab_command(raw)?;
        let undefined_end =
            u64::from(dysymtab.undefined_index()) + u64::from(dysymtab.undefined_count());
        if symbol_count.is_none_or(|count| undefined_end > count as u64)
            || dysymtab.indirect_count() > MAXIMUM_INDIRECT_SYMBOLS
        {
            return Err(DyldError::Format("invalid dynamic symbol table"));
        }
        let size = u64::from(dysymtab.indirect_count()) * INDIRECT_ENTRY_SIZE;
        if !valid_range(
            self.cache.member_size(self.member),
            u64::from(dysymtab.indirect_offset()),
            size,
        ) {
            return Err(DyldError::Format("indirect symbols exceed cache member"));
        }
        let mut encoded = vec![0; to_usize(size)?];
        self.cache.read_member(
            self.member,
            &mut encoded,
            u64::from(dysymtab.indirect_offset()),
        )?;
        let indirect = encoded
            .as_chunks::<INDIRECT_ENTRY_BYTES>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        Ok((dysymtab, indirect))
    }
}

#[cfg(test)]
mod tests {
    use super::super::dyld::export::fixtures::{
        dysymtab_command, dysymtab_fields, symtab_command, u32_of,
    };
    use super::super::dyld::fixtures::{
        CacheFixture, IMAGE_PATH, INDIRECT_ENTRIES, LINKEDIT_MEMBER, STRING_SIZE, STRINGS,
        SUBCACHE_SIZE, SYMBOL_COUNT, SYMBOLS, image_commands, replace_command,
    };
    use super::*;

    const INDIRECT_TABLE: u32 = 0x1200;

    fn restore(commands: &[Vec<u8>]) -> Result<MachImage, DyldError> {
        let fixture = CacheFixture::with_commands(commands);
        let cache = fixture.open().expect("open cache");
        let image = cache.image(IMAGE_PATH).expect("image");
        let (header, raw) = cache.image_commands(&image).expect("image commands");
        let mut macho = MachImage::parse(&header, &raw, &[export::LC_SYMTAB, export::LC_DYSYMTAB])
            .expect("parse image");
        restore_image_symbols(&cache, &image, LINKEDIT_MEMBER, &mut macho).map(|()| macho)
    }

    fn with_command(command: u32, replacement: Option<&[u8]>) -> Vec<Vec<u8>> {
        replace_command(image_commands(), command, replacement)
    }

    fn assert_format(result: Result<MachImage, DyldError>, expected: &str) {
        match result {
            Err(DyldError::Format(message)) => assert_eq!(message, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }

    #[test]
    fn restores_symbol_tables_in_load_command_order() {
        let macho = restore(&image_commands()).expect("restore symbols");
        let commands: Vec<u32> = macho.loads.iter().map(LoadCommand::command).collect();
        let expected: Vec<u32> = image_commands()
            .iter()
            .filter_map(|raw| le_u32(raw, 0))
            .collect();
        assert_eq!(commands, expected);
        let names: Vec<&[u8]> = macho.symbols.iter().map(|s| s.name.as_slice()).collect();
        assert_eq!(
            names,
            [
                b"_local".as_slice(),
                b"_exported",
                b"_indirect",
                b"_undef",
                b""
            ]
        );
        assert!(macho.symbols[2].is_indirect());
        assert_eq!(macho.indirect_symbols, INDIRECT_ENTRIES);
        let symtab = macho.symtab().expect("symtab");
        assert_eq!(
            (
                symtab.symbol_offset,
                symtab.symbol_count,
                symtab.string_offset
            ),
            (SYMBOLS, SYMBOL_COUNT, STRINGS)
        );
    }

    #[test]
    fn rejects_invalid_symbol_tables() {
        let beyond = u32_of(SUBCACHE_SIZE);
        for symtab in [
            symtab_command(SYMBOLS, MAXIMUM_SYMBOLS + 1, STRINGS, STRING_SIZE),
            symtab_command(beyond, SYMBOL_COUNT, STRINGS, STRING_SIZE),
            symtab_command(SYMBOLS, SYMBOL_COUNT, beyond, STRING_SIZE),
        ] {
            assert_format(
                restore(&with_command(export::LC_SYMTAB, Some(&symtab))),
                "invalid image symbol table",
            );
        }
    }

    #[test]
    fn rejects_invalid_dynamic_symbol_tables() {
        const INVALID: &str = "invalid dynamic symbol table";
        assert_format(restore(&with_command(export::LC_SYMTAB, None)), INVALID);
        for fields in [
            dysymtab_fields([2, 2, 2], INDIRECT_TABLE, 2),
            dysymtab_fields([2, 2, 1], INDIRECT_TABLE, MAXIMUM_INDIRECT_SYMBOLS + 1),
        ] {
            let dysymtab = dysymtab_command(fields);
            assert_format(
                restore(&with_command(export::LC_DYSYMTAB, Some(&dysymtab))),
                INVALID,
            );
        }
        let outside = dysymtab_command(dysymtab_fields([2, 2, 1], u32_of(SUBCACHE_SIZE), 2));
        assert_format(
            restore(&with_command(export::LC_DYSYMTAB, Some(&outside))),
            "indirect symbols exceed cache member",
        );
    }

    #[test]
    fn rejects_load_commands_missing_from_the_parsed_image() {
        let fixture = CacheFixture::new();
        let cache = fixture.open().expect("open cache");
        let image = cache.image(IMAGE_PATH).expect("image");
        let (header, raw) = cache.image_commands(&image).expect("image commands");
        let mut macho = MachImage::parse(&header, &raw, &[]).expect("parse image");
        macho.loads.clear();
        assert!(matches!(
            restore_image_symbols(&cache, &image, LINKEDIT_MEMBER, &mut macho),
            Err(DyldError::Format("image load command order changed"))
        ));
    }

    #[test]
    fn next_command_rejects_short_and_oversized_commands() {
        assert!(next_command(&[0; 4], 0).is_err());
        let mut commands = vec![0u8; 16];
        commands[4..8].copy_from_slice(&4u32.to_le_bytes());
        assert!(next_command(&commands, 0).is_err());
        commands[4..8].copy_from_slice(&32u32.to_le_bytes());
        assert!(next_command(&commands, 0).is_err());
        commands[4..8].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(next_command(&commands, 0).map(<[u8]>::len).ok(), Some(16));
    }

    #[test]
    fn matching_load_requires_same_command() {
        let raw = LoadCommand::Raw(vec![0x1b, 0, 0, 0, 24, 0, 0, 0]);
        assert!(matching_load(Some(raw.clone()), Some(0x1b)).is_ok());
        assert!(matching_load(Some(raw), Some(0x2a)).is_err());
        assert!(matching_load(None, Some(0x2a)).is_err());
    }
}
