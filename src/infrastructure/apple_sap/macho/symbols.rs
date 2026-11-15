//! Symbol table and export-trie lookup.

use super::dyld_info::ByteReader;
use super::error::{MachoError, MachoResult};
use super::layout::{SymtabCommand, cstring, le64};

const NLIST_SIZE: usize = 16;
const N_TYPE_MASK: u8 = 0x0e;
const N_INDR: u8 = 0x0a;
const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;
const MAX_TRIE_DEPTH: usize = 128;

/// One `nlist_64` entry of the image's symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name (Go-style `_pkg.name` symbols lose their leading `_`).
    pub name: String,
    /// Name of the aliased symbol for `N_INDR` entries, else empty.
    pub indirect_name: String,
    /// Raw `n_type`.
    pub kind: u8,
    /// Raw `n_sect`.
    pub section: u8,
    /// Raw `n_desc`.
    pub description: u16,
    /// Raw `n_value` (preferred address for defined symbols).
    pub value: u64,
}

fn strip_go_prefix(name: String) -> String {
    if name.contains('.') && name.starts_with('_') {
        name[1..].to_owned()
    } else {
        name
    }
}

fn string_at(strings: &[u8], offset: u64) -> Option<String> {
    let start = usize::try_from(offset).ok()?;
    strings
        .get(start..)
        .map(|tail| strip_go_prefix(cstring(tail)))
}

/// Parses every `nlist_64` entry in table order.
pub(crate) fn parse_symtab(
    image: &str,
    data: &[u8],
    command: SymtabCommand,
) -> MachoResult<Vec<Symbol>> {
    let strings = linkedit(data, command.string_offset, u64::from(command.string_size))
        .ok_or_else(|| MachoError::malformed(image, "string table exceeds image"))?;
    let length = u64::from(command.symbol_count) * NLIST_SIZE as u64;
    let entries = linkedit(data, command.symbol_offset, length)
        .ok_or_else(|| MachoError::malformed(image, "symbol table exceeds image"))?;
    Ok(entries
        .as_chunks::<NLIST_SIZE>()
        .0
        .iter()
        .map(|entry| parse_nlist(entry, strings))
        .collect())
}

fn linkedit(data: &[u8], offset: u32, length: u64) -> Option<&[u8]> {
    let start = offset as usize;
    let end = start.checked_add(usize::try_from(length).ok()?)?;
    data.get(start..end)
}

fn parse_nlist(entry: &[u8], strings: &[u8]) -> Symbol {
    let name_offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
    let kind = entry[4];
    let value = le64(entry, 8).unwrap_or(0);
    let indirect_name = if kind & N_TYPE_MASK == N_INDR {
        string_at(strings, value).unwrap_or_default()
    } else {
        String::new()
    };
    Symbol {
        name: string_at(strings, u64::from(name_offset)).unwrap_or_default(),
        indirect_name,
        kind,
        section: entry[5],
        description: u16::from_le_bytes([entry[6], entry[7]]),
        value,
    }
}

/// Unicode simple case-insensitive comparison, matching Go's `strings.EqualFold`
/// for the identifiers found in Mach-O symbol tables.
pub(crate) fn equal_fold(left: &str, right: &str) -> bool {
    let mut lhs = left.chars();
    let mut rhs = right.chars();
    loop {
        match (lhs.next(), rhs.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b || a.to_lowercase().eq(b.to_lowercase()) => {}
            _ => return false,
        }
    }
}

/// A terminal node of a dyld export trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrieExport {
    pub(crate) name: String,
    pub(crate) address: u64,
}

/// Parses a dyld export trie in depth-first order. Re-exports have address 0.
pub(crate) fn parse_export_trie(trie: &[u8], load_address: u64) -> Option<Vec<TrieExport>> {
    let mut exports = Vec::new();
    walk_trie(trie, 0, &mut Vec::new(), load_address, &mut exports, 0)?;
    Some(exports)
}

fn walk_trie(
    trie: &[u8],
    position: usize,
    prefix: &mut Vec<u8>,
    load_address: u64,
    exports: &mut Vec<TrieExport>,
    depth: usize,
) -> Option<()> {
    if depth > MAX_TRIE_DEPTH {
        return None;
    }
    let mut reader = ByteReader::at(trie, position);
    let terminal_size = reader.uleb()?;
    if terminal_size != 0 {
        exports.push(read_terminal(&mut reader, prefix, load_address)?);
    }
    let mut reader = ByteReader::at(
        trie,
        position.checked_add(usize::try_from(terminal_size).ok()? + 1)?,
    );
    let children = reader.byte()?;
    for _ in 0..children {
        let edge = reader.bytes_until_nul();
        let child = usize::try_from(reader.uleb()?).ok()?;
        let saved = prefix.len();
        prefix.extend_from_slice(&edge);
        walk_trie(trie, child, prefix, load_address, exports, depth + 1)?;
        prefix.truncate(saved);
    }
    Some(())
}

fn read_terminal(
    reader: &mut ByteReader<'_>,
    name: &[u8],
    load_address: u64,
) -> Option<TrieExport> {
    let flags = reader.uleb()?;
    let name = String::from_utf8_lossy(name).into_owned();
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        return Some(TrieExport { name, address: 0 });
    }
    let offset = reader.uleb()?;
    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        reader.uleb()?;
    }
    Some(TrieExport {
        name,
        address: load_address.wrapping_add(offset),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_fold_matches_go_semantics() {
        assert!(equal_fold("_X46O5IeS", "_x46o5ies"));
        assert!(!equal_fold("_abc", "_abcd"));
        assert!(!equal_fold("_abc", "_abd"));
    }

    #[test]
    fn go_symbols_lose_underscore() {
        assert_eq!(strip_go_prefix("_main.init".to_owned()), "main.init");
        assert_eq!(strip_go_prefix("_malloc".to_owned()), "_malloc");
    }

    #[test]
    fn parses_nlist_entries() {
        let strings = b"\0_alpha\0_beta\0";
        let mut entry = Vec::new();
        entry.extend_from_slice(&1u32.to_le_bytes());
        entry.extend_from_slice(&[0x0f, 1, 0, 0]);
        entry.extend_from_slice(&0x1234u64.to_le_bytes());
        let symbol = parse_nlist(&entry, strings);
        assert_eq!(symbol.name, "_alpha");
        assert_eq!(symbol.value, 0x1234);
        assert_eq!(symbol.section, 1);
    }

    #[test]
    fn parses_export_trie() {
        // root: no terminal, one child "_f" -> node at 6; node: terminal (flags 0, offset 0x10).
        let trie = [0, 1, b'_', b'f', 0, 6, 2, 0, 0x10, 0];
        let exports = parse_export_trie(&trie, 0x1000);
        assert_eq!(
            exports,
            Some(vec![TrieExport {
                name: "_f".to_owned(),
                address: 0x1010
            }])
        );
    }
}
