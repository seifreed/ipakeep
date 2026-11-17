//! go-macho's `LC_DYLD_EXPORTS_TRIE` walker, including its quirks: a
//! re-export entry's address is read as one more ULEB128 after the imported
//! name.

use super::ExportError;

const KIND_MASK: u64 = 0x03;
const KIND_REGULAR: u64 = 0x00;
const KIND_THREAD_LOCAL: u64 = 0x01;
const FLAG_REEXPORT: u64 = 0x08;
const FLAG_STUB_AND_RESOLVER: u64 = 0x10;
const ULEB_PAYLOAD_MASK: u8 = 0x7f;
const ULEB_CONTINUE: u8 = 0x80;
const ULEB_SHIFT_STEP: u32 = 7;
const MAXIMUM_TRIE_DEPTH: usize = 4096;

/// One terminal of the export trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieExport {
    /// Exported symbol name.
    pub name: Vec<u8>,
    /// Imported name for re-exports.
    pub re_export: Vec<u8>,
    /// Raw export flags.
    pub flags: u64,
    /// Resolved address (see go-macho `ReadExport`).
    pub address: u64,
}

impl TrieExport {
    /// go-macho adds `!Regular() || ReExport()` exports to the symbol table.
    pub fn is_listed_in_symtab(&self) -> bool {
        self.flags & KIND_MASK != KIND_REGULAR || self.flags == FLAG_REEXPORT
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, ExportError> {
        let byte = *self
            .data
            .get(self.position)
            .ok_or(ExportError::Format("export trie is truncated"))?;
        self.position += 1;
        Ok(byte)
    }

    fn uleb(&mut self) -> Result<u64, ExportError> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            result |= u64::from(byte & ULEB_PAYLOAD_MASK)
                .checked_shl(shift)
                .unwrap_or(0);
            if byte & ULEB_CONTINUE == 0 {
                return Ok(result);
            }
            shift = shift.saturating_add(ULEB_SHIFT_STEP);
        }
    }

    fn string(&mut self) -> Vec<u8> {
        let mut value = Vec::new();
        while let Some(&byte) = self.data.get(self.position) {
            self.position += 1;
            if byte == 0 {
                break;
            }
            value.push(byte);
        }
        value
    }
}

struct Terminal {
    offset: usize,
    name: Vec<u8>,
}

/// Parses every export in trie order (go-macho `ParseTrieExports`).
///
/// # Errors
/// Fails on a truncated or excessively deep trie.
pub fn parse_exports(data: &[u8], load_address: u64) -> Result<Vec<TrieExport>, ExportError> {
    let mut terminals = Vec::new();
    collect(data, 0, &mut Vec::new(), &mut terminals, 0)?;
    terminals
        .into_iter()
        .map(|terminal| read_export(data, terminal, load_address))
        .collect()
}

fn collect(
    data: &[u8],
    position: u64,
    prefix: &mut Vec<u8>,
    terminals: &mut Vec<Terminal>,
    depth: usize,
) -> Result<(), ExportError> {
    if depth > MAXIMUM_TRIE_DEPTH {
        return Err(ExportError::Format("export trie is too deep"));
    }
    let start = trie_offset(position)?;
    let mut cursor = Cursor {
        data,
        position: start,
    };
    let terminal_size = cursor.uleb()?;
    if terminal_size != 0 {
        terminals.push(Terminal {
            offset: cursor.position,
            name: prefix.clone(),
        });
    }
    cursor.position = trie_offset(position.wrapping_add(terminal_size).wrapping_add(1))?;
    let children = cursor.byte()?;
    for _ in 0..children {
        let edge = cursor.string();
        let child = cursor.uleb()?;
        let length = prefix.len();
        prefix.extend_from_slice(&edge);
        collect(data, child, prefix, terminals, depth + 1)?;
        prefix.truncate(length);
    }
    Ok(())
}

/// Convert a trie offset to an index; fails only where `usize` is narrower than 64 bits.
fn trie_offset(value: u64) -> Result<usize, ExportError> {
    usize::try_from(value).map_err(|_| ExportError::Format("export trie offset overflows"))
}

fn read_export(
    data: &[u8],
    terminal: Terminal,
    load_address: u64,
) -> Result<TrieExport, ExportError> {
    let mut cursor = Cursor {
        data,
        position: terminal.offset,
    };
    let flags = cursor.uleb()?;
    let mut re_export = Vec::new();
    if flags == FLAG_REEXPORT {
        cursor.uleb()?;
        re_export = cursor.string();
    } else if flags == FLAG_STUB_AND_RESOLVER {
        cursor.uleb()?;
    }
    let mut address = cursor.uleb()?;
    let kind = flags & KIND_MASK;
    if (kind == KIND_REGULAR || kind == KIND_THREAD_LOCAL) && flags != FLAG_REEXPORT {
        address = address.wrapping_add(load_address);
    }
    Ok(TrieExport {
        name: terminal.name,
        re_export,
        flags,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_regular_and_re_exported_symbols() {
        // root: no terminal, 2 children: "_a" -> node A, "_b" -> node B
        let mut trie = vec![0x00, 0x02];
        trie.extend_from_slice(b"_a\0");
        trie.push(0x0c);
        trie.extend_from_slice(b"_b\0");
        trie.push(0x10);
        trie.extend_from_slice(&[0x00, 0x00]);
        // node A at 12: terminal size 2, flags 0, address 0x10, no children
        trie.extend_from_slice(&[0x02, 0x00, 0x10, 0x00]);
        // node B at 16: re-export, ordinal 1, name "_c", trailing byte read as address
        trie.extend_from_slice(&[0x05, 0x08, 0x01, b'_', b'c', 0x00, 0x00]);
        let exports = parse_exports(&trie, 0x1000).expect("parse trie");
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].address, 0x1010);
        assert!(!exports[0].is_listed_in_symtab());
        assert_eq!(exports[1].re_export, b"_c");
        assert!(exports[1].is_listed_in_symtab());
    }

    #[test]
    fn stub_and_resolver_export_uses_resolver_offset_as_address() {
        // root terminal: size 3, flags stub-and-resolver, stub 4, resolver 8.
        let trie = [0x03, 0x10, 0x04, 0x08, 0x00];
        let exports = parse_exports(&trie, 0x1000).expect("parse trie");
        assert_eq!(
            exports,
            [TrieExport {
                name: Vec::new(),
                re_export: Vec::new(),
                flags: FLAG_STUB_AND_RESOLVER,
                address: 0x1008,
            }]
        );
        assert!(!exports[0].is_listed_in_symtab());
    }

    #[test]
    fn thread_local_export_is_listed_and_relocated() {
        let trie = [0x02, 0x01, 0x10, 0x00];
        let exports = parse_exports(&trie, 0x1000).expect("parse trie");
        assert_eq!(exports[0].address, 0x1010);
        assert!(exports[0].is_listed_in_symtab());
    }

    #[test]
    fn truncated_trie_is_rejected() {
        for trie in [&[][..], &[0x80], &[0x00], &[0x01, 0x80]] {
            assert!(matches!(
                parse_exports(trie, 0),
                Err(ExportError::Format("export trie is truncated"))
            ));
        }
    }

    #[test]
    fn cyclic_trie_hits_the_depth_limit() {
        const DEEP_STACK: usize = 64 << 20;
        // root: no terminal, one child "a" pointing back at the root.
        let result = std::thread::Builder::new()
            .stack_size(DEEP_STACK)
            .spawn(|| parse_exports(&[0x00, 0x01, b'a', 0x00, 0x00], 0))
            .expect("spawn parser")
            .join()
            .expect("parser thread");
        assert!(matches!(
            result,
            Err(ExportError::Format("export trie is too deep"))
        ));
    }

    #[test]
    fn oversized_uleb_drops_high_bits_and_strings_stop_at_end() {
        let mut bytes = vec![0xff; 10];
        bytes.extend_from_slice(&[0x81, 0x01, b'a', b'b']);
        let mut cursor = Cursor {
            data: &bytes,
            position: 0,
        };
        assert_eq!(cursor.uleb().expect("uleb"), u64::MAX);
        assert_eq!(cursor.string(), b"ab");
        assert_eq!(cursor.string(), b"");
    }
}
