//! `LC_DYLD_CHAINED_FIXUPS` decoding.

use super::dyld_info::FixupContext;
use super::error::{MachoError, MachoResult};
use super::layout::{cstring, le32, le64, le64_at};
use super::relocation::Relocation;

/// `dyld_chained_ptr_*` pointer formats.
pub(crate) mod format {
    /// Unauthenticated targets are absolute VM addresses.
    pub(crate) const ARM64E: u16 = 1;
    /// Generic 64-bit, target is a VM address.
    pub(crate) const PTR_64: u16 = 2;
    /// Generic 64-bit, target is an image-relative offset.
    pub(crate) const PTR_64_OFFSET: u16 = 6;
    /// arm64e kernel, 4-byte stride.
    pub(crate) const ARM64E_KERNEL: u16 = 7;
    /// 64-bit kernel cache.
    pub(crate) const PTR_64_KERNEL_CACHE: u16 = 8;
    /// arm64e userland, targets are image offsets.
    pub(crate) const ARM64E_USERLAND: u16 = 9;
    /// arm64e firmware, 4-byte stride.
    pub(crate) const ARM64E_FIRMWARE: u16 = 10;
    /// `x86_64` kernel cache, 1-byte stride.
    pub(crate) const X86_64_KERNEL_CACHE: u16 = 11;
    /// arm64e userland with 24-bit bind ordinals.
    pub(crate) const ARM64E_USERLAND24: u16 = 12;
}

const START_NONE: u16 = 0xffff;
const START_MULTI: u16 = 0x8000;
const START_LAST: u16 = 0x8000;
const HEADER_FIELDS: usize = 7;
const STARTS_IN_SEGMENT_FIXED_SIZE: usize = 22;
const IMPORT_FORMAT_PLAIN: u32 = 1;
const IMPORT_FORMAT_ADDEND: u32 = 2;
const IMPORT_FORMAT_ADDEND64: u32 = 3;
const ARM64E_BIND_BIT: u32 = 62;
const ARM64E_AUTH_BIT: u32 = 63;
const GENERIC64_BIND_BIT: u32 = 63;
const NEXT_SHIFT: u32 = 51;
const ARM64E_NEXT_BITS: u32 = 11;
const GENERIC64_NEXT_BITS: u32 = 12;
const ARM64E_TARGET_BITS: u32 = 43;
const ARM64E_AUTH_TARGET_BITS: u32 = 32;
const GENERIC64_TARGET_BITS: u32 = 36;
const KERNEL_CACHE_TARGET_BITS: u32 = 30;
const HIGH8_SHIFT_ARM64E: u32 = 43;
const HIGH8_SHIFT_GENERIC64: u32 = 36;
const HIGH8_BITS: u32 = 8;
const HIGH8_DESTINATION: u32 = 56;
const ARM64E_ABSOLUTE_MASK: u64 = 0x00ff_ffff_ffff_ffff;
const ORDINAL16_BITS: u32 = 16;
const ORDINAL24_BITS: u32 = 24;
const ADDEND19_SHIFT: u32 = 32;
const ADDEND19_BITS: u32 = 19;
const ADDEND19_SIGN: u64 = 0x4_0000;
const ADDEND19_EXTENSION: u64 = 0xffff_ffff_fffc_0000;
const GENERIC64_ADDEND_SHIFT: u32 = 24;
const GENERIC64_ADDEND_BITS: u32 = 8;
const IMPORT_NAME_SHIFT: u32 = 9;
const IMPORT_NAME_BITS: u32 = 23;
const IMPORT64_NAME_SHIFT: u32 = 32;

pub(crate) fn bits(value: u64, shift: u32, width: u32) -> u64 {
    (value >> shift) & ((1u64 << width) - 1)
}

fn stride(pointer_format: u16) -> Option<u64> {
    match pointer_format {
        format::ARM64E | format::ARM64E_USERLAND | format::ARM64E_USERLAND24 => Some(8),
        format::ARM64E_KERNEL
        | format::ARM64E_FIRMWARE
        | format::PTR_64
        | format::PTR_64_OFFSET
        | format::PTR_64_KERNEL_CACHE => Some(4),
        format::X86_64_KERNEL_CACHE => Some(1),
        _ => None,
    }
}

fn is_arm64e(pointer_format: u16) -> bool {
    matches!(
        pointer_format,
        format::ARM64E
            | format::ARM64E_KERNEL
            | format::ARM64E_USERLAND
            | format::ARM64E_FIRMWARE
            | format::ARM64E_USERLAND24
    )
}

/// One `dyld_chained_import*` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainedImport {
    pub(crate) name: String,
    pub(crate) addend: i64,
}

#[derive(Debug, Clone, Default)]
struct SegmentStarts {
    page_size: u16,
    pointer_format: u16,
    segment_offset: u64,
    page_starts: Vec<u16>,
}

/// Parsed chained-fixup metadata: per-segment chain starts and imports.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChainedFixups {
    starts: Vec<Option<SegmentStarts>>,
    imports: Vec<ChainedImport>,
    /// Pointer format of the first described segment (go-macho's `PointerFormat`).
    pointer_format: u16,
}

impl ChainedFixups {
    /// Parses the `LC_DYLD_CHAINED_FIXUPS` payload.
    pub(crate) fn parse(context: &FixupContext<'_>, payload: &[u8]) -> MachoResult<Self> {
        let truncated = || MachoError::malformed(context.image, "truncated chained fixups");
        let header: Vec<u32> = (0..HEADER_FIELDS)
            .map(|index| le32(payload, index * 4))
            .collect::<Option<_>>()
            .ok_or_else(truncated)?;
        let (starts_offset, imports_offset, symbols_offset) = (header[1], header[2], header[3]);
        let (imports_count, imports_format) = (header[4], header[5]);
        let mut fixups =
            Self::parse_starts(payload, starts_offset as usize).ok_or_else(truncated)?;
        for (index, start) in fixups.starts.iter_mut().enumerate() {
            if let (Some(start), Some(segment)) = (start.as_mut(), context.segments.get(index)) {
                start.segment_offset = segment.file_offset;
            }
        }
        fixups.imports = parse_imports(
            payload,
            imports_offset,
            symbols_offset,
            imports_count,
            imports_format,
        )
        .ok_or_else(truncated)?;
        Ok(fixups)
    }

    fn parse_starts(payload: &[u8], at: usize) -> Option<Self> {
        let count = le32(payload, at)? as usize;
        let mut fixups = Self::default();
        for index in 0..count {
            let info = le32(payload, at + 4 + index * 4)? as usize;
            if info == 0 {
                fixups.starts.push(None);
                continue;
            }
            let start = parse_segment_starts(payload, at.checked_add(info)?)?;
            if fixups.pointer_format == 0 {
                fixups.pointer_format = start.pointer_format;
            }
            fixups.starts.push(Some(start));
        }
        Some(fixups)
    }

    /// Walks every chain and decodes each fixup, in segment/page/chain order.
    pub(crate) fn relocations(&self, context: &FixupContext<'_>) -> MachoResult<Vec<Relocation>> {
        let mut output = Vec::new();
        for start in self.starts.iter().flatten() {
            for page in 0..start.page_starts.len() {
                self.walk_page(context, start, page, &mut output)?;
            }
        }
        Ok(output)
    }

    fn walk_page(
        &self,
        context: &FixupContext<'_>,
        start: &SegmentStarts,
        page: usize,
        output: &mut Vec<Relocation>,
    ) -> MachoResult<()> {
        let offset_in_page = start.page_starts[page];
        if offset_in_page == START_NONE {
            return Ok(());
        }
        if offset_in_page & START_MULTI == 0 {
            return self.walk_chain(context, start, page, offset_in_page, output);
        }
        let mut overflow = usize::from(offset_in_page & !START_MULTI);
        loop {
            let entry = *start.page_starts.get(overflow).ok_or_else(|| {
                MachoError::malformed(context.image, "chained start index out of range")
            })?;
            self.walk_chain(context, start, page, entry & !START_LAST, output)?;
            if entry & START_LAST != 0 {
                return Ok(());
            }
            overflow += 1;
        }
    }

    fn walk_chain(
        &self,
        context: &FixupContext<'_>,
        start: &SegmentStarts,
        page: usize,
        offset_in_page: u16,
        output: &mut Vec<Relocation>,
    ) -> MachoResult<()> {
        let pointer_format = start.pointer_format;
        let step = stride(pointer_format).ok_or_else(|| {
            MachoError::unsupported(
                context.image,
                format!("pointer chain format {pointer_format}"),
            )
        })?;
        let page_start = start.segment_offset + page as u64 * u64::from(start.page_size);
        let mut location = page_start + u64::from(offset_in_page);
        loop {
            let raw = read_pointer(context, location)?;
            output.push(self.decode(context, pointer_format, location, raw)?);
            let next = if is_arm64e(pointer_format) {
                bits(raw, NEXT_SHIFT, ARM64E_NEXT_BITS)
            } else {
                bits(raw, NEXT_SHIFT, GENERIC64_NEXT_BITS)
            };
            if next == 0 {
                return Ok(());
            }
            location += next * step;
        }
    }

    fn decode(
        &self,
        context: &FixupContext<'_>,
        pointer_format: u16,
        offset: u64,
        raw: u64,
    ) -> MachoResult<Relocation> {
        if is_arm64e(pointer_format) {
            return self.decode_arm64e(context, pointer_format, offset, raw);
        }
        match pointer_format {
            format::PTR_64 | format::PTR_64_OFFSET if bits(raw, GENERIC64_BIND_BIT, 1) != 0 => {
                let ordinal = bits(raw, 0, ORDINAL24_BITS);
                let addend = bits(raw, GENERIC64_ADDEND_SHIFT, GENERIC64_ADDEND_BITS).cast_signed();
                Ok(self.bind(offset, ordinal, addend))
            }
            format::PTR_64_OFFSET => Ok(Relocation::Rebase {
                offset,
                target: unpack_generic64(raw),
            }),
            format::PTR_64 => Ok(Relocation::Rebase {
                offset,
                target: unpack_generic64(raw).wrapping_sub(context.base),
            }),
            _ => Ok(Relocation::Rebase {
                offset,
                target: bits(raw, 0, KERNEL_CACHE_TARGET_BITS),
            }),
        }
    }

    fn decode_arm64e(
        &self,
        context: &FixupContext<'_>,
        pointer_format: u16,
        offset: u64,
        raw: u64,
    ) -> MachoResult<Relocation> {
        let is_bind = bits(raw, ARM64E_BIND_BIT, 1) != 0;
        let is_auth = bits(raw, ARM64E_AUTH_BIT, 1) != 0;
        if is_bind {
            let wide = pointer_format == format::ARM64E_USERLAND24;
            let ordinal = bits(raw, 0, if wide { ORDINAL24_BITS } else { ORDINAL16_BITS });
            if wide && ordinal >= self.imports.len() as u64 {
                return Err(MachoError::malformed(
                    context.image,
                    format!("chained bind ordinal {ordinal} out of range"),
                ));
            }
            let addend = if is_auth {
                0
            } else {
                sign_extended_addend19(raw)
            };
            return Ok(self.bind(offset, ordinal, addend));
        }
        let target = if is_auth {
            bits(raw, 0, ARM64E_AUTH_TARGET_BITS)
        } else {
            self.arm64e_rebase_target(context, offset, raw)?
        };
        Ok(Relocation::Rebase { offset, target })
    }

    fn arm64e_rebase_target(
        &self,
        context: &FixupContext<'_>,
        offset: u64,
        raw: u64,
    ) -> MachoResult<u64> {
        let target = bits(raw, 0, ARM64E_TARGET_BITS);
        if self.pointer_format != format::ARM64E {
            return Ok(target);
        }
        let high8 = bits(raw, HIGH8_SHIFT_ARM64E, HIGH8_BITS);
        let absolute = ((high8 << HIGH8_DESTINATION) | target) & ARM64E_ABSOLUTE_MASK;
        absolute.checked_sub(context.base).ok_or_else(|| {
            MachoError::malformed(
                context.image,
                format!("chained rebase at {offset:#x} precedes the image base"),
            )
        })
    }

    fn bind(&self, offset: u64, ordinal: u64, pointer_addend: i64) -> Relocation {
        let import = usize::try_from(ordinal)
            .ok()
            .and_then(|index| self.imports.get(index));
        let symbol = import.map(|import| import.name.clone()).unwrap_or_default();
        let addend = pointer_addend.wrapping_add(import.map_or(0, |import| import.addend));
        Relocation::Bind {
            offset,
            symbol,
            addend,
        }
    }
}

fn unpack_generic64(raw: u64) -> u64 {
    let high8 = bits(raw, HIGH8_SHIFT_GENERIC64, HIGH8_BITS);
    (high8 << HIGH8_DESTINATION) | bits(raw, 0, GENERIC64_TARGET_BITS)
}

fn sign_extended_addend19(raw: u64) -> i64 {
    let addend = bits(raw, ADDEND19_SHIFT, ADDEND19_BITS);
    if addend & ADDEND19_SIGN != 0 {
        (addend | ADDEND19_EXTENSION).cast_signed()
    } else {
        addend.cast_signed()
    }
}

fn read_pointer(context: &FixupContext<'_>, location: u64) -> MachoResult<u64> {
    le64_at(context.data, location).ok_or_else(|| {
        MachoError::malformed(
            context.image,
            format!("chained fixup at {location:#x} exceeds image"),
        )
    })
}

fn parse_segment_starts(payload: &[u8], at: usize) -> Option<SegmentStarts> {
    let fixed = payload.get(at..at.checked_add(STARTS_IN_SEGMENT_FIXED_SIZE)?)?;
    let page_count = usize::from(u16::from_le_bytes([fixed[20], fixed[21]]));
    let pages = payload.get(
        at + STARTS_IN_SEGMENT_FIXED_SIZE..at + STARTS_IN_SEGMENT_FIXED_SIZE + page_count * 2,
    )?;
    Some(SegmentStarts {
        page_size: u16::from_le_bytes([fixed[4], fixed[5]]),
        pointer_format: u16::from_le_bytes([fixed[6], fixed[7]]),
        segment_offset: le64(fixed, 8)?,
        page_starts: pages
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect(),
    })
}

/// Returns `(name_offset, addend, entry_size)` for one import record.
fn import_entry(payload: &[u8], at: usize, imports_format: u32) -> Option<(u64, i64, usize)> {
    match imports_format {
        IMPORT_FORMAT_PLAIN => {
            let word = u64::from(le32(payload, at)?);
            Some((bits(word, IMPORT_NAME_SHIFT, IMPORT_NAME_BITS), 0, 4))
        }
        IMPORT_FORMAT_ADDEND => {
            let word = u64::from(le32(payload, at)?);
            let addend = i64::from(le32(payload, at + 4)?.cast_signed());
            Some((bits(word, IMPORT_NAME_SHIFT, IMPORT_NAME_BITS), addend, 8))
        }
        _ => {
            let word = le64(payload, at)?;
            let addend = le64(payload, at + 8)?.cast_signed();
            Some((bits(word, IMPORT64_NAME_SHIFT, 32), addend, 16))
        }
    }
}

fn parse_imports(
    payload: &[u8],
    imports_offset: u32,
    symbols_offset: u32,
    count: u32,
    imports_format: u32,
) -> Option<Vec<ChainedImport>> {
    if !matches!(
        imports_format,
        IMPORT_FORMAT_PLAIN | IMPORT_FORMAT_ADDEND | IMPORT_FORMAT_ADDEND64
    ) {
        return Some(Vec::new());
    }
    let pool = payload.get(symbols_offset as usize..)?;
    let mut at = imports_offset as usize;
    let mut imports = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (name_offset, addend, size) = import_entry(payload, at, imports_format)?;
        let tail = pool.get(usize::try_from(name_offset).ok()?..)?;
        tail.contains(&0).then_some(())?;
        imports.push(ChainedImport {
            name: cstring(tail),
            addend,
        });
        at += size;
    }
    Some(imports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::apple_sap::macho::layout::Segment;

    const BASE: u64 = 0x1_0000_0000;

    fn arm64e_rebase(target: u64, high8: u64, next: u64) -> u64 {
        target | (high8 << HIGH8_SHIFT_ARM64E) | (next << NEXT_SHIFT)
    }

    fn arm64e_bind(ordinal: u64, addend: u64, next: u64, auth: bool) -> u64 {
        ordinal
            | (addend << ADDEND19_SHIFT)
            | (next << NEXT_SHIFT)
            | (1 << ARM64E_BIND_BIT)
            | (u64::from(auth) << ARM64E_AUTH_BIT)
    }

    fn fixups(pointer_format: u16) -> ChainedFixups {
        ChainedFixups {
            starts: vec![Some(SegmentStarts {
                page_size: 0x1000,
                pointer_format,
                segment_offset: 0,
                page_starts: vec![0x10],
            })],
            imports: vec![
                ChainedImport {
                    name: "_malloc".to_owned(),
                    addend: 0,
                },
                ChainedImport {
                    name: "_free".to_owned(),
                    addend: 4,
                },
            ],
            pointer_format,
        }
    }

    fn decode_chain(pointer_format: u16, words: &[u64]) -> MachoResult<Vec<Relocation>> {
        let mut data = vec![0u8; 0x100];
        for (index, word) in words.iter().enumerate() {
            let at = 0x10 + index * 8;
            data[at..at + 8].copy_from_slice(&word.to_le_bytes());
        }
        let segments: Vec<Segment> = Vec::new();
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments,
            base: BASE,
        };
        fixups(pointer_format).relocations(&context)
    }

    #[test]
    fn arm64e_absolute_rebase_subtracts_base() {
        let words = [
            arm64e_rebase(BASE + 0x40, 0xaa, 1),
            arm64e_bind(1, 0x7_ffff, 0, false),
        ];
        let decoded = decode_chain(format::ARM64E, &words).ok();
        assert_eq!(
            decoded,
            Some(vec![
                Relocation::Rebase {
                    offset: 0x10,
                    target: 0x40
                },
                Relocation::Bind {
                    offset: 0x18,
                    symbol: "_free".to_owned(),
                    addend: 3
                },
            ])
        );
    }

    #[test]
    fn userland24_rebase_is_offset_and_auth_bind_has_no_addend() {
        let auth_rebase = (1u64 << ARM64E_AUTH_BIT) | 0x1234 | (0xffff << 32) | (1 << NEXT_SHIFT);
        let words = [
            auth_rebase,
            arm64e_rebase(0x80, 0, 1),
            arm64e_bind(0, 5, 0, true),
        ];
        let decoded = decode_chain(format::ARM64E_USERLAND24, &words).ok();
        assert_eq!(
            decoded,
            Some(vec![
                Relocation::Rebase {
                    offset: 0x10,
                    target: 0x1234
                },
                Relocation::Rebase {
                    offset: 0x18,
                    target: 0x80
                },
                Relocation::Bind {
                    offset: 0x20,
                    symbol: "_malloc".to_owned(),
                    addend: 0
                },
            ])
        );
    }

    #[test]
    fn userland24_rejects_out_of_range_ordinal() {
        let words = [arm64e_bind(9, 0, 0, false)];
        assert!(decode_chain(format::ARM64E_USERLAND24, &words).is_err());
    }

    #[test]
    fn ptr64_offset_keeps_image_relative_target() {
        // DYLD_CHAINED_PTR_64_OFFSET targets are image-relative; the base is not subtracted.
        let raw = 0x2000 | (0x12 << HIGH8_SHIFT_GENERIC64);
        let decoded = decode_chain(format::PTR_64_OFFSET, &[raw]).ok();
        assert_eq!(
            decoded,
            Some(vec![Relocation::Rebase {
                offset: 0x10,
                target: 0x1200_0000_0000_2000
            }])
        );
    }

    #[test]
    fn ptr64_vmaddr_rebase_subtracts_base_and_bind_uses_unsigned_addend() {
        let bind = (1u64 << GENERIC64_BIND_BIT) | 1 | (0xff << GENERIC64_ADDEND_SHIFT);
        let words = [(BASE + 0x30) | (4 << NEXT_SHIFT), 0, bind];
        let decoded = decode_chain(format::PTR_64, &words).ok();
        assert_eq!(
            decoded,
            Some(vec![
                Relocation::Rebase {
                    offset: 0x10,
                    target: 0x30
                },
                Relocation::Bind {
                    offset: 0x20,
                    symbol: "_free".to_owned(),
                    addend: 0xff + 4
                },
            ])
        );
    }

    #[test]
    fn sign_extends_negative_addend() {
        assert_eq!(
            sign_extended_addend19(0x4_0000u64 << ADDEND19_SHIFT),
            -0x4_0000
        );
        assert_eq!(
            sign_extended_addend19(0x3_ffffu64 << ADDEND19_SHIFT),
            0x3_ffff
        );
    }
}
