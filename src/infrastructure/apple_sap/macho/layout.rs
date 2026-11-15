//! Mach-O header and load-command parsing.

use super::error::{MachoError, MachoResult};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const HEADER_SIZE: usize = 32;
const LOAD_COMMAND_HEADER_SIZE: usize = 8;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const SEGMENT_COMMAND_SIZE: usize = 72;
const SECTION_SIZE: usize = 80;
const NAME_SIZE: usize = 16;
const SECTION_ATTRIBUTES_MASK: u32 = 0xffff_ff00;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const TEXT_SEGMENT: &str = "__TEXT";

/// Reads a little-endian `u32` at `at`, or `None` when out of bounds.
pub(crate) fn le32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian `u64` at `at`, or `None` when out of bounds.
pub(crate) fn le64(data: &[u8], at: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(8)?)?;
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    Some(u64::from_le_bytes(word))
}

/// Reads a little-endian `u64` at a 64-bit file offset.
pub(crate) fn le64_at(data: &[u8], at: u64) -> Option<u64> {
    le64(data, usize::try_from(at).ok()?)
}

/// Reads a NUL-terminated string (or the remainder of `data`).
pub(crate) fn cstring(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// A `LC_SEGMENT_64` as declared by the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Segment name, e.g. `__TEXT`.
    pub name: String,
    /// Preferred virtual address.
    pub address: u64,
    /// Virtual size.
    pub size: u64,
    /// File offset of the segment data within the thin image.
    pub file_offset: u64,
    /// Number of bytes backed by the file.
    pub file_size: u64,
    /// Maximum VM protection (`VM_PROT_*`).
    pub max_protection: u32,
    /// Initial VM protection (`VM_PROT_*`).
    pub initial_protection: u32,
}

/// A section inside a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Section {
    pub(crate) address: u64,
    pub(crate) size: u64,
    pub(crate) offset: u32,
    pub(crate) flags: u32,
    pub(crate) name: String,
}

impl Section {
    pub(crate) fn has_instructions(&self) -> bool {
        let attributes = self.flags & SECTION_ATTRIBUTES_MASK;
        attributes & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }
}

/// `LC_SYMTAB` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SymtabCommand {
    pub(crate) symbol_offset: u32,
    pub(crate) symbol_count: u32,
    pub(crate) string_offset: u32,
    pub(crate) string_size: u32,
}

/// An `(offset, size)` pair addressing `__LINKEDIT` data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LinkeditRange {
    pub(crate) offset: u32,
    pub(crate) size: u32,
}

/// `LC_DYLD_INFO(_ONLY)` opcode streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DyldInfoCommand {
    pub(crate) rebase: LinkeditRange,
    pub(crate) bind: LinkeditRange,
    pub(crate) weak_bind: LinkeditRange,
    pub(crate) lazy_bind: LinkeditRange,
    pub(crate) export: LinkeditRange,
}

/// Parsed load commands relevant to emulation.
#[derive(Debug, Clone, Default)]
pub(crate) struct Layout {
    pub(crate) segments: Vec<Segment>,
    pub(crate) sections: Vec<Section>,
    pub(crate) symtab: Option<SymtabCommand>,
    pub(crate) dyld_info: Option<DyldInfoCommand>,
    pub(crate) dyld_info_only: Option<DyldInfoCommand>,
    pub(crate) chained_fixups: Option<LinkeditRange>,
}

impl Layout {
    /// Parses the header and load commands of a thin 64-bit arm64 image.
    pub(crate) fn parse(image: &str, data: &[u8]) -> MachoResult<Self> {
        if le32(data, 0) != Some(MH_MAGIC_64) || data.len() < HEADER_SIZE {
            return Err(MachoError::NotArm64 {
                image: image.to_owned(),
            });
        }
        if le32(data, 4) != Some(CPU_TYPE_ARM64) {
            return Err(MachoError::NotArm64 {
                image: image.to_owned(),
            });
        }
        let count = le32(data, 16).unwrap_or(0);
        let mut layout = Self::default();
        let mut offset = HEADER_SIZE;
        for _ in 0..count {
            let command = le32(data, offset)
                .ok_or_else(|| MachoError::malformed(image, "truncated load command"))?;
            let size = le32(data, offset + 4).unwrap_or(0) as usize;
            let end = offset.checked_add(size).filter(|&end| end <= data.len());
            let Some(end) = end.filter(|_| size >= LOAD_COMMAND_HEADER_SIZE) else {
                return Err(MachoError::malformed(image, "load command exceeds image"));
            };
            layout.apply(image, command, &data[offset..end])?;
            offset = end;
        }
        Ok(layout)
    }

    fn apply(&mut self, image: &str, command: u32, body: &[u8]) -> MachoResult<()> {
        let truncated =
            || MachoError::malformed(image, format!("truncated load command {command:#x}"));
        match command {
            LC_SEGMENT_64 => self.push_segment(body).ok_or_else(truncated),
            LC_SYMTAB => {
                self.symtab = Some(parse_symtab(body).ok_or_else(truncated)?);
                Ok(())
            }
            LC_DYLD_INFO => {
                self.dyld_info = Some(parse_dyld_info(body).ok_or_else(truncated)?);
                Ok(())
            }
            LC_DYLD_INFO_ONLY => {
                self.dyld_info_only = Some(parse_dyld_info(body).ok_or_else(truncated)?);
                Ok(())
            }
            LC_DYLD_CHAINED_FIXUPS => {
                self.chained_fixups = Some(parse_range(body, 8).ok_or_else(truncated)?);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn push_segment(&mut self, body: &[u8]) -> Option<()> {
        let segment = Segment {
            name: cstring(body.get(8..8 + NAME_SIZE)?),
            address: le64(body, 24)?,
            size: le64(body, 32)?,
            file_offset: le64(body, 40)?,
            file_size: le64(body, 48)?,
            max_protection: le32(body, 56)?,
            initial_protection: le32(body, 60)?,
        };
        let section_count = le32(body, 64)? as usize;
        for index in 0..section_count {
            let at = SEGMENT_COMMAND_SIZE + index * SECTION_SIZE;
            let header = body.get(at..at + SECTION_SIZE)?;
            self.sections.push(Section {
                name: cstring(&header[..NAME_SIZE]),
                address: le64(header, 32)?,
                size: le64(header, 40)?,
                offset: le32(header, 48)?,
                flags: le32(header, 64)?,
            });
        }
        self.segments.push(segment);
        Some(())
    }

    /// The preferred load address: the `__TEXT` segment's address, else 0.
    pub(crate) fn base(&self) -> u64 {
        self.segments
            .iter()
            .find(|segment| segment.name == TEXT_SEGMENT)
            .map_or(0, |segment| segment.address)
    }

    /// `LC_DYLD_INFO` takes precedence over `LC_DYLD_INFO_ONLY`.
    pub(crate) fn dyld_info(&self) -> Option<DyldInfoCommand> {
        self.dyld_info.or(self.dyld_info_only)
    }
}

fn parse_symtab(body: &[u8]) -> Option<SymtabCommand> {
    Some(SymtabCommand {
        symbol_offset: le32(body, 8)?,
        symbol_count: le32(body, 12)?,
        string_offset: le32(body, 16)?,
        string_size: le32(body, 20)?,
    })
}

fn parse_range(body: &[u8], at: usize) -> Option<LinkeditRange> {
    Some(LinkeditRange {
        offset: le32(body, at)?,
        size: le32(body, at + 4)?,
    })
}

fn parse_dyld_info(body: &[u8]) -> Option<DyldInfoCommand> {
    Some(DyldInfoCommand {
        rebase: parse_range(body, 8)?,
        bind: parse_range(body, 16)?,
        weak_bind: parse_range(body, 24)?,
        lazy_bind: parse_range(body, 32)?,
        export: parse_range(body, 40)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::apple_sap::macho::test_support::{
        BASE, LINKEDIT_AT, MachOBuilder, PROT_RX, TEXT_SECTION, u32_of,
    };

    const SEGMENT_FIELDS: usize = (SEGMENT_COMMAND_SIZE - LOAD_COMMAND_HEADER_SIZE) / 4;
    const SECTION_COUNT_FIELD: usize = 14;

    fn parse(data: &[u8]) -> MachoResult<Layout> {
        Layout::parse("t", data)
    }

    fn malformed_reason(data: &[u8]) -> String {
        match parse(data) {
            Err(MachoError::Malformed { reason, .. }) => reason,
            other => panic!("expected a malformed image, got {other:?}"),
        }
    }

    fn streams(first: usize) -> [(usize, usize); 5] {
        [0, 1, 2, 3, 4].map(|index| (first + index * 0x10, index + 1))
    }

    #[test]
    fn parses_segments_sections_and_linkedit_commands() {
        let data = MachOBuilder::standard()
            .symtab(LINKEDIT_AT, 2, LINKEDIT_AT + 0x40, 0x20)
            .dyld_info(LC_DYLD_INFO_ONLY, streams(LINKEDIT_AT))
            .chained_fixups(LINKEDIT_AT + 0x100, 0x30)
            .command(0x1b, &[0; 4])
            .build();
        let layout = parse(&data).unwrap();
        assert_eq!(layout.base(), BASE);
        assert_eq!(layout.segments.len(), 4);
        assert_eq!(layout.segments[1].initial_protection, PROT_RX);
        assert_eq!(layout.segments[1].max_protection, PROT_RX);
        let sections: Vec<(&str, u32, bool)> = layout
            .sections
            .iter()
            .map(|section| {
                (
                    section.name.as_str(),
                    section.offset,
                    section.has_instructions(),
                )
            })
            .collect();
        assert_eq!(
            sections,
            [
                ("__text", u32_of(TEXT_SECTION), true),
                ("__const", 0x900, false)
            ]
        );
        assert_eq!(layout.sections[0].address, BASE + 0x800);
        assert_eq!(layout.sections[0].size, 8);
        let symtab = layout.symtab.unwrap();
        assert_eq!(
            (symtab.symbol_offset, symtab.symbol_count),
            (u32_of(LINKEDIT_AT), 2)
        );
        assert_eq!((symtab.string_offset, symtab.string_size), (0x2040, 0x20));
        let info = layout.dyld_info().unwrap();
        assert_eq!(
            info.rebase,
            LinkeditRange {
                offset: 0x2000,
                size: 1
            }
        );
        assert_eq!(
            info.export,
            LinkeditRange {
                offset: 0x2040,
                size: 5
            }
        );
        assert_eq!(layout.dyld_info, None);
        assert_eq!(
            layout.chained_fixups,
            Some(LinkeditRange {
                offset: 0x2100,
                size: 0x30
            })
        );
    }

    #[test]
    fn dyld_info_takes_precedence_over_dyld_info_only() {
        let data = MachOBuilder::new(0x100)
            .dyld_info(LC_DYLD_INFO_ONLY, streams(0x100))
            .dyld_info(LC_DYLD_INFO, streams(0x200))
            .build();
        let layout = parse(&data).unwrap();
        assert_eq!(layout.dyld_info().map(|info| info.bind.offset), Some(0x210));
        assert_eq!(
            layout.dyld_info_only.map(|info| info.bind.offset),
            Some(0x110)
        );
        assert_eq!(layout.base(), 0);
    }

    #[test]
    fn rejects_images_that_are_not_arm64() {
        let valid = MachOBuilder::new(0).build();
        assert!(parse(&valid).is_ok());
        let mut wrong_cpu = valid.clone();
        wrong_cpu[4] = 7;
        let mut wrong_magic = valid.clone();
        wrong_magic[0] = 0;
        for data in [&valid[..8], &wrong_cpu[..], &wrong_magic[..], &[][..]] {
            assert!(matches!(parse(data), Err(MachoError::NotArm64 { .. })));
        }
    }

    #[test]
    fn rejects_load_commands_outside_the_image() {
        let mut missing = MachOBuilder::new(0).build();
        missing[16] = 1;
        missing.extend_from_slice(&[0x19, 0]);
        assert_eq!(malformed_reason(&missing), "truncated load command");
        let mut undersized = MachOBuilder::new(0).command(0x1b, &[]).build();
        undersized[36] = 4;
        assert_eq!(malformed_reason(&undersized), "load command exceeds image");
        let mut oversized = MachOBuilder::new(0).command(0x1b, &[]).build();
        oversized[36] = 0x40;
        assert_eq!(malformed_reason(&oversized), "load command exceeds image");
    }

    #[test]
    fn rejects_truncated_command_bodies() {
        let mut section_count = [0u32; SEGMENT_FIELDS];
        section_count[SECTION_COUNT_FIELD] = 1;
        let cases = [
            (LC_SEGMENT_64, &[0u32; 4][..]),
            (LC_SEGMENT_64, &section_count[..]),
            (LC_SYMTAB, &[0; 2][..]),
            (LC_DYLD_INFO, &[0; 2][..]),
            (LC_DYLD_INFO_ONLY, &[0; 9][..]),
            (LC_DYLD_CHAINED_FIXUPS, &[0; 1][..]),
        ];
        for (command, fields) in cases {
            let data = MachOBuilder::new(0).command(command, fields).build();
            assert_eq!(
                malformed_reason(&data),
                format!("truncated load command {command:#x}")
            );
        }
    }

    #[test]
    fn byte_helpers_are_bounds_checked() {
        assert_eq!(le32(&[1, 2, 3], 0), None);
        assert_eq!(le32(&[1, 0, 0, 0], usize::MAX), None);
        assert_eq!(le64(&[1, 0, 0, 0, 0, 0, 0, 0], 0), Some(1));
        assert_eq!(le64_at(&[0; 8], u64::MAX), None);
        assert_eq!(cstring(b"_name\0tail"), "_name");
        assert_eq!(cstring(b"_unterminated"), "_unterminated");
    }
}
