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
pub(crate) mod tests {
    use super::*;

    fn u32_of(value: usize) -> u32 {
        u32::try_from(value).unwrap_or(u32::MAX)
    }

    /// Builds a minimal arm64 Mach-O with the given segments
    /// `(name, vmaddr, vmsize, fileoff, filesize)` and extra load commands.
    pub(crate) fn synthetic_image(
        segments: &[(&str, u64, u64, u64, u64)],
        extra_commands: &[Vec<u8>],
        file_size: usize,
    ) -> Vec<u8> {
        let mut commands = Vec::new();
        for &(name, address, size, offset, length) in segments {
            let mut command = Vec::new();
            command.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
            command.extend_from_slice(&u32_of(SEGMENT_COMMAND_SIZE).to_le_bytes());
            let mut raw_name = [0u8; NAME_SIZE];
            raw_name[..name.len()].copy_from_slice(name.as_bytes());
            command.extend_from_slice(&raw_name);
            for value in [address, size, offset, length] {
                command.extend_from_slice(&value.to_le_bytes());
            }
            command.extend_from_slice(&[7, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            commands.push(command);
        }
        commands.extend(extra_commands.iter().cloned());
        let mut data = Vec::new();
        data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        data.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&6u32.to_le_bytes());
        data.extend_from_slice(&u32_of(commands.len()).to_le_bytes());
        let total: usize = commands.iter().map(Vec::len).sum();
        data.extend_from_slice(&u32_of(total).to_le_bytes());
        data.extend_from_slice(&[0u8; 8]);
        for command in commands {
            data.extend_from_slice(&command);
        }
        data.resize(file_size.max(data.len()), 0);
        data
    }

    #[test]
    fn parses_segments_and_base() {
        let data = synthetic_image(
            &[
                ("__PAGEZERO", 0, 0x1000, 0, 0),
                ("__TEXT", 0x4000, 0x1000, 0, 0x1000),
            ],
            &[],
            0x1000,
        );
        let layout = Layout::parse("t", &data).ok();
        let layout = layout.as_ref();
        assert_eq!(layout.map(|item| item.segments.len()), Some(2));
        assert_eq!(layout.map(Layout::base), Some(0x4000));
        assert_eq!(
            layout.map(|item| item.segments[1].initial_protection),
            Some(3)
        );
    }

    #[test]
    fn rejects_non_arm64() {
        let mut data = synthetic_image(&[], &[], 64);
        data[4] = 7;
        assert!(matches!(
            Layout::parse("t", &data),
            Err(MachoError::NotArm64 { .. })
        ));
    }

    #[test]
    fn rejects_truncated_command() {
        let mut data = synthetic_image(&[("__TEXT", 0, 0x10, 0, 0x10)], &[], 0);
        data.truncate(60);
        assert!(matches!(
            Layout::parse("t", &data),
            Err(MachoError::Malformed { .. })
        ));
    }
}
