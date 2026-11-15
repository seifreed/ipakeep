//! Classic `LC_DYLD_INFO` rebase and bind opcode streams.

use super::error::{MachoError, MachoResult};
use super::layout::{Segment, le64_at};
use super::relocation::Relocation;

const OPCODE_MASK: u8 = 0xf0;
const IMMEDIATE_MASK: u8 = 0x0f;
const POINTER_SIZE: u64 = 8;
const ULEB_PAYLOAD_BITS: u32 = 7;
const ULEB_CONTINUATION: u8 = 0x80;
const ULEB_PAYLOAD_MASK: u8 = 0x7f;
const SLEB_SIGN_BIT: u8 = 0x40;
const MAX_LEB_SHIFT: u32 = 63;

const REBASE_DONE: u8 = 0x00;
const REBASE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_ADD_ADDR_ULEB: u8 = 0x30;
const REBASE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
const REBASE_DO_REBASE_IMM_TIMES: u8 = 0x50;
const REBASE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
const REBASE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
const REBASE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;
const REBASE_TYPE_POINTER: u8 = 1;

const BIND_DONE: u8 = 0x00;
const BIND_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
const BIND_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
const BIND_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
const BIND_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
const BIND_SET_TYPE_IMM: u8 = 0x50;
const BIND_SET_ADDEND_SLEB: u8 = 0x60;
const BIND_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
const BIND_ADD_ADDR_ULEB: u8 = 0x80;
const BIND_DO_BIND: u8 = 0x90;
const BIND_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
const BIND_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
const BIND_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;
const BIND_TYPE_POINTER: u8 = 1;

/// Sequential reader over opcode and trie bytes.
pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> ByteReader<'a> {
    /// Starts reading `data` at `position`.
    pub(crate) fn at(data: &'a [u8], position: usize) -> Self {
        Self { data, position }
    }

    pub(crate) fn byte(&mut self) -> Option<u8> {
        let value = *self.data.get(self.position)?;
        self.position += 1;
        Some(value)
    }

    pub(crate) fn uleb(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift <= MAX_LEB_SHIFT {
                result |= u64::from(byte & ULEB_PAYLOAD_MASK) << shift;
            }
            shift += ULEB_PAYLOAD_BITS;
            if byte & ULEB_CONTINUATION == 0 {
                return Some(result);
            }
        }
    }

    pub(crate) fn sleb(&mut self) -> Option<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift <= MAX_LEB_SHIFT {
                result |= i64::from(byte & ULEB_PAYLOAD_MASK) << shift;
            }
            shift += ULEB_PAYLOAD_BITS;
            if byte & ULEB_CONTINUATION == 0 {
                if shift <= MAX_LEB_SHIFT && byte & SLEB_SIGN_BIT != 0 {
                    result |= -1i64 << shift;
                }
                return Some(result);
            }
        }
    }

    /// Reads bytes up to (excluding) the next NUL, consuming the NUL.
    pub(crate) fn bytes_until_nul(&mut self) -> Vec<u8> {
        let tail = self.data.get(self.position..).unwrap_or_default();
        let nul = tail.iter().position(|&byte| byte == 0);
        let length = nul.unwrap_or(tail.len());
        self.position += (length + 1).min(tail.len());
        tail[..length].to_vec()
    }
}

/// Shared context for converting segment-relative fixups to file offsets.
pub(crate) struct FixupContext<'a> {
    pub(crate) image: &'a str,
    pub(crate) data: &'a [u8],
    pub(crate) segments: &'a [Segment],
    pub(crate) base: u64,
}

impl FixupContext<'_> {
    fn segment(&self, index: u8) -> MachoResult<&Segment> {
        let by_index = self.segments.get(usize::from(index)).ok_or_else(|| {
            MachoError::malformed(self.image, format!("fixup references segment {index}"))
        })?;
        Ok(self
            .segments
            .iter()
            .find(|segment| segment.name == by_index.name)
            .unwrap_or(by_index))
    }

    /// Validates an 8-byte fixup at `offset` inside `segment` and returns its file offset.
    fn file_offset(&self, segment: &Segment, offset: u64) -> MachoResult<u64> {
        let end = offset.checked_add(POINTER_SIZE);
        let Some(end) = end.filter(|&end| end <= segment.size && end <= segment.file_size) else {
            return Err(MachoError::malformed(
                self.image,
                format!("fixup at {offset:#x} exceeds segment {}", segment.name),
            ));
        };
        let result = segment.file_offset.checked_add(offset);
        result
            .filter(|&start| start + (end - offset) <= self.data.len() as u64)
            .ok_or_else(|| {
                MachoError::malformed(self.image, format!("fixup at {offset:#x} exceeds image"))
            })
    }

    fn malformed_stream(&self, stream: &str) -> MachoError {
        MachoError::malformed(self.image, format!("truncated {stream} opcode stream"))
    }
}

/// Decodes a rebase opcode stream into image-relative rebases.
pub(crate) fn parse_rebases(
    context: &FixupContext<'_>,
    stream: &[u8],
) -> MachoResult<Vec<Relocation>> {
    let mut state = RebaseState {
        context,
        reader: ByteReader::at(stream, 0),
        segment: None,
        offset: 0,
        kind: 0,
        output: Vec::new(),
    };
    while let Some(byte) = state.reader.byte() {
        if byte & OPCODE_MASK == REBASE_DONE {
            break;
        }
        state.step(byte & OPCODE_MASK, byte & IMMEDIATE_MASK)?;
    }
    Ok(state.output)
}

struct RebaseState<'a, 'b> {
    context: &'a FixupContext<'b>,
    reader: ByteReader<'a>,
    segment: Option<&'a Segment>,
    offset: u64,
    kind: u8,
    output: Vec<Relocation>,
}

impl RebaseState<'_, '_> {
    fn uleb(&mut self) -> MachoResult<u64> {
        self.reader
            .uleb()
            .ok_or_else(|| self.context.malformed_stream("rebase"))
    }

    fn step(&mut self, opcode: u8, immediate: u8) -> MachoResult<()> {
        match opcode {
            REBASE_SET_TYPE_IMM => self.kind = immediate,
            REBASE_SET_SEGMENT_AND_OFFSET_ULEB => {
                self.segment = Some(self.context.segment(immediate)?);
                self.offset = self.uleb()?;
            }
            REBASE_ADD_ADDR_ULEB => self.offset = self.offset.wrapping_add(self.uleb()?),
            REBASE_ADD_ADDR_IMM_SCALED => {
                self.offset = self
                    .offset
                    .wrapping_add(u64::from(immediate) * POINTER_SIZE);
            }
            REBASE_DO_REBASE_IMM_TIMES => self.repeat(u64::from(immediate), 0)?,
            REBASE_DO_REBASE_ULEB_TIMES => {
                let count = self.uleb()?;
                self.repeat(count, 0)?;
            }
            REBASE_DO_REBASE_ADD_ADDR_ULEB => {
                self.emit()?;
                let skip = self.uleb()?;
                self.offset = self.offset.wrapping_add(skip);
            }
            REBASE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let count = self.uleb()?;
                let skip = self.uleb()?;
                self.repeat(count, skip)?;
            }
            _ => {
                return Err(MachoError::malformed(
                    self.context.image,
                    format!("bad rebase opcode {opcode:#04x}"),
                ));
            }
        }
        Ok(())
    }

    fn repeat(&mut self, count: u64, skip: u64) -> MachoResult<()> {
        for _ in 0..count {
            self.emit()?;
            self.offset = self.offset.wrapping_add(skip);
        }
        Ok(())
    }

    fn emit(&mut self) -> MachoResult<()> {
        let context = self.context;
        let segment = self.segment.ok_or_else(|| {
            MachoError::malformed(context.image, "rebase before segment selection")
        })?;
        if self.kind != REBASE_TYPE_POINTER {
            return Err(MachoError::unsupported(
                context.image,
                format!("rebase type {}", self.kind),
            ));
        }
        let file_offset = context.file_offset(segment, self.offset)?;
        let value = le64_at(context.data, file_offset).unwrap_or(0);
        let target = value
            .checked_sub(context.base)
            .ok_or_else(|| MachoError::malformed(context.image, "rebase below image base"))?;
        self.output.push(Relocation::Rebase {
            offset: file_offset,
            target,
        });
        self.offset = self.offset.wrapping_add(POINTER_SIZE);
        Ok(())
    }
}

/// Which bind stream is being decoded; lazy streams continue after `DONE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindStream {
    /// Regular or weak binds: `DONE` ends the stream.
    Eager,
    /// Lazy binds: `DONE` separates records.
    Lazy,
}

/// Decodes a bind opcode stream into symbol binds.
pub(crate) fn parse_binds(
    context: &FixupContext<'_>,
    stream: &[u8],
    kind: BindStream,
) -> MachoResult<Vec<Relocation>> {
    let mut state = BindState {
        context,
        reader: ByteReader::at(stream, 0),
        segment: None,
        offset: 0,
        record: BindRecord::default(),
        output: Vec::new(),
    };
    while let Some(byte) = state.reader.byte() {
        let opcode = byte & OPCODE_MASK;
        if opcode == BIND_DONE {
            if kind == BindStream::Eager {
                break;
            }
            state.record = BindRecord::default();
            continue;
        }
        state.step(opcode, byte & IMMEDIATE_MASK)?;
    }
    Ok(state.output)
}

#[derive(Debug, Clone, Default)]
struct BindRecord {
    symbol: String,
    kind: u8,
    addend: i64,
}

struct BindState<'a, 'b> {
    context: &'a FixupContext<'b>,
    reader: ByteReader<'a>,
    segment: Option<&'a Segment>,
    offset: u64,
    record: BindRecord,
    output: Vec<Relocation>,
}

impl BindState<'_, '_> {
    fn uleb(&mut self) -> MachoResult<u64> {
        self.reader
            .uleb()
            .ok_or_else(|| self.context.malformed_stream("bind"))
    }

    fn step(&mut self, opcode: u8, immediate: u8) -> MachoResult<()> {
        match opcode {
            BIND_SET_DYLIB_ORDINAL_IMM | BIND_SET_DYLIB_SPECIAL_IMM => {}
            BIND_SET_DYLIB_ORDINAL_ULEB => {
                self.uleb()?;
            }
            BIND_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                self.record.symbol =
                    String::from_utf8_lossy(&self.reader.bytes_until_nul()).into_owned();
            }
            BIND_SET_TYPE_IMM => self.record.kind = immediate,
            BIND_SET_ADDEND_SLEB => {
                self.record.addend = self
                    .reader
                    .sleb()
                    .ok_or_else(|| self.context.malformed_stream("bind"))?;
            }
            BIND_SET_SEGMENT_AND_OFFSET_ULEB => {
                self.segment = Some(self.context.segment(immediate)?);
                self.offset = self.uleb()?;
            }
            BIND_ADD_ADDR_ULEB => self.offset = self.offset.wrapping_add(self.uleb()?),
            _ => self.step_bind(opcode, immediate)?,
        }
        Ok(())
    }

    fn step_bind(&mut self, opcode: u8, immediate: u8) -> MachoResult<()> {
        match opcode {
            BIND_DO_BIND => self.emit(0),
            BIND_DO_BIND_ADD_ADDR_ULEB => {
                let skip = self.uleb()?;
                self.emit(skip)
            }
            BIND_DO_BIND_ADD_ADDR_IMM_SCALED => self.emit(u64::from(immediate) * POINTER_SIZE),
            BIND_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = self.uleb()?;
                let skip = self.uleb()?;
                (0..count).try_for_each(|_| self.emit(skip))
            }
            _ => Err(MachoError::unsupported(
                self.context.image,
                format!("bind opcode {opcode:#04x}"),
            )),
        }
    }

    fn emit(&mut self, skip: u64) -> MachoResult<()> {
        let context = self.context;
        let segment = self
            .segment
            .ok_or_else(|| MachoError::malformed(context.image, "bind before segment selection"))?;
        if self.record.kind != 0 && self.record.kind != BIND_TYPE_POINTER {
            return Err(MachoError::unsupported(
                context.image,
                format!("bind type {} for {}", self.record.kind, self.record.symbol),
            ));
        }
        let file_offset = context.file_offset(segment, self.offset)?;
        self.output.push(Relocation::Bind {
            offset: file_offset,
            symbol: self.record.symbol.clone(),
            addend: self.record.addend,
        });
        self.offset = self.offset.wrapping_add(skip).wrapping_add(POINTER_SIZE);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segments() -> Vec<Segment> {
        vec![
            Segment {
                name: "__TEXT".to_owned(),
                address: 0x1_0000_0000,
                size: 0x100,
                file_offset: 0,
                file_size: 0x100,
                max_protection: 5,
                initial_protection: 5,
            },
            Segment {
                name: "__DATA".to_owned(),
                address: 0x1_0000_0100,
                size: 0x100,
                file_offset: 0x100,
                file_size: 0x100,
                max_protection: 3,
                initial_protection: 3,
            },
        ]
    }

    #[test]
    fn leb128_round_trip() {
        let mut reader = ByteReader::at(&[0xe5, 0x8e, 0x26, 0x7f, 0x80, 0x7f], 0);
        assert_eq!(reader.uleb(), Some(624_485));
        assert_eq!(reader.sleb(), Some(-1));
        assert_eq!(reader.sleb(), Some(-128));
        assert_eq!(reader.byte(), None);
    }

    #[test]
    fn decodes_rebase_stream() {
        let mut data = vec![0u8; 0x200];
        data[0x110..0x118].copy_from_slice(&0x1_0000_0040u64.to_le_bytes());
        data[0x118..0x120].copy_from_slice(&0x1_0000_0080u64.to_le_bytes());
        let segments = segments();
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments,
            base: 0x1_0000_0000,
        };
        // type pointer, segment 1 offset 0x10, rebase x2, done.
        let stream = [0x11, 0x21, 0x10, 0x52, 0x00];
        let rebases = parse_rebases(&context, &stream).ok();
        assert_eq!(
            rebases,
            Some(vec![
                Relocation::Rebase {
                    offset: 0x110,
                    target: 0x40
                },
                Relocation::Rebase {
                    offset: 0x118,
                    target: 0x80
                },
            ])
        );
    }

    #[test]
    fn decodes_bind_stream_with_addend() {
        let data = vec![0u8; 0x200];
        let segments = segments();
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments,
            base: 0x1_0000_0000,
        };
        // ordinal 1, symbol "_f", type pointer, addend -8, seg 1 off 0x20, bind, done.
        let stream = [
            0x11, 0x40, b'_', b'f', 0, 0x51, 0x60, 0x78, 0x71, 0x20, 0x90, 0x00,
        ];
        let binds = parse_binds(&context, &stream, BindStream::Eager).ok();
        assert_eq!(
            binds,
            Some(vec![Relocation::Bind {
                offset: 0x120,
                symbol: "_f".to_owned(),
                addend: -8
            }])
        );
    }

    #[test]
    fn rejects_threaded_binds() {
        let data = vec![0u8; 0x200];
        let segments = segments();
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments,
            base: 0,
        };
        let result = parse_binds(&context, &[0xd0], BindStream::Eager);
        assert!(matches!(result, Err(MachoError::Unsupported { .. })));
    }

    const BASE: u64 = 0x1_0000_0000;

    fn image_with_pointers(value: u64) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        for slot in data[0x100..].as_chunks_mut::<8>().0 {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        data
    }

    fn rebases(data: &[u8], segments: &[Segment], stream: &[u8]) -> MachoResult<Vec<u64>> {
        let context = FixupContext {
            image: "t",
            data,
            segments,
            base: BASE,
        };
        let decoded = parse_rebases(&context, stream)?;
        Ok(decoded.iter().map(Relocation::offset).collect())
    }

    fn binds(stream: &[u8], kind: BindStream) -> MachoResult<Vec<Relocation>> {
        let data = vec![0u8; 0x200];
        let segments = segments();
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments,
            base: BASE,
        };
        parse_binds(&context, stream, kind)
    }

    fn reason(result: MachoResult<impl std::fmt::Debug>) -> String {
        match result {
            Err(MachoError::Malformed { reason, .. } | MachoError::Unsupported { reason, .. }) => {
                reason
            }
            other => panic!("expected a decoding error, got {other:?}"),
        }
    }

    #[test]
    fn rebase_opcodes_cover_every_addressing_mode() {
        let data = image_with_pointers(BASE + 0x40);
        let stream = [
            0x11, 0x21, 0x00, 0x30, 0x08, 0x41, 0x60, 0x02, 0x70, 0x08, 0x80, 0x02, 0x08, 0x00,
            0x51,
        ];
        let offsets = rebases(&data, &segments(), &stream).unwrap();
        assert_eq!(offsets, [0x110, 0x118, 0x120, 0x130, 0x140]);
        let context = FixupContext {
            image: "t",
            data: &data,
            segments: &segments(),
            base: BASE,
        };
        let targets = parse_rebases(&context, &[0x11, 0x21, 0x00, 0x51]).unwrap();
        assert_eq!(
            targets,
            [Relocation::Rebase {
                offset: 0x100,
                target: 0x40
            }]
        );
    }

    #[test]
    fn rebase_streams_are_validated() {
        let data = image_with_pointers(BASE);
        let segments = segments();
        let failures: [(&[u8], &str); 6] = [
            (&[0x51], "rebase before segment selection"),
            (&[0x12, 0x21, 0x00, 0x51], "rebase type 2"),
            (&[0x11, 0x21], "truncated rebase opcode stream"),
            (&[0x90], "bad rebase opcode 0x90"),
            (&[0x11, 0x2f, 0x00], "fixup references segment 15"),
            (
                &[0x11, 0x21, 0xf9, 0x01, 0x51],
                "fixup at 0xf9 exceeds segment __DATA",
            ),
        ];
        for (stream, expected) in failures {
            assert_eq!(reason(rebases(&data, &segments, stream)), expected);
        }
        let below = image_with_pointers(0x40);
        let error = rebases(&below, &segments, &[0x11, 0x21, 0x00, 0x51]);
        assert_eq!(reason(error), "rebase below image base");
    }

    #[test]
    fn fixups_must_fit_in_the_file() {
        let data = image_with_pointers(BASE);
        let mut segments = segments();
        segments[1].file_offset = 0x1f8;
        let error = rebases(&data, &segments, &[0x11, 0x21, 0x08, 0x51]);
        assert_eq!(reason(error), "fixup at 0x8 exceeds image");
    }

    #[test]
    fn duplicate_segment_names_resolve_to_the_first_declaration() {
        let data = image_with_pointers(BASE);
        let mut segments = segments();
        segments.push(Segment {
            file_offset: 0x180,
            ..segments[1].clone()
        });
        let offsets = rebases(&data, &segments, &[0x11, 0x22, 0x00, 0x51]).unwrap();
        assert_eq!(offsets, [0x100]);
    }

    #[test]
    fn bind_opcodes_cover_every_addressing_mode() {
        let stream = [
            0x11, 0x22, 0x01, 0x3e, 0x40, b'_', b'a', 0, 0x51, 0x60, 0x10, 0x71, 0x00, 0x80, 0x08,
            0x90, 0xa0, 0x08, 0xb1, 0xc0, 0x02, 0x08, 0x00, 0x90,
        ];
        let decoded = binds(&stream, BindStream::Eager).unwrap();
        let offsets: Vec<u64> = decoded.iter().map(Relocation::offset).collect();
        assert_eq!(offsets, [0x108, 0x110, 0x120, 0x130, 0x140]);
        assert!(decoded.iter().all(|relocation| matches!(
            relocation,
            Relocation::Bind { symbol, addend: 16, .. } if symbol == "_a"
        )));
    }

    #[test]
    fn lazy_binds_reset_their_record_after_done() {
        let stream = [
            0x71, 0x00, 0x40, b'_', b'x', 0, 0x60, 0x7f, 0x90, 0x00, 0x90, 0x00,
        ];
        let bind = |offset, symbol: &str, addend| Relocation::Bind {
            offset,
            symbol: symbol.to_owned(),
            addend,
        };
        assert_eq!(
            binds(&stream, BindStream::Lazy).unwrap(),
            [bind(0x100, "_x", -1), bind(0x108, "", 0)]
        );
        assert_eq!(
            binds(&stream, BindStream::Eager).unwrap(),
            [bind(0x100, "_x", -1)]
        );
        let unterminated = binds(&[0x71, 0x00, 0x40, b'_', b'y'], BindStream::Eager);
        assert_eq!(unterminated.unwrap(), []);
    }

    #[test]
    fn bind_streams_are_validated() {
        let failures: [(&[u8], &str); 5] = [
            (&[0x90], "bind before segment selection"),
            (&[0x52, 0x71, 0x00, 0x90], "bind type 2 for "),
            (&[0x60], "truncated bind opcode stream"),
            (&[0x22], "truncated bind opcode stream"),
            (&[0x7f, 0x00], "fixup references segment 15"),
        ];
        for (stream, expected) in failures {
            assert_eq!(reason(binds(stream, BindStream::Eager)), expected);
        }
    }

    #[test]
    fn oversized_leb128_values_drop_high_bits() {
        let mut long = vec![0x81u8; 10];
        long.push(0x01);
        assert_eq!(ByteReader::at(&long, 0).uleb(), Some(0x8102_0408_1020_4081));
        let mut negative = vec![0xffu8; 10];
        negative.push(0x7f);
        assert_eq!(ByteReader::at(&negative, 0).sleb(), Some(-1));
        assert_eq!(ByteReader::at(&[0x80], 0).sleb(), None);
    }
}
