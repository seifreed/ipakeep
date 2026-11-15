//! LZVN, LZFSE and LZBITMAP block decoders used by APFS transparent
//! compression (decmpfs).
//!
//! Ported from ipatool `internal/sap/assets` and the Go decoders it uses
//! (`github.com/go-compressions/lzfse` for LZVN and
//! `github.com/deploymenttheory/go-macos-pkg/pkg/lzbitmap`). LZFSE is
//! delegated to the `lzfse_rust` crate.

use thiserror::Error;

/// Errors raised while decoding a compressed block.
#[derive(Debug, Error)]
pub enum LzError {
    /// The LZVN stream is malformed.
    #[error("lzvn: {0}")]
    Lzvn(&'static str),
    /// The LZBITMAP stream is malformed.
    #[error("lzbitmap: {0}")]
    Lzbitmap(&'static str),
    /// The LZFSE stream is malformed.
    #[error("lzfse: {0}")]
    Lzfse(String),
}

/// Decodes an LZFSE stream (`bvx*` blocks terminated by `bvx$`).
///
/// # Errors
///
/// Returns [`LzError::Lzfse`] when the stream is malformed.
pub fn decompress_lzfse(src: &[u8]) -> Result<Vec<u8>, LzError> {
    let mut output = Vec::new();
    lzfse_rust::decode_bytes(src, &mut output).map_err(|err| LzError::Lzfse(err.to_string()))?;
    Ok(output)
}

const LZVN_END_OF_STREAM: u8 = 0x06;
const LZVN_NOP_A: u8 = 0x0E;
const LZVN_NOP_B: u8 = 0x16;
const LZVN_LARGE_MATCH: u8 = 0xF0;
const LZVN_LARGE_LITERAL: u8 = 0xE0;
const LZVN_MEDIUM_DISTANCE: u8 = 0xA0;
const LZVN_MEDIUM_DISTANCE_END: u8 = 0xC0;
const LZVN_LARGE_BIAS: usize = 16;
const LZVN_MATCH_BIAS: usize = 3;
const LZVN_LOW_NIBBLE: u8 = 0x0F;
const LZVN_PREVIOUS_DISTANCE: u8 = 6;
const LZVN_LARGE_DISTANCE: u8 = 7;
const LZVN_OPCODE_KIND_MASK: u8 = 0x07;

/// Decodes a raw LZVN opcode stream into at most `max_out` bytes.
///
/// # Errors
///
/// Returns [`LzError::Lzvn`] when the stream is malformed or would exceed
/// `max_out` bytes.
pub fn decompress_lzvn(src: &[u8], max_out: usize) -> Result<Vec<u8>, LzError> {
    let mut decoder = LzvnDecoder {
        src,
        spos: 0,
        dst: Vec::with_capacity(max_out),
        limit: max_out,
        previous_distance: 0,
    };
    decoder.run()?;
    Ok(decoder.dst)
}

struct LzvnDecoder<'a> {
    src: &'a [u8],
    spos: usize,
    dst: Vec<u8>,
    limit: usize,
    previous_distance: usize,
}

impl LzvnDecoder<'_> {
    fn run(&mut self) -> Result<(), LzError> {
        while let Some(&opcode) = self.src.get(self.spos) {
            self.spos += 1;
            match opcode {
                LZVN_END_OF_STREAM => return Ok(()),
                LZVN_NOP_A | LZVN_NOP_B => {}
                LZVN_LARGE_MATCH.. => self.match_only(opcode)?,
                LZVN_LARGE_LITERAL.. => self.literal_only(opcode)?,
                LZVN_MEDIUM_DISTANCE..LZVN_MEDIUM_DISTANCE_END => self.medium_distance(opcode)?,
                _ => self.small_opcode(opcode)?,
            }
        }
        Ok(())
    }

    fn next_byte(&mut self, what: &'static str) -> Result<u8, LzError> {
        let byte = *self.src.get(self.spos).ok_or(LzError::Lzvn(what))?;
        self.spos += 1;
        Ok(byte)
    }

    fn sized_operand(
        &mut self,
        opcode: u8,
        large: u8,
        what: &'static str,
    ) -> Result<usize, LzError> {
        if opcode == large {
            Ok(usize::from(self.next_byte(what)?) + LZVN_LARGE_BIAS)
        } else {
            Ok(usize::from(opcode & LZVN_LOW_NIBBLE))
        }
    }

    fn match_only(&mut self, opcode: u8) -> Result<(), LzError> {
        let length = self.sized_operand(opcode, LZVN_LARGE_MATCH, "truncated lrg_m opcode")?;
        if self.previous_distance == 0 {
            return Err(LzError::Lzvn("match without prior distance"));
        }
        self.copy_match(self.previous_distance, length)
    }

    fn literal_only(&mut self, opcode: u8) -> Result<(), LzError> {
        let length = self.sized_operand(opcode, LZVN_LARGE_LITERAL, "truncated lrg_l opcode")?;
        self.copy_literal(length, "literal overflow")
    }

    fn medium_distance(&mut self, opcode: u8) -> Result<(), LzError> {
        if self.spos + 2 > self.src.len() {
            return Err(LzError::Lzvn("truncated med_d opcode"));
        }
        let first = self.src[self.spos];
        let second = self.src[self.spos + 1];
        self.spos += 2;
        let literal = usize::from((opcode >> 3) & 0x03);
        let length = usize::from(((opcode & 0x07) << 2) | (first & 0x03)) + LZVN_MATCH_BIAS;
        let distance = usize::from(first >> 2) | (usize::from(second) << 6);
        self.literal_then_match(literal, length, distance, "med_d literal overflow")
    }

    fn small_opcode(&mut self, opcode: u8) -> Result<(), LzError> {
        let literal = usize::from(opcode >> 6);
        let length = usize::from((opcode >> 3) & 0x07) + LZVN_MATCH_BIAS;
        match opcode & LZVN_OPCODE_KIND_MASK {
            LZVN_PREVIOUS_DISTANCE => {
                if self.previous_distance == 0 {
                    return Err(LzError::Lzvn("pre_d without prior distance"));
                }
                self.copy_literal(literal, "pre_d literal overflow")?;
                self.copy_match(self.previous_distance, length)
            }
            LZVN_LARGE_DISTANCE => {
                if self.spos + 2 > self.src.len() {
                    return Err(LzError::Lzvn("truncated lrg_d opcode"));
                }
                let distance = usize::from(u16::from_le_bytes([
                    self.src[self.spos],
                    self.src[self.spos + 1],
                ]));
                self.spos += 2;
                self.literal_then_match(literal, length, distance, "lrg_d literal overflow")
            }
            high => {
                let low = self.next_byte("truncated sml_d opcode")?;
                let distance = (usize::from(high) << 8) | usize::from(low);
                self.literal_then_match(literal, length, distance, "sml_d literal overflow")
            }
        }
    }

    fn literal_then_match(
        &mut self,
        literal: usize,
        length: usize,
        distance: usize,
        overflow: &'static str,
    ) -> Result<(), LzError> {
        if distance == 0 {
            return Err(LzError::Lzvn("zero match distance"));
        }
        self.copy_literal(literal, overflow)?;
        self.copy_match(distance, length)?;
        self.previous_distance = distance;
        Ok(())
    }

    fn copy_literal(&mut self, length: usize, overflow: &'static str) -> Result<(), LzError> {
        let end = self.spos + length;
        if end > self.src.len() || self.dst.len() + length > self.limit {
            return Err(LzError::Lzvn(overflow));
        }
        self.dst.extend_from_slice(&self.src[self.spos..end]);
        self.spos = end;
        Ok(())
    }

    fn copy_match(&mut self, distance: usize, length: usize) -> Result<(), LzError> {
        if distance == 0 || distance > self.dst.len() {
            return Err(LzError::Lzvn("invalid match distance"));
        }
        if self.dst.len() + length > self.limit {
            return Err(LzError::Lzvn("match overflow"));
        }
        let start = self.dst.len() - distance;
        for index in 0..length {
            let byte = self.dst[start + index];
            self.dst.push(byte);
        }
        Ok(())
    }
}

const LZBITMAP_MAGIC: &[u8; 4] = b"ZBM\x09";
/// Bytes before the first chunk: the stream magic.
const LZBITMAP_STREAM_HEADER: usize = LZBITMAP_MAGIC.len();
const LZBITMAP_MAX_CHUNK: usize = 0x8000;
const LZBITMAP_CHUNK_HEADER: usize = 6;
const LZBITMAP_COMPRESSED_HEADER: usize = 15;
const LZBITMAP_BITMAP_COUNT: usize = 12;
const LZBITMAP_BITMAP_BASE: u8 = 3;
const LZBITMAP_BITMAP_BYTES: usize = 17;
const LZBITMAP_MAX_PERIOD_BYTES: u8 = 2;
const LZBITMAP_REPEAT_BASE: usize = 4;
const LZBITMAP_REPEAT_MARKER: u8 = 0x0F;
const LZBITMAP_DEFAULT_PERIOD: usize = 8;
/// Error for a bitmap number that is the repetition marker.
const REPEAT_MARKER_AS_BITMAP: &str = "0xf is a repetition marker, not a bitmap";
const LZBITMAP_BITS_PER_BITMAP: usize = 8;
const LZBITMAP_PERIOD_FIELD_BITS: usize = 2;

/// Decodes a whole LZBITMAP (`ZBM\x09`) stream.
///
/// # Errors
///
/// Returns [`LzError::Lzbitmap`] when the stream is malformed.
pub fn decompress_lzbitmap(src: &[u8]) -> Result<Vec<u8>, LzError> {
    if src.len() < LZBITMAP_MAGIC.len() || &src[..LZBITMAP_MAGIC.len()] != LZBITMAP_MAGIC {
        return Err(LzError::Lzbitmap("missing ZBM\\x09 magic"));
    }
    let mut decoder = LzbitmapDecoder::new(src);
    loop {
        decoder.chunk()?;
        decoder.pos = decoder.end;
        decoder.prewritten += decoder.decompressed_len;
        if decoder.decompressed_len == 0 {
            return Ok(decoder.out);
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Bitmap {
    bits: u8,
    period_bytes: u8,
}

struct LzbitmapDecoder<'a> {
    src: &'a [u8],
    out: Vec<u8>,
    pos: usize,
    end: usize,
    decompressed_len: usize,
    written: usize,
    prewritten: usize,
    period: usize,
    data: usize,
    meta1: usize,
    meta2: usize,
    meta3: usize,
    high_nibble: bool,
    bitmaps: [Bitmap; LZBITMAP_BITMAP_COUNT],
}

fn u24(bytes: &[u8]) -> usize {
    usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16)
}

impl<'a> LzbitmapDecoder<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            out: Vec::new(),
            pos: LZBITMAP_STREAM_HEADER,
            end: 0,
            decompressed_len: 0,
            written: 0,
            prewritten: 0,
            period: LZBITMAP_DEFAULT_PERIOD,
            data: 0,
            meta1: 0,
            meta2: 0,
            meta3: 0,
            high_nibble: false,
            bitmaps: [Bitmap::default(); LZBITMAP_BITMAP_COUNT],
        }
    }

    fn chunk(&mut self) -> Result<(), LzError> {
        if self.pos + LZBITMAP_CHUNK_HEADER > self.src.len() {
            return Err(LzError::Lzbitmap("truncated chunk header"));
        }
        let length = u24(&self.src[self.pos..]);
        if length < LZBITMAP_CHUNK_HEADER || self.pos + length > self.src.len() {
            return Err(LzError::Lzbitmap("chunk length outside the stream"));
        }
        self.end = self.pos + length;
        self.decompressed_len = u24(&self.src[self.pos + 3..]);
        if self.decompressed_len > LZBITMAP_MAX_CHUNK {
            return Err(LzError::Lzbitmap("chunk decompresses over the limit"));
        }
        if length == self.decompressed_len + LZBITMAP_CHUNK_HEADER {
            let stored = &self.src[self.pos + LZBITMAP_CHUNK_HEADER..self.end];
            self.out.extend_from_slice(stored);
            self.written = self.decompressed_len;
            return Ok(());
        }
        self.compressed_chunk(length)
    }

    fn compressed_chunk(&mut self, length: usize) -> Result<(), LzError> {
        if length < LZBITMAP_COMPRESSED_HEADER {
            return Err(LzError::Lzbitmap("compressed chunk has no header"));
        }
        self.written = 0;
        self.period = LZBITMAP_DEFAULT_PERIOD;
        self.data = self.pos + LZBITMAP_COMPRESSED_HEADER;
        let offsets = [
            u24(&self.src[self.pos + 6..]),
            u24(&self.src[self.pos + 9..]),
            u24(&self.src[self.pos + 12..]),
        ];
        if offsets.iter().any(|&offset| offset >= length) {
            return Err(LzError::Lzbitmap("metadata offset outside the chunk"));
        }
        self.meta1 = self.pos + offsets[0];
        self.meta2 = self.pos + offsets[1];
        self.meta3 = self.pos + offsets[2];
        self.high_nibble = false;
        self.read_bitmaps(length)?;
        while self.written < self.decompressed_len {
            self.one_bitmap()?;
        }
        Ok(())
    }

    fn read_bitmaps(&mut self, length: usize) -> Result<(), LzError> {
        if length < LZBITMAP_BITMAP_BYTES {
            return Err(LzError::Lzbitmap("chunk too short to hold its bitmaps"));
        }
        let table = &self.src[self.end - LZBITMAP_BITMAP_BYTES..self.end];
        let bit = |index: usize| (table[index / 8] >> (index % 8)) & 1;
        let field_bits = LZBITMAP_BITS_PER_BITMAP + LZBITMAP_PERIOD_FIELD_BITS;
        for (index, slot) in self.bitmaps.iter_mut().enumerate() {
            let base = index * field_bits;
            let bits = (0..LZBITMAP_BITS_PER_BITMAP).fold(0u8, |acc, j| acc | (bit(base + j) << j));
            let period_bytes = bit(base + 8) | (bit(base + 9) << 1);
            if period_bytes > LZBITMAP_MAX_PERIOD_BYTES {
                return Err(LzError::Lzbitmap("bitmap wants too many period bytes"));
            }
            *slot = Bitmap { bits, period_bytes };
        }
        Ok(())
    }

    fn read_nibble(&mut self) -> Result<u8, LzError> {
        let index = self.meta3;
        let byte = self.src.get(index).filter(|_| index < self.end);
        let byte = *byte.ok_or(LzError::Lzbitmap("bitmap numbers run past the chunk"))?;
        if self.high_nibble {
            self.high_nibble = false;
            self.meta3 += 1;
            Ok(byte >> 4)
        } else {
            self.high_nibble = true;
            Ok(byte & 0x0F)
        }
    }

    fn rewind_nibble(&mut self) {
        if self.high_nibble {
            self.high_nibble = false;
        } else {
            self.high_nibble = true;
            self.meta3 -= 1;
        }
    }

    fn one_bitmap(&mut self) -> Result<(), LzError> {
        let number = self.read_nibble()?;
        let repeat = self.repetition_count()?;
        for _ in 0..repeat {
            self.apply_number(number)?;
        }
        Ok(())
    }

    fn repetition_count(&mut self) -> Result<usize, LzError> {
        if self.decompressed_len - self.written <= LZBITMAP_BITS_PER_BITMAP {
            return Ok(1);
        }
        let mut nibble = self.read_nibble()?;
        if nibble != LZBITMAP_REPEAT_MARKER {
            self.rewind_nibble();
            return Ok(1);
        }
        let mut total = LZBITMAP_REPEAT_BASE;
        while nibble == LZBITMAP_REPEAT_MARKER {
            nibble = self.read_nibble()?;
            total += usize::from(nibble);
            if total > LZBITMAP_MAX_CHUNK {
                return Err(LzError::Lzbitmap("repetition count over the limit"));
            }
        }
        Ok(total)
    }

    fn apply_number(&mut self, number: u8) -> Result<(), LzError> {
        if number == LZBITMAP_REPEAT_MARKER {
            return Err(LzError::Lzbitmap(REPEAT_MARKER_AS_BITMAP));
        }
        if number > LZBITMAP_MAX_PERIOD_BYTES {
            let bitmap = self.bitmaps[usize::from(number - LZBITMAP_BITMAP_BASE)];
            return self.apply(bitmap);
        }
        if self.meta2 >= self.end {
            return Err(LzError::Lzbitmap("inline bitmaps run past the chunk"));
        }
        let bitmap = Bitmap {
            bits: self.src[self.meta2],
            period_bytes: number,
        };
        self.meta2 += 1;
        self.apply(bitmap)
    }

    fn apply(&mut self, bitmap: Bitmap) -> Result<(), LzError> {
        if bitmap.period_bytes > 0 {
            self.period = 0;
            for index in 0..usize::from(bitmap.period_bytes) {
                if self.meta1 >= self.end {
                    return Err(LzError::Lzbitmap("periods run past the chunk"));
                }
                self.period |= usize::from(self.src[self.meta1]) << (index * 8);
                self.meta1 += 1;
            }
        }
        if self.period == 0 {
            return Err(LzError::Lzbitmap("zero repetition period"));
        }
        let remaining = self.decompressed_len.saturating_sub(self.written);
        for index in 0..LZBITMAP_BITS_PER_BITMAP.min(remaining) {
            self.emit(bitmap.bits & (1 << index) != 0)?;
        }
        Ok(())
    }

    fn emit(&mut self, literal: bool) -> Result<(), LzError> {
        let byte = if literal {
            if self.data >= self.end {
                return Err(LzError::Lzbitmap("literals run past the chunk"));
            }
            self.data += 1;
            self.src[self.data - 1]
        } else {
            if self.prewritten + self.written < self.period {
                return Err(LzError::Lzbitmap("period reaches before the output"));
            }
            self.out[self.out.len() - self.period]
        };
        self.out.push(byte);
        self.written += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/apple_sap/B/");
    const TEXT_SIZE: usize = 9486;
    const TEXT_SHA: &str = "36674690265c39b639100b1ec0fbd85bc3e6b738ccb28994ea013cb9047a3930";
    const BINARY_SIZE: usize = 65536;
    const BINARY_SHA: &str = "fe37fcc21fc12bdb448babddef10c809aad5e73f5ae52554b58aea75d96245dd";
    const APPLE_SIZE: usize = 300_732;
    const APPLE_SHA: &str = "2347b7e52cc1f6ef9da95bf10bd06dbf7985724a2f6ae5108665b910cdfd62a0";

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}{name}")).expect("read fixture")
    }

    fn assert_digest(data: &[u8], size: usize, digest: &str) {
        assert_eq!(data.len(), size);
        assert_eq!(hex::encode(Sha256::digest(data)), digest);
    }

    #[test]
    fn lzvn_decodes_go_encoder_vectors() {
        let text = decompress_lzvn(&fixture("text.lzvn"), TEXT_SIZE).expect("text");
        assert_digest(&text, TEXT_SIZE, TEXT_SHA);
        let binary = decompress_lzvn(&fixture("binary.lzvn"), BINARY_SIZE).expect("binary");
        assert_digest(&binary, BINARY_SIZE, BINARY_SHA);
    }

    #[test]
    fn lzvn_rejects_output_over_limit() {
        assert!(decompress_lzvn(&fixture("text.lzvn"), TEXT_SIZE - 1).is_err());
    }

    #[test]
    fn lzvn_handles_overlapping_match_and_end_of_stream() {
        let stream = [
            0xE1,
            b'a',
            0x38,
            0x01,
            LZVN_END_OF_STREAM,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let decoded = decompress_lzvn(&stream, 16).expect("decode");
        assert_eq!(decoded, b"aaaaaaaaaaa".to_vec());
    }

    #[test]
    fn lzvn_rejects_match_without_distance() {
        assert!(decompress_lzvn(&[0xF3], 16).is_err());
    }

    #[test]
    fn lzbitmap_decodes_go_encoder_vectors() {
        let text = decompress_lzbitmap(&fixture("text.lzbitmap")).expect("text");
        assert_digest(&text, TEXT_SIZE, TEXT_SHA);
        let binary = decompress_lzbitmap(&fixture("binary.lzbitmap")).expect("binary");
        assert_digest(&binary, BINARY_SIZE, BINARY_SHA);
    }

    #[test]
    fn lzbitmap_decodes_apple_encoder_stream() {
        let decoded = decompress_lzbitmap(&fixture("apple.lzbitmap")).expect("apple");
        assert_digest(&decoded, APPLE_SIZE, APPLE_SHA);
    }

    #[test]
    fn lzbitmap_rejects_bad_magic_and_truncation() {
        assert!(decompress_lzbitmap(b"ZBM\x08").is_err());
        let stream = fixture("text.lzbitmap");
        assert!(decompress_lzbitmap(&stream[..stream.len() / 2]).is_err());
    }

    fn lzvn_error(stream: &[u8], limit: usize) -> &'static str {
        match decompress_lzvn(stream, limit) {
            Err(LzError::Lzvn(reason)) => reason,
            other => panic!("expected an LZVN error, got {other:?}"),
        }
    }

    #[test]
    fn lzvn_skips_nops_and_stops_at_end_of_input() {
        let stream = [LZVN_NOP_A, 0xE2, b'h', b'i', LZVN_NOP_B];
        assert_eq!(decompress_lzvn(&stream, 8).expect("decode"), b"hi".to_vec());
    }

    #[test]
    fn lzvn_decodes_medium_large_and_previous_distance_opcodes() {
        let stream = [
            0xE2,
            b'a',
            b'b', // two literals
            0xA0,
            0x08,
            0x00, // med_d: no literal, match 3 at distance 2
            0x07,
            0x02,
            0x00, // lrg_d: no literal, match 3 at distance 2
            0x06 | 0x40,
            b'z', // pre_d: one literal, match 3 at the previous distance
            LZVN_END_OF_STREAM,
        ];
        assert_eq!(
            decompress_lzvn(&stream, 32).expect("decode"),
            b"ababababzbzb".to_vec()
        );
    }

    #[test]
    fn lzvn_rejects_truncated_operands() {
        assert_eq!(lzvn_error(&[0xA0, 0x00], 8), "truncated med_d opcode");
        assert_eq!(lzvn_error(&[0x07, 0x01], 8), "truncated lrg_d opcode");
        assert_eq!(lzvn_error(&[0x01], 8), "truncated sml_d opcode");
        assert_eq!(lzvn_error(&[LZVN_LARGE_MATCH], 8), "truncated lrg_m opcode");
        assert_eq!(lzvn_error(&[0xE3, b'a'], 8), "literal overflow");
    }

    #[test]
    fn lzvn_rejects_invalid_distances() {
        assert_eq!(lzvn_error(&[0x1E], 8), "pre_d without prior distance");
        assert_eq!(lzvn_error(&[0x00, 0x00], 8), "zero match distance");
        assert_eq!(
            lzvn_error(&[0xE1, b'a', 0x00, 0x02], 8),
            "invalid match distance"
        );
        assert_eq!(lzvn_error(&[0xE1, b'a', 0x38, 0x01], 4), "match overflow");
    }

    /// Layout of one compressed LZBITMAP chunk: the 15-byte header, the
    /// literal, period, inline-bitmap and nibble areas, then the 17-byte
    /// bitmap table.
    #[derive(Default)]
    struct Chunk {
        decompressed: usize,
        literals: Vec<u8>,
        periods: Vec<u8>,
        inline: Vec<u8>,
        nibbles: Vec<u8>,
        table: [u8; LZBITMAP_BITMAP_BYTES],
    }

    fn put_u24(out: &mut Vec<u8>, value: usize) {
        out.extend_from_slice(&u32::try_from(value).expect("u24").to_le_bytes()[..3]);
    }

    impl Chunk {
        fn encode(&self) -> Vec<u8> {
            let periods = LZBITMAP_COMPRESSED_HEADER + self.literals.len();
            let inline = periods + self.periods.len();
            let nibbles = inline + self.inline.len();
            let length = nibbles + self.nibbles.len() + LZBITMAP_BITMAP_BYTES;
            self.encode_with_offsets(length, [periods, inline, nibbles])
        }

        fn encode_with_offsets(&self, length: usize, offsets: [usize; 3]) -> Vec<u8> {
            let mut out = Vec::new();
            put_u24(&mut out, length);
            put_u24(&mut out, self.decompressed);
            for offset in offsets {
                put_u24(&mut out, offset);
            }
            for area in [&self.literals, &self.periods, &self.inline, &self.nibbles] {
                out.extend_from_slice(area);
            }
            out.extend_from_slice(&self.table);
            out.resize(length, 0);
            out
        }
    }

    fn lzbitmap_stream(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut stream = LZBITMAP_MAGIC.to_vec();
        for chunk in chunks {
            stream.extend_from_slice(chunk);
        }
        stream.extend_from_slice(&[6, 0, 0, 0, 0, 0]);
        stream
    }

    fn lzbitmap_error(chunks: &[Vec<u8>]) -> &'static str {
        match decompress_lzbitmap(&lzbitmap_stream(chunks)) {
            Err(LzError::Lzbitmap(reason)) => reason,
            other => panic!("expected an LZBITMAP error, got {other:?}"),
        }
    }

    #[test]
    fn lzbitmap_decodes_inline_table_and_repeated_bitmaps() {
        let mut table = [0u8; LZBITMAP_BITMAP_BYTES];
        table[0] = 0xFF;
        let chunk = Chunk {
            decompressed: 48,
            literals: b"abcdefghXY".to_vec(),
            periods: vec![2],
            inline: vec![0b0000_0011],
            nibbles: vec![0x13, 0xF4, 0x00],
            table,
        };
        let decoded = decompress_lzbitmap(&lzbitmap_stream(&[chunk.encode()])).expect("decode");
        let mut expected = b"abcdefghXY".to_vec();
        while expected.len() < 48 {
            expected.push(expected[expected.len() - 2]);
        }
        assert_eq!(decoded, expected);
    }

    #[test]
    fn lzbitmap_rejects_malformed_chunk_headers() {
        assert_eq!(
            lzbitmap_error(&[vec![200, 0, 0]]),
            "chunk length outside the stream"
        );
        assert_eq!(
            decompress_lzbitmap(b"ZBM\x09\x06\x00")
                .map_err(|error| error.to_string())
                .err(),
            Some("lzbitmap: truncated chunk header".to_owned())
        );
        assert_eq!(
            lzbitmap_error(&[vec![6, 0, 0, 0x01, 0x80, 0x00]]),
            "chunk decompresses over the limit"
        );
        assert_eq!(
            lzbitmap_error(&[vec![8, 0, 0, 1, 0, 0, 0, 0]]),
            "compressed chunk has no header"
        );
        let chunk = Chunk {
            decompressed: 1,
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[chunk.encode_with_offsets(40, [40, 0, 0])]),
            "metadata offset outside the chunk"
        );
        assert_eq!(
            lzbitmap_error(&[chunk.encode_with_offsets(16, [0, 0, 0])]),
            "chunk too short to hold its bitmaps"
        );
    }

    #[test]
    fn lzbitmap_rejects_bitmaps_with_three_period_bytes() {
        let mut table = [0u8; LZBITMAP_BITMAP_BYTES];
        table[1] = 0b11;
        let chunk = Chunk {
            decompressed: 1,
            table,
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[chunk.encode()]),
            "bitmap wants too many period bytes"
        );
    }

    #[test]
    fn lzbitmap_rejects_metadata_running_past_the_chunk() {
        let mut table = [0u8; LZBITMAP_BITMAP_BYTES];
        table[LZBITMAP_BITMAP_BYTES - 1] = 0xFF;
        let inline = Chunk {
            decompressed: 16,
            literals: vec![1; 8],
            nibbles: vec![0x00],
            table,
            ..Chunk::default()
        };
        let length = inline.encode().len();
        let nibbles = LZBITMAP_COMPRESSED_HEADER + 8;
        assert_eq!(
            lzbitmap_error(&[inline.encode_with_offsets(length, [0, length - 1, nibbles])]),
            "inline bitmaps run past the chunk"
        );
        let periods = Chunk {
            decompressed: 4,
            nibbles: vec![0x02],
            ..Chunk::default()
        };
        let length = periods.encode().len();
        let nibbles = LZBITMAP_COMPRESSED_HEADER;
        assert_eq!(
            lzbitmap_error(&[periods.encode_with_offsets(length, [length - 1, 0, nibbles])]),
            "periods run past the chunk"
        );
        let mut table = [0u8; LZBITMAP_BITMAP_BYTES];
        table[0] = 0xFF;
        table[LZBITMAP_BITMAP_BYTES - 1] = 0x33;
        let numbers = Chunk {
            decompressed: 24,
            table,
            ..Chunk::default()
        };
        let length = numbers.encode().len();
        assert_eq!(
            lzbitmap_error(&[numbers.encode_with_offsets(length, [0, 0, length - 1])]),
            "bitmap numbers run past the chunk"
        );
    }

    #[test]
    fn lzbitmap_rejects_bad_bitmap_numbers_and_periods() {
        let marker = Chunk {
            decompressed: 4,
            nibbles: vec![0x0F],
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[marker.encode()]),
            "0xf is a repetition marker, not a bitmap"
        );
        let zero_period = Chunk {
            decompressed: 4,
            periods: vec![0],
            inline: vec![0],
            nibbles: vec![0x01],
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[zero_period.encode()]),
            "zero repetition period"
        );
        let before_output = Chunk {
            decompressed: 4,
            inline: vec![0],
            nibbles: vec![0x00],
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[before_output.encode()]),
            "period reaches before the output"
        );
        let endless = Chunk {
            decompressed: 0x8000,
            nibbles: [vec![0xF3], vec![0xFF; 1200]].concat(),
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[endless.encode()]),
            "repetition count over the limit"
        );
    }

    #[test]
    fn lzbitmap_rejects_literals_running_past_the_chunk() {
        let chunk = Chunk {
            decompressed: 64,
            inline: vec![0xFF; 8],
            nibbles: vec![0; 4],
            ..Chunk::default()
        };
        assert_eq!(
            lzbitmap_error(&[chunk.encode()]),
            "literals run past the chunk"
        );
    }

    #[test]
    fn lzfse_decodes_go_encoder_vectors() {
        let text = decompress_lzfse(&fixture("text.lzfse")).expect("text");
        assert_digest(&text, TEXT_SIZE, TEXT_SHA);
        let binary = decompress_lzfse(&fixture("binary.lzfse")).expect("binary");
        assert_digest(&binary, BINARY_SIZE, BINARY_SHA);
    }
}
