//! Selection of the arm64e slice from universal (fat) binaries.

use std::io::{self, Read};

use super::error::{MachoError, MachoResult};

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_HEADER_LEN: usize = 8;
const FAT_ARCH_LEN: usize = 20;
const FAT_HEADER_SIZE: u64 = FAT_HEADER_LEN as u64;
const FAT_ARCH_SIZE: u64 = FAT_ARCH_LEN as u64;
const MAGIC_SIZE: usize = 4;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;
const CPU_SUBTYPE_ARM64E: u32 = 2;

/// Location of the arm64e slice within a universal binary entry table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FatSlice {
    offset: u64,
    size: u64,
}

fn be32(data: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&data[at..at + 4]);
    u32::from_be_bytes(word)
}

fn index(value: u64) -> MachoResult<usize> {
    usize::try_from(value).map_err(|_| MachoError::InvalidFat("offset exceeds address space"))
}

fn is_fat(prefix: &[u8]) -> bool {
    prefix.len() >= MAGIC_SIZE && be32(prefix, 0) == FAT_MAGIC
}

fn validated_count(header: &[u8], size: u64) -> MachoResult<u64> {
    let count = u64::from(be32(header, 4));
    if count == 0 || count > (size - FAT_HEADER_SIZE) / FAT_ARCH_SIZE {
        return Err(MachoError::InvalidFat("invalid architecture count"));
    }
    Ok(count)
}

/// Returns the slice described by `arch` when it is arm64e and in bounds.
fn arm64e_entry(arch: &[u8], count: u64, size: u64) -> MachoResult<Option<FatSlice>> {
    let cpu = be32(arch, 0);
    let subtype = be32(arch, 4);
    if cpu != CPU_TYPE_ARM64 || subtype & CPU_SUBTYPE_MASK != CPU_SUBTYPE_ARM64E {
        return Ok(None);
    }
    let offset = u64::from(be32(arch, 8));
    let length = u64::from(be32(arch, 12));
    let table_end = FAT_HEADER_SIZE + count * FAT_ARCH_SIZE;
    let in_bounds = offset.checked_add(length).is_some_and(|end| end <= size);
    if length == 0 || offset < table_end || !in_bounds {
        return Err(MachoError::InvalidFat(
            "arm64e slice exceeds input size or overlaps universal binary header",
        ));
    }
    Ok(Some(FatSlice {
        offset,
        size: length,
    }))
}

/// Selects the arm64e image without parsing other architectures.
///
/// Thin images are returned unchanged.
///
/// # Errors
/// Fails when a universal header is malformed or lacks an arm64e slice.
pub fn arm64_slice(input: &[u8]) -> MachoResult<&[u8]> {
    if !is_fat(input) {
        return Ok(input);
    }
    let size = input.len() as u64;
    if size < FAT_HEADER_SIZE {
        return Err(MachoError::InvalidFat("truncated header"));
    }
    let count = validated_count(input, size)?;
    for index in 0..count {
        let start = self::index(FAT_HEADER_SIZE + index * FAT_ARCH_SIZE)?;
        let arch = &input[start..start + FAT_ARCH_LEN];
        if let Some(slice) = arm64e_entry(arch, count, size)? {
            return Ok(&input[self::index(slice.offset)?..self::index(slice.offset + slice.size)?]);
        }
    }
    Err(MachoError::MissingArm64e)
}

/// Locates a thin image or the arm64e slice using only its headers.
///
/// `read_at(offset, buffer)` must fill `buffer` from `offset` of a source of
/// `size` bytes. Returns `(offset, length)` of the image to read.
///
/// # Errors
/// Fails on read errors, malformed universal headers or a missing arm64e slice.
pub fn arm64_range<F>(mut read_at: F, size: u64) -> MachoResult<(u64, u64)>
where
    F: FnMut(u64, &mut [u8]) -> io::Result<()>,
{
    if size < MAGIC_SIZE as u64 {
        return Ok((0, size));
    }
    let mut header = [0u8; FAT_HEADER_LEN];
    read_at(0, &mut header[..MAGIC_SIZE])?;
    if !is_fat(&header) {
        return Ok((0, size));
    }
    if size < FAT_HEADER_SIZE {
        return Err(MachoError::InvalidFat("truncated header"));
    }
    read_at(MAGIC_SIZE as u64, &mut header[MAGIC_SIZE..])?;
    let count = validated_count(&header, size)?;
    let mut arch = [0u8; FAT_ARCH_LEN];
    for index in 0..count {
        read_at(FAT_HEADER_SIZE + index * FAT_ARCH_SIZE, &mut arch)?;
        if let Some(slice) = arm64e_entry(&arch, count, size)? {
            return Ok((slice.offset, slice.size));
        }
    }
    Err(MachoError::MissingArm64e)
}

/// Consumes exactly `size` bytes, retaining only the arm64e image of a
/// universal binary (or the whole thin image).
///
/// # Errors
/// Fails on short reads, malformed universal headers or a missing arm64e slice.
pub fn read_arm64<R: Read>(input: &mut R, size: usize) -> MachoResult<Vec<u8>> {
    let prefix = size.min(MAGIC_SIZE);
    let mut header = [0u8; FAT_HEADER_LEN];
    input.read_exact(&mut header[..prefix])?;
    if prefix < MAGIC_SIZE || !is_fat(&header) {
        let mut data = vec![0u8; size];
        data[..prefix].copy_from_slice(&header[..prefix]);
        input.read_exact(&mut data[prefix..])?;
        return Ok(data);
    }
    let total = size as u64;
    if total < FAT_HEADER_SIZE {
        return Err(MachoError::InvalidFat("truncated header"));
    }
    input.read_exact(&mut header[MAGIC_SIZE..])?;
    let count = validated_count(&header, total)?;
    let slice = read_fat_table(input, count, total)?;
    let table_end = FAT_HEADER_SIZE + count * FAT_ARCH_SIZE;
    discard(input, slice.offset - table_end)?;
    let mut data = vec![0u8; index(slice.size)?];
    input.read_exact(&mut data)?;
    discard(input, total - slice.offset - slice.size)?;
    Ok(data)
}

fn read_fat_table<R: Read>(input: &mut R, count: u64, size: u64) -> MachoResult<FatSlice> {
    let mut selected = None;
    let mut arch = [0u8; FAT_ARCH_LEN];
    for _ in 0..count {
        input.read_exact(&mut arch)?;
        if selected.is_none() {
            selected = arm64e_entry(&arch, count, size)?;
        }
    }
    selected.ok_or(MachoError::MissingArm64e)
}

/// I/O error message for a universal binary shorter than its fat table claims.
const TRUNCATED_UNIVERSAL: &str = "universal binary truncated";

fn discard<R: Read>(input: &mut R, count: u64) -> io::Result<()> {
    let copied = io::copy(&mut input.take(count), &mut io::sink())?;
    if copied != count {
        let truncated = io::Error::new(io::ErrorKind::UnexpectedEof, TRUNCATED_UNIVERSAL);
        return Err(truncated);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat_with_arm64e(payload: &[u8]) -> Vec<u8> {
        let offset = 0x40u32;
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        for (cpu, subtype, off) in [
            (0x0100_0007u32, 3u32, 0x30u32),
            (CPU_TYPE_ARM64, 0x8000_0002, offset),
        ] {
            data.extend_from_slice(&cpu.to_be_bytes());
            data.extend_from_slice(&subtype.to_be_bytes());
            data.extend_from_slice(&off.to_be_bytes());
            data.extend_from_slice(
                &u32::try_from(payload.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes(),
            );
            data.extend_from_slice(&0u32.to_be_bytes());
        }
        data.resize(offset as usize, 0xaa);
        data.extend_from_slice(payload);
        data.extend_from_slice(&[0xbb; 7]);
        data
    }

    #[test]
    fn thin_image_is_returned_unchanged() {
        let thin = [0xcf, 0xfa, 0xed, 0xfe, 1, 2];
        assert_eq!(arm64_slice(&thin).ok(), Some(&thin[..]));
        let mut reader = &thin[..];
        assert_eq!(
            read_arm64(&mut reader, thin.len()).ok(),
            Some(thin.to_vec())
        );
    }

    #[test]
    fn selects_arm64e_slice_three_ways() {
        let fat = fat_with_arm64e(b"arm64e!");
        assert_eq!(arm64_slice(&fat).ok(), Some(&b"arm64e!"[..]));
        let range = arm64_range(
            |offset, buffer| {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                buffer.copy_from_slice(&fat[start..start + buffer.len()]);
                Ok(())
            },
            fat.len() as u64,
        );
        assert_eq!(range.ok(), Some((0x40, 7)));
        let mut reader = &fat[..];
        assert_eq!(
            read_arm64(&mut reader, fat.len()).ok(),
            Some(b"arm64e!".to_vec())
        );
        assert_eq!(reader, b"");
    }

    #[test]
    fn rejects_fat_without_arm64e() {
        let mut fat = fat_with_arm64e(b"x");
        fat[8 + 20 + 7] = 1;
        assert!(matches!(arm64_slice(&fat), Err(MachoError::MissingArm64e)));
    }

    fn range_of(data: &[u8]) -> MachoResult<(u64, u64)> {
        range_with_size(data, data.len() as u64)
    }

    fn range_with_size(data: &[u8], size: u64) -> MachoResult<(u64, u64)> {
        arm64_range(
            |offset, buffer| {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let source = data.get(start..start + buffer.len());
                buffer.copy_from_slice(source.ok_or(io::ErrorKind::UnexpectedEof)?);
                Ok(())
            },
            size,
        )
    }

    fn read_all(data: &[u8]) -> MachoResult<Vec<u8>> {
        read_arm64(&mut &data[..], data.len())
    }

    fn is_invalid<T>(result: &MachoResult<T>, reason: &str) -> bool {
        matches!(result, Err(MachoError::InvalidFat(actual)) if *actual == reason)
    }

    #[test]
    fn short_inputs_are_thin_images() {
        let short = [0xcf, 0xfa];
        assert_eq!(range_of(&short).ok(), Some((0, 2)));
        assert_eq!(read_all(&short).ok(), Some(short.to_vec()));
        let thin = [0xcf, 0xfa, 0xed, 0xfe, 0, 0];
        assert_eq!(range_of(&thin).ok(), Some((0, 6)));
    }

    #[test]
    fn rejects_truncated_universal_headers() {
        let truncated = [0xca, 0xfe, 0xba, 0xbe, 0, 0];
        assert!(is_invalid(&arm64_slice(&truncated), "truncated header"));
        assert!(is_invalid(&range_of(&truncated), "truncated header"));
        assert!(is_invalid(&read_all(&truncated), "truncated header"));
    }

    #[test]
    fn rejects_invalid_architecture_counts() {
        let empty = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0];
        let mut excessive = fat_with_arm64e(b"x");
        excessive[7] = 0xff;
        for data in [&empty[..], &excessive[..]] {
            assert!(is_invalid(&arm64_slice(data), "invalid architecture count"));
            assert!(is_invalid(&range_of(data), "invalid architecture count"));
            assert!(is_invalid(&read_all(data), "invalid architecture count"));
        }
    }

    #[test]
    fn missing_arm64e_is_reported_by_every_reader() {
        let mut fat = fat_with_arm64e(b"x");
        fat[8 + 20 + 7] = 1;
        assert!(matches!(range_of(&fat), Err(MachoError::MissingArm64e)));
        assert!(matches!(read_all(&fat), Err(MachoError::MissingArm64e)));
    }

    #[test]
    fn read_errors_propagate() {
        let fat = fat_with_arm64e(b"arm64e!");
        assert!(matches!(
            range_with_size(&fat[..12], fat.len() as u64),
            Err(MachoError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
        let declared = fat.len() + 5;
        let short = read_arm64(&mut &fat[..], declared);
        assert!(matches!(
            short,
            Err(MachoError::Io(error)) if error.to_string() == "universal binary truncated"
        ));
    }

    #[test]
    fn rejects_overlapping_slice() {
        let mut fat = fat_with_arm64e(b"x");
        fat[8 + 20 + 11] = 4;
        assert!(matches!(arm64_slice(&fat), Err(MachoError::InvalidFat(_))));
    }
}
