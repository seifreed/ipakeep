//! Fat/universal Mach-O helpers.

use std::fs;
use std::io::{Read, Seek, SeekFrom};

use super::{CPU_TYPE_ARM64, reader::read_array};

// Fat (universal) Mach-O magic values are stored big-endian on disk.
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_ARCH_LEN: usize = 20;
const FAT_ARCH_64_LEN: usize = 32;

/// Read arm64 slice offsets from a fat header.
pub(super) fn arm64_fat_bases(file: &mut fs::File, magic: u32) -> Result<Vec<u64>, String> {
    match magic {
        FAT_MAGIC => fat_bases(file, FAT_ARCH_LEN, 4),
        FAT_MAGIC_64 => fat_bases(file, FAT_ARCH_64_LEN, 8),
        _ => Ok(Vec::new()),
    }
}

/// Read the offset of each arm64 slice from a fat header. `word_len` is 4 for
/// classic fat (`fat_arch.offset` is `u32`) and 8 for fat-64; `arch_len` is the
/// on-disk size of one arch entry.
fn fat_bases(file: &mut fs::File, arch_len: usize, word_len: usize) -> Result<Vec<u64>, String> {
    file.seek(SeekFrom::Start(4)).map_err(|e| e.to_string())?;
    let mut count = [0_u8; 4];
    file.read_exact(&mut count).map_err(|e| e.to_string())?;
    let nfat = u32::from_be_bytes(count) as usize;

    let mut bases = Vec::new();
    let mut cursor = 8_u64;
    for _ in 0..nfat {
        file.seek(SeekFrom::Start(cursor))
            .map_err(|e| e.to_string())?;
        let mut cputype = [0_u8; 4];
        file.read_exact(&mut cputype).map_err(|e| e.to_string())?;
        if u32::from_be_bytes(cputype) == CPU_TYPE_ARM64 {
            // offset field sits 8 bytes into the arch entry for both fat and fat-64.
            bases.push(read_be_word_at(file, cursor + 8, word_len)?);
        }
        cursor += arch_len as u64;
    }
    Ok(bases)
}

fn read_be_word_at(file: &mut fs::File, offset: u64, len: usize) -> Result<u64, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    match len {
        4 => Ok(u64::from(u32::from_be_bytes(read_array::<4>(&bytes)?))),
        8 => Ok(u64::from_be_bytes(read_array::<8>(&bytes)?)),
        _ => Err("unsupported fat word size".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const X86_64: u32 = 0x0100_0007;

    fn file(bytes: &[u8]) -> fs::File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn fat_header(magic: u32, count: u32) -> Vec<u8> {
        [magic.to_be_bytes(), count.to_be_bytes()].concat()
    }

    #[test]
    fn reads_arm64_offsets_from_fat32_and_fat64_entries() {
        let mut fat32 = fat_header(FAT_MAGIC, 2);
        for (cpu, offset) in [(CPU_TYPE_ARM64, 0x100_u32), (X86_64, 0x200)] {
            for word in [cpu, 0, offset, 0x40, 0] {
                fat32.extend_from_slice(&word.to_be_bytes());
            }
        }
        assert_eq!(
            arm64_fat_bases(&mut file(&fat32), FAT_MAGIC).unwrap(),
            [0x100]
        );

        let mut fat64 = fat_header(FAT_MAGIC_64, 1);
        fat64.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        fat64.extend_from_slice(&0_u32.to_be_bytes());
        fat64.extend_from_slice(&0x1_0000_0000_u64.to_be_bytes());
        fat64.extend_from_slice(&0x40_u64.to_be_bytes());
        fat64.extend_from_slice(&[0; 8]);
        assert_eq!(
            arm64_fat_bases(&mut file(&fat64), FAT_MAGIC_64).unwrap(),
            [0x1_0000_0000]
        );
    }

    #[test]
    fn ignores_unknown_magic_and_non_arm64_architectures() {
        assert!(arm64_fat_bases(&mut file(b"data"), 0).unwrap().is_empty());
        let mut bytes = fat_header(FAT_MAGIC, 1);
        for word in [X86_64, 0, 0x100, 0x40, 0] {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        assert!(
            arm64_fat_bases(&mut file(&bytes), FAT_MAGIC)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn truncated_headers_and_offsets_are_errors() {
        assert!(arm64_fat_bases(&mut file(&FAT_MAGIC.to_be_bytes()), FAT_MAGIC).is_err());
        let mut bytes = fat_header(FAT_MAGIC, 1);
        bytes.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        assert!(arm64_fat_bases(&mut file(&bytes), FAT_MAGIC).is_err());
    }

    #[test]
    fn rejects_unsupported_big_endian_word_sizes() {
        assert!(
            read_be_word_at(&mut file(&[0; 8]), 0, 3)
                .unwrap_err()
                .contains("unsupported fat word size")
        );
    }
}
