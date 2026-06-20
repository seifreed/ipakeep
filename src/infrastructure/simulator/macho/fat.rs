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
