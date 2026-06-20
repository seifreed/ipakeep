//! `FairPlay` encryption detection for Mach-O files.

use super::{MACH_HEADER_64_LEN, MACH_HEADER_64_SIZE, arm64_slice_bases, read_load_command};
use crate::infrastructure::simulator::macho::reader::read_le_u32;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const LC_ENCRYPTION_INFO: u32 = 0x21;
pub(in crate::infrastructure::simulator) const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

/// Return FairPlay-encrypted Mach-O files under a path.
///
/// # Errors
///
/// Returns an error if a Mach-O file cannot be read.
pub(in crate::infrastructure::simulator) fn encrypted_macho_files(
    path: &Path,
) -> Result<Vec<PathBuf>, String> {
    let mut encrypted = Vec::new();
    encrypted_macho_files_inner(path, &mut encrypted)?;
    Ok(encrypted)
}

fn encrypted_macho_files_inner(path: &Path, encrypted: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if macho_is_encrypted(path)? {
            encrypted.push(path.to_path_buf());
        }
        return Ok(());
    }

    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
            encrypted_macho_files_inner(&entry.map_err(|e| e.to_string())?.path(), encrypted)?;
        }
    }
    Ok(())
}

pub(in crate::infrastructure::simulator) fn macho_is_encrypted(
    path: &Path,
) -> Result<bool, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bases = arm64_slice_bases(&mut file)?;
    if bases.is_empty() {
        return Ok(false);
    }
    for base in bases {
        if slice_is_encrypted(&mut file, base)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn slice_is_encrypted(file: &mut fs::File, base: u64) -> Result<bool, String> {
    file.seek(SeekFrom::Start(base))
        .map_err(|e| e.to_string())?;
    let mut header = [0_u8; MACH_HEADER_64_LEN];
    match file.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error.to_string()),
    }
    let ncmds = read_le_u32(&header, 16)?;

    let mut offset = base + MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let command = read_load_command(file, offset)?;
        if command.cmd == LC_ENCRYPTION_INFO || command.cmd == LC_ENCRYPTION_INFO_64 {
            file.seek(SeekFrom::Start(offset + 16))
                .map_err(|e| e.to_string())?;
            let mut cryptid = [0_u8; 4];
            file.read_exact(&mut cryptid).map_err(|e| e.to_string())?;
            return Ok(u32::from_le_bytes(cryptid) != 0);
        }
        if command.cmdsize == 0 {
            return Err(format!("invalid zero-size load command at {offset:#x}"));
        }
        offset += u64::from(command.cmdsize);
    }
    Ok(false)
}
