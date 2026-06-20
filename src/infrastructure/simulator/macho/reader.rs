//! Thin Mach-O reader helpers.

use std::fs;
use std::io::{Read, Seek, SeekFrom};

use super::MACH_HEADER_64_LEN;

#[derive(Debug)]
pub(crate) struct MachHeader {
    pub(crate) ncmds: u32,
    pub(crate) sizeofcmds: u32,
}

#[derive(Debug)]
pub(crate) struct LoadCommand {
    pub(crate) cmd: u32,
    pub(crate) cmdsize: u32,
}

pub(crate) fn read_mach_header_at(
    file: &mut fs::File,
    base: u64,
) -> Result<Option<MachHeader>, String> {
    file.seek(SeekFrom::Start(base))
        .map_err(|e| e.to_string())?;
    let mut bytes = [0_u8; MACH_HEADER_64_LEN];
    match file.read_exact(&mut bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }

    Ok(Some(MachHeader {
        ncmds: read_le_u32(&bytes, 16)?,
        sizeofcmds: read_le_u32(&bytes, 20)?,
    }))
}

/// Read the `platform` field of an `LC_BUILD_VERSION` load command at
/// `offset` (the offset of the command itself, not its data section).
pub(crate) fn read_platform_at(file: &mut fs::File, offset: u64) -> Result<u32, String> {
    file.seek(SeekFrom::Start(offset + 8))
        .map_err(|e| e.to_string())?;
    let mut bytes = [0_u8; 4];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
pub(crate) fn read_mach_header(file: &mut fs::File) -> Result<Option<MachHeader>, String> {
    read_mach_header_at(file, 0)
}

pub(crate) fn read_load_command(file: &mut fs::File, offset: u64) -> Result<LoadCommand, String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = [0_u8; 8];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(LoadCommand {
        cmd: read_le_u32(&bytes, 0)?,
        cmdsize: read_le_u32(&bytes, 4)?,
    })
}

pub(crate) fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "invalid u32 offset".to_string())?;
    let word = bytes
        .get(offset..end)
        .ok_or_else(|| "missing u32 field".to_string())?;
    Ok(u32::from_le_bytes(read_array::<4>(word)?))
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes, got {}", bytes.len()))
}
