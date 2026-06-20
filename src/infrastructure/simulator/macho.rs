//! Mach-O helpers for iOS-device to iOS-Simulator conversion.

mod dylib;
mod encryption;
mod fat;
mod reader;

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub(super) use dylib::ensure_simulator_dylib;
#[cfg(test)]
pub(super) use dylib::{AdHocSigner, ensure_simulator_dylib_with_signer, thin_to_arm64_inplace};
pub(super) use encryption::encrypted_macho_files;
#[cfg(test)]
pub(super) use encryption::{LC_ENCRYPTION_INFO_64, macho_is_encrypted};
pub(super) use fat::FAT_MAGIC;
use fat::{FAT_MAGIC_64, arm64_fat_bases};
use reader::read_le_u32;
#[cfg(test)]
pub(super) use reader::read_mach_header;
pub(super) use reader::{read_load_command, read_mach_header_at, read_platform_at};

pub(super) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(super) const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub(super) const LC_BUILD_VERSION: u32 = 0x32;
pub(super) const PLATFORM_IOSSIMULATOR: u32 = 7;
pub(super) const SIMULATOR_VERSION_14_0: u32 = 0x000e_0000;
pub(super) const MACH_HEADER_64_SIZE: u64 = 32;
pub(super) const MACH_HEADER_64_LEN: usize = 32;
pub(super) const BUILD_VERSION_COMMAND_SIZE: u32 = 24;
pub(super) const BUILD_VERSION_COMMAND_LEN: usize = 24;

/// Convert an arm64 Mach-O file (thin or universal/fat) to the iOS Simulator
/// platform by flipping `LC_BUILD_VERSION.platform` to `PLATFORM_IOSSIMULATOR`
/// in every arm64 slice. Preserves the existing load-command size and tools
/// array so the command chain stays intact.
///
/// # Errors
///
/// Returns an error if the file looks like a convertible Mach-O but cannot be
/// read or written.
pub(super) fn convert_macho_file(path: &Path) -> Result<bool, String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    let bases = arm64_slice_bases(&mut file)?;
    if bases.is_empty() {
        return Ok(false);
    }

    let mut converted = false;
    for base in bases {
        converted |= convert_slice_at(&mut file, base, path)?;
    }
    Ok(converted)
}

/// File offsets of every arm64 Mach-O slice in `file`: `[0]` for a thin arm64
/// binary, one entry per arm64 arch in a fat archive, or empty for non-arm64 /
/// non-Mach-O files.
///
/// # Errors
///
/// Returns an error if the file header cannot be read.
pub(super) fn arm64_slice_bases(file: &mut fs::File) -> Result<Vec<u64>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut magic = [0_u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Vec::new()),
        Err(error) => return Err(error.to_string()),
    }

    let magic_be = u32::from_be_bytes(magic);
    match magic_be {
        FAT_MAGIC | FAT_MAGIC_64 => arm64_fat_bases(file, magic_be),
        _ if u32::from_le_bytes(magic) == MH_MAGIC_64 => {
            file.seek(SeekFrom::Start(4)).map_err(|e| e.to_string())?;
            let mut cpu = [0_u8; 4];
            file.read_exact(&mut cpu).map_err(|e| e.to_string())?;
            if u32::from_le_bytes(cpu) == CPU_TYPE_ARM64 {
                Ok(vec![0])
            } else {
                Ok(Vec::new())
            }
        }
        _ => Ok(Vec::new()),
    }
}

/// Convert the arm64 Mach-O slice starting at `base` in `file` to the iOS
/// Simulator platform. Returns `true` if the slice was a convertible arm64
/// Mach-O.
///
/// # Errors
///
/// Returns an error if a load command is malformed or a write fails.
fn convert_slice_at(file: &mut fs::File, base: u64, path: &Path) -> Result<bool, String> {
    file.seek(SeekFrom::Start(base))
        .map_err(|e| e.to_string())?;
    let mut header_bytes = [0_u8; MACH_HEADER_64_LEN];
    match file.read_exact(&mut header_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error.to_string()),
    }

    let magic = read_le_u32(&header_bytes, 0)?;
    let cpu_type = read_le_u32(&header_bytes, 4)?;
    if magic != MH_MAGIC_64 || cpu_type != CPU_TYPE_ARM64 {
        return Ok(false);
    }

    let ncmds = read_le_u32(&header_bytes, 16)?;

    let mut offset = base + MACH_HEADER_64_SIZE;
    for _ in 0..ncmds {
        let command = read_load_command(file, offset)?;
        if command.cmd == LC_BUILD_VERSION {
            patch_build_version(file, offset)?;
            return Ok(true);
        }
        if command.cmdsize == 0 {
            return Err(format!(
                "{}: invalid zero-size load command at {offset:#x}",
                path.display()
            ));
        }
        offset += u64::from(command.cmdsize);
    }

    // No LC_BUILD_VERSION present: append one at the end of the load-command
    // region and bump the header counts. Relies on the padding linkers leave
    // between the load commands and the first section, so the larger
    // sizeofcmds does not overrun section data.
    insert_build_version(file, base, offset, &header_bytes, path)?;
    Ok(true)
}

/// Patch `platform`/`minos`/`sdk` of an existing `LC_BUILD_VERSION` in place,
/// preserving `cmd`, `cmdsize` and `ntools` (and any trailing tools array) so
/// the load-command chain is not corrupted.
fn patch_build_version(file: &mut fs::File, offset: u64) -> Result<(), String> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = [0_u8; BUILD_VERSION_COMMAND_LEN];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    bytes[8..12].copy_from_slice(&PLATFORM_IOSSIMULATOR.to_le_bytes());
    bytes[12..16].copy_from_slice(&SIMULATOR_VERSION_14_0.to_le_bytes());
    bytes[16..20].copy_from_slice(&SIMULATOR_VERSION_14_0.to_le_bytes());
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes).map_err(|e| e.to_string())
}

/// Append a new `LC_BUILD_VERSION` (platform = iOS Simulator, minos/sdk 14.0)
/// at `offset` and update the slice's Mach-O header counts.
fn insert_build_version(
    file: &mut fs::File,
    base: u64,
    offset: u64,
    header_bytes: &[u8; MACH_HEADER_64_LEN],
    path: &Path,
) -> Result<(), String> {
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    if offset != file_len {
        return Err(format!(
            "{}: cannot insert LC_BUILD_VERSION without rewriting Mach-O layout",
            path.display()
        ));
    }

    let values = [
        LC_BUILD_VERSION,
        BUILD_VERSION_COMMAND_SIZE,
        PLATFORM_IOSSIMULATOR,
        SIMULATOR_VERSION_14_0,
        SIMULATOR_VERSION_14_0,
        0,
    ];
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    for value in values {
        file.write_all(&value.to_le_bytes())
            .map_err(|e| e.to_string())?;
    }

    let ncmds = read_le_u32(header_bytes, 16)? + 1;
    let sizeofcmds = read_le_u32(header_bytes, 20)? + BUILD_VERSION_COMMAND_SIZE;
    file.seek(SeekFrom::Start(base + 16))
        .map_err(|e| e.to_string())?;
    file.write_all(&ncmds.to_le_bytes())
        .map_err(|e| e.to_string())?;
    file.write_all(&sizeofcmds.to_le_bytes())
        .map_err(|e| e.to_string())
}

pub(super) fn is_macho_file(path: &Path) -> Result<bool, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(!arm64_slice_bases(&mut file)?.is_empty())
}

/// Returns `true` when the arm64 slice at `base` carries
/// `LC_BUILD_VERSION.platform == PLATFORM_IOSSIMULATOR`.
pub(super) fn is_arm64_simulator_binary(path: &Path) -> Result<bool, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bases = arm64_slice_bases(&mut file)?;
    let Some(&base) = bases.first() else {
        return Ok(false);
    };
    let header = read_mach_header_at(&mut file, base)?;
    let Some(header) = header else {
        return Ok(false);
    };
    let mut offset = base + MACH_HEADER_64_SIZE;
    let command_limit = offset + u64::from(header.sizeofcmds);
    for _ in 0..header.ncmds {
        if offset + 8 > command_limit {
            return Err(format!(
                "{}: load command header extends beyond sizeofcmds",
                path.display()
            ));
        }
        let command = read_load_command(&mut file, offset)?;
        if command.cmdsize == 0 {
            return Err(format!(
                "{}: invalid zero-size load command at {offset:#x}",
                path.display()
            ));
        }
        if offset + u64::from(command.cmdsize) > command_limit {
            return Err(format!(
                "{}: load command extends beyond sizeofcmds",
                path.display()
            ));
        }
        if command.cmd == LC_BUILD_VERSION {
            if command.cmdsize < BUILD_VERSION_COMMAND_SIZE {
                return Err(format!(
                    "{}: LC_BUILD_VERSION command is too small",
                    path.display()
                ));
            }
            return Ok(read_platform_at(&mut file, offset)? == PLATFORM_IOSSIMULATOR);
        }
        offset += u64::from(command.cmdsize);
    }
    Ok(false)
}
