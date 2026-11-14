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

#[cfg(test)]
mod tests {
    use super::*;

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;

    fn macho(command: Option<(u32, u32, u32)>) -> Vec<u8> {
        let mut bytes = Vec::new();
        let (cmd, cmdsize, cryptid) = command.unwrap_or((0, 0, 0));
        for value in [
            MH_MAGIC_64,
            CPU_TYPE_ARM64,
            0,
            2,
            u32::from(command.is_some()),
            cmdsize,
            0,
            0,
            cmd,
            cmdsize,
            0,
            0,
            cryptid,
            0,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    fn is_encrypted(bytes: &[u8]) -> Result<bool, String> {
        let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let path = dir.path().join("binary");
        fs::write(&path, bytes).map_err(|error| error.to_string())?;
        macho_is_encrypted(&path)
    }

    #[test]
    fn detects_32_and_64_bit_encryption_commands_and_cryptid() {
        for cmd in [LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64] {
            assert!(is_encrypted(&macho(Some((cmd, 24, 1)))).unwrap());
            assert!(!is_encrypted(&macho(Some((cmd, 24, 0)))).unwrap());
        }
    }

    #[test]
    fn skips_non_arm64_and_unencrypted_machos() {
        assert!(!is_encrypted(b"data").unwrap());
        let mut other_arch = macho(None);
        other_arch[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        assert!(!is_encrypted(&other_arch).unwrap());
        assert!(!is_encrypted(&macho(None)).unwrap());
        assert!(!is_encrypted(&macho(Some((0x99, 8, 0)))).unwrap());
    }

    #[test]
    fn malformed_headers_and_commands_return_errors_or_false_at_eof() {
        assert!(
            is_encrypted(&macho(Some((0, 0, 1))))
                .unwrap_err()
                .contains("zero-size")
        );
        assert!(is_encrypted(&macho(Some((LC_ENCRYPTION_INFO_64, 24, 1)))[..34]).is_err());
        assert!(!is_encrypted(&macho(Some((LC_ENCRYPTION_INFO_64, 24, 1)))[..8]).unwrap());
        assert!(is_encrypted(&MH_MAGIC_64.to_le_bytes()).is_err());
        assert!(is_encrypted(&macho(Some((LC_ENCRYPTION_INFO_64, 24, 1)))[..48]).is_err());
    }

    #[test]
    fn recursively_finds_encrypted_binaries_and_ignores_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("Frameworks");
        fs::create_dir(&nested).unwrap();
        let encrypted = nested.join("encrypted");
        fs::write(&encrypted, macho(Some((LC_ENCRYPTION_INFO_64, 24, 1)))).unwrap();
        fs::write(dir.path().join("plain"), b"not a Mach-O").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&encrypted, dir.path().join("linked")).unwrap();

        assert_eq!(encrypted_macho_files(dir.path()).unwrap(), [encrypted]);
        assert!(encrypted_macho_files(&dir.path().join("missing")).is_err());
        assert!(macho_is_encrypted(&dir.path().join("missing")).is_err());
    }
}
