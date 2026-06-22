//! In-memory, fat-aware Mach-O parser for the `decrypt` flow.
//!
//! Models the same byte layout the `simulator::macho` module reads from
//! `fs::File`, but over an owned `&[u8]` (a zip entry held in memory) and
//! exposing the extra fields the decrypt bridge needs: per-slice arch, the full
//! `LC_ENCRYPTION_INFO(_64)` triple, and `LC_BUILD_VERSION` `minos`/`sdk`.
//!
//! `ponytail:` constants are duplicated from `simulator::macho` (well-known
//! Mach-O magic numbers) to keep the two modules decoupled — promote to a shared
//! `infrastructure::macho` module only if a third consumer appears.

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;

const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_MASK: u32 = 0x00ff_ffff;
const CPU_SUBTYPE_ARM64E: u32 = 2;

const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_BUILD_VERSION: u32 = 0x32;

const MACH_HEADER_64_LEN: u64 = 32;

/// The `LC_ENCRYPTION_INFO(_64)` payload plus the absolute file offset of the
/// command itself, so a patcher can zero `cryptid` in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EncryptionInfo {
    /// Offset of the encrypted region, relative to the slice base.
    pub(super) cryptoff: u32,
    /// Size of the encrypted region in bytes.
    pub(super) cryptsize: u32,
    /// Non-zero when the slice is FairPlay-encrypted.
    pub(super) cryptid: u32,
    /// Absolute offset (into the whole Mach-O bytes) of the load command.
    /// `cryptid` lives at `command_offset + 16`.
    pub(super) command_offset: u64,
}

/// `LC_BUILD_VERSION` `minos`/`sdk`, each a packed `xxxx.yy.zz` nibble version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BuildVersion {
    pub(super) minos: u32,
    pub(super) sdk: u32,
}

/// One architecture slice of a thin or fat Mach-O.
#[derive(Debug, Clone)]
pub(super) struct Slice {
    /// `arm64`, `arm64e`, `x86_64`, or `cpu-<type>:<subtype>` for the unknown.
    pub(super) arch: String,
    /// Offset of the slice's Mach-O header within the whole bytes.
    pub(super) base: u64,
    pub(super) encryption: Option<EncryptionInfo>,
    pub(super) build_version: Option<BuildVersion>,
}

impl Slice {
    /// File offset of the encrypted region within the whole Mach-O bytes.
    pub(super) fn crypt_range(&self) -> Option<(usize, usize)> {
        let info = self.encryption?;
        let start = usize::try_from(self.base + u64::from(info.cryptoff)).ok()?;
        let end = start.checked_add(usize::try_from(info.cryptsize).ok()?)?;
        Some((start, end))
    }
}

/// True when `bytes` begins with a thin-64 or fat Mach-O magic.
pub(super) fn is_macho(bytes: &[u8]) -> bool {
    let Some(magic_be) = read_be_u32(bytes, 0) else {
        return false;
    };
    matches!(magic_be, FAT_MAGIC | FAT_MAGIC_64) || read_le_u32(bytes, 0) == Some(MH_MAGIC_64)
}

/// Parse every architecture slice of a thin or fat Mach-O.
///
/// # Errors
///
/// Returns an error when the header or a load command is truncated.
pub(super) fn parse(bytes: &[u8]) -> Result<Vec<Slice>, String> {
    let magic_be = read_be_u32(bytes, 0).ok_or("file too small for a Mach-O")?;
    match magic_be {
        FAT_MAGIC => parse_fat(bytes, 4),
        FAT_MAGIC_64 => parse_fat(bytes, 8),
        _ if read_le_u32(bytes, 0) == Some(MH_MAGIC_64) => Ok(vec![parse_slice(bytes, 0)?]),
        _ => Err("not a 64-bit Mach-O".into()),
    }
}

fn parse_fat(bytes: &[u8], offset_width: usize) -> Result<Vec<Slice>, String> {
    let nfat = u64::from(read_be_u32(bytes, 4).ok_or("truncated fat header")?);
    // Classic fat arch is 20 bytes, fat-64 is 32 bytes; both keep cputype at +0,
    // cpusubtype at +4, and the slice offset at +8.
    let arch_len: u64 = if offset_width == 8 { 32 } else { 20 };
    let mut slices = Vec::new();
    let mut cursor = 8_u64;
    for _ in 0..nfat {
        let base: usize = cursor.try_into().map_err(|_| "fat offset overflow")?;
        let slice_off = read_be_word(bytes, base + 8, offset_width).ok_or("truncated fat arch")?;
        slices.push(parse_slice(bytes, slice_off)?);
        cursor += arch_len;
    }
    Ok(slices)
}

fn parse_slice(bytes: &[u8], base: u64) -> Result<Slice, String> {
    let header = usize::try_from(base).map_err(|_| "slice offset overflow")?;
    let cputype = read_le_u32(bytes, header + 4).ok_or("truncated Mach-O header")?;
    let cpusubtype = read_le_u32(bytes, header + 8).ok_or("truncated Mach-O header")?;
    let arch = arch_label(cputype, cpusubtype);

    let mut encryption = None;
    let mut build_version = None;

    if read_le_u32(bytes, header) == Some(MH_MAGIC_64) {
        let ncmds = read_le_u32(bytes, header + 16).ok_or("truncated Mach-O header")?;
        let mut offset = base + MACH_HEADER_64_LEN;
        for _ in 0..ncmds {
            let cmd_at = usize::try_from(offset).map_err(|_| "load command offset overflow")?;
            let cmd = read_le_u32(bytes, cmd_at).ok_or("truncated load command")?;
            let cmdsize = read_le_u32(bytes, cmd_at + 4).ok_or("truncated load command")?;
            if cmdsize == 0 {
                return Err(format!("invalid zero-size load command at {offset:#x}"));
            }
            match cmd {
                LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                    encryption = Some(EncryptionInfo {
                        cryptoff: read_le_u32(bytes, cmd_at + 8).ok_or("truncated crypt info")?,
                        cryptsize: read_le_u32(bytes, cmd_at + 12).ok_or("truncated crypt info")?,
                        cryptid: read_le_u32(bytes, cmd_at + 16).ok_or("truncated crypt info")?,
                        command_offset: offset,
                    });
                }
                LC_BUILD_VERSION => {
                    build_version = Some(BuildVersion {
                        minos: read_le_u32(bytes, cmd_at + 12).ok_or("truncated build version")?,
                        sdk: read_le_u32(bytes, cmd_at + 16).ok_or("truncated build version")?,
                    });
                }
                _ => {}
            }
            offset += u64::from(cmdsize);
        }
    }

    Ok(Slice {
        arch,
        base,
        encryption,
        build_version,
    })
}

fn arch_label(cputype: u32, cpusubtype: u32) -> String {
    match (cputype, cpusubtype & CPU_SUBTYPE_MASK) {
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e".into(),
        (CPU_TYPE_ARM64, _) => "arm64".into(),
        (CPU_TYPE_X86_64, _) => "x86_64".into(),
        (cpu, sub) => format!("cpu-{cpu:#x}:{sub:#x}"),
    }
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes
        .get(offset..end)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes
        .get(offset..end)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_be_word(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    match width {
        4 => read_be_u32(bytes, offset).map(u64::from),
        8 => {
            let end = offset.checked_add(8)?;
            bytes
                .get(offset..end)
                .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        }
        _ => None,
    }
}
