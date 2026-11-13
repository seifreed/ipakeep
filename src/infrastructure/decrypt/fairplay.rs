//! Self-contained offline `FairPlay` decryption of App Store Mach-O binaries.
//!
//! Given an IPA's SINF and SUPF/SUPP records and a 16-byte per-account
//! credential, this decrypts every encrypted page of one Mach-O slice on the
//! host, with no device involved. It is a faithful 1:1 port of the Go
//! `internal/fairplay` package (itself a port of the open-source
//! `fairplay-decrypt` research), matching its byte-for-byte behaviour.
//!
//! A fat binary is thinned to a single slice (plain `arm64`, else `arm64e`,
//! else `arm64_32`, else 32-bit ARM) exactly as the on-device helper does.

use aes::Aes128;
use aes::cipher::KeyInit;

/// Fixed length, in bytes, of a `FairPlay` account credential.
pub const CREDENTIAL_SIZE: usize = 16;

const CPU_TYPE_ARM: u32 = 0x0000_000C;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000C;
const CPU_SUBTYPE_ARMV7: u32 = 9;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_MASK: u32 = 0x00FF_FFFF;
const PAGE_SIZE: usize = 4096;

const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const MACHO_MAGIC_LE: u32 = 0xFEED_FACE;
const MACHO_MAGIC_64_LE: u32 = 0xFEED_FACF;

const ROUND_SELECTORS: [[[usize; 2]; 4]; 4] = [
    [[0, 1], [2, 3], [4, 5], [6, 7]],
    [[2, 1], [0, 3], [4, 7], [6, 5]],
    [[2, 0], [4, 1], [6, 3], [7, 5]],
    [[1, 2], [4, 0], [7, 3], [5, 6]],
];
const ROUND_CONSTANTS: [u32; 4] = [0x6854_7C2E, 0x7E05_E1DE, 0xD495_038B, 0x0AB2_4ADD];
const FINAL_SELECTORS: [[usize; 4]; 4] = [[0, 1, 2, 3], [0, 2, 4, 6], [0, 3, 5, 7], [4, 5, 6, 7]];
const FINAL_CONSTANTS: [u32; 4] = [0x5B71_98C7, 0xEB5D_E22C, 0x0F8A_A8FA, 0xF6E1_BB3F];

/// The slice selected for decryption and its encrypted region within a
/// (possibly fat) Mach-O.
struct MachoInfo {
    base: usize,
    size: usize,
    cpu: u32,
    subtype: u32,
    crypt_off: usize,
    crypt_size: usize,
    cryptid_offset: usize,
}

struct ArmSlice {
    base: usize,
    size: usize,
    cpu: u32,
    subtype: u32,
}

/// A parsed MP4-style atom: its tag and the `[start, end)` byte range of its
/// payload within the backing buffer.
struct Atom {
    tag: [u8; 4],
    start: usize,
    end: usize,
}

fn be_u32(data: &[u8], off: usize) -> Result<u32, String> {
    data.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "unexpected end of data".to_string())
}

fn be_u64(data: &[u8], off: usize) -> Result<u64, String> {
    data.get(off..off + 8)
        .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or_else(|| "unexpected end of data".to_string())
}

fn le_u32(data: &[u8], off: usize) -> Result<u32, String> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| "unexpected end of data".to_string())
}

/// Parse the architecture table (fat) or single header (thin) of a Mach-O,
/// returning every slice it describes, unclassified.
fn collect_slices(data: &[u8]) -> Result<Vec<ArmSlice>, String> {
    let mut raw = Vec::new();

    match data {
        [0xca, 0xfe, 0xba, 0xbe, ..] => {
            let count = be_u32(data, 4)?;
            if count == 0 || count > 16 || 8 + count as usize * 20 > data.len() {
                return Err("invalid FAT32 architecture table".to_string());
            }
            for i in 0..count as usize {
                let off = 8 + i * 20;
                raw.push(ArmSlice {
                    cpu: be_u32(data, off)?,
                    subtype: be_u32(data, off + 4)?,
                    base: be_u32(data, off + 8)? as usize,
                    size: be_u32(data, off + 12)? as usize,
                });
            }
        }
        [0xca, 0xfe, 0xba, 0xbf, ..] => {
            let count = be_u32(data, 4)?;
            if count == 0 || count > 16 || 8 + count as usize * 32 > data.len() {
                return Err("invalid FAT64 architecture table".to_string());
            }
            for i in 0..count as usize {
                let off = 8 + i * 32;
                raw.push(ArmSlice {
                    cpu: be_u32(data, off)?,
                    subtype: be_u32(data, off + 4)?,
                    base: usize::try_from(be_u64(data, off + 8)?)
                        .map_err(|_| "Mach-O slice offset too large".to_string())?,
                    size: usize::try_from(be_u64(data, off + 16)?)
                        .map_err(|_| "Mach-O slice size too large".to_string())?,
                });
            }
        }
        [m0, 0xfa, 0xed, 0xfe, ..] if (*m0 == 0xce || *m0 == 0xcf) && data.len() >= 28 => {
            raw.push(ArmSlice {
                cpu: le_u32(data, 4)?,
                subtype: le_u32(data, 8)?,
                base: 0,
                size: data.len(),
            });
        }
        _ => return Err("not a supported ARM Mach-O".to_string()),
    }

    Ok(raw)
}

/// Choose the one slice to decrypt: plain `arm64`, else `arm64e`, else
/// `arm64_32`, else 32-bit ARM (preferring `armv7` when several are present).
fn select_slice(raw: Vec<ArmSlice>) -> Result<ArmSlice, String> {
    let mut plain = Vec::new();
    let mut arm64e = Vec::new();
    let mut arm64_32 = Vec::new();
    let mut arm32 = Vec::new();

    for slice in raw {
        if slice.cpu == CPU_TYPE_ARM64 && slice.subtype & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E {
            arm64e.push(slice);
        } else if slice.cpu == CPU_TYPE_ARM64 {
            plain.push(slice);
        } else if slice.cpu == CPU_TYPE_ARM64_32 {
            arm64_32.push(slice);
        } else if slice.cpu == CPU_TYPE_ARM {
            arm32.push(slice);
        }
    }

    let mut slices = if !plain.is_empty() {
        plain
    } else if !arm64e.is_empty() {
        arm64e
    } else if !arm64_32.is_empty() {
        arm64_32
    } else {
        arm32
    };

    // Fat 32-bit apps pair armv7 with armv7s or armv6; armv7 runs on every
    // device that runs either.
    if slices.len() > 1 && slices[0].cpu == CPU_TYPE_ARM {
        slices.retain(|slice| slice.subtype & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARMV7);
    }

    if slices.len() != 1 {
        return Err(format!(
            "expected one ARM slice to decrypt, found {}",
            slices.len()
        ));
    }

    Ok(slices.remove(0))
}

/// Parse the chosen slice's header and load commands and locate its encrypted
/// region. Returns `Ok(None)` when the slice is not actively encrypted (no
/// encryption command, or exactly one with `cryptid == 0`).
fn parse_encryption(data: &[u8], chosen: &ArmSlice) -> Result<Option<MachoInfo>, String> {
    // arm64_32 uses the 32-bit header and load command, like 32-bit ARM.
    let is64 = chosen.cpu == CPU_TYPE_ARM64;
    let (header_size, enc_cmd, want_magic) = if is64 {
        (32usize, LC_ENCRYPTION_INFO_64, MACHO_MAGIC_64_LE)
    } else {
        (28usize, LC_ENCRYPTION_INFO, MACHO_MAGIC_LE)
    };

    let base = chosen.base;
    let slice_size = chosen.size;

    if base > data.len() || slice_size > data.len() - base || header_size > data.len() - base {
        return Err("Mach-O slice exceeds file".to_string());
    }

    let magic = le_u32(data, base)?;
    let cpu = le_u32(data, base + 4)?;
    let ncmds = le_u32(data, base + 16)?;
    let sizeofcmds = le_u32(data, base + 20)? as usize;

    if magic != want_magic || cpu != chosen.cpu || ncmds > 1000 {
        return Err("invalid Mach-O slice header".to_string());
    }

    let mut pos = base + header_size;
    let commands_end = pos + sizeofcmds;
    if commands_end > base + slice_size {
        return Err("load commands exceed Mach-O slice".to_string());
    }

    let mut crypt_off = 0usize;
    let mut crypt_size = 0usize;
    let mut cryptid = 0u32;
    let mut cryptid_offset = 0usize;
    let mut found = 0u32;

    for _ in 0..ncmds {
        if pos + 8 > commands_end {
            return Err("truncated load command".to_string());
        }

        let cmd = le_u32(data, pos)?;
        let cmd_size = le_u32(data, pos + 4)? as usize;
        if cmd_size < 8 || pos + cmd_size > commands_end {
            return Err("invalid load command".to_string());
        }

        if cmd == enc_cmd {
            if cmd_size < 20 {
                return Err("short encryption info command".to_string());
            }
            crypt_off = le_u32(data, pos + 8)? as usize;
            crypt_size = le_u32(data, pos + 12)? as usize;
            cryptid = le_u32(data, pos + 16)?;
            cryptid_offset = pos + 16;
            found += 1;
        }

        pos += cmd_size;
    }

    if pos != commands_end {
        return Err("load command sizes do not match Mach-O header".to_string());
    }

    if found == 0 || (found == 1 && cryptid == 0) {
        return Ok(None);
    }

    if found != 1 {
        return Err(format!("expected one encryption command, found {found}"));
    }

    if cryptid != 1 || crypt_size == 0 || !crypt_size.is_multiple_of(PAGE_SIZE) {
        return Err(format!("unsupported cryptid/size: {cryptid}, {crypt_size}"));
    }

    if crypt_off + crypt_size > slice_size || cryptid_offset >= base + crypt_off {
        return Err("invalid encrypted region bounds".to_string());
    }

    Ok(Some(MachoInfo {
        base,
        size: slice_size,
        cpu: chosen.cpu,
        subtype: chosen.subtype,
        crypt_off,
        crypt_size,
        cryptid_offset,
    }))
}

/// Locate the encrypted region of the slice the output is thinned to. Returns
/// `Ok(None)` when that slice carries no active encryption command.
fn arm_encryption_info(data: &[u8]) -> Result<Option<MachoInfo>, String> {
    let chosen = select_slice(collect_slices(data)?)?;
    parse_encryption(data, &chosen)
}

/// Parse the child atoms contained in `data[start..end]`.
fn atom_children(data: &[u8], start: usize, end: usize) -> Result<Vec<Atom>, String> {
    let mut out = Vec::new();

    let mut offset = start;
    while offset < end {
        if offset + 8 > end {
            return Err("truncated SINF atom".to_string());
        }

        let size = be_u32(data, offset)? as usize;
        if size < 8 || offset + size > end {
            return Err(format!("invalid SINF atom size at {offset:#x}"));
        }

        let mut tag = [0u8; 4];
        tag.copy_from_slice(&data[offset + 4..offset + 8]);
        out.push(Atom {
            tag,
            start: offset + 8,
            end: offset + size,
        });
        offset += size;
    }

    Ok(out)
}

/// Return the bytes of the single `schi` field tagged `wanted`.
fn sinf_field(sinf: &[u8], wanted: [u8; 4]) -> Result<&[u8], String> {
    let roots = atom_children(sinf, 0, sinf.len())?;
    if roots.len() != 1 || &roots[0].tag != b"sinf" {
        return Err("expected outer sinf atom".to_string());
    }

    let children = atom_children(sinf, roots[0].start, roots[0].end)?;

    let mut schi: Option<&Atom> = None;
    for child in &children {
        if &child.tag == b"schi" {
            if schi.is_some() {
                return Err("expected one schi container".to_string());
            }
            schi = Some(child);
        }
    }
    let schi = schi.ok_or_else(|| "expected one schi container".to_string())?;

    let fields = atom_children(sinf, schi.start, schi.end)?;

    let mut matched: Option<&Atom> = None;
    for field in &fields {
        if field.tag == wanted {
            if matched.is_some() {
                return Err(format!(
                    "expected one {:?} field",
                    String::from_utf8_lossy(&wanted)
                ));
            }
            matched = Some(field);
        }
    }
    let matched = matched
        .ok_or_else(|| format!("expected one {:?} field", String::from_utf8_lossy(&wanted)))?;

    Ok(&sinf[matched.start..matched.end])
}

/// Unwrap the account credential against a SINF priv record to obtain the
/// per-app 16-byte work key.
fn derive_work16(credential: &[u8], sinf: &[u8]) -> Result<[u8; 16], String> {
    let name_field = sinf_field(sinf, *b"name")?;
    let name = match name_field.iter().position(|&b| b == 0) {
        Some(i) => &name_field[..i],
        None => name_field,
    };

    let iviv = sinf_field(sinf, *b"iviv")?;
    let raw_priv_full = sinf_field(sinf, *b"priv")?;

    let raw_priv: &[u8] = match raw_priv_full.len() {
        448 => raw_priv_full,
        440 => {
            if !raw_priv_full[raw_priv_full.len() - 8..]
                .iter()
                .all(|&b| b == 0)
            {
                return Err("invalid SINF priv-record trailer".to_string());
            }
            &raw_priv_full[..raw_priv_full.len() - 8]
        }
        _ => return Err("unsupported SINF priv-record length".to_string()),
    };

    if credential.len() != 16 || iviv.len() != 16 {
        return Err("invalid SINF priv-record dimensions".to_string());
    }

    let mut md_input = Vec::with_capacity(name.len() + iviv.len());
    md_input.extend_from_slice(name);
    md_input.extend_from_slice(iviv);
    let iv = md5::compute(&md_input);

    let mut key = [0u8; 16];
    for (dst, &src) in key.iter_mut().zip(credential.iter()) {
        *dst = src ^ b'0';
    }

    let clear = aes128_cbc_decrypt_no_pad(&key, &iv.0, raw_priv)?;

    if clear.len() < 48
        || &clear[0..4] != b"itun"
        || &clear[20..24] != b"key "
        || &clear[44..48] != b"iviv"
    {
        return Err("credential does not decode this SINF priv record".to_string());
    }

    let mut work = [0u8; 16];
    work.copy_from_slice(&clear[24..40]);
    Ok(work)
}

/// Offset of the 32-byte key for `absolute_page` in a SUPP (one table indexing
/// every 4 KB page from offset 0; v01 carries a 20-byte SHA-1 that v04 omits).
fn pclass_page_key_offset(supp: &[u8], absolute_page: usize) -> Result<usize, String> {
    if supp.len() < 8 || (supp[0] != 1 && supp[0] != 4) {
        return Err("unsupported SUPP format".to_string());
    }

    let mut pos = 4usize;
    if supp[0] == 1 {
        pos += 20;
    }

    if pos + 4 > supp.len() {
        return Err("truncated SUPP header".to_string());
    }

    let count = be_u32(supp, pos)? as usize;
    if count == 0 || count > (1 << 20) || pos + 4 + count * 32 > supp.len() {
        return Err("invalid SUPP page count".to_string());
    }

    if absolute_page >= count {
        return Err("SUPP page key missing".to_string());
    }

    Ok(pos + 4 + 32 * absolute_page)
}

/// Locate the per-page record block of the slice with the given cputype and
/// subtype in a SUPF (subtypes compared without their capability bits).
fn arm_supf_record_offset(
    supf: &[u8],
    required_pages: usize,
    wanted_cpu: u32,
    wanted_subtype: u32,
) -> Result<usize, String> {
    if supf.len() < 12 || (supf[0] != 3 && supf[0] != 5) {
        return Err("unsupported SUPF format".to_string());
    }

    let magic = &supf[1..4];
    if !matches!(
        magic,
        b"319" | b"322" | b"502" | b"507" | b"510" | b"611" | b"612"
    ) {
        return Err("unsupported SUPF format".to_string());
    }

    let header_size = if supf[0] == 3 { 32usize } else { 12usize };

    let count = be_u32(supf, 8)?;
    if count == 0 || count > 16 {
        return Err("invalid SUPF architecture count".to_string());
    }

    let mut pos = 12usize;
    for _ in 0..count {
        if pos + 4 + header_size > supf.len() {
            return Err("truncated SUPF architecture header".to_string());
        }

        let length = be_u32(supf, pos)? as usize;
        let cpu = be_u32(supf, pos + 4)?;
        let subtype = be_u32(supf, pos + 8)?;
        if length < header_size || pos + 4 + length > supf.len() {
            return Err("invalid SUPF architecture length".to_string());
        }

        let pages = be_u32(supf, pos + header_size)? as usize;
        if cpu == wanted_cpu && subtype & CPU_SUBTYPE_MASK == wanted_subtype & CPU_SUBTYPE_MASK {
            if pages < required_pages || length < header_size + pages * 32 {
                return Err("SUPF page records are incomplete".to_string());
            }
            return Ok(pos + 4 + header_size);
        }

        pos += length + 4;
    }

    Err(format!(
        "SUPF record missing for cputype=0x{wanted_cpu:x} cpusubtype=0x{wanted_subtype:x}"
    ))
}

/// Build the three AES source blocks for a page from its 16-byte wrapped
/// record and absolute page index. `wrapped` must be exactly 16 bytes.
fn source_blocks(wrapped: &[u8], absolute_index: u32) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let page_offset = (u64::from(absolute_index) << 12).to_be_bytes();

    let mut first = [0u8; 16];
    first[..8].copy_from_slice(&wrapped[8..16]);
    first[8..].copy_from_slice(&page_offset);

    let mut second = [0u8; 16];
    second.copy_from_slice(&wrapped[..16]);

    let mut third = [0u8; 16];
    third[..8].copy_from_slice(&page_offset);
    third[8..].copy_from_slice(&wrapped[..8]);

    (first, second, third)
}

/// Mix a block as eight big-endian 16-bit words: four rounds over word pairs,
/// then one over 32-bit word quartets, mixed back into the input.
fn finish(state: &[u8; 16]) -> [u8; 16] {
    let mut initial = [0u32; 8];
    for (i, word) in initial.iter_mut().enumerate() {
        *word = u32::from(u16::from_be_bytes([state[i * 2], state[i * 2 + 1]]));
    }

    let mut src = initial;
    for selectors in &ROUND_SELECTORS {
        let mut dst = [0u32; 8];
        for (i, pair) in selectors.iter().enumerate() {
            // carry bit kept (sum fits in u32 before squaring)
            let mixed = src[pair[0]].wrapping_add(src[pair[1]]);
            let value = mixed.wrapping_mul(mixed) ^ (mixed >> 16) ^ ROUND_CONSTANTS[i];
            dst[i * 2] = value & 0xFFFF;
            dst[i * 2 + 1] = value >> 16;
        }
        src = dst;
    }

    let mut out = [0u8; 16];
    for (i, quartet) in FINAL_SELECTORS.iter().enumerate() {
        let low_half = (src[quartet[1]] << 16) | src[quartet[0]];
        let high_half = (src[quartet[3]] << 16) | src[quartet[2]];
        // carry bit dropped (wrap at u32, then square in u64)
        let mixed = low_half.wrapping_add(high_half);
        let wide = u64::from(mixed);
        let square = wide.wrapping_mul(wide);
        let bytes = square.to_le_bytes();
        let low = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let high = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let value = low ^ high ^ FINAL_CONSTANTS[i];

        let lo = (initial[i * 2] ^ (value & 0xFFFF)).to_be_bytes();
        let hi = (initial[i * 2 + 1] ^ (value >> 16)).to_be_bytes();
        out[i * 4] = lo[2];
        out[i * 4 + 1] = lo[3];
        out[i * 4 + 2] = hi[2];
        out[i * 4 + 3] = hi[3];
    }

    out
}

/// AES-128-ECB single-block encryption of `source` under the work-key cipher.
fn block_transform(cipher: &Aes128, source: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::BlockEncrypt;
    use aes::cipher::generic_array::GenericArray;

    let mut block = GenericArray::clone_from_slice(source);
    cipher.encrypt_block(&mut block);

    let mut out = [0u8; 16];
    out.copy_from_slice(block.as_slice());
    out
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (dst, (x, y)) in out.iter_mut().zip(a.iter().zip(b.iter())) {
        *dst = x ^ y;
    }
    out
}

/// Derive the 16-byte AES-128 page key from a 16-byte wrapped record: three
/// `block_transform`s folded together through `finish` and XOR.
fn derive_page_key(cipher: &Aes128, wrapped: &[u8], absolute_index: u32) -> [u8; 16] {
    let (first, second, third) = source_blocks(wrapped, absolute_index);

    let ta = block_transform(cipher, &first);
    let tb = block_transform(cipher, &second);
    let tc = block_transform(cipher, &third);

    let fa = finish(&ta);
    let fb = finish(&xor16(&fa, &tb));
    finish(&xor16(&fb, &tc))
}

/// AES-128-CBC decryption with no padding. `ciphertext` length must be a
/// multiple of the 16-byte block size.
fn aes128_cbc_decrypt_no_pad(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::block_padding::NoPadding;
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use cbc::Decryptor;

    let decryptor = Decryptor::<Aes128>::new_from_slices(key, iv)
        .map_err(|e| format!("invalid AES key/IV: {e}"))?;

    let mut buffer = ciphertext.to_vec();
    let plaintext = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|e| format!("CBC decryption failed: {e}"))?;

    Ok(plaintext.to_vec())
}

/// Report whether `sinf` is an Apple Arcade license, which only the account's
/// Arcade credential decodes (its `key ` field's first byte is 4).
#[must_use]
pub fn is_arcade_sinf(sinf: &[u8]) -> bool {
    match sinf_field(sinf, *b"key ") {
        Ok(key) => key.len() == 4 && key[0] == 4,
        Err(_) => false,
    }
}

/// Report whether `credential` unwraps `sinf`'s priv record, i.e. whether it is
/// the credential of that license's account and kind.
#[must_use]
pub fn credential_decodes(credential: &[u8], sinf: &[u8]) -> bool {
    derive_work16(credential, sinf).is_ok()
}

/// Decrypt every encrypted page of one Mach-O slice and clear its `cryptid`.
///
/// `supf` holds either a SUPF (`.supf`/`.v5.supf`) or a SUPP (`.supp`/
/// `.v4.supp`). A fat binary is thinned to the single slice selected by
/// [`arm_encryption_info`] (plain `arm64`, else `arm64e`, else `arm64_32`,
/// else 32-bit ARM), dropping the others as the on-device helper does.
///
/// Returns `Ok(Some((decrypted_thin_macho, pages)))` on success,
/// `Ok(None)` when the chosen slice is not encrypted (caller skips it).
///
/// # Errors
///
/// Returns an error when the Mach-O, SINF, or SUPF/SUPP records are malformed,
/// the credential does not decode the SINF, or a required page key is missing.
pub fn decrypt_binary(
    source: &[u8],
    sinf: &[u8],
    supf: &[u8],
    credential: &[u8],
) -> Result<Option<(Vec<u8>, usize)>, String> {
    let Some(info) = arm_encryption_info(source)? else {
        return Ok(None);
    };

    let page_count = info.crypt_size / PAGE_SIZE;
    let first_page = (info.base + info.crypt_off) / PAGE_SIZE;
    let pclass = !supf.is_empty() && (supf[0] == 1 || supf[0] == 4);

    let mut record_start = 0usize;
    if !pclass {
        record_start = arm_supf_record_offset(supf, page_count, info.cpu, info.subtype)?;
    }

    let work = derive_work16(credential, sinf)?;
    let key_cipher = Aes128::new_from_slice(&work).map_err(|e| format!("invalid work key: {e}"))?;

    let slice = &source[info.base..info.base + info.size];
    let mut result = slice.to_vec();

    for local_page in 0..page_count {
        let absolute_index = first_page + local_page;
        if pclass {
            record_start = pclass_page_key_offset(supf, absolute_index)?;
        }

        if record_start + 32 > supf.len() {
            return Err("truncated SUPF/SUPP page record".to_string());
        }

        let record = &supf[record_start..record_start + 32];
        record_start += 32;

        let index =
            u32::try_from(absolute_index).map_err(|_| "page index too large".to_string())?;
        let key = derive_page_key(&key_cipher, &record[..16], index);

        let start = info.crypt_off + PAGE_SIZE * local_page;
        let ciphertext = &slice[start..start + PAGE_SIZE];

        let plain = aes128_cbc_decrypt_no_pad(&key, &record[16..32], ciphertext)?;
        result[start..start + PAGE_SIZE].copy_from_slice(&plain);
    }

    let off = info.cryptid_offset - info.base;
    result[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

    Ok(Some((result, page_count)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an MP4-style atom: 4-byte big-endian size, 4-byte tag, payload.
    fn atom(tag: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = u32::try_from(8 + payload.len()).unwrap();
        let mut out = Vec::with_capacity(8 + payload.len());
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&tag);
        out.extend_from_slice(payload);
        out
    }

    /// A minimal SINF atom: sinf -> schi -> {name, iviv, priv, key }.
    fn synthetic_sinf(key_payload: &[u8]) -> Vec<u8> {
        let mut schi = Vec::new();
        schi.extend_from_slice(&atom(*b"name", b"app\x00"));
        schi.extend_from_slice(&atom(*b"iviv", &[0u8; 16]));
        schi.extend_from_slice(&atom(*b"priv", &[0u8; 448]));
        schi.extend_from_slice(&atom(*b"key ", key_payload));
        let schi = atom(*b"schi", &schi);
        atom(*b"sinf", &schi)
    }

    /// A minimal thin arm64 Mach-O carrying one `LC_ENCRYPTION_INFO_64` command.
    fn thin_arm64_macho(cryptid: u32) -> Vec<u8> {
        let mut data = vec![0u8; 8192];
        // mach_header_64
        data[0..4].copy_from_slice(&MACHO_MAGIC_64_LE.to_le_bytes());
        data[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        data[8..12].copy_from_slice(&0u32.to_le_bytes()); // cpusubtype
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
        data[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds
        data[20..24].copy_from_slice(&24u32.to_le_bytes()); // sizeofcmds
        data[24..28].copy_from_slice(&0u32.to_le_bytes()); // flags
        data[28..32].copy_from_slice(&0u32.to_le_bytes()); // reserved
        // LC_ENCRYPTION_INFO_64 at offset 32
        data[32..36].copy_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes()); // cmd
        data[36..40].copy_from_slice(&24u32.to_le_bytes()); // cmdsize
        data[40..44].copy_from_slice(&4096u32.to_le_bytes()); // cryptoff
        data[44..48].copy_from_slice(&4096u32.to_le_bytes()); // cryptsize
        data[48..52].copy_from_slice(&cryptid.to_le_bytes()); // cryptid
        data[52..56].copy_from_slice(&0u32.to_le_bytes()); // pad
        data
    }

    #[test]
    fn finish_matches_go_reference_vectors() {
        // Gold vectors produced by running the Go `finish` verbatim.
        let mut seq = [0u8; 16];
        for (i, b) in seq.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        assert_eq!(
            finish(&seq),
            [
                0x70, 0x1b, 0xc3, 0x34, 0x16, 0x4a, 0x1a, 0x54, 0xe8, 0x0d, 0x03, 0x15, 0x0d, 0x2c,
                0x9d, 0x22
            ]
        );

        assert_eq!(
            finish(&[0u8; 16]),
            [
                0xf1, 0xca, 0x53, 0xc9, 0xa1, 0x03, 0x79, 0x18, 0xc8, 0xaf, 0x96, 0x24, 0x5b, 0xd5,
                0x99, 0x21
            ]
        );

        let deadbeef = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb,
        ];
        assert_eq!(
            finish(&deadbeef),
            [
                0x39, 0x73, 0x43, 0x0b, 0x7e, 0x98, 0xe3, 0x4d, 0x99, 0xd9, 0x0e, 0x10, 0xbd, 0x88,
                0xe9, 0x4c
            ]
        );
    }

    #[test]
    fn finish_is_deterministic() {
        let input = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        assert_eq!(finish(&input), finish(&input));
    }

    #[test]
    fn source_blocks_layout_is_correct() {
        let mut wrapped = [0u8; 16];
        for (i, b) in wrapped.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }

        let (first, second, third) = source_blocks(&wrapped, 1);

        // page_offset = (1 << 12) big-endian over 8 bytes = 0x0000000000001000
        let page_offset = [0, 0, 0, 0, 0, 0, 0x10, 0];

        let mut expected_first = [0u8; 16];
        expected_first[..8].copy_from_slice(&wrapped[8..16]);
        expected_first[8..].copy_from_slice(&page_offset);
        assert_eq!(first, expected_first);

        assert_eq!(second, wrapped);

        let mut expected_third = [0u8; 16];
        expected_third[..8].copy_from_slice(&page_offset);
        expected_third[8..].copy_from_slice(&wrapped[..8]);
        assert_eq!(third, expected_third);
    }

    #[test]
    fn source_blocks_shifts_index_by_twelve_bits() {
        let wrapped = [0xAAu8; 16];
        let (first, _, third) = source_blocks(&wrapped, 0x5);
        // 0x5 << 12 = 0x5000
        assert_eq!(&first[8..], &[0, 0, 0, 0, 0, 0, 0x50, 0]);
        assert_eq!(&third[..8], &[0, 0, 0, 0, 0, 0, 0x50, 0]);
    }

    #[test]
    fn xor16_xors_componentwise() {
        let a = [0xFFu8; 16];
        let b = [0x0Fu8; 16];
        assert_eq!(xor16(&a, &b), [0xF0u8; 16]);
        // XOR with self is zero.
        assert_eq!(xor16(&a, &a), [0u8; 16]);
    }

    #[test]
    fn sinf_field_reads_named_fields() {
        let sinf = synthetic_sinf(&[4, 0, 0, 0]);

        assert_eq!(sinf_field(&sinf, *b"name").unwrap(), b"app\x00");
        assert_eq!(sinf_field(&sinf, *b"iviv").unwrap(), &[0u8; 16]);
        assert_eq!(sinf_field(&sinf, *b"priv").unwrap().len(), 448);
        assert_eq!(sinf_field(&sinf, *b"key ").unwrap(), &[4, 0, 0, 0]);
    }

    #[test]
    fn sinf_field_rejects_missing_field() {
        let sinf = synthetic_sinf(&[4, 0, 0, 0]);
        assert!(sinf_field(&sinf, *b"xxxx").is_err());
    }

    #[test]
    fn sinf_field_rejects_non_sinf_root() {
        let not_sinf = atom(*b"moov", &atom(*b"schi", b""));
        assert!(sinf_field(&not_sinf, *b"name").is_err());
    }

    #[test]
    fn is_arcade_sinf_detects_key_tag_four() {
        assert!(is_arcade_sinf(&synthetic_sinf(&[4, 0, 0, 0])));
        assert!(!is_arcade_sinf(&synthetic_sinf(&[1, 0, 0, 0])));
        // Wrong length key is not Arcade.
        assert!(!is_arcade_sinf(&synthetic_sinf(&[4, 0, 0])));
        assert!(!is_arcade_sinf(b"not a sinf"));
    }

    #[test]
    fn arm_encryption_info_parses_encrypted_thin_slice() {
        let macho = thin_arm64_macho(1);
        let info = arm_encryption_info(&macho)
            .expect("parse should succeed")
            .expect("slice should be encrypted");

        assert_eq!(info.base, 0);
        assert_eq!(info.size, 8192);
        assert_eq!(info.cpu, CPU_TYPE_ARM64);
        assert_eq!(info.crypt_off, 4096);
        assert_eq!(info.crypt_size, 4096);
        assert_eq!(info.cryptid_offset, 48);
    }

    #[test]
    fn arm_encryption_info_reports_unencrypted_slice_as_none() {
        let macho = thin_arm64_macho(0);
        assert!(arm_encryption_info(&macho).unwrap().is_none());
    }

    #[test]
    fn arm_encryption_info_rejects_non_macho() {
        assert!(arm_encryption_info(b"not a mach-o at all......").is_err());
    }

    #[test]
    fn derive_work16_rejects_wrong_credential_length() {
        let sinf = synthetic_sinf(&[4, 0, 0, 0]);
        // 15-byte credential is rejected before any AES work.
        assert!(derive_work16(&[0u8; 15], &sinf).is_err());
        assert!(!credential_decodes(&[0u8; 15], &sinf));
    }

    #[test]
    fn pclass_page_key_offset_indexes_pages() {
        // SUPP v04: format byte 4, no SHA-1 prefix. header: [4][000][count u32]
        let count: u32 = 4;
        let mut supp = vec![4u8, 0, 0, 0];
        supp.extend_from_slice(&count.to_be_bytes());
        supp.extend_from_slice(&[0u8; 4 * 32]);

        assert_eq!(pclass_page_key_offset(&supp, 0).unwrap(), 8);
        assert_eq!(pclass_page_key_offset(&supp, 3).unwrap(), 8 + 3 * 32);
        assert!(pclass_page_key_offset(&supp, 4).is_err());
    }

    #[test]
    fn pclass_page_key_offset_skips_v01_sha1() {
        // SUPP v01: format byte 1, 20-byte SHA-1, then count.
        let count: u32 = 2;
        let mut supp = vec![1u8, 0, 0, 0];
        supp.extend_from_slice(&[0u8; 20]);
        supp.extend_from_slice(&count.to_be_bytes());
        supp.extend_from_slice(&[0u8; 2 * 32]);

        // pos = 4 + 20 = 24, first key at 24 + 4 = 28.
        assert_eq!(pclass_page_key_offset(&supp, 0).unwrap(), 28);
        assert_eq!(pclass_page_key_offset(&supp, 1).unwrap(), 28 + 32);
    }

    #[test]
    fn arm_supf_record_offset_finds_matching_arch() {
        // SUPF v05 ("502"): header_size 12. Byte layout:
        //   [0]=5 ["502"] [4..8 reserved] [8..12 arch_count u32]
        // then, at pos=12, one arch entry:
        //   [length u32] [cpu u32] [subtype u32] [pages u32] [32-byte records...]
        // `length` spans everything after itself (cpu..records); the arch loop
        // advances by `length + 4`, and `pages` sits at pos + header_size.
        let header_size = 12usize;
        let pages: u32 = 1;
        let record_bytes = vec![0u8; 32]; // one page record

        let mut arch = Vec::new();
        arch.extend_from_slice(&CPU_TYPE_ARM64.to_be_bytes()); // cpu (pos+4)
        arch.extend_from_slice(&CPU_SUBTYPE_ARM64E.to_be_bytes()); // subtype (pos+8)
        arch.extend_from_slice(&pages.to_be_bytes()); // pages (pos+header_size = pos+12)
        arch.extend_from_slice(&record_bytes);
        let length = u32::try_from(arch.len()).unwrap();

        let mut supf = vec![5u8];
        supf.extend_from_slice(b"502");
        supf.extend_from_slice(&[0u8; 4]); // reserved (offset 4..8)
        supf.extend_from_slice(&1u32.to_be_bytes()); // arch_count (offset 8..12)
        supf.extend_from_slice(&length.to_be_bytes()); // length at pos=12
        supf.extend_from_slice(&arch);

        // records start at pos(12) + 4 + header_size(12) = 28.
        let off = arm_supf_record_offset(&supf, 1, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E).unwrap();
        assert_eq!(off, 28);
        assert_eq!(header_size, 12);

        // Missing arch is reported.
        assert!(arm_supf_record_offset(&supf, 1, CPU_TYPE_ARM, CPU_SUBTYPE_ARMV7).is_err());
        // Requiring more pages than present fails.
        assert!(arm_supf_record_offset(&supf, 2, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E).is_err());
    }
}
