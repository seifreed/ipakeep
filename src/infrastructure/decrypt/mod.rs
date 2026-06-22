//! `FairPlay` decrypt bridge — inspect, patch, and re-sign.
//!
//! ipakeep never decrypts on its own: an external on-device dumper (see
//! `scripts/frida/`) produces the plaintext bytes per slice. This module reports
//! exactly what is encrypted and where ([`inspect_ipa`]), patches dumped bytes
//! back into the archive while zeroing `cryptid` ([`patch_ipa_decrypted`]), and
//! re-signs a bundle preserving its entitlements ([`resign_app`]).

pub mod dump;
mod entitlements;
mod ios;
mod macho;

pub use dump::{DumpDevice, DumpRequest, Dumper, run_dump};
pub use entitlements::{EntitlementRisk, EntitlementVerdict};

use crate::infrastructure::ipa::{copy_zip_entry, entry_options};
use macho::Slice;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use std::process::Command;

/// Per-iOS-major dumpability verdict for one slice.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DumpTarget {
    /// iOS major version (18, 26, or 27).
    pub ios_major: u32,
    /// Whether the slice's minimum OS allows loading on that major.
    pub dumpable: bool,
}

/// One architecture slice of an inspected Mach-O.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SliceReport {
    /// Architecture label: `arm64`, `arm64e`, or `x86_64`.
    pub arch: String,
    /// True when FairPlay-encrypted (`cryptid != 0`).
    pub encrypted: bool,
    /// `LC_ENCRYPTION_INFO` `cryptid`, when the command is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptid: Option<u32>,
    /// Offset of the encrypted region within the slice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptoff: Option<u32>,
    /// Size of the encrypted region in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptsize: Option<u32>,
    /// Minimum OS from `LC_BUILD_VERSION`, formatted `major.minor.patch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_os: Option<String>,
    /// File name the dumper must produce; consumed by `decrypt patch --from`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dump_filename: Option<String>,
    /// Per-iOS-major dumpability, when the minimum OS is known.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dumpable_on: Vec<DumpTarget>,
}

/// One Mach-O archive entry and its slices.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MachoReport {
    /// Zip entry path inside the IPA.
    pub entry: String,
    /// One report per architecture slice.
    pub slices: Vec<SliceReport>,
}

/// Full result of inspecting an IPA.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InspectReport {
    /// `CFBundleExecutable` from the app's `Info.plist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_executable: Option<String>,
    /// `MinimumOSVersion` from the app's `Info.plist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_os_version: Option<String>,
    /// Every Mach-O entry found in the archive.
    pub machos: Vec<MachoReport>,
    /// True when at least one slice is FairPlay-encrypted.
    pub encrypted: bool,
}

/// Inspect every Mach-O in an IPA: arch, encryption info, and dumpability.
///
/// # Errors
///
/// Returns an error if the archive cannot be read or a Mach-O is malformed.
pub fn inspect_ipa(ipa_bytes: &[u8]) -> Result<InspectReport, String> {
    let mut archive = open_archive(ipa_bytes)?;
    let (bundle_executable, minimum_os_version) = read_app_info(&mut archive)?;

    let mut machos = Vec::new();
    let mut any_encrypted = false;
    for i in 0..archive.len() {
        let Some((name, bytes)) = read_if_macho(&mut archive, i)? else {
            continue;
        };
        let slices = macho::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let basename = entry_basename(&name);
        let slice_reports: Vec<SliceReport> = slices
            .iter()
            .map(|slice| slice_report(slice, &basename))
            .collect();
        any_encrypted |= slice_reports.iter().any(|s| s.encrypted);
        machos.push(MachoReport {
            entry: name,
            slices: slice_reports,
        });
    }

    Ok(InspectReport {
        bundle_executable,
        minimum_os_version,
        machos,
        encrypted: any_encrypted,
    })
}

fn slice_report(slice: &Slice, basename: &str) -> SliceReport {
    let encryption = slice.encryption;
    let encrypted = encryption.is_some_and(|e| e.cryptid != 0);
    let minimum_os = slice.build_version.map(|b| format_version(b.minos));
    let dumpable_on = slice
        .build_version
        .map(|b| {
            ios::SUPPORTED_IOS_MAJORS
                .iter()
                .map(|&ios_major| DumpTarget {
                    ios_major,
                    dumpable: ios::dumpable_on(b.minos, ios_major),
                })
                .collect()
        })
        .unwrap_or_default();

    SliceReport {
        arch: slice.arch.clone(),
        encrypted,
        cryptid: encryption.map(|e| e.cryptid),
        cryptoff: encryption.map(|e| e.cryptoff),
        cryptsize: encryption.map(|e| e.cryptsize),
        minimum_os,
        dump_filename: encrypted.then(|| dump_filename(basename, &slice.arch)),
        dumpable_on,
    }
}

/// Patch dumped plaintext slices back into an IPA and zero every `cryptid`.
///
/// `from_dir` holds one file per encrypted slice, named as `inspect` reports
/// (`<basename>.<arch>.bin`). Every encrypted slice must have a matching,
/// correctly sized file, or the patch aborts rather than emit a partially
/// decrypted IPA.
///
/// # Errors
///
/// Returns an error if a dumped slice is missing/mis-sized or the archive
/// cannot be rewritten.
pub fn patch_ipa_decrypted(ipa_bytes: &[u8], from_dir: &Path) -> Result<Vec<u8>, String> {
    let mut scan = open_archive(ipa_bytes)?;
    let mut patched: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for i in 0..scan.len() {
        let Some((name, mut bytes)) = read_if_macho(&mut scan, i)? else {
            continue;
        };
        let slices = macho::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let basename = entry_basename(&name);
        let mut touched = false;
        for slice in &slices {
            let Some(info) = slice.encryption.filter(|e| e.cryptid != 0) else {
                continue;
            };
            let filename = dump_filename(&basename, &slice.arch);
            let dumped = read_dumped_slice(from_dir, &filename, info.cryptsize)?;
            apply_slice(&mut bytes, slice, &dumped, info.command_offset)?;
            touched = true;
        }
        if touched {
            patched.insert(name, bytes);
        }
    }

    if patched.is_empty() {
        return Err("no encrypted Mach-O slices found to patch".into());
    }

    repack(ipa_bytes, &patched)
}

fn apply_slice(
    bytes: &mut [u8],
    slice: &Slice,
    dumped: &[u8],
    command_offset: u64,
) -> Result<(), String> {
    let (start, end) = slice
        .crypt_range()
        .ok_or("encrypted slice without a crypt range")?;
    let region = bytes
        .get_mut(start..end)
        .ok_or("crypt range exceeds Mach-O bounds")?;
    region.copy_from_slice(dumped);

    let cryptid_at = usize::try_from(command_offset + 16).map_err(|_| "cryptid offset overflow")?;
    let cryptid = bytes
        .get_mut(cryptid_at..cryptid_at + 4)
        .ok_or("cryptid field out of bounds")?;
    cryptid.copy_from_slice(&0_u32.to_le_bytes());
    Ok(())
}

fn read_dumped_slice(from_dir: &Path, filename: &str, expected: u32) -> Result<Vec<u8>, String> {
    let path = from_dir.join(filename);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("missing dumped slice {}: {e}", path.display()))?;
    if bytes.len() as u64 != u64::from(expected) {
        return Err(format!(
            "{}: expected {expected} bytes (cryptsize), got {}",
            path.display(),
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn repack(ipa_bytes: &[u8], patched: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
    let mut archive = open_archive(ipa_bytes)?;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().to_string();
        if let Some(bytes) = patched.get(&name) {
            let options = entry_options(&file, 0o755);
            writer
                .start_file(&name, options)
                .map_err(|e| e.to_string())?;
            writer.write_all(bytes).map_err(|e| e.to_string())?;
        } else {
            copy_zip_entry(&mut writer, file).map_err(|e| e.to_string())?;
        }
    }

    let cursor = writer.finish().map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

/// Re-sign an extracted `.app` bundle, preserving its entitlements.
///
/// When `entitlements_override` is `None`, the original entitlements are read
/// from the bundle's main executable with `codesign -d`.
///
/// # Errors
///
/// Returns an error if entitlements cannot be read or signing fails.
pub fn resign_app(
    app: &Path,
    identity: &str,
    entitlements_override: Option<&Path>,
) -> Result<(), String> {
    if let Some(entitlements) = entitlements_override {
        return crate::infrastructure::simulator::resign_bundle(app, identity, Some(entitlements));
    }

    let executable = bundle_executable_on_disk(app)?;
    let xml = extract_entitlements(&app.join(&executable))?;
    if xml.trim().is_empty() {
        // No custom entitlements to preserve; sign without an override.
        return crate::infrastructure::simulator::resign_bundle(app, identity, None);
    }

    let temp = std::env::temp_dir().join(format!("ipakeep-entitlements-{executable}.plist"));
    std::fs::write(&temp, xml).map_err(|e| format!("{}: {e}", temp.display()))?;
    let result = crate::infrastructure::simulator::resign_bundle(app, identity, Some(&temp));
    let _ = std::fs::remove_file(&temp);
    result
}

fn extract_entitlements(executable: &Path) -> Result<String, String> {
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-", "--xml"])
        .arg(executable)
        .output()
        .map_err(|e| format!("failed to run codesign: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn bundle_executable_on_disk(app: &Path) -> Result<String, String> {
    let info = app.join("Info.plist");
    let plist = plist::Value::from_file(&info).map_err(|e| format!("{}: {e}", info.display()))?;
    plist
        .as_dictionary()
        .and_then(|dict| dict.get("CFBundleExecutable"))
        .and_then(plist::Value::as_string)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{} missing CFBundleExecutable", info.display()))
}

fn open_archive(ipa_bytes: &[u8]) -> Result<zip::ZipArchive<Cursor<&[u8]>>, String> {
    zip::ZipArchive::new(Cursor::new(ipa_bytes)).map_err(|e| e.to_string())
}

/// Read a zip entry in full only if its first bytes are a Mach-O/fat magic.
///
/// IPAs hold thousands of non-Mach-O assets; peeking 4 bytes and skipping them
/// avoids decompressing/reading every one just to test the magic.
fn read_if_macho<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: usize,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let mut file = archive.by_index(index).map_err(|e| e.to_string())?;
    let name = file.name().to_string();
    if !file.is_file() {
        return Ok(None);
    }
    let mut magic = [0_u8; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    if !macho::is_macho(&magic) {
        return Ok(None);
    }
    let mut bytes = magic.to_vec();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(Some((name, bytes)))
}

fn read_app_info<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<(Option<String>, Option<String>), String> {
    let mut info_name = None;
    for i in 0..archive.len() {
        let name = archive
            .by_index(i)
            .map_err(|e| e.to_string())?
            .name()
            .to_string();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            info_name = Some(name);
            break;
        }
    }
    let Some(info_name) = info_name else {
        return Ok((None, None));
    };

    let mut data = Vec::new();
    archive
        .by_name(&info_name)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let plist = plist::Value::from_reader(Cursor::new(data)).map_err(|e| e.to_string())?;
    let dict = plist.as_dictionary();
    let string = |key: &str| {
        dict.and_then(|d| d.get(key))
            .and_then(plist::Value::as_string)
            .map(str::to_string)
    };
    Ok((string("CFBundleExecutable"), string("MinimumOSVersion")))
}

fn entry_basename(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_string()
}

fn dump_filename(basename: &str, arch: &str) -> String {
    format!("{basename}.{arch}.bin")
}

fn format_version(packed: u32) -> String {
    format!(
        "{}.{}.{}",
        packed >> 16,
        (packed >> 8) & 0xff,
        packed & 0xff
    )
}

/// Verdict for one slice of a (supposedly) decrypted Mach-O.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SliceVerify {
    /// Architecture label.
    pub arch: String,
    /// True when no `LC_ENCRYPTION_INFO` retains a non-zero `cryptid`.
    pub cryptid_zero: bool,
    /// True when the slice parsed as a structurally valid Mach-O.
    pub valid: bool,
    /// Heuristic: the formerly-encrypted region no longer looks like filler
    /// (not all-zero, not a single repeated byte). `None` when not encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub looks_decrypted: Option<bool>,
}

/// One Mach-O entry's verification result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MachoVerify {
    /// Zip entry path.
    pub entry: String,
    /// One verdict per slice.
    pub slices: Vec<SliceVerify>,
}

/// Result of verifying a decrypted IPA.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// True when every slice is valid and fully decrypted (`cryptid == 0`).
    pub ok: bool,
    /// Per Mach-O entry.
    pub machos: Vec<MachoVerify>,
    /// `entry[arch]` of every slice still carrying `cryptid != 0`.
    pub still_encrypted: Vec<String>,
}

/// Verify that an IPA is fully decrypted: every slice has `cryptid == 0`, parses
/// cleanly, and its formerly-encrypted region no longer looks like filler.
///
/// This is a structural check; confirming the binary actually *loads* requires a
/// device or an Apple Silicon Mac.
///
/// # Errors
///
/// Returns an error if the archive cannot be read.
pub fn verify_ipa(ipa_bytes: &[u8]) -> Result<VerifyReport, String> {
    let mut archive = open_archive(ipa_bytes)?;
    let mut machos = Vec::new();
    let mut still_encrypted = Vec::new();
    let mut ok = true;

    for i in 0..archive.len() {
        let Some((name, bytes)) = read_if_macho(&mut archive, i)? else {
            continue;
        };
        let Ok(slices) = macho::parse(&bytes) else {
            ok = false;
            machos.push(MachoVerify {
                entry: name,
                slices: Vec::new(),
            });
            continue;
        };

        let mut slice_reports = Vec::new();
        for slice in &slices {
            let cryptid_zero = slice.encryption.is_none_or(|e| e.cryptid == 0);
            let looks_decrypted = slice.encryption.map(|_| {
                slice
                    .crypt_range()
                    .is_some_and(|(s, e)| looks_decrypted(&bytes[s..e]))
            });
            if !cryptid_zero {
                still_encrypted.push(format!("{name}[{}]", slice.arch));
                ok = false;
            }
            slice_reports.push(SliceVerify {
                arch: slice.arch.clone(),
                cryptid_zero,
                valid: true,
                looks_decrypted,
            });
        }
        machos.push(MachoVerify {
            entry: name,
            slices: slice_reports,
        });
    }

    Ok(VerifyReport {
        ok,
        machos,
        still_encrypted,
    })
}

/// A region "looks decrypted" if it is neither empty, all-zero, nor a single
/// repeated byte — a cheap guard against an unfilled / still-ciphered region.
fn looks_decrypted(region: &[u8]) -> bool {
    match region.first() {
        None => false,
        Some(&first) => region.iter().any(|&b| b != first),
    }
}

/// Extract and classify a binary's (or bundle's) entitlements by re-sign risk.
///
/// # Errors
///
/// Returns an error if the executable cannot be located or `codesign` fails.
pub fn entitlements_report(path: &Path) -> Result<Vec<EntitlementVerdict>, String> {
    let binary = if path.extension().is_some_and(|e| e == "app") {
        path.join(bundle_executable_on_disk(path)?)
    } else {
        path.to_path_buf()
    };
    let xml = extract_entitlements(&binary)?;
    if xml.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value = plist::Value::from_reader(Cursor::new(xml.into_bytes()))
        .map_err(|e| format!("parsing entitlements: {e}"))?;
    let dict = value
        .as_dictionary()
        .ok_or("entitlements are not a plist dictionary")?;
    Ok(entitlements::classify(dict))
}

/// Patch every `LC_BUILD_VERSION.minos` and the app's `MinimumOSVersion` down to
/// `version` (e.g. `"16.0"`), so the IPA *installs* on an older iOS.
///
/// Note: installing is not running — apps that call newer APIs crash. The CLI
/// warns about this; this function only performs the patch.
///
/// # Errors
///
/// Returns an error if `version` is malformed or no patch target exists.
pub fn set_min_os(ipa_bytes: &[u8], version: &str) -> Result<Vec<u8>, String> {
    let packed = parse_version(version)?;
    let mut archive = open_archive(ipa_bytes)?;
    let mut patched: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for i in 0..archive.len() {
        let Some((name, mut bytes)) = read_if_macho(&mut archive, i)? else {
            continue;
        };
        let slices = macho::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let mut touched = false;
        for slice in &slices {
            let Some(build) = slice.build_version else {
                continue;
            };
            let at = usize::try_from(build.minos_offset).map_err(|_| "minos offset overflow")?;
            bytes
                .get_mut(at..at + 4)
                .ok_or("minos field out of bounds")?
                .copy_from_slice(&packed.to_le_bytes());
            touched = true;
        }
        if touched {
            patched.insert(name, bytes);
        }
    }

    if let Some((info_name, info_bytes)) = patched_info_plist(&mut archive, version)? {
        patched.insert(info_name, info_bytes);
    }

    if patched.is_empty() {
        return Err("no LC_BUILD_VERSION or Info.plist found to patch".into());
    }
    repack(ipa_bytes, &patched)
}

/// Parse `"x"`, `"x.y"`, or `"x.y.z"` into a packed `LC_BUILD_VERSION` word.
fn parse_version(version: &str) -> Result<u32, String> {
    let mut parts = version.split('.');
    let mut next = |what: &str| -> Result<u32, String> {
        match parts.next() {
            None => Ok(0),
            Some(p) => p
                .parse::<u32>()
                .map_err(|_| format!("invalid {what} in version {version:?}")),
        }
    };
    let major = next("major")?;
    let minor = next("minor")?;
    let patch = next("patch")?;
    if major > 0xffff || minor > 0xff || patch > 0xff {
        return Err(format!("version out of range: {version:?}"));
    }
    Ok((major << 16) | (minor << 8) | patch)
}

/// Re-serialize the app's `Info.plist` with `MinimumOSVersion = version`.
fn patched_info_plist<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    version: &str,
) -> Result<Option<(String, Vec<u8>)>, String> {
    let Some(info_name) = find_info_plist_name(archive)? else {
        return Ok(None);
    };
    let mut data = Vec::new();
    archive
        .by_name(&info_name)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let mut value = plist::Value::from_reader(Cursor::new(data)).map_err(|e| e.to_string())?;
    let dict = value
        .as_dictionary_mut()
        .ok_or("Info.plist is not a dictionary")?;
    dict.insert(
        "MinimumOSVersion".to_string(),
        plist::Value::String(version.to_string()),
    );
    let mut buf = Vec::new();
    value
        .to_writer_xml(&mut buf)
        .map_err(|e| format!("re-encoding Info.plist: {e}"))?;
    Ok(Some((info_name, buf)))
}

fn find_info_plist_name<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
) -> Result<Option<String>, String> {
    for i in 0..archive.len() {
        let name = archive
            .by_index(i)
            .map_err(|e| e.to_string())?
            .name()
            .to_string();
        if name.starts_with("Payload/") && name.ends_with(".app/Info.plist") {
            return Ok(Some(name));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
