//! `FairPlay` decrypt bridge — inspect, patch, and re-sign.
//!
//! ipakeep never decrypts on its own: an external on-device dumper (see
//! `scripts/frida/`) produces the plaintext bytes per slice, or `ipadecrypt`
//! decrypts a local IPA offline ([`run_offline`]). This module reports
//! exactly what is encrypted and where ([`inspect_ipa`]), patches dumped bytes
//! back into the archive while zeroing `cryptid` ([`patch_ipa_decrypted`]), and
//! re-signs a bundle preserving its entitlements ([`resign_app`]).

pub mod dump;
mod entitlements;
mod fairplay;
mod fairplay_ipa;
mod ios;
mod macho;
mod min_os;
mod offline;
mod verify;

pub use dump::{DumpDevice, DumpRequest, Dumper, SshParams, run_dump};
pub use entitlements::{EntitlementRisk, EntitlementVerdict};
pub use min_os::set_min_os;
pub use offline::run_offline;
pub(crate) use verify::ensure_decrypted;
pub use verify::{MachoVerify, SliceVerify, VerifyReport, verify_ipa};

use crate::infrastructure::exec::observed_output;
use crate::infrastructure::ipa::{copy_zip_entry, entry_options};
use macho::Slice;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use std::process::Command;

/// Per-iOS-major dumpability verdict for one slice.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DumpTarget {
    /// iOS major version represented in the minimum-OS compatibility matrix.
    pub ios_major: u32,
    /// Whether the slice's minimum OS is at or below that major. This does not
    /// establish API, entitlement, or Frida compatibility.
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
    /// Per-iOS-major minimum-OS compatibility, when the minimum OS is known.
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
        let slice_reports: Vec<SliceReport> = slices
            .iter()
            .map(|slice| slice_report(slice, &name))
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

fn slice_report(slice: &Slice, entry: &str) -> SliceReport {
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
        dump_filename: encrypted.then(|| dump_filename(entry, &slice.arch)),
        dumpable_on,
    }
}

/// Patch dumped plaintext slices back into an IPA and zero every `cryptid`.
///
/// `from_dir` holds one file per dumped slice, named as `inspect` reports
/// (`<bundle-relative path>.<arch>.bin`, with `/` escaped as `%2F`); the legacy
/// `<basename>.<arch>.bin` name is accepted as a fallback. A large slice may
/// instead arrive as `<name>.part.<offset>` chunks, and a `<name>.uuid` sidecar
/// carries the dumped module's `LC_UUID`.
///
/// Encrypted slices of a fat Mach-O without a dump (the device only runs one
/// architecture) are removed from the binary; the drop is logged. A Mach-O
/// whose every encrypted slice lacks a dump aborts the patch rather than emit a
/// still-encrypted IPA.
///
/// # Errors
///
/// Returns an error if a dumped slice is missing/mis-sized, belongs to a
/// different build (`LC_UUID` mismatch), or the archive cannot be rewritten.
pub fn patch_ipa_decrypted(ipa_bytes: &[u8], from_dir: &Path) -> Result<Vec<u8>, String> {
    patch_ipa_decrypted_with(ipa_bytes, from_dir, false)
}

/// [`patch_ipa_decrypted`], optionally removing app extensions (`.appex`)
/// that have no dump instead of failing. Extensions such as notification
/// services only run when iOS triggers them, so they often cannot be dumped;
/// dropping them still yields a working decrypted main app.
///
/// # Errors
///
/// Same as [`patch_ipa_decrypted`], except undumped extensions are removed
/// when `drop_undumped_extensions` is set.
pub fn patch_ipa_decrypted_with(
    ipa_bytes: &[u8],
    from_dir: &Path,
    drop_undumped_extensions: bool,
) -> Result<Vec<u8>, String> {
    let outcome = patch_with_report(ipa_bytes, from_dir, drop_undumped_extensions)?;
    for bundle in &outcome.dropped_bundles {
        tracing::warn!(
            event_name = "decrypt.patch.extension_dropped",
            bundle = %bundle,
            "no dump for app extension; removed it from the IPA"
        );
    }
    for slice in &outcome.dropped_slices {
        tracing::warn!(
            event_name = "decrypt.patch.slice_dropped",
            slice = %slice,
            "no dump for encrypted slice; removed it from the fat binary"
        );
    }
    for slice in &outcome.unverified_slices {
        tracing::warn!(
            event_name = "decrypt.patch.uuid_unverified",
            slice = %slice,
            "dump has no LC_UUID sidecar; cannot confirm it matches the IPA build"
        );
    }
    Ok(outcome.ipa)
}

/// Result of [`patch_with_report`]: the patched IPA plus what was dropped or
/// could not be matched by `LC_UUID`.
struct PatchOutcome {
    ipa: Vec<u8>,
    /// `entry[arch]` of encrypted slices removed for lack of a dump.
    dropped_slices: Vec<String>,
    /// `entry[arch]` of patched slices whose dump carried no `LC_UUID`.
    unverified_slices: Vec<String>,
    /// `.appex/` archive prefixes removed because they had no dump.
    dropped_bundles: BTreeSet<String>,
}

fn patch_with_report(
    ipa_bytes: &[u8],
    from_dir: &Path,
    drop_undumped_extensions: bool,
) -> Result<PatchOutcome, String> {
    let mut scan = open_archive(ipa_bytes)?;
    let mut dropped_bundles = BTreeSet::new();
    let mut patched: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut dropped_slices = Vec::new();
    let mut unverified_slices = Vec::new();

    for i in 0..scan.len() {
        let Some((name, bytes)) = read_if_macho(&mut scan, i)? else {
            continue;
        };
        let Some(entry) = patch_macho_entry(name, bytes, from_dir, drop_undumped_extensions)?
        else {
            continue;
        };
        if let Some(bundle) = entry.dropped_bundle {
            dropped_bundles.insert(bundle);
        }
        dropped_slices.extend(entry.dropped_slices);
        unverified_slices.extend(entry.unverified_slices);
        patched.insert(entry.name, entry.bytes);
    }

    patched.retain(|name, _| !in_dropped_bundle(name, &dropped_bundles));
    if patched.is_empty() {
        return Err("no encrypted Mach-O slices found to patch".into());
    }

    Ok(PatchOutcome {
        ipa: repack(ipa_bytes, &patched, &dropped_bundles)?,
        dropped_slices,
        unverified_slices,
        dropped_bundles,
    })
}

struct PatchedEntry {
    name: String,
    bytes: Vec<u8>,
    dropped_bundle: Option<String>,
    dropped_slices: Vec<String>,
    unverified_slices: Vec<String>,
}

struct AvailableDumps {
    missing: Vec<(usize, String)>,
    unverified: Vec<String>,
    touched: bool,
}

fn patch_macho_entry(
    name: String,
    mut bytes: Vec<u8>,
    from_dir: &Path,
    drop_undumped_extensions: bool,
) -> Result<Option<PatchedEntry>, String> {
    let slices = macho::parse(&bytes).map_err(|error| format!("{name}: {error}"))?;
    let dumps = apply_available_dumps(&name, &mut bytes, &slices, from_dir)?;
    let dropped_bundle = handle_missing_dumps(
        &name,
        &dumps.missing,
        dumps.touched,
        from_dir,
        drop_undumped_extensions,
    )?;
    if !dumps.touched && dropped_bundle.is_none() {
        return Ok(None);
    }
    let dropped_slices = if dumps.touched {
        remove_missing_slices(&name, &mut bytes, &slices, &dumps.missing)?
    } else {
        Vec::new()
    };

    Ok(Some(PatchedEntry {
        name,
        bytes,
        dropped_bundle,
        dropped_slices,
        unverified_slices: dumps.unverified,
    }))
}

fn apply_available_dumps(
    name: &str,
    bytes: &mut [u8],
    slices: &[Slice],
    from_dir: &Path,
) -> Result<AvailableDumps, String> {
    let mut missing = Vec::new();
    let mut unverified = Vec::new();
    let mut touched = false;
    for (index, slice) in slices.iter().enumerate() {
        let Some(info) = slice
            .encryption
            .filter(|encryption| encryption.cryptid != 0)
        else {
            continue;
        };
        let candidates = dump_filenames(name, &slice.arch);
        let Some(dump) = read_dumped_slice(from_dir, &candidates, info.cryptsize)? else {
            missing.push((index, candidates[0].clone()));
            continue;
        };
        let label = format!("{name}[{}]", slice.arch);
        if check_uuid(slice.uuid, dump.uuid, &label)? {
            unverified.push(label);
        }
        apply_slice(bytes, slice, &dump.bytes, info.command_offset)?;
        touched = true;
    }
    Ok(AvailableDumps {
        missing,
        unverified,
        touched,
    })
}

fn handle_missing_dumps(
    name: &str,
    missing: &[(usize, String)],
    touched: bool,
    from_dir: &Path,
    drop_undumped_extensions: bool,
) -> Result<Option<String>, String> {
    if touched || missing.is_empty() {
        return Ok(None);
    }
    let (_, filename) = &missing[0];
    let Some(bundle) = extension_bundle_prefix(name) else {
        return Err(format!(
            "missing dumped slice {}: no dump for {name}",
            from_dir.join(filename).display()
        ));
    };
    if drop_undumped_extensions {
        return Ok(Some(bundle.to_string()));
    }
    Err(format!(
        "missing dumped slice {}: no dump for app extension {name}; \
         trigger the extension while dumping, or pass \
         --drop-undumped-extensions to remove it",
        from_dir.join(filename).display()
    ))
}

fn remove_missing_slices(
    name: &str,
    bytes: &mut Vec<u8>,
    slices: &[Slice],
    missing: &[(usize, String)],
) -> Result<Vec<String>, String> {
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    *bytes = macho::retain_slices(bytes, |index| {
        missing.iter().all(|(dropped, _)| *dropped != index)
    })
    .map_err(|error| format!("{name}: {error}"))?;
    Ok(missing
        .iter()
        .map(|(index, _)| format!("{name}[{}]", slices[*index].arch))
        .collect())
}

/// Archive prefix of the innermost `.appex` bundle containing `name`, e.g.
/// `Payload/App.app/PlugIns/Share.appex/`.
fn extension_bundle_prefix(name: &str) -> Option<&str> {
    name.rfind(".appex/")
        .map(|end| &name[..end + ".appex/".len()])
}

fn in_dropped_bundle(name: &str, dropped: &BTreeSet<String>) -> bool {
    dropped
        .iter()
        .any(|bundle| name.starts_with(bundle.as_str()))
}

/// Reject a dump whose `LC_UUID` differs from the IPA slice's. Returns `true`
/// when the match could not be verified (either side lacks a UUID).
fn check_uuid(
    expected: Option<[u8; 16]>,
    dumped: Option<[u8; 16]>,
    label: &str,
) -> Result<bool, String> {
    match (expected, dumped) {
        (Some(expected), Some(dumped)) if expected != dumped => Err(format!(
            "{label}: dumped LC_UUID {} does not match the IPA's {} \
             (the installed app is a different build)",
            hex(&dumped),
            hex(&expected)
        )),
        (Some(_), Some(_)) => Ok(false),
        _ => Ok(true),
    }
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

/// Plaintext of one slice as dumped on device, plus its `LC_UUID` if reported.
struct DumpedSlice {
    bytes: Vec<u8>,
    uuid: Option<[u8; 16]>,
}

/// Read the first dump found among `candidates` (whole file, else chunks).
/// `Ok(None)` means no candidate exists.
fn read_dumped_slice(
    from_dir: &Path,
    candidates: &[String],
    expected: u32,
) -> Result<Option<DumpedSlice>, String> {
    for filename in candidates {
        let Some(bytes) = read_whole_or_chunks(from_dir, filename)? else {
            continue;
        };
        if bytes.len() as u64 != u64::from(expected) {
            return Err(format!(
                "{}: expected {expected} bytes (cryptsize), got {}",
                from_dir.join(filename).display(),
                bytes.len()
            ));
        }
        let uuid = read_uuid_sidecar(from_dir, filename)?;
        return Ok(Some(DumpedSlice { bytes, uuid }));
    }
    Ok(None)
}

fn read_whole_or_chunks(from_dir: &Path, filename: &str) -> Result<Option<Vec<u8>>, String> {
    let path = from_dir.join(filename);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            read_chunks(from_dir, filename)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Reassemble `<filename>.part.<offset>` chunks; they must tile `[0, len)`.
fn read_chunks(from_dir: &Path, filename: &str) -> Result<Option<Vec<u8>>, String> {
    let prefix = format!("{filename}.part.");
    let entries = match std::fs::read_dir(from_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", from_dir.display())),
    };
    let mut chunks = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(offset) = name.strip_prefix(&prefix) else {
            continue;
        };
        let offset: usize = offset
            .parse()
            .map_err(|_| format!("{name}: invalid chunk offset"))?;
        chunks.insert(offset, entry.path());
    }
    if chunks.is_empty() {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    for (offset, path) in chunks {
        if offset != bytes.len() {
            return Err(format!(
                "{}: chunk at offset {offset} does not follow {} assembled bytes",
                from_dir.join(filename).display(),
                bytes.len()
            ));
        }
        let chunk = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        bytes.extend(chunk);
    }
    Ok(Some(bytes))
}

/// Read `<filename>.uuid` (hex text, dashes allowed). Absent → `None`.
fn read_uuid_sidecar(from_dir: &Path, filename: &str) -> Result<Option<[u8; 16]>, String> {
    let path = from_dir.join(format!("{filename}.uuid"));
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    parse_uuid(&text)
        .map(Some)
        .ok_or_else(|| format!("{}: not a 16-byte hex UUID", path.display()))
}

fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| !matches!(b, b'-' | b' ' | b'\n' | b'\r'))
        .collect();
    if digits.len() != 32 {
        return None;
    }
    let mut uuid = [0_u8; 16];
    for (byte, pair) in uuid.iter_mut().zip(digits.chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(uuid)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02X}");
        out
    })
}

fn repack(
    ipa_bytes: &[u8],
    patched: &BTreeMap<String, Vec<u8>>,
    dropped_bundles: &BTreeSet<String>,
) -> Result<Vec<u8>, String> {
    let mut archive = open_archive(ipa_bytes)?;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));

    for i in 0..archive.len() {
        let file = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = file.name().map_err(|error| error.to_string())?.into_owned();
        if in_dropped_bundle(&name, dropped_bundles) {
            continue;
        }
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

pub(crate) fn extract_entitlements(executable: &Path) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/codesign");
    command
        .args(["-d", "--entitlements", ":-", "--xml"])
        .arg(executable);
    let output =
        observed_output(&mut command).map_err(|e| format!("failed to run codesign: {e}"))?;
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
    let name = file.name().map_err(|error| error.to_string())?.into_owned();
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
            .map_err(|error| error.to_string())?
            .into_owned();
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

fn entry_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Path of a zip entry relative to its `.app` bundle root (e.g.
/// `Frameworks/Foo.framework/Foo`); the basename when no `.app/` is present.
fn bundle_relative_path(name: &str) -> &str {
    name.find(".app/")
        .map_or_else(|| entry_basename(name), |at| &name[at + ".app/".len()..])
}

/// Dump file name for a slice: the bundle-relative path with `%` and `/`
/// escaped so it stays one flat file name, plus `.<arch>.bin`. Must match
/// `dumpName` in `scripts/frida/ipakeep_dump.js`.
fn dump_filename(entry: &str, arch: &str) -> String {
    let escaped = bundle_relative_path(entry)
        .replace('%', "%25")
        .replace('/', "%2F");
    format!("{escaped}.{arch}.bin")
}

/// Candidate dump names, preferred first: path-based, then legacy basename.
fn dump_filenames(entry: &str, arch: &str) -> Vec<String> {
    let preferred = dump_filename(entry, arch);
    let legacy = format!("{}.{arch}.bin", entry_basename(entry));
    if legacy == preferred {
        vec![preferred]
    } else {
        vec![preferred, legacy]
    }
}

fn format_version(packed: u32) -> String {
    format!(
        "{}.{}.{}",
        packed >> 16,
        (packed >> 8) & 0xff,
        packed & 0xff
    )
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

#[cfg(test)]
mod tests;
