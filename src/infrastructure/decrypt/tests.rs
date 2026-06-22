//! Synthetic Mach-O / IPA round-trip tests for the decrypt bridge.

use super::*;
use std::io::{Cursor, Read};

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const FAT_MAGIC: u32 = 0xcafe_babe;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_BUILD_VERSION: u32 = 0x32;

const CRYPTOFF: u32 = 0x100;
const CRYPTSIZE: u32 = 0x40;
const MINOS_16: u32 = 16 << 16;

fn push_u32_le(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend(value.to_le_bytes());
}

/// A thin 64-bit Mach-O with an `LC_ENCRYPTION_INFO_64` (cryptid=1) and an
/// `LC_BUILD_VERSION`, padded so `[CRYPTOFF, CRYPTOFF+CRYPTSIZE)` exists and is
/// filled with `filler`.
fn thin_macho(cputype: u32, cpusubtype: u32, minos: u32, filler: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    // mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    for value in [MH_MAGIC_64, cputype, cpusubtype, 2, 2, 48, 0, 0] {
        push_u32_le(&mut bytes, value);
    }
    // LC_ENCRYPTION_INFO_64: cmd, cmdsize, cryptoff, cryptsize, cryptid, pad
    for value in [LC_ENCRYPTION_INFO_64, 24, CRYPTOFF, CRYPTSIZE, 1, 0] {
        push_u32_le(&mut bytes, value);
    }
    // LC_BUILD_VERSION: cmd, cmdsize, platform(iOS=2), minos, sdk, ntools=0
    for value in [LC_BUILD_VERSION, 24, 2, minos, minos, 0] {
        push_u32_le(&mut bytes, value);
    }
    bytes.resize(CRYPTOFF as usize, 0);
    bytes.resize((CRYPTOFF + CRYPTSIZE) as usize, filler);
    bytes
}

/// A classic fat archive over an arm64 + `x86_64` slice.
fn fat_macho(slices: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut placed = Vec::new();
    let mut cursor = u32::try_from(8 + slices.len() * 20).unwrap();
    for (cputype, cpusubtype, slice) in slices {
        cursor = cursor.div_ceil(0x40) * 0x40; // page-ish align
        placed.push((*cputype, *cpusubtype, cursor, slice));
        cursor += u32::try_from(slice.len()).unwrap();
    }

    let mut bytes = Vec::new();
    bytes.extend(FAT_MAGIC.to_be_bytes());
    bytes.extend(u32::try_from(slices.len()).unwrap().to_be_bytes());
    for (cputype, cpusubtype, offset, slice) in &placed {
        bytes.extend(cputype.to_be_bytes());
        bytes.extend(cpusubtype.to_be_bytes());
        bytes.extend(offset.to_be_bytes());
        bytes.extend(u32::try_from(slice.len()).unwrap().to_be_bytes());
        bytes.extend(0_u32.to_be_bytes()); // align
    }
    for (_, _, offset, slice) in &placed {
        bytes.resize(*offset as usize, 0);
        bytes.extend(slice.iter());
    }
    bytes
}

fn build_ipa(executable: &[u8]) -> Vec<u8> {
    let info = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>TestExec</string>
<key>MinimumOSVersion</key><string>16.0</string>
</dict></plist>"#;

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in [
        ("Payload/Test.app/Info.plist", info.as_bytes()),
        ("Payload/Test.app/TestExec", executable),
        ("Payload/Test.app/SC_Info/TestExec.sinf", b"STUBSINF"),
    ] {
        writer.start_file(name, opts).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn inspect_thin_arm64_reports_encryption_and_dumpability() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));
    let report = inspect_ipa(&ipa).unwrap();

    assert_eq!(report.bundle_executable.as_deref(), Some("TestExec"));
    assert_eq!(report.minimum_os_version.as_deref(), Some("16.0"));
    assert!(report.encrypted);

    let macho = report
        .machos
        .iter()
        .find(|m| m.entry.ends_with("TestExec"))
        .unwrap();
    assert_eq!(macho.slices.len(), 1);
    let slice = &macho.slices[0];
    assert_eq!(slice.arch, "arm64");
    assert!(slice.encrypted);
    assert_eq!(slice.cryptid, Some(1));
    assert_eq!(slice.cryptoff, Some(CRYPTOFF));
    assert_eq!(slice.cryptsize, Some(CRYPTSIZE));
    assert_eq!(slice.minimum_os.as_deref(), Some("16.0.0"));
    assert_eq!(slice.dump_filename.as_deref(), Some("TestExec.arm64.bin"));
    assert_eq!(
        slice
            .dumpable_on
            .iter()
            .map(|t| t.ios_major)
            .collect::<Vec<_>>(),
        vec![18, 26, 27]
    );
    assert!(slice.dumpable_on.iter().all(|t| t.dumpable));
}

#[test]
fn inspect_fat_labels_each_arch() {
    let fat = fat_macho(&[
        (
            CPU_TYPE_ARM64,
            0,
            thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11),
        ),
        (
            CPU_TYPE_X86_64,
            0,
            thin_macho(CPU_TYPE_X86_64, 0, MINOS_16, 0x22),
        ),
    ]);
    let report = inspect_ipa(&build_ipa(&fat)).unwrap();
    let slices = &report
        .machos
        .iter()
        .find(|m| m.entry.ends_with("TestExec"))
        .unwrap()
        .slices;

    let archs: Vec<&str> = slices.iter().map(|s| s.arch.as_str()).collect();
    assert_eq!(archs, vec!["arm64", "x86_64"]);
    assert!(slices.iter().all(|s| s.encrypted));
    assert_eq!(
        slices[0].dump_filename.as_deref(),
        Some("TestExec.arm64.bin")
    );
    assert_eq!(
        slices[1].dump_filename.as_deref(),
        Some("TestExec.x86_64.bin")
    );
}

#[test]
fn patch_zeros_cryptid_replaces_region_and_keeps_sinf() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));
    let dir = tempfile::TempDir::new().unwrap();
    let plaintext = vec![0xAB_u8; CRYPTSIZE as usize];
    std::fs::write(dir.path().join("TestExec.arm64.bin"), &plaintext).unwrap();

    let patched = patch_ipa_decrypted(&ipa, dir.path()).unwrap();

    let mut archive = zip::ZipArchive::new(Cursor::new(patched)).unwrap();
    let mut exec = Vec::new();
    archive
        .by_name("Payload/Test.app/TestExec")
        .unwrap()
        .read_to_end(&mut exec)
        .unwrap();

    let slice = &macho::parse(&exec).unwrap()[0];
    assert_eq!(slice.encryption.unwrap().cryptid, 0);
    let (start, end) = slice.crypt_range().unwrap();
    assert_eq!(&exec[start..end], plaintext.as_slice());

    // The injected sinf survives the repack.
    assert!(
        archive
            .by_name("Payload/Test.app/SC_Info/TestExec.sinf")
            .is_ok()
    );
}

#[test]
fn patch_errors_when_dump_missing() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));
    let dir = tempfile::TempDir::new().unwrap();
    let err = patch_ipa_decrypted(&ipa, dir.path()).unwrap_err();
    assert!(err.contains("missing dumped slice"), "{err}");
}

#[test]
fn patch_errors_on_size_mismatch() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join("TestExec.arm64.bin"), [0xAB; 8]).unwrap();
    let err = patch_ipa_decrypted(&ipa, dir.path()).unwrap_err();
    assert!(err.contains("cryptsize"), "{err}");
}

#[test]
fn verify_flags_still_encrypted_and_passes_after_patch() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));

    let before = verify_ipa(&ipa).unwrap();
    assert!(!before.ok);
    assert!(
        before
            .still_encrypted
            .iter()
            .any(|s| s.contains("TestExec") && s.contains("arm64"))
    );

    let dir = tempfile::TempDir::new().unwrap();
    let plaintext: Vec<u8> = (0..CRYPTSIZE)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    std::fs::write(dir.path().join("TestExec.arm64.bin"), &plaintext).unwrap();
    let patched = patch_ipa_decrypted(&ipa, dir.path()).unwrap();

    let after = verify_ipa(&patched).unwrap();
    assert!(after.ok, "{:?}", after.still_encrypted);
    let slice = &after
        .machos
        .iter()
        .find(|m| m.entry.ends_with("TestExec"))
        .unwrap()
        .slices[0];
    assert!(slice.cryptid_zero);
    assert_eq!(slice.looks_decrypted, Some(true));
}

#[test]
fn verify_warns_on_filler_region() {
    // cryptid=0 but the region is a single repeated byte → looks like filler.
    let mut macho = thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x00);
    // zero the cryptid (LC_ENCRYPTION_INFO_64 is the first command at offset 32).
    let cryptid_at = 32 + 16;
    macho[cryptid_at..cryptid_at + 4].copy_from_slice(&0_u32.to_le_bytes());
    let report = verify_ipa(&build_ipa(&macho)).unwrap();
    let slice = &report
        .machos
        .iter()
        .find(|m| m.entry.ends_with("TestExec"))
        .unwrap()
        .slices[0];
    assert!(slice.cryptid_zero);
    assert_eq!(slice.looks_decrypted, Some(false));
}

#[test]
fn set_min_os_patches_build_version_and_info_plist() {
    let ipa = build_ipa(&thin_macho(CPU_TYPE_ARM64, 0, MINOS_16, 0x11));
    let patched = set_min_os(&ipa, "12.0").unwrap();

    let mut archive = zip::ZipArchive::new(Cursor::new(patched)).unwrap();
    let mut exec = Vec::new();
    archive
        .by_name("Payload/Test.app/TestExec")
        .unwrap()
        .read_to_end(&mut exec)
        .unwrap();
    let slice = &macho::parse(&exec).unwrap()[0];
    assert_eq!(slice.build_version.unwrap().minos, 12 << 16);

    let mut info = Vec::new();
    archive
        .by_name("Payload/Test.app/Info.plist")
        .unwrap()
        .read_to_end(&mut info)
        .unwrap();
    let plist = plist::Value::from_reader(Cursor::new(info)).unwrap();
    assert_eq!(
        plist
            .as_dictionary()
            .and_then(|d| d.get("MinimumOSVersion"))
            .and_then(plist::Value::as_string),
        Some("12.0")
    );
}

#[test]
fn parse_version_packs_and_validates() {
    assert_eq!(parse_version("16").unwrap(), 16 << 16);
    assert_eq!(parse_version("16.4").unwrap(), (16 << 16) | (4 << 8));
    assert_eq!(parse_version("16.4.1").unwrap(), (16 << 16) | (4 << 8) | 1);
    assert!(parse_version("16.300").is_err());
    assert!(parse_version("x.y").is_err());
}

/// A thin arm64 Mach-O whose minimum OS comes from `LC_VERSION_MIN_IPHONEOS`
/// (`version` at +8), not `LC_BUILD_VERSION` — as many real frameworks do.
fn thin_macho_version_min(minos: u32) -> Vec<u8> {
    const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
    let mut bytes = Vec::new();
    // header: ncmds=2, sizeofcmds = 24 (enc info) + 16 (version min)
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 2, 2, 40, 0, 0] {
        push_u32_le(&mut bytes, value);
    }
    for value in [LC_ENCRYPTION_INFO_64, 24, CRYPTOFF, CRYPTSIZE, 1, 0] {
        push_u32_le(&mut bytes, value);
    }
    // LC_VERSION_MIN_IPHONEOS: cmd, cmdsize=16, version, sdk
    for value in [LC_VERSION_MIN_IPHONEOS, 16, minos, minos] {
        push_u32_le(&mut bytes, value);
    }
    bytes.resize(CRYPTOFF as usize, 0);
    bytes.resize((CRYPTOFF + CRYPTSIZE) as usize, 0x11);
    bytes
}

#[test]
fn inspect_and_set_min_os_handle_version_min_command() {
    // Regression for real frameworks (e.g. Agora) that carry only
    // LC_VERSION_MIN_IPHONEOS: minos must be reported and patchable.
    let ipa = build_ipa(&thin_macho_version_min(13 << 16));

    let report = inspect_ipa(&ipa).unwrap();
    let slice = &report
        .machos
        .iter()
        .find(|m| m.entry.ends_with("TestExec"))
        .unwrap()
        .slices[0];
    assert_eq!(slice.minimum_os.as_deref(), Some("13.0.0"));
    assert!(!slice.dumpable_on.is_empty());

    let patched = set_min_os(&ipa, "11.0").unwrap();
    let mut archive = zip::ZipArchive::new(Cursor::new(patched)).unwrap();
    let mut exec = Vec::new();
    archive
        .by_name("Payload/Test.app/TestExec")
        .unwrap()
        .read_to_end(&mut exec)
        .unwrap();
    assert_eq!(
        macho::parse(&exec).unwrap()[0].build_version.unwrap().minos,
        11 << 16
    );
}

/// Opt-in end-to-end check against a real App Store IPA. Skipped unless
/// `IPAKEEP_TEST_IPA` points to one (a 200+ MB copyrighted binary can't live in
/// the repo). Run with: `IPAKEEP_TEST_IPA=ipas/<app>.ipa cargo test real_ipa`.
#[test]
fn real_ipa_inspect_patch_verify_roundtrip() {
    let Ok(path) = std::env::var("IPAKEEP_TEST_IPA") else {
        return;
    };
    let ipa = std::fs::read(&path).expect("read IPAKEEP_TEST_IPA");

    let report = inspect_ipa(&ipa).expect("inspect");
    assert!(report.minimum_os_version.is_some());
    let encrypted: Vec<_> = report
        .machos
        .iter()
        .flat_map(|m| m.slices.iter().filter(|s| s.encrypted))
        .collect();
    assert!(!encrypted.is_empty(), "expected encrypted slices");

    // Fabricate plaintext of the real cryptsize for every encrypted slice.
    let dir = tempfile::TempDir::new().unwrap();
    for slice in &encrypted {
        let name = slice.dump_filename.as_ref().unwrap();
        let size = slice.cryptsize.unwrap() as usize;
        std::fs::write(dir.path().join(name), vec![0x5A_u8; size]).unwrap();
    }

    let patched = patch_ipa_decrypted(&ipa, dir.path()).expect("patch");
    let verified = verify_ipa(&patched).expect("verify");
    assert!(
        verified.ok,
        "still encrypted: {:?}",
        verified.still_encrypted
    );
}
