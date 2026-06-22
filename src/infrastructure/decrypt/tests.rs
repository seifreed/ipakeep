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
