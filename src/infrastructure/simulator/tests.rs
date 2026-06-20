use super::*;
use crate::domain::usecase::log_capture::LogCapture;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[test]
fn convert_macho_adds_simulator_build_version() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("AppBinary");
    write_minimal_arm64_macho(&path);

    assert!(convert_macho_file(&path).unwrap());

    let mut file = File::open(path).unwrap();
    let header = read_mach_header(&mut file).unwrap().unwrap();
    assert_eq!(header.ncmds, 1);
    assert_eq!(header.sizeofcmds, BUILD_VERSION_COMMAND_SIZE);
    let command = read_load_command(&mut file, MACH_HEADER_64_SIZE).unwrap();
    assert_eq!(command.cmd, LC_BUILD_VERSION);

    let mut platform = [0_u8; 4];
    file.seek(SeekFrom::Start(MACH_HEADER_64_SIZE + 8)).unwrap();
    file.read_exact(&mut platform).unwrap();
    assert_eq!(u32::from_le_bytes(platform), PLATFORM_IOSSIMULATOR);
}

#[test]
fn convert_macho_rejects_insert_that_would_overwrite_payload() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("PackedBinary");
    write_arm64_macho_without_load_commands_but_with_payload(&path);
    let before = fs::read(&path).unwrap();

    let error = convert_macho_file(&path).unwrap_err();

    assert!(error.contains("cannot insert LC_BUILD_VERSION"));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn prepare_path_recurses_into_app_bundle() {
    let dir = tempfile::TempDir::new().unwrap();
    let app = dir.path().join("Payload").join("Example.app");
    fs::create_dir_all(&app).unwrap();
    let binary = app.join("Example");
    write_minimal_arm64_macho(&binary);

    let converted = prepare_path(dir.path()).unwrap();

    assert_eq!(converted, vec![binary]);
}

#[test]
fn prepare_path_logs_summary() {
    let capture = LogCapture::default();
    let _guard = capture.install();
    let dir = tempfile::TempDir::new().unwrap();
    let binary = dir.path().join("Example");
    write_minimal_arm64_macho(&binary);

    let converted = prepare_path(dir.path()).unwrap();

    assert_eq!(converted, vec![binary]);
    let logs = capture.contents();
    assert!(logs.contains("preparing simulator path"));
    assert!(logs.contains("simulator path prepared"));
    assert!(logs.contains("converted_count=1"));
}

#[cfg(unix)]
#[test]
fn prepare_path_skips_symlinks() {
    let dir = tempfile::TempDir::new().unwrap();
    let outside_dir = tempfile::TempDir::new().unwrap();
    let outside = outside_dir.path().join("OutsideBinary");
    let link = dir.path().join("App.app").join("LinkedBinary");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    write_minimal_arm64_macho(&outside);
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let converted = prepare_path(dir.path()).unwrap();

    assert!(converted.is_empty());
    let mut file = File::open(outside).unwrap();
    let header = read_mach_header(&mut file).unwrap().unwrap();
    assert_eq!(header.ncmds, 0);
}

#[test]
fn encrypted_macho_files_detects_fairplay_cryptid() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("Encrypted");
    write_encrypted_arm64_macho(&path);

    let encrypted = encrypted_macho_files(dir.path()).unwrap();

    assert_eq!(encrypted, vec![path]);
}

#[cfg(unix)]
#[test]
fn encrypted_macho_files_skips_symlinks() {
    let dir = tempfile::TempDir::new().unwrap();
    let outside = dir.path().join("Encrypted");
    let link = dir.path().join("Payload").join("Linked");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    write_encrypted_arm64_macho(&outside);
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let encrypted = encrypted_macho_files(link.parent().unwrap()).unwrap();

    assert!(encrypted.is_empty());
}

#[test]
fn is_arm64_simulator_binary_rejects_load_commands_beyond_sizeofcmds() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("Malformed");
    let mut bytes = Vec::new();
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 0, 1, 0, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    fs::write(&path, bytes).unwrap();

    let error = is_arm64_simulator_binary(&path).unwrap_err();

    assert!(error.contains("sizeofcmds"));
}

/// Real device builds carry an `LC_BUILD_VERSION` with a tools array
/// (cmdsize > 24). The patch must flip only `platform`/`minos`/`sdk` and
/// leave `cmdsize` intact, otherwise the load-command chain breaks.
#[test]
fn convert_preserves_existing_build_version_cmdsize() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("DeviceBinary");
    write_device_arm64_macho_with_tools(&path);

    assert!(convert_macho_file(&path).unwrap());

    let mut file = File::open(path).unwrap();
    let header = read_mach_header(&mut file).unwrap().unwrap();
    assert_eq!(header.ncmds, 2);
    assert_eq!(header.sizeofcmds, 56);

    // Existing LC_BUILD_VERSION at offset 32: cmdsize stays 32, platform flips to 7.
    let build_version = read_load_command(&mut file, MACH_HEADER_64_SIZE).unwrap();
    assert_eq!(build_version.cmd, LC_BUILD_VERSION);
    assert_eq!(build_version.cmdsize, 32);

    let mut platform = [0_u8; 4];
    file.seek(SeekFrom::Start(MACH_HEADER_64_SIZE + 8)).unwrap();
    file.read_exact(&mut platform).unwrap();
    assert_eq!(u32::from_le_bytes(platform), PLATFORM_IOSSIMULATOR);

    // The following load command is still reachable at offset 64 (chain intact).
    let next = read_load_command(&mut file, MACH_HEADER_64_SIZE + 32).unwrap();
    assert_eq!(next.cmd, 0xDEAD_BEEF);
}

/// Universal (fat) Mach-O archives must be walked so each arm64 slice gets
/// converted at its own file offset.
#[test]
fn convert_macho_file_handles_fat_arm64() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("FatBinary");
    write_fat_arm64_macho(&path, 0x1000);

    assert!(convert_macho_file(&path).unwrap());

    let mut file = File::open(path).unwrap();
    let mut platform = [0_u8; 4];
    file.seek(SeekFrom::Start(0x1000 + MACH_HEADER_64_SIZE + 8))
        .unwrap();
    file.read_exact(&mut platform).unwrap();
    assert_eq!(u32::from_le_bytes(platform), PLATFORM_IOSSIMULATOR);
}

#[test]
fn encrypted_macho_files_detects_fairplay_cryptid_in_fat_slice() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("FatEncrypted");
    // Thin encrypted slice placed at offset 0x800 inside a fat wrapper.
    let mut slice = Vec::new();
    for value in [
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        0,
        0,
        1,
        24,
        0,
        0,
        LC_ENCRYPTION_INFO_64,
        24,
        0,
        4096,
        1,
        0,
    ] {
        slice.extend(value.to_le_bytes());
    }
    write_fat_with_slice(&path, 0x800, &slice);

    assert!(macho_is_encrypted(&path).unwrap());
}

fn write_device_arm64_macho_with_tools(path: &Path) {
    let mut bytes = Vec::new();
    // mach_header_64: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 0, 2, 56, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    // LC_BUILD_VERSION with cmdsize=32 (ntools=1 + one 8-byte tool entry), platform=PLATFORM_IOS(2)
    for value in [
        LC_BUILD_VERSION,
        32,
        2,
        SIMULATOR_VERSION_14_0,
        0x001a_0200,
        1,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    // one build_tool_command: tool(u32), version(u32)
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(0_u32.to_le_bytes());
    // A trailing load command so we can prove the chain survives.
    for value in [0xDEAD_BEEF_u32, 24_u32] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend([0_u8; 16]);
    fs::write(path, bytes).unwrap();
}

fn write_fat_arm64_macho(path: &Path, slice_offset: u32) {
    let slice = build_minimal_device_slice();
    write_fat_with_slice(path, slice_offset, &slice);
}

fn build_minimal_device_slice() -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 0, 1, 24, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    for value in [
        LC_BUILD_VERSION,
        BUILD_VERSION_COMMAND_SIZE,
        2,
        SIMULATOR_VERSION_14_0,
        SIMULATOR_VERSION_14_0,
        0,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

fn write_fat_with_slice(path: &Path, slice_offset: u32, slice: &[u8]) {
    let mut bytes = Vec::new();
    // fat_header: magic + nfat_arch (big-endian)
    bytes.extend(FAT_MAGIC.to_be_bytes());
    bytes.extend(1_u32.to_be_bytes());
    // fat_arch: cputype, cpusubtype, offset, size, align (big-endian)
    bytes.extend(CPU_TYPE_ARM64.to_be_bytes());
    bytes.extend(0_u32.to_be_bytes());
    bytes.extend(slice_offset.to_be_bytes());
    bytes.extend(u32::try_from(slice.len()).unwrap().to_be_bytes());
    bytes.extend(14_u32.to_be_bytes());

    // pad up to slice_offset, then write the slice
    let padding = slice_offset as usize - bytes.len();
    bytes.extend(vec![0_u8; padding]);
    bytes.extend_from_slice(slice);
    fs::write(path, bytes).unwrap();
}

/// Build a fat Mach-O with an arm64 and an `x86_64` slice sharing the
/// same `LC_BUILD_VERSION` device payload (just different `cputype`
/// and `cpusubtype` headers). Lets `thin_to_arm64_inplace` prove it
/// actually drops the non-arm64 slice instead of just rewriting the
/// arm64 one in place.
fn write_fat_x86_64_arm64_macho(path: &Path) {
    let arm64_offset: u32 = 0x1000;
    let x86_64_offset: u32 = 0x2000;
    let arm64 = build_slice_with_cputype(CPU_TYPE_ARM64, 0);
    let x86_64 = build_slice_with_cputype(0x0100_0007, 3);

    let mut bytes = Vec::new();
    bytes.extend(FAT_MAGIC.to_be_bytes());
    bytes.extend(2_u32.to_be_bytes());
    for (cputype, cpusubtype, offset, slice) in [
        (CPU_TYPE_ARM64, 0_u32, arm64_offset, &arm64),
        (0x0100_0007_u32, 3_u32, x86_64_offset, &x86_64),
    ] {
        bytes.extend(cputype.to_be_bytes());
        bytes.extend(cpusubtype.to_be_bytes());
        bytes.extend(offset.to_be_bytes());
        bytes.extend(u32::try_from(slice.len()).unwrap().to_be_bytes());
        bytes.extend(14_u32.to_be_bytes());
    }
    let arm64_pad = arm64_offset as usize - bytes.len();
    bytes.extend(vec![0_u8; arm64_pad]);
    bytes.extend_from_slice(&arm64);
    let x86_64_pad = x86_64_offset as usize - bytes.len();
    bytes.extend(vec![0_u8; x86_64_pad]);
    bytes.extend_from_slice(&x86_64);

    fs::write(path, bytes).unwrap();
}

/// Same shape as `build_minimal_device_slice` but with caller-supplied
/// `cputype`/`cpusubtype`, so a fat archive can carry arch variants of
/// the same payload.
fn build_slice_with_cputype(cputype: u32, cpusubtype: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [MH_MAGIC_64, cputype, cpusubtype, 0, 1, 24, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    for value in [
        LC_BUILD_VERSION,
        BUILD_VERSION_COMMAND_SIZE,
        2,
        SIMULATOR_VERSION_14_0,
        SIMULATOR_VERSION_14_0,
        0,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    bytes
}

fn write_minimal_arm64_macho(path: &Path) {
    let mut bytes = Vec::new();
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 0, 0, 0, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

fn write_arm64_macho_without_load_commands_but_with_payload(path: &Path) {
    let mut bytes = Vec::new();
    for value in [MH_MAGIC_64, CPU_TYPE_ARM64, 0, 0, 0, 0, 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend([0xAA_u8; BUILD_VERSION_COMMAND_LEN]);
    fs::write(path, bytes).unwrap();
}

fn write_encrypted_arm64_macho(path: &Path) {
    let mut bytes = Vec::new();
    for value in [
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        0,
        0,
        1,
        24,
        0,
        0,
        LC_ENCRYPTION_INFO_64,
        24,
        0,
        4096,
        1,
        0,
    ] {
        bytes.extend(value.to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

// -----------------------------------------------------------------
// Tests for the new portable `ensure_simulator_dylib` plumbing
// (lipo-thin + patch in pure Rust, ad-hoc signing injected).
// -----------------------------------------------------------------

#[test]
fn thin_to_arm64_inplace_keeps_only_arm64_slice() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("FatDylib");
    write_fat_x86_64_arm64_macho(&path);

    assert!(thin_to_arm64_inplace(&path).unwrap());

    let mut file = File::open(&path).unwrap();
    let bases = arm64_slice_bases(&mut file).unwrap();
    assert_eq!(bases, vec![0], "x86_64 slice must be dropped");
    let mut magic = [0_u8; 4];
    file.seek(SeekFrom::Start(0)).unwrap();
    file.read_exact(&mut magic).unwrap();
    assert_eq!(u32::from_le_bytes(magic), MH_MAGIC_64);
}

#[test]
fn ensure_simulator_dylib_with_signer_thins_patches_and_signs() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("UniversalDylib");
    write_fat_x86_64_arm64_macho(&path);

    let recorder = RecordingSigner::default();
    ensure_simulator_dylib_with_signer(&path, &recorder).unwrap();

    // Lipothinned to a single arm64 slice at offset 0.
    let mut file = File::open(&path).unwrap();
    let bases = arm64_slice_bases(&mut file).unwrap();
    assert_eq!(bases, vec![0]);

    // Patched to PLATFORM_IOSSIMULATOR by `convert_macho_file`.
    let platform = read_platform_at(&mut file, MACH_HEADER_64_SIZE).unwrap();
    assert_eq!(platform, PLATFORM_IOSSIMULATOR);

    // Signer invoked exactly once, after the patch.
    assert_eq!(recorder.signed(), vec![path.clone()]);
}

#[test]
fn build_launch_command_sets_console_arg_and_dyld_insert_libraries() {
    let dylibs = [
        PathBuf::from("/path/a.dylib"),
        PathBuf::from("/path/b.dylib"),
    ];
    let command = build_launch_command("UDID-X", "com.example.app", &dylibs, true);

    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        args,
        vec![
            "simctl".to_string(),
            "launch".to_string(),
            "--console".to_string(),
            "UDID-X".to_string(),
            "com.example.app".to_string(),
        ]
    );

    let envs: Vec<(String, String)> = command
        .get_envs()
        .filter_map(|(key, value)| {
            Some((
                key.to_string_lossy().into_owned(),
                value?.to_string_lossy().into_owned(),
            ))
        })
        .collect();
    assert!(
        envs.iter()
            .any(|(key, value)| key == "SIMCTL_CHILD_DYLD_INSERT_LIBRARIES"
                && value == "/path/a.dylib:/path/b.dylib")
    );
}

#[test]
fn build_launch_command_omits_console_and_env_when_disabled() {
    let command = build_launch_command("UDID-X", "com.example.app", &[], false);

    let args: Vec<String> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        args,
        vec![
            "simctl".to_string(),
            "launch".to_string(),
            "UDID-X".to_string(),
            "com.example.app".to_string(),
        ]
    );

    let carries_dyld = command
        .get_envs()
        .any(|(key, _)| key.to_string_lossy() == "SIMCTL_CHILD_DYLD_INSERT_LIBRARIES");
    assert!(
        !carries_dyld,
        "env must not be set when there are no dylibs"
    );
}

#[derive(Default)]
struct RecordingSigner {
    signed: std::sync::Mutex<Vec<PathBuf>>,
}

impl RecordingSigner {
    fn signed(&self) -> Vec<PathBuf> {
        self.signed.lock().unwrap().clone()
    }
}

impl AdHocSigner for RecordingSigner {
    fn sign(&self, path: &Path) -> Result<(), String> {
        self.signed.lock().unwrap().push(path.to_path_buf());
        Ok(())
    }
}
