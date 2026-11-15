//! Byte-for-byte comparison against upstream `machimage` on the pinned assets.
//!
//! Golden files were produced by a Go harness that runs upstream
//! `machimage.OpenShared` + `Relocate`/`PreparePrelinked`/
//! `RelocateKernelCachePointers` + `Load` exactly as `machine.openRuntime`
//! does, with a deterministic FNV-1a resolver.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::fmt::Write as _;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::{MachImage, PreparationCache, Relocation};

const ASSET_DIRECTORY: &str = "Library/Caches/ipatool/sap/apple-assets-macos-27-26A434-arm64-v5";
const FIXTURE_DIRECTORY: &str = "tests/fixtures/apple_sap/D";
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
const RESOLVED_PREFIX: u64 = 0x0000_0f00_0000_0000;
const RESOLVED_MASK: u64 = 0x0000_00ff_ffff_fff0;

const AMS_FUNCTIONS: [(u64, &str); 23] = [
    (0x0000_0001_8067_5ce8, "_malloc"),
    (0x0000_0001_8067_66f0, "_free"),
    (0x0000_0001_806c_f570, "_dispatch_once"),
    (0x0000_0001_8071_acc8, "_sysctlbyname"),
    (0x0000_0001_8071_bec4, "_gettimeofday"),
    (0x0000_0001_8072_1fb8, "_arc4random"),
    (0x0000_0001_8072_38a4, "___memset_chk"),
    (0x0000_0001_8079_03c4, "_abort"),
    (0x0000_0001_8084_9604, "___error"),
    (0x0000_0001_8088_9bc4, "_pthread_once"),
    (0x0000_0001_8088_a6f8, "_pthread_rwlock_unlock"),
    (0x0000_0001_8088_a7c0, "_pthread_rwlock_wrlock"),
    (0x0000_0001_8088_b2d8, "_pthread_rwlock_init"),
    (0x0000_0001_8089_4b40, "_strlen"),
    (0x0000_0001_808c_f540, "_CFStringCreateWithCString"),
    (0x0000_0001_808d_4200, "_CFStringGetLength"),
    (0x0000_0001_808d_44dc, "_CFStringGetCString"),
    (0x0000_0001_808d_7278, "_CFRelease"),
    (0x0000_0001_808e_89e8, "_CFDataGetLength"),
    (0x0000_0001_84d6_b4cc, "_IOServiceMatching"),
    (0x0000_0001_84d6_c168, "_IOServiceGetMatchingServices"),
    (0x0000_0001_84d6_c4fc, "_IOIteratorNext"),
    (0x0000_0001_84d6_cb50, "_IOObjectRelease"),
];

struct Spec {
    name: &'static str,
    base: u64,
    prelinked: bool,
    kernel_base: u64,
    exports: &'static [&'static str],
}

const SPECS: [Spec; 6] = [
    Spec {
        name: "CoreFP",
        base: 0x0000_1000_0000_0000,
        prelinked: false,
        kernel_base: 0,
        exports: &[
            "_WIn9UJ86JKdV4dM",
            "_X46O5IeS",
            "_YlCJ3lg",
            "_dku592fbFAj",
            "_fdjkDSAFjklaf2s",
            "_lxpgvVMLd0S7uRl",
        ],
    },
    Spec {
        name: "AppleMediaServices",
        base: 0,
        prelinked: true,
        kernel_base: 0,
        exports: &[
            "_cp2g1b9ro",
            "_Mib5yocT",
            "_Fc3vhtJDvr",
            "_IPaI1oem5iL",
            "_jEHf8Xzsv8K",
        ],
    },
    Spec {
        name: "commerce",
        base: 0x0000_1000_c000_0000,
        prelinked: false,
        kernel_base: 0,
        exports: &[],
    },
    Spec {
        name: "adid",
        base: 0x0000_2000_0000_0000,
        prelinked: false,
        kernel_base: 0,
        exports: &[],
    },
    Spec {
        name: "fairplayd",
        base: 0x0000_6000_0000_0000,
        prelinked: false,
        kernel_base: 0,
        exports: &[],
    },
    Spec {
        name: "FairPlayIOKit",
        base: 0x0000_7000_0000_0510,
        prelinked: false,
        kernel_base: 0xffff_fe00_0700_4000,
        exports: &[],
    },
];

fn fake_address(name: &str) -> u64 {
    let hash = name.bytes().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    });
    RESOLVED_PREFIX | (hash & RESOLVED_MASK)
}

fn index(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn sha_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data))
}

fn describe_static(image: &MachImage, out: &mut String) -> std::fmt::Result {
    writeln!(out, "base {:#x}", image.base())?;
    for segment in image.segments() {
        let s = segment;
        writeln!(
            out,
            "seg {} {:#x} {:#x} {:#x} {:#x}",
            s.name, s.address, s.size, s.file_offset, s.file_size
        )?;
    }
    describe_patches(image, out)?;
    describe_fixups(image, out)?;
    let mut symbols = String::new();
    for symbol in image.symbols() {
        writeln!(symbols, "{} {:#x}", symbol.name, symbol.value)?;
    }
    writeln!(
        out,
        "symbols {} {}",
        image.symbols().len(),
        sha_hex(symbols)
    )?;
    for (start, end) in image.instruction_ranges() {
        writeln!(out, "code {start:#x} {end:#x}")?;
    }
    Ok(())
}

fn describe_patches(image: &MachImage, out: &mut String) -> std::fmt::Result {
    let original = std::fs::read(asset_path(image.name())).unwrap_or_default();
    let original = super::arm64_slice(&original).unwrap_or_default();
    let mut patches = BTreeMap::new();
    for (index, (old, new)) in original
        .chunks_exact(4)
        .zip(image.data().chunks_exact(4))
        .enumerate()
    {
        if old != new {
            patches.insert(
                index * 4,
                u32::from_le_bytes([new[0], new[1], new[2], new[3]]),
            );
        }
    }
    let mut listing = String::new();
    for (offset, value) in &patches {
        writeln!(listing, "{offset:#x}:{value:#x}")?;
    }
    writeln!(out, "patches {} {}", patches.len(), sha_hex(listing))
}

fn describe_fixups(image: &MachImage, out: &mut String) -> std::fmt::Result {
    let mut listing = String::new();
    for relocation in image.relocations() {
        match relocation {
            Relocation::Rebase { offset, target } => {
                writeln!(listing, "crebase {offset:#x} {target:#x}")?;
            }
            Relocation::Bind {
                offset,
                symbol,
                addend,
            } => {
                writeln!(listing, "cbind {offset:#x} {symbol} {addend}")?;
            }
        }
    }
    writeln!(
        out,
        "fixups {} {}",
        image.relocations().len(),
        sha_hex(listing)
    )?;
    for symbol in image.imports() {
        writeln!(out, "import {symbol}")?;
    }
    Ok(())
}

fn asset_path(name: &str) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_default()
        .join(ASSET_DIRECTORY)
        .join(name)
}

fn relocate(image: &mut MachImage, spec: &Spec, out: &mut String) -> std::fmt::Result {
    let mut calls = Vec::new();
    let mut resolver = |name: &str| -> Result<u64, Infallible> {
        calls.push(name.to_owned());
        Ok(fake_address(name))
    };
    if spec.prelinked {
        let external: HashMap<u64, String> = AMS_FUNCTIONS
            .iter()
            .map(|(a, n)| (*a, (*n).to_owned()))
            .collect();
        assert!(image.prepare_prelinked(&external, &mut resolver).is_ok());
        return Ok(());
    }
    assert!(image.relocate(spec.base, &mut resolver).is_ok());
    if spec.kernel_base != 0 {
        let result =
            image.relocate_kernel_cache_pointers(spec.base, spec.kernel_base, &mut resolver);
        assert!(result.is_ok());
    }
    let mut unique = Vec::new();
    for call in &calls {
        if !unique.contains(call) {
            unique.push(call.clone());
        }
    }
    let mut listing = String::new();
    for name in &unique {
        writeln!(listing, "{name}")?;
    }
    writeln!(
        out,
        "resolveorder {} {} {}",
        calls.len(),
        unique.len(),
        sha_hex(listing)
    )
}

type GuestRegions = Vec<(u64, Vec<u8>)>;

fn materialize(image: &MachImage) -> Result<GuestRegions, std::fmt::Error> {
    let plan = image.load_plan().map_err(|_| std::fmt::Error)?;
    let mut regions: GuestRegions = plan
        .regions
        .iter()
        .map(|region| (region.address, vec![0u8; index(region.size)]))
        .collect();
    for segment in &plan.segments {
        let length = segment.data.len() as u64;
        let (start, buffer) = find_region(&mut regions, segment.address, length)?;
        let at = index(segment.address - start);
        buffer[at..at + segment.data.len()].copy_from_slice(segment.data);
    }
    Ok(regions)
}

fn find_region(
    regions: &mut GuestRegions,
    address: u64,
    length: u64,
) -> Result<(u64, &mut Vec<u8>), std::fmt::Error> {
    regions
        .iter_mut()
        .find(|(start, buffer)| {
            address >= *start && address + length <= *start + buffer.len() as u64
        })
        .map(|(start, buffer)| (*start, buffer))
        .ok_or(std::fmt::Error)
}

fn describe_memory(image: &MachImage, out: &mut String) -> std::fmt::Result {
    let mut regions = materialize(image)?;
    for (start, buffer) in &regions {
        writeln!(
            out,
            "map {start:#x} {:#x} {}",
            buffer.len(),
            sha_hex(buffer)
        )?;
    }
    let loaded_base = image.loaded_base().ok_or(std::fmt::Error)?;
    let base = image.base();
    for segment in image
        .segments()
        .iter()
        .filter(|s| s.name != "__PAGEZERO" && s.size != 0)
    {
        let address = loaded_base.wrapping_add(segment.address.wrapping_sub(base));
        let (start, buffer) = find_region(&mut regions, address, segment.size)?;
        let at = index(address - start);
        let digest = sha_hex(&buffer[at..at + index(segment.size)]);
        let name = &segment.name;
        writeln!(
            out,
            "segbytes {name} {address:#x} {:#x} {digest}",
            segment.size
        )?;
    }
    Ok(())
}

fn describe(spec: &Spec, cache: Option<&PreparationCache>) -> Result<String, String> {
    let input = std::fs::read(asset_path(spec.name)).map_err(|error| error.to_string())?;
    let mut image =
        MachImage::open_with_cache(spec.name, &input, cache).map_err(|error| error.to_string())?;
    let mut out = format!("image {}\n", spec.name);
    describe_static(&image, &mut out).map_err(|error| error.to_string())?;
    let load_base = if spec.prelinked {
        image.base()
    } else {
        spec.base
    };
    for name in spec.exports {
        let address = image
            .export(name, load_base)
            .map_err(|error| error.to_string())?;
        writeln!(out, "export {name} {address:#x}").map_err(|error| error.to_string())?;
    }
    relocate(&mut image, spec, &mut out).map_err(|error| error.to_string())?;
    describe_memory(&image, &mut out).map_err(|error| error.to_string())?;
    Ok(out)
}

fn golden(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIRECTORY)
        .join(format!("{name}.golden"));
    std::fs::read_to_string(path).unwrap_or_default()
}

fn assert_matches_golden(cache: Option<&PreparationCache>) {
    for spec in &SPECS {
        let actual = describe(spec, cache);
        assert_eq!(
            actual.as_deref(),
            Ok(golden(spec.name).as_str()),
            "{} diverges from upstream",
            spec.name
        );
    }
}

#[test]
#[ignore = "requires the cached Apple SAP assets under ~/Library/Caches/ipatool/sap"]
fn prepared_images_match_upstream_byte_for_byte() {
    assert_matches_golden(None);
}

#[test]
#[ignore = "requires the cached Apple SAP assets under ~/Library/Caches/ipatool/sap"]
fn cached_preparations_match_upstream_byte_for_byte() {
    let directory =
        std::env::temp_dir().join(format!("ipakeep-macho-golden-{}", std::process::id()));
    let cache = PreparationCache::new(&directory);
    assert_matches_golden(Some(&cache));
    assert_matches_golden(Some(&cache));
    let _ = std::fs::remove_dir_all(&directory);
}
