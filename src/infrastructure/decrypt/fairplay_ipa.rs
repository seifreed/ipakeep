//! Pure IPA planning and repack for native offline `FairPlay` decryption.
//!
//! This is the no-crypto half of the offline decryptor ported from londek's
//! `ipadecrypt` (Go). It maps each per-page-key file (`SUPF`/`SUPP`) in an
//! encrypted IPA to its Mach-O binary and `SINF` license, reads every zip
//! member, and repacks a decrypted IPA from caller-supplied replacement bytes.
//!
//! It deliberately does not depend on the crypto module: the orchestrator plans
//! with [`plan_entries`], decrypts each binary separately, then repacks with
//! [`assemble`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;

/// The page-key file suffixes, best first: `SUPF` (f-class: `.supf`/`.v5.supf`)
/// and `SUPP` (p-class: `.supp`/`.v4.supp`). Newer generations (`.v5.supf`,
/// `.v4.supp`) rank ahead of legacy ones, and `SUPF` ahead of `SUPP`.
const PAGE_KEY_SUFFIXES: [&str; 4] = [".v5.supf", ".v4.supp", ".supf", ".supp"];

const SC_INFO_SEP: &str = "/SC_Info/";

/// Bundle suffix marking an `.app` directory. A named constant keeps the suffix
/// comparison exact and case-sensitive, matching the Go `strings.HasSuffix`.
const APP_SUFFIX: &str = ".app";

/// `SINF` license file suffix, matched case-sensitively like the Go source.
const SINF_SUFFIX: &str = ".sinf";

/// One planned decrypt target: a `FairPlay`-protected binary with its page-key
/// file (`SUPF`/`SUPP`) and `SINF` license, plus its enclosing bundle path.
#[derive(Debug, Clone)]
pub struct PlanEntry {
    /// Zip path of the Mach-O binary to decrypt.
    pub binary_path: String,
    /// Zip path of the page-key file (`.v5.supf`/`.v4.supp`/`.supf`/`.supp`).
    pub supf_path: String,
    /// Zip path of the `SINF` license for the binary.
    pub sinf_path: String,
    /// Zip path of the bundle that encloses the binary (no trailing slash).
    pub bundle: String,
}

/// Rank and suffix of `name` in [`PAGE_KEY_SUFFIXES`], or `None` when `name` is
/// not a page-key file.
fn page_key_suffix(name: &str) -> Option<(usize, &'static str)> {
    PAGE_KEY_SUFFIXES
        .iter()
        .enumerate()
        .find(|(_, suffix)| name.ends_with(**suffix))
        .map(|(rank, suffix)| (rank, *suffix))
}

/// Keep, per binary stem, the `SUPF`/`SUPP` whose suffix ranks best in
/// [`PAGE_KEY_SUFFIXES`]. Returns the kept paths sorted.
fn supf_paths(names: &BTreeSet<String>) -> Vec<String> {
    let mut best: BTreeMap<String, (usize, String)> = BTreeMap::new();

    for name in names {
        let Some((rank, suffix)) = page_key_suffix(name) else {
            continue;
        };
        let stem = name[..name.len() - suffix.len()].to_string();
        match best.get(&stem) {
            Some((cur_rank, _)) if *cur_rank <= rank => {}
            _ => {
                best.insert(stem, (rank, name.clone()));
            }
        }
    }

    let mut out: Vec<String> = best.into_values().map(|(_, name)| name).collect();
    out.sort();
    out
}

/// Map every `SUPF`/`SUPP` in the IPA to its binary and `SINF`. Mirrors
/// `ipa.go` `planEntries` + `supfPaths`.
///
/// # Errors
///
/// Returns an error if a page-key file lies outside an `SC_Info` directory or
/// has no matching binary in `names`.
pub fn plan_entries(names: &BTreeSet<String>) -> Result<Vec<PlanEntry>, String> {
    let mut entries = Vec::new();

    for supf_path in supf_paths(names) {
        let Some(idx) = supf_path.rfind(SC_INFO_SEP) else {
            return Err(format!("SUPF/SUPP outside SC_Info: {supf_path}"));
        };

        let bundle = supf_path[..idx].to_string();
        let filename = &supf_path[idx + SC_INFO_SEP.len()..];

        let suffix = page_key_suffix(filename).map_or("", |(_, suffix)| suffix);
        let stem = &filename[..filename.len() - suffix.len()];
        let binary_path = format!("{bundle}/{stem}");

        let mut sinf_path = format!("{bundle}/SC_Info/{stem}.sinf");
        if suffix == ".v5.supf" || suffix == ".v4.supp" {
            let v4 = format!("{bundle}/SC_Info/{stem}.v4.sinf");
            if names.contains(&v4) {
                sinf_path = v4;
            }
        }

        if !names.contains(&binary_path) {
            return Err(format!("SUPF/SUPP lacks binary/SINF: {supf_path}"));
        }

        entries.push(PlanEntry {
            binary_path,
            supf_path,
            sinf_path,
            bundle,
        });
    }

    Ok(entries)
}

/// Find a usable `SINF` in the nearest enclosing `.app` bundle, used when an
/// extension or framework has no `SINF` of its own. Mirrors `ipa.go`
/// `enclosingAppSinf`: prefer `<app>.sinf`, then `<app>.v4.sinf`, then the first
/// non-`.v4.sinf`, then the first `SINF`.
#[must_use]
pub fn enclosing_app_sinf(names: &BTreeSet<String>, bundle: &str) -> Option<String> {
    let parts: Vec<&str> = bundle.split('/').collect();

    for i in (1..=parts.len()).rev() {
        let prefix = parts[..i].join("/");
        if prefix.ends_with(APP_SUFFIX)
            && let Some(sinf) = find_app_sinf(names, &prefix)
        {
            return Some(sinf);
        }
    }

    None
}

fn find_app_sinf(names: &BTreeSet<String>, prefix: &str) -> Option<String> {
    let sc_info = format!("{prefix}/SC_Info/");
    let depth = sc_info.matches('/').count();
    let sinfs: Vec<&String> = names
        .iter()
        .filter(|name| {
            name.starts_with(&sc_info)
                && name.ends_with(SINF_SUFFIX)
                && name.matches('/').count() == depth
        })
        .collect();
    if sinfs.is_empty() {
        return None;
    }

    let base = prefix.rsplit('/').next().unwrap_or(prefix);
    let stem = base.rfind('.').map_or(base, |dot| &base[..dot]);
    for suffix in [".sinf", ".v4.sinf"] {
        let preferred = format!("{sc_info}{stem}{suffix}");
        if sinfs.iter().any(|name| **name == preferred) {
            return Some(preferred);
        }
    }
    sinfs
        .iter()
        .find(|name| !name.ends_with(".v4.sinf"))
        .or_else(|| sinfs.first())
        .map(|name| (*name).clone())
}

/// Read all members of the zip at `ipa_path` into a map `name -> bytes`.
/// Mirrors the `ipa.go` `readMember` loop, rejecting duplicate members.
///
/// # Errors
///
/// Returns an error if the archive cannot be opened or read, or if it contains
/// a duplicate member name.
pub fn read_members(ipa_path: &Path) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let file = std::fs::File::open(ipa_path).map_err(|e| format!("{}: {e}", ipa_path.display()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    if archive.has_duplicate_names() {
        return Err("input zip has duplicate member names".into());
    }

    let mut members = BTreeMap::new();
    for i in 0..archive.len() {
        let mut member = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = member.name().map_err(|e| e.to_string())?.into_owned();
        let mut data = Vec::new();
        member
            .read_to_end(&mut data)
            .map_err(|e| format!("read {name}: {e}"))?;
        members.insert(name, data);
    }

    Ok(members)
}

/// Repack a decrypted IPA: copy the source zip at `src_ipa`, substituting
/// members named in `replacements` with the supplied decrypted bytes, stripping
/// `SC_Info/*`, `iTunesMetadata.plist`, `iTunesArtwork`, `META-INF`,
/// `BCSymbolMaps`, `Symbols`, and `.dSYM`, and dropping Watch apps unless
/// `keep_watch`. Mirrors `pipeline.Assemble`. Returns the output IPA bytes.
///
/// # Errors
///
/// Returns an error if the source archive cannot be opened or any member cannot
/// be read or rewritten.
pub fn assemble(
    src_ipa: &Path,
    replacements: &BTreeMap<String, Vec<u8>>,
    keep_watch: bool,
) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(src_ipa).map_err(|e| format!("{}: {e}", src_ipa.display()))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let written = write_replacements(&mut writer, replacements, keep_watch)?;

    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let entry = archive.by_index_raw(i).map_err(|e| e.to_string())?;
        let name = entry.name().map_err(|e| e.to_string())?.into_owned();
        names.push(name);
    }

    for (i, name) in names.iter().enumerate() {
        if written.contains(name) || is_excluded_ipa_entry(name, keep_watch) {
            continue;
        }
        let member = archive.by_index_raw(i).map_err(|e| e.to_string())?;
        writer
            .raw_copy_file(member)
            .map_err(|e| format!("copy {name}: {e}"))?;
    }

    let cursor = writer.finish().map_err(|e| e.to_string())?;
    Ok(cursor.into_inner())
}

fn write_replacements<W: Write + Seek>(
    writer: &mut zip::ZipWriter<W>,
    replacements: &BTreeMap<String, Vec<u8>>,
    keep_watch: bool,
) -> Result<BTreeSet<String>, String> {
    let mut written = BTreeSet::new();
    for (name, data) in replacements {
        if is_excluded_ipa_entry(name, keep_watch) {
            continue;
        }
        writer
            .start_file(name, SimpleFileOptions::default())
            .map_err(|e| format!("create {name}: {e}"))?;
        writer
            .write_all(data)
            .map_err(|e| format!("write {name}: {e}"))?;
        written.insert(name.clone());
    }
    Ok(written)
}

/// Report whether `name` is stripped from the output IPA. Mirrors
/// `pipeline.isExcludedIPAEntry`: `SC_Info`, Watch/`WatchKitSupport2` (unless
/// `keep_watch`), `.dSYM`, `BCSymbolMaps`, `Symbols`, `META-INF`,
/// `iTunesMetadata.plist`, and `iTunesArtwork`.
fn is_excluded_ipa_entry(name: &str, keep_watch: bool) -> bool {
    let s = name.strip_suffix('/').unwrap_or(name);

    if s == "iTunesMetadata.plist"
        || s == "Payload/iTunesMetadata.plist"
        || s == "Payload/iTunesArtwork"
    {
        return true;
    }

    if s == "Payload/META-INF" || s.starts_with("Payload/META-INF/") {
        return true;
    }

    let parts: Vec<&str> = s.split('/').collect();

    // Walk segments inside Payload/<app>.app/ (skip "Payload" and "<app>.app").
    for seg in parts.iter().skip(2) {
        match *seg {
            "Watch" | "WatchKitSupport2" if !keep_watch => return true,
            "SC_Info" | "BCSymbolMaps" | "Symbols" => return true,
            _ => {}
        }
        if seg.ends_with(".dSYM") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|&s| s.to_string()).collect()
    }

    #[test]
    fn plan_entries_maps_v5_supf_to_v4_sinf_and_binary() {
        let names = set(&[
            "Payload/App.app/App",
            "Payload/App.app/SC_Info/App.v5.supf",
            "Payload/App.app/SC_Info/App.v4.sinf",
            "Payload/App.app/SC_Info/App.sinf",
            "Payload/App.app/Info.plist",
        ]);

        let entries = plan_entries(&names).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.binary_path, "Payload/App.app/App");
        assert_eq!(entry.supf_path, "Payload/App.app/SC_Info/App.v5.supf");
        // .v5.supf prefers the .v4.sinf license when present.
        assert_eq!(entry.sinf_path, "Payload/App.app/SC_Info/App.v4.sinf");
        assert_eq!(entry.bundle, "Payload/App.app");
    }

    #[test]
    fn plan_entries_legacy_supf_uses_plain_sinf() {
        let names = set(&[
            "Payload/App.app/App",
            "Payload/App.app/SC_Info/App.supf",
            "Payload/App.app/SC_Info/App.v4.sinf",
            "Payload/App.app/SC_Info/App.sinf",
        ]);

        let entries = plan_entries(&names).unwrap();
        assert_eq!(entries.len(), 1);
        // Legacy .supf keeps the plain .sinf even when a .v4.sinf exists.
        assert_eq!(entries[0].sinf_path, "Payload/App.app/SC_Info/App.sinf");
    }

    #[test]
    fn plan_entries_errors_without_binary() {
        let names = set(&["Payload/App.app/SC_Info/App.v5.supf"]);
        assert!(plan_entries(&names).is_err());
    }

    #[test]
    fn plan_entries_rejects_page_keys_outside_sc_info() {
        let names = set(&["Payload/App.app/App.supf"]);
        assert!(
            plan_entries(&names)
                .unwrap_err()
                .contains("outside SC_Info")
        );
    }

    #[test]
    fn supf_ranking_prefers_v5_then_supf_then_supp() {
        let names = set(&[
            "Payload/App.app/SC_Info/App.v5.supf",
            "Payload/App.app/SC_Info/App.supf",
            "Payload/App.app/SC_Info/App.supp",
        ]);
        assert_eq!(
            supf_paths(&names),
            vec!["Payload/App.app/SC_Info/App.v5.supf".to_string()]
        );

        let names = set(&[
            "Payload/App.app/SC_Info/App.supf",
            "Payload/App.app/SC_Info/App.supp",
        ]);
        assert_eq!(
            supf_paths(&names),
            vec!["Payload/App.app/SC_Info/App.supf".to_string()]
        );
    }

    #[test]
    fn enclosing_app_sinf_falls_back_to_app_bundle() {
        let names = set(&[
            "Payload/App.app/SC_Info/App.sinf",
            "Payload/App.app/SC_Info/App.v4.sinf",
        ]);
        let found = enclosing_app_sinf(&names, "Payload/App.app/Frameworks/Foo.framework");
        assert_eq!(found.as_deref(), Some("Payload/App.app/SC_Info/App.sinf"));
    }

    #[test]
    fn enclosing_app_sinf_prefers_non_v4_then_first() {
        // No App-stemmed sinf: the first non-.v4.sinf wins.
        let names = set(&[
            "Payload/App.app/SC_Info/Other.sinf",
            "Payload/App.app/SC_Info/Zed.v4.sinf",
        ]);
        let found = enclosing_app_sinf(&names, "Payload/App.app/PlugIns/Ext.appex");
        assert_eq!(found.as_deref(), Some("Payload/App.app/SC_Info/Other.sinf"));
    }

    #[test]
    fn enclosing_app_sinf_falls_back_to_the_first_v4_sinf() {
        let names = set(&[
            "Payload/App.app/SC_Info/Other.v4.sinf",
            "Payload/App.app/SC_Info/Zed.v4.sinf",
        ]);
        let found = enclosing_app_sinf(&names, "Payload/App.app/PlugIns/Ext.appex");
        assert_eq!(
            found.as_deref(),
            Some("Payload/App.app/SC_Info/Other.v4.sinf")
        );
    }

    #[test]
    fn enclosing_app_sinf_none_without_app() {
        let names = set(&["Payload/App.app/SC_Info/App.sinf"]);
        assert!(enclosing_app_sinf(&names, "Payload/Loose/Dir").is_none());
    }

    #[test]
    fn is_excluded_matches_go_exclude_set() {
        assert!(is_excluded_ipa_entry("iTunesMetadata.plist", false));
        assert!(is_excluded_ipa_entry("Payload/META-INF", false));
        assert!(is_excluded_ipa_entry(
            "Payload/App.app/SC_Info/App.sinf",
            false
        ));
        assert!(is_excluded_ipa_entry(
            "Payload/App.app/Watch/W.app/W",
            false
        ));
        assert!(!is_excluded_ipa_entry(
            "Payload/App.app/Watch/W.app/W",
            true
        ));
        assert!(is_excluded_ipa_entry(
            "Payload/App.app/WatchKitSupport2",
            false
        ));
        assert!(is_excluded_ipa_entry(
            "Payload/App.app/Frameworks/Foo.dSYM/Contents/Info.plist",
            true
        ));
        assert!(!is_excluded_ipa_entry("Payload/App.app/App", false));
        assert!(!is_excluded_ipa_entry("Payload/App.app/Info.plist", false));
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn read_zip(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        let mut out = BTreeMap::new();
        for i in 0..archive.len() {
            let mut member = archive.by_index(i).unwrap();
            let name = member.name().unwrap().into_owned();
            let mut data = Vec::new();
            member.read_to_end(&mut data).unwrap();
            out.insert(name, data);
        }
        out
    }

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ipakeep-fairplay-{tag}-{nanos}.ipa"))
    }

    #[test]
    fn read_members_reads_every_entry() {
        let zip = build_zip(&[
            ("Payload/App.app/App", b"binary"),
            ("Payload/App.app/Info.plist", b"plist"),
        ]);
        let path = temp_path("read");
        std::fs::write(&path, &zip).unwrap();

        let members = read_members(&path).unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(members.get("Payload/App.app/App").unwrap(), b"binary");
        assert_eq!(members.get("Payload/App.app/Info.plist").unwrap(), b"plist");
    }

    #[test]
    fn read_members_rejects_duplicate_names() {
        let mut zip = build_zip(&[("first.txt", b"first"), ("other.txt", b"second")]);
        let positions: Vec<usize> = zip
            .windows(b"other.txt".len())
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == b"other.txt").then_some(index))
            .collect();
        assert_eq!(positions.len(), 2);
        for position in positions {
            zip[position..position + b"other.txt".len()].copy_from_slice(b"first.txt");
        }

        let path = temp_path("duplicate");
        std::fs::write(&path, &zip).unwrap();
        let result = read_members(&path);
        let _ = std::fs::remove_file(&path);

        assert!(result.unwrap_err().contains("duplicate member"));
    }

    #[test]
    fn assemble_strips_excluded_and_substitutes_binary() {
        let zip = build_zip(&[
            ("Payload/App.app/App", b"encrypted-binary"),
            ("Payload/App.app/Info.plist", b"the-plist"),
            ("Payload/App.app/SC_Info/App.sinf", b"sinf"),
            ("Payload/App.app/SC_Info/App.v5.supf", b"supf"),
            ("iTunesMetadata.plist", b"meta"),
        ]);
        let path = temp_path("assemble");
        std::fs::write(&path, &zip).unwrap();

        let mut replacements = BTreeMap::new();
        replacements.insert(
            "Payload/App.app/App".to_string(),
            b"decrypted-binary".to_vec(),
        );
        replacements.insert(
            "Payload/App.app/SC_Info/Replacement.sinf".to_string(),
            b"replacement-sinf".to_vec(),
        );

        let out = assemble(&path, &replacements, false).unwrap();
        let _ = std::fs::remove_file(&path);
        let members = read_zip(&out);

        // Substituted binary carries the decrypted bytes.
        assert_eq!(
            members.get("Payload/App.app/App").unwrap(),
            b"decrypted-binary"
        );
        // Verbatim member is preserved.
        assert_eq!(
            members.get("Payload/App.app/Info.plist").unwrap(),
            b"the-plist"
        );
        // SC_Info and iTunesMetadata are stripped.
        assert!(!members.contains_key("Payload/App.app/SC_Info/App.sinf"));
        assert!(!members.contains_key("Payload/App.app/SC_Info/App.v5.supf"));
        assert!(!members.contains_key("Payload/App.app/SC_Info/Replacement.sinf"));
        assert!(!members.contains_key("iTunesMetadata.plist"));
    }

    fn write_temp_zip(tag: &str, zip: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{tag}.ipa"));
        std::fs::write(&path, zip).unwrap();
        (directory, path)
    }

    #[test]
    fn read_members_reports_corrupt_member_data() {
        let zip = super::super::tests::corrupt_stored_data(
            super::super::tests::zip_members(&[("Payload/App.app/App", b"binary-bytes")]),
            b"binary-bytes",
        );
        let (_directory, path) = write_temp_zip("crc", &zip);

        let error = read_members(&path).unwrap_err();
        assert!(error.starts_with("read Payload/App.app/App: "), "{error}");
    }

    #[test]
    fn assemble_reports_unreadable_member_headers() {
        let zip = super::super::tests::corrupt_local_header(
            super::super::tests::zip_members(&[("Payload/App.app/App", b"binary")]),
            0,
        );
        let (_directory, path) = write_temp_zip("header", &zip);

        let error = assemble(&path, &BTreeMap::new(), false).unwrap_err();
        assert!(error.contains("Invalid local file header"), "{error}");
    }

    /// A name the source zip can hold (its length is a `u16`) but too long for
    /// a copied local header, which must also fit the 30 fixed bytes in 64 KiB.
    const UNCOPYABLE_NAME_LENGTH: u16 = 65_520;
    const LOCAL_HEADER_SIGNATURE: u32 = 0x0403_4b50;
    const CENTRAL_HEADER_SIGNATURE: u32 = 0x0201_4b50;
    const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
    const ZIP_VERSION: u16 = 20;
    /// 1980-01-01, the first valid DOS date.
    const DOS_DATE: u16 = 0x21;

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// Version, flags, method, time, date, CRC and sizes of an empty stored
    /// entry, then the name length and an empty extra field.
    fn push_entry_fields(out: &mut Vec<u8>, name: &[u8]) {
        for value in [ZIP_VERSION, 0, 0, 0, DOS_DATE] {
            push_u16(out, value);
        }
        for _ in 0..3 {
            push_u32(out, 0);
        }
        push_u16(out, u16::try_from(name.len()).unwrap());
        push_u16(out, 0);
    }

    /// Hand-built single-entry zip (an empty stored member named `name`):
    /// `ZipWriter` itself refuses names this long.
    fn single_entry_zip(name: &[u8]) -> Vec<u8> {
        let mut zip = Vec::new();
        push_u32(&mut zip, LOCAL_HEADER_SIGNATURE);
        push_entry_fields(&mut zip, name);
        zip.extend_from_slice(name);
        let central_start = zip.len();
        push_u32(&mut zip, CENTRAL_HEADER_SIGNATURE);
        push_u16(&mut zip, ZIP_VERSION);
        push_entry_fields(&mut zip, name);
        for value in [0, 0, 0] {
            push_u16(&mut zip, value);
        }
        push_u32(&mut zip, 0);
        push_u32(&mut zip, 0);
        zip.extend_from_slice(name);
        let central_size = zip.len() - central_start;
        push_u32(&mut zip, END_OF_CENTRAL_DIRECTORY_SIGNATURE);
        for value in [0, 0, 1, 1] {
            push_u16(&mut zip, value);
        }
        push_u32(&mut zip, u32::try_from(central_size).unwrap());
        push_u32(&mut zip, u32::try_from(central_start).unwrap());
        push_u16(&mut zip, 0);
        zip
    }

    #[test]
    fn assemble_reports_members_that_cannot_be_copied() {
        let name = "a".repeat(usize::from(UNCOPYABLE_NAME_LENGTH));
        let (_directory, path) = write_temp_zip("long-name", &single_entry_zip(name.as_bytes()));

        let error = assemble(&path, &BTreeMap::new(), false).unwrap_err();
        assert!(error.starts_with(&format!("copy {name}: ")), "{error}");
    }

    /// Longer than the 64 KiB a zip local header can hold.
    const OVERSIZED_NAME_LENGTH: usize = 70_000;

    #[test]
    fn write_replacements_reports_entries_that_cannot_be_created() {
        let name = "a".repeat(OVERSIZED_NAME_LENGTH);
        let replacements = BTreeMap::from([(name.clone(), b"data".to_vec())]);
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));

        let error = write_replacements(&mut writer, &replacements, false).unwrap_err();
        assert!(error.starts_with(&format!("create {name}: ")), "{error}");
    }

    /// Bytes the failing writer accepts: room for a local header, not the data.
    const WRITABLE_PREFIX: u64 = 128;
    /// Enough incompressible data to force the deflater to flush.
    const INCOMPRESSIBLE_LENGTH: usize = 1 << 20;

    /// Seekable writer that fails once its position passes `WRITABLE_PREFIX`.
    struct FailingWriter(Cursor<Vec<u8>>);

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.position() + bytes.len() as u64 > WRITABLE_PREFIX {
                return Err(std::io::Error::other("disk full"));
            }
            self.0.write(bytes)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for FailingWriter {
        fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(position)
        }
    }

    fn incompressible(length: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn write_replacements_reports_entries_that_cannot_be_written() {
        let name = "Payload/App.app/App".to_string();
        let replacements = BTreeMap::from([(name, incompressible(INCOMPRESSIBLE_LENGTH))]);
        let mut writer = zip::ZipWriter::new(FailingWriter(Cursor::new(Vec::new())));

        let error = write_replacements(&mut writer, &replacements, false).unwrap_err();
        assert!(
            error.starts_with("write Payload/App.app/App: ") && error.contains("disk full"),
            "{error}"
        );
    }
}
