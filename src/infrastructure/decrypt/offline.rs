//! Native offline `FairPlay` decryption.
//!
//! Decrypts an encrypted App Store IPA on this computer with a 16-byte
//! per-account `FairPlay` credential, so the app never has to run on a device.
//! This is a native Rust reimplementation of londek's `ipadecrypt` credential
//! path (the `internal/fairplay` package): no external binary, no emulator.
//! The hard crypto lives in [`super::fairplay`]; the IPA zip planning and
//! repack in [`super::fairplay_ipa`]. ipakeep verifies the result itself
//! before accepting it.

use super::ensure_decrypted;
use super::fairplay::{self, CREDENTIAL_SIZE};
use super::fairplay_ipa::{self, PlanEntry};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Environment overrides pointing at raw 16-byte credential files.
const STANDARD_ENV: &str = "IPAKEEP_FAIRPLAY_CREDENTIAL";
const ARCADE_ENV: &str = "IPAKEEP_FAIRPLAY_ARCADE_CREDENTIAL";

/// The account's `FairPlay` credentials: `standard` decodes regular App Store
/// licenses, `arcade` (optional) decodes Apple Arcade ones.
struct Credentials {
    standard: Vec<u8>,
    arcade: Option<Vec<u8>>,
}

/// Decrypt `ipa` natively and return the verified decrypted IPA bytes.
///
/// `allow_on_device` is accepted for CLI compatibility but is a no-op: the
/// native decryptor is always offline and never touches a device.
///
/// # Errors
///
/// Returns an error if the input is not a local `.ipa`, no credential is
/// available, the credential does not match the app's account, the IPA has no
/// decryptable binary, or the produced IPA does not verify as decrypted.
pub fn run_offline(ipa: &Path, allow_on_device: bool) -> Result<Vec<u8>, String> {
    let _ = allow_on_device;
    let ipa = local_ipa(ipa)?;
    let creds = load_credentials()?;
    let bytes = decrypt_ipa(&ipa, &creds, false, false)?;
    ensure_decrypted(bytes)
}

/// Decrypt every `FairPlay`-protected binary in the IPA whose SINF the loaded
/// credential decodes, and repack a decrypted IPA. Mirrors `ipa.go` `Decrypt`.
fn decrypt_ipa(
    ipa: &Path,
    creds: &Credentials,
    skip_appex: bool,
    keep_watch: bool,
) -> Result<Vec<u8>, String> {
    let members = fairplay_ipa::read_members(ipa)?;
    let names: BTreeSet<String> = members.keys().cloned().collect();
    let entries = fairplay_ipa::plan_entries(&names)?;

    let mut replacements: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    for entry in entries {
        if skip_appex && entry.binary_path.contains(".appex/") {
            continue;
        }
        if !keep_watch && entry.binary_path.contains("/Watch/") {
            continue;
        }
        if let Some(decrypted) = decrypt_entry(&members, &names, &entry, creds)? {
            replacements.insert(entry.binary_path, decrypted);
        }
    }

    if replacements.is_empty() {
        return Err("no encrypted binaries with supported SINF/SUPF/SUPP".to_string());
    }

    fairplay_ipa::assemble(ipa, &replacements, keep_watch)
}

fn decrypt_entry(
    members: &BTreeMap<String, Vec<u8>>,
    names: &BTreeSet<String>,
    entry: &PlanEntry,
    creds: &Credentials,
) -> Result<Option<Vec<u8>>, String> {
    let source = members
        .get(&entry.binary_path)
        .ok_or_else(|| format!("missing binary member {}", entry.binary_path))?;
    let sinf = read_entry_sinf(members, names, entry)?;
    let supf = members
        .get(&entry.supf_path)
        .ok_or_else(|| format!("missing page-key member {}", entry.supf_path))?;
    let credential = entry_credential(creds, sinf)?;
    if !fairplay::credential_decodes(credential, sinf) {
        return Err(format!(
            "the loaded credential does not decode {}'s license — it is from a \
             different Apple ID than the one that owns this app",
            entry.binary_path
        ));
    }
    Ok(fairplay::decrypt_binary(source, sinf, supf, credential)?.map(|(decrypted, _)| decrypted))
}

fn entry_credential<'a>(creds: &'a Credentials, sinf: &[u8]) -> Result<&'a [u8], String> {
    if fairplay::is_arcade_sinf(sinf) {
        creds
            .arcade
            .as_deref()
            .ok_or_else(|| "this Apple Arcade app needs the account's Arcade credential".into())
    } else {
        Ok(creds.standard.as_slice())
    }
}

/// The SINF bytes for an entry: its own, else a fallback from the enclosing
/// `.app` (frameworks and extensions share the app's SINF). Mirrors `ipa.go`.
fn read_entry_sinf<'a>(
    members: &'a BTreeMap<String, Vec<u8>>,
    names: &BTreeSet<String>,
    entry: &PlanEntry,
) -> Result<&'a [u8], String> {
    let sinf_path = if names.contains(&entry.sinf_path) {
        entry.sinf_path.clone()
    } else {
        fairplay_ipa::enclosing_app_sinf(names, &entry.bundle)
            .ok_or_else(|| format!("SUPF/SUPP lacks binary/SINF: {}", entry.supf_path))?
    };
    members
        .get(&sinf_path)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing SINF member {sinf_path}"))
}

/// Accept only an existing local `.ipa`.
fn local_ipa(ipa: &Path) -> Result<PathBuf, String> {
    let is_ipa = ipa
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("ipa"));
    if !is_ipa {
        return Err(format!("{} is not an .ipa file", ipa.display()));
    }
    if !ipa.is_file() {
        return Err(format!("{}: no such IPA file", ipa.display()));
    }
    std::path::absolute(ipa).map_err(|e| format!("{}: {e}", ipa.display()))
}

/// Resolve the account credential(s). Order: the `IPAKEEP_FAIRPLAY_CREDENTIAL`
/// env path, else the single `*.bin` under a known credential directory.
fn load_credentials() -> Result<Credentials, String> {
    let standard = match std::env::var_os(STANDARD_ENV) {
        Some(path) => read_credential(Path::new(&path))?,
        None => read_credential(&sole_credential_file()?)?,
    };
    let arcade = match std::env::var_os(ARCADE_ENV) {
        Some(path) => Some(read_credential(Path::new(&path))?),
        None => None,
    };
    Ok(Credentials { standard, arcade })
}

/// Read and validate a raw 16-byte credential file.
fn read_credential(path: &Path) -> Result<Vec<u8>, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("read credential {}: {e}", path.display()))?;
    if data.len() != CREDENTIAL_SIZE {
        return Err(format!(
            "credential {} must be exactly {CREDENTIAL_SIZE} bytes, got {}",
            path.display(),
            data.len()
        ));
    }
    Ok(data)
}

/// The one `*.bin` credential in a known directory, or an actionable error.
fn sole_credential_file() -> Result<PathBuf, String> {
    let mut found: Vec<PathBuf> = Vec::new();
    for dir in credential_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "bin") {
                found.push(path);
            }
        }
        if !found.is_empty() {
            break;
        }
    }
    match found.len() {
        0 => Err(format!(
            "no FairPlay credential found; set {STANDARD_ENV}=/path/to/credential.bin \
             (a 16-byte per-account credential)"
        )),
        1 => Ok(found.remove(0)),
        _ => Err(format!(
            "multiple credentials found; pick one with {STANDARD_ENV}=/path/to/credential.bin"
        )),
    }
}

/// Directories searched for a cached credential, best first.
fn credential_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        dirs.push(
            home.join("Library")
                .join("Application Support")
                .join("ipakeep")
                .join("credentials"),
        );
        dirs.push(home.join(".ipadecrypt").join("credentials"));
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn plan_entry() -> PlanEntry {
        PlanEntry {
            binary_path: "Payload/Game.app/Game".into(),
            supf_path: "Payload/Game.app/SC_Info/Game.supf".into(),
            sinf_path: "Payload/Game.app/SC_Info/Game.sinf".into(),
            bundle: "Payload/Game.app".into(),
        }
    }

    fn atom(tag: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut atom = Vec::with_capacity(payload.len() + 8);
        atom.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
        atom.extend_from_slice(tag);
        atom.extend_from_slice(payload);
        atom
    }

    fn arcade_sinf() -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&atom(b"key ", &[4, 0, 0, 0]));
        atom(b"sinf", &atom(b"schi", &key))
    }

    #[test]
    fn only_existing_local_ipas_are_accepted() {
        let work = tempfile::tempdir().unwrap();
        let ipa = work.path().join("App.IPA");
        assert!(local_ipa(&ipa).unwrap_err().contains("no such IPA"));

        std::fs::write(&ipa, b"PK").unwrap();
        assert_eq!(local_ipa(&ipa).unwrap(), ipa);
        assert!(
            local_ipa(Path::new("com.example.App"))
                .unwrap_err()
                .contains("not an .ipa")
        );
    }

    #[test]
    fn credential_must_be_sixteen_bytes() {
        let work = tempfile::tempdir().unwrap();
        let short = work.path().join("c.bin");
        std::fs::write(&short, [0u8; 8]).unwrap();
        assert!(read_credential(&short).unwrap_err().contains("16 bytes"));

        let ok = work.path().join("ok.bin");
        std::fs::write(&ok, [7u8; 16]).unwrap();
        assert_eq!(read_credential(&ok).unwrap(), vec![7u8; 16]);
        assert!(read_credential(&work.path().join("missing.bin")).is_err());
    }

    #[test]
    fn arcade_entries_require_and_select_the_arcade_credential() {
        let sinf = arcade_sinf();
        let standard = vec![1; CREDENTIAL_SIZE];
        let arcade = vec![2; CREDENTIAL_SIZE];
        let without_arcade = Credentials {
            standard: standard.clone(),
            arcade: None,
        };
        let with_arcade = Credentials {
            standard: standard.clone(),
            arcade: Some(arcade.clone()),
        };

        assert_eq!(
            entry_credential(&without_arcade, b"ordinary").unwrap(),
            standard
        );
        assert!(entry_credential(&without_arcade, &sinf).is_err());
        assert_eq!(entry_credential(&with_arcade, &sinf).unwrap(), arcade);
    }

    #[test]
    fn sinf_lookup_prefers_binary_license_then_enclosing_app() {
        let entry = plan_entry();
        let own_names = BTreeSet::from([entry.sinf_path.clone()]);
        let own_members = BTreeMap::from([(entry.sinf_path.clone(), vec![1, 2, 3])]);
        assert_eq!(
            read_entry_sinf(&own_members, &own_names, &entry).unwrap(),
            [1, 2, 3]
        );

        let fallback = "Payload/Game.app/SC_Info/Game.sinf".to_string();
        let fallback_names = BTreeSet::from([fallback.clone()]);
        let fallback_members = BTreeMap::from([(fallback, vec![4, 5, 6])]);
        assert_eq!(
            read_entry_sinf(&fallback_members, &fallback_names, &entry).unwrap(),
            [4, 5, 6]
        );
        assert!(read_entry_sinf(&BTreeMap::new(), &BTreeSet::new(), &entry).is_err());
        assert!(read_entry_sinf(&BTreeMap::new(), &own_names, &entry).is_err());
    }

    #[test]
    fn decrypt_entry_reports_missing_members_and_wrong_credentials() {
        let entry = plan_entry();
        let creds = Credentials {
            standard: vec![0; CREDENTIAL_SIZE],
            arcade: None,
        };
        let empty_names = BTreeSet::from([entry.sinf_path.clone()]);
        assert!(
            decrypt_entry(&BTreeMap::new(), &empty_names, &entry, &creds)
                .unwrap_err()
                .contains("missing binary")
        );

        let missing_page_key = BTreeMap::from([
            (entry.binary_path.clone(), vec![0]),
            (entry.sinf_path.clone(), b"invalid sinf".to_vec()),
        ]);
        assert!(
            decrypt_entry(&missing_page_key, &empty_names, &entry, &creds)
                .unwrap_err()
                .contains("missing page-key")
        );

        let wrong_credential = BTreeMap::from([
            (entry.binary_path.clone(), vec![0]),
            (entry.sinf_path.clone(), b"invalid sinf".to_vec()),
            (entry.supf_path.clone(), vec![0]),
        ]);
        assert!(
            decrypt_entry(&wrong_credential, &empty_names, &entry, &creds)
                .unwrap_err()
                .contains("different Apple ID")
        );
    }

    #[test]
    fn offline_entry_points_reject_invalid_ipa_before_loading_credentials() {
        let path = Path::new("not-an-ipa.txt");
        assert!(
            run_offline(path, false)
                .unwrap_err()
                .contains("not an .ipa")
        );
        assert!(run_offline(path, true).unwrap_err().contains("not an .ipa"));
    }

    #[test]
    fn malformed_ipa_fails_before_decryption() {
        let work = tempfile::tempdir().unwrap();
        let ipa = work.path().join("broken.ipa");
        std::fs::write(&ipa, b"not a zip archive").unwrap();
        let creds = Credentials {
            standard: vec![0; CREDENTIAL_SIZE],
            arcade: None,
        };

        assert!(decrypt_ipa(&ipa, &creds, false, false).is_err());
    }
}
