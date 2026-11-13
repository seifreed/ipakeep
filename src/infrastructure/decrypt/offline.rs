//! Offline decryption through londek's `ipadecrypt`.
//!
//! `ipadecrypt` decrypts an encrypted IPA on this computer with a per-account
//! credential minted once by `ipadecrypt bootstrap`, so the app never has to run
//! on a device. ipakeep drives it on a local IPA, then verifies the result
//! itself before accepting it.

use super::ensure_decrypted;
use crate::infrastructure::exec::{find_in_path, run_inherit, temp_dir};
use std::path::{Path, PathBuf};
use std::process::Command;

const PROGRAM: &str = "ipadecrypt";
const NO_UPDATE_CHECK_ENV: &str = "IPADECRYPT_NO_UPDATE_CHECK";
const OUTPUT_NAME: &str = "ipadecrypt-output.ipa";
const SETUP_HINT: &str = "install it (`go install github.com/londek/ipadecrypt/cmd/ipadecrypt@latest` \
     or a release from https://github.com/londek/ipadecrypt/releases) and run \
     `ipadecrypt bootstrap` once for the Apple ID that owns the app";

/// Decrypt `ipa` with `ipadecrypt` and return the verified decrypted IPA bytes.
///
/// With `allow_on_device`, `ipadecrypt` may fall back to its own jailbroken
/// device when the offline decryptor cannot handle the app.
///
/// # Errors
///
/// Returns an error if `ipadecrypt` is missing or not bootstrapped, the input is
/// not a local `.ipa`, or the produced IPA does not verify as decrypted.
pub fn run_offline(ipa: &Path, allow_on_device: bool) -> Result<Vec<u8>, String> {
    let ipa = local_ipa(ipa)?;
    if find_in_path(PROGRAM).is_none() {
        return Err(format!("`{PROGRAM}` not found on PATH — {SETUP_HINT}"));
    }
    let work = temp_dir("offline")?;
    let result = decrypt_into(&ipa, &work, allow_on_device);
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn decrypt_into(ipa: &Path, work: &Path, allow_on_device: bool) -> Result<Vec<u8>, String> {
    let output = work.join(OUTPUT_NAME);
    let mut command = Command::new(PROGRAM);
    command
        .args(offline_argv(ipa, &output, allow_on_device))
        .env(NO_UPDATE_CHECK_ENV, "1");
    run_inherit(command)?;

    let produced = produced_ipa(&output)?;
    let bytes = std::fs::read(&produced).map_err(|e| format!("{}: {e}", produced.display()))?;
    ensure_decrypted(bytes)
}

/// `ipadecrypt` treats any argument not ending in `.ipa` as an App Store
/// identifier and downloads it, so only an existing local `.ipa` is accepted.
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

/// Argv for `ipadecrypt decrypt` on a local IPA. Pure for testing.
fn offline_argv(ipa: &Path, output: &Path, allow_on_device: bool) -> Vec<String> {
    let mut args = vec![
        "decrypt".to_string(),
        ipa.to_string_lossy().into_owned(),
        "--output".to_string(),
        output.to_string_lossy().into_owned(),
    ];
    if !allow_on_device {
        args.push("--no-on-device".to_string());
    }
    args
}

/// `ipadecrypt` reports failures (including a missing account or credential)
/// and still exits 0, removing its partial output; the IPA at the requested
/// output path is the only reliable success signal.
fn produced_ipa(output: &Path) -> Result<PathBuf, String> {
    if output.is_file() {
        Ok(output.to_path_buf())
    } else {
        Err(format!(
            "{PROGRAM} produced no decrypted IPA (see its messages above). If it reported \
             no Apple account or no decryption credential, run `ipadecrypt bootstrap` once \
             for the Apple ID that owns the app"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_decrypts_the_local_ipa_into_the_requested_output() {
        let args = offline_argv(Path::new("/in/App.ipa"), Path::new("/w/out.ipa"), true);
        assert_eq!(args, ["decrypt", "/in/App.ipa", "--output", "/w/out.ipa"]);
    }

    #[test]
    fn argv_suppresses_the_device_fallback_on_request() {
        let args = offline_argv(Path::new("/in/App.ipa"), Path::new("/w/out.ipa"), false);
        assert_eq!(args.last().unwrap(), "--no-on-device");
    }

    #[test]
    fn produced_ipa_is_the_requested_output_file() {
        let work = tempfile::tempdir().unwrap();
        let output = work.path().join(OUTPUT_NAME);
        let missing = produced_ipa(&output).unwrap_err();
        assert!(missing.contains("ipadecrypt bootstrap"));

        std::fs::write(&output, b"PK").unwrap();
        assert_eq!(produced_ipa(&output).unwrap(), output);
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
}
