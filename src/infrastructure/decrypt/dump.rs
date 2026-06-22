//! Dump orchestration: drive a builtin or external dumper to produce a fully
//! decrypted IPA.
//!
//! The builtin backend runs `scripts/frida/ipakeep_dump.py` (per-slice bins) and
//! patches them into the encrypted IPA. The external backends shell out to
//! third-party tools that already emit a decrypted IPA, which we normalize.
//!
//! The argv builders are pure and unit-tested; the actual execution needs a
//! device (USB) or an Apple Silicon Mac (`Local`).

use super::patch_ipa_decrypted;
use crate::infrastructure::exec::{newest_ipa, require_program, run_inherit, temp_dir};
use std::path::Path;
use std::process::Command;

/// Which dumper backend to drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dumper {
    /// ipakeep's own Frida agent (per-slice bins → patched here).
    Builtin,
    /// `AloneMonkey`'s frida-ios-dump.
    FridaIosDump,
    /// bagbak.
    Bagbak,
    /// r2flutch.
    R2flutch,
}

impl Dumper {
    /// Parse a `--dumper` value.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "builtin" => Ok(Self::Builtin),
            "frida-ios-dump" => Ok(Self::FridaIosDump),
            "bagbak" => Ok(Self::Bagbak),
            "r2flutch" => Ok(Self::R2flutch),
            other => Err(format!(
                "unknown dumper {other:?} (expected builtin|frida-ios-dump|bagbak|r2flutch)"
            )),
        }
    }
}

/// Frida device the builtin runner targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpDevice {
    /// USB-attached iOS device.
    Usb,
    /// Local machine (iOS app on an Apple Silicon Mac).
    Local,
}

impl DumpDevice {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Usb => "usb",
            Self::Local => "local",
        }
    }
}

/// Everything needed to produce a decrypted IPA.
pub struct DumpRequest<'a> {
    /// Backend to drive.
    pub dumper: Dumper,
    /// App bundle id (target on the device/Mac).
    pub bundle_id: &'a str,
    /// Encrypted IPA to patch — required by the builtin backend.
    pub ipa: Option<&'a Path>,
    /// Frida device for the builtin backend.
    pub device: DumpDevice,
    /// Path to `ipakeep_dump.py` for the builtin backend.
    pub agent: &'a Path,
    /// Seconds to wait for lazily-loaded frameworks (builtin).
    pub settle: f64,
    /// Spawn the app rather than attach (builtin).
    pub spawn: bool,
}

/// Run the dump and return the decrypted IPA bytes.
///
/// # Errors
///
/// Returns an error if the tool is missing, the dump fails, or (builtin) the
/// IPA cannot be patched.
pub fn run_dump(req: &DumpRequest) -> Result<Vec<u8>, String> {
    let work = temp_dir("dump")?;
    let result = match req.dumper {
        Dumper::Builtin => run_builtin(req, &work),
        external => run_external(external, req.bundle_id, &work),
    };
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn run_builtin(req: &DumpRequest, work: &Path) -> Result<Vec<u8>, String> {
    let ipa = req
        .ipa
        .ok_or("builtin dumper needs --ipa <encrypted.ipa> to patch")?;
    require_program("python3")?;
    let (program, args) = builtin_argv(
        req.agent,
        req.bundle_id,
        req.device,
        work,
        req.settle,
        req.spawn,
    );
    let mut command = Command::new(program);
    command.args(&args);
    run_inherit(command)?;

    let ipa_bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    patch_ipa_decrypted(&ipa_bytes, work)
}

fn run_external(dumper: Dumper, bundle_id: &str, work: &Path) -> Result<Vec<u8>, String> {
    let (program, args) = external_argv(dumper, bundle_id, work)?;
    require_program(&program)?;
    let mut command = Command::new(&program);
    command.args(&args);
    run_inherit(command)?;

    let produced = newest_ipa(work)
        .ok_or_else(|| format!("{program} produced no .ipa in {}", work.display()))?;
    std::fs::read(&produced).map_err(|e| format!("{}: {e}", produced.display()))
}

/// Argv for the builtin Python runner. Pure for testing.
pub(super) fn builtin_argv(
    agent: &Path,
    bundle_id: &str,
    device: DumpDevice,
    out_dir: &Path,
    settle: f64,
    spawn: bool,
) -> (String, Vec<String>) {
    let mut args = vec![
        agent.to_string_lossy().into_owned(),
        "--out".into(),
        out_dir.to_string_lossy().into_owned(),
        "--device".into(),
        device.as_arg().into(),
        "--settle".into(),
        format!("{settle}"),
    ];
    if spawn {
        args.push("--spawn".into());
    }
    args.push(bundle_id.to_string());
    ("python3".into(), args)
}

/// Argv for an external dumper writing its decrypted IPA into `out_dir`.
///
/// These mirror each tool's common CLI; adjust if a tool version differs.
///
/// # Errors
///
/// Returns an error for the builtin variant (handled elsewhere).
pub(super) fn external_argv(
    dumper: Dumper,
    bundle_id: &str,
    out_dir: &Path,
) -> Result<(String, Vec<String>), String> {
    let dir = out_dir.to_string_lossy().into_owned();
    Ok(match dumper {
        Dumper::FridaIosDump => (
            "frida-ios-dump".into(),
            vec![
                "-o".into(),
                out_dir
                    .join("frida-ios-dump.ipa")
                    .to_string_lossy()
                    .into_owned(),
                bundle_id.to_string(),
            ],
        ),
        Dumper::Bagbak => (
            "bagbak".into(),
            vec!["--output".into(), dir, bundle_id.to_string()],
        ),
        Dumper::R2flutch => (
            "r2flutch".into(),
            vec!["-o".into(), dir, bundle_id.to_string()],
        ),
        Dumper::Builtin => return Err("builtin has no external argv".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_dumpers_and_rejects_unknown() {
        assert_eq!(Dumper::parse("builtin").unwrap(), Dumper::Builtin);
        assert_eq!(Dumper::parse("bagbak").unwrap(), Dumper::Bagbak);
        assert!(Dumper::parse("nope").is_err());
    }

    #[test]
    fn builtin_argv_threads_device_settle_and_spawn() {
        let (program, args) = builtin_argv(
            Path::new("/x/ipakeep_dump.py"),
            "com.example.App",
            DumpDevice::Local,
            Path::new("/tmp/out"),
            7.5,
            true,
        );
        assert_eq!(program, "python3");
        assert_eq!(args[0], "/x/ipakeep_dump.py");
        assert!(args.windows(2).any(|w| w == ["--device", "local"]));
        assert!(args.windows(2).any(|w| w == ["--settle", "7.5"]));
        assert!(args.contains(&"--spawn".to_string()));
        assert_eq!(args.last().unwrap(), "com.example.App");
    }

    #[test]
    fn external_argv_per_backend() {
        let dir = Path::new("/tmp/d");
        let (p, a) = external_argv(Dumper::Bagbak, "com.x.App", dir).unwrap();
        assert_eq!(p, "bagbak");
        assert!(a.windows(2).any(|w| w == ["--output", "/tmp/d"]));
        assert_eq!(a.last().unwrap(), "com.x.App");

        let (p, a) = external_argv(Dumper::FridaIosDump, "com.x.App", dir).unwrap();
        assert_eq!(p, "frida-ios-dump");
        assert!(a.iter().any(|s| s.ends_with("frida-ios-dump.ipa")));

        assert!(external_argv(Dumper::Builtin, "com.x.App", dir).is_err());
    }
}
