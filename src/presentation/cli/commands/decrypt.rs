//! Decrypt command handlers — inspect, patch, and re-sign.

use crate::domain::repository::CredentialRepository;
use crate::infrastructure::decrypt::{
    DumpDevice, DumpRequest, Dumper, EntitlementRisk, EntitlementVerdict, InspectReport,
    MachoReport, SshParams, VerifyReport, entitlements_report, inspect_ipa, patch_ipa_decrypted,
    resign_app, run_dump, run_offline, set_min_os, verify_ipa,
};
use crate::infrastructure::developer::{self, ProvisionRequest, ProvisionResult};
use crate::presentation::cli::output::OutputFormat;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Inspect an IPA and report each Mach-O's encryption info and dumpability.
///
/// # Errors
///
/// Returns an error if the IPA cannot be read or a Mach-O is malformed.
pub fn handle_inspect(ipa: &Path, format: &OutputFormat) -> Result<(), String> {
    let bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    let report = inspect_ipa(&bytes)?;
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| format!("serialize failed: {e}"))?
        ),
        OutputFormat::Text => print!("{}", render_text(&report)),
    }
    Ok(())
}

/// Patch dumped plaintext slices back into an IPA.
///
/// # Errors
///
/// Returns an error if a dumped slice is missing/mis-sized or the archive
/// cannot be rewritten.
pub fn handle_patch(ipa: &Path, from: &Path, output: Option<&Path>) -> Result<(), String> {
    let bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    let patched = patch_ipa_decrypted(&bytes, from)?;
    let out = output.map_or_else(|| default_output(ipa), Path::to_path_buf);
    std::fs::write(&out, patched).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("Wrote decrypted IPA: {}", out.display());
    Ok(())
}

/// Re-sign an extracted .app bundle, preserving its entitlements.
///
/// # Errors
///
/// Returns an error if entitlements cannot be read or signing fails.
pub fn handle_resign(
    app: &Path,
    identity: Option<&str>,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    resign_app(app, identity.unwrap_or("-"), entitlements)?;
    println!("Re-signed: {}", app.display());
    Ok(())
}

/// Verify a (decrypted) IPA structurally.
///
/// # Errors
///
/// Returns an error if the IPA cannot be read. Returns `Err` when any slice is
/// still encrypted, so the process exits non-zero.
pub fn handle_verify(ipa: &Path, format: &OutputFormat) -> Result<(), String> {
    let bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    let report = verify_ipa(&bytes)?;
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| format!("serialize failed: {e}"))?
        ),
        OutputFormat::Text => print!("{}", render_verify(&report)),
    }
    if report.ok {
        Ok(())
    } else if report.still_encrypted.is_empty() {
        Err("IPA failed structural verification (missing, malformed, or filler Mach-O code)".into())
    } else {
        Err(format!(
            "still encrypted: {}",
            report.still_encrypted.join(", ")
        ))
    }
}

/// Report which entitlements will break after re-signing.
///
/// # Errors
///
/// Returns an error if the executable cannot be located or `codesign` fails.
pub fn handle_entitlements(path: &Path, format: &OutputFormat) -> Result<(), String> {
    let verdicts = entitlements_report(path)?;
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&verdicts)
                .map_err(|e| format!("serialize failed: {e}"))?
        ),
        OutputFormat::Text => print!("{}", render_entitlements(&verdicts)),
    }
    Ok(())
}

/// Lower an IPA's `MinimumOSVersion` so it installs on an older iOS.
///
/// # Errors
///
/// Returns an error if the version is malformed or no patch target exists.
pub fn handle_set_min_os(ipa: &Path, version: &str, output: Option<&Path>) -> Result<(), String> {
    let bytes = std::fs::read(ipa).map_err(|e| format!("{}: {e}", ipa.display()))?;
    let patched = set_min_os(&bytes, version)?;
    let out = output.map_or_else(|| min_os_output(ipa), Path::to_path_buf);
    std::fs::write(&out, patched).map_err(|e| format!("{}: {e}", out.display()))?;
    eprintln!(
        "WARNING: lowering MinimumOSVersion lets the IPA INSTALL on iOS {version}, but apps that \
         call newer APIs usually CRASH at launch. Downgrade rarely yields a runnable app."
    );
    println!("Wrote min-os-patched IPA: {}", out.display());
    Ok(())
}

/// Parsed `decrypt dump` arguments.
pub struct DumpArgs<'a> {
    /// App bundle id.
    pub bundle_id: &'a str,
    /// Dumper backend name.
    pub dumper: &'a str,
    /// Encrypted IPA to patch (builtin).
    pub ipa: Option<&'a Path>,
    /// Frida device (`usb`/`local`).
    pub device: &'a str,
    /// Custom Frida runner; `None` uses the bundled scripts.
    pub agent: Option<&'a Path>,
    /// Spawn rather than attach (builtin).
    pub spawn: bool,
    /// Settle seconds (builtin).
    pub settle: f64,
    /// Output IPA path.
    pub output: Option<&'a Path>,
    /// Remove app extensions that could not be dumped instead of failing.
    pub drop_undumped_extensions: bool,
    /// SSH host for the on-device `fouldecrypt` backend.
    pub ssh_host: &'a str,
    /// SSH port for the on-device `fouldecrypt` backend.
    pub ssh_port: u16,
    /// SSH user for the on-device `fouldecrypt` backend.
    pub ssh_user: &'a str,
}

/// Drive a dumper to produce a decrypted IPA.
///
/// # Errors
///
/// Returns an error if the dumper/tool fails or the output cannot be written.
pub fn handle_dump(args: &DumpArgs) -> Result<(), String> {
    let device = match args.device {
        "usb" => DumpDevice::Usb,
        "local" => DumpDevice::Local,
        other => return Err(format!("unknown device {other:?} (expected usb|local)")),
    };
    let req = DumpRequest {
        dumper: Dumper::parse(args.dumper)?,
        bundle_id: args.bundle_id,
        ssh: SshParams {
            host: args.ssh_host,
            port: args.ssh_port,
            user: args.ssh_user,
        },
        ipa: args.ipa,
        device,
        agent: args.agent,
        settle: args.settle,
        spawn: args.spawn,
        drop_undumped_extensions: args.drop_undumped_extensions,
    };
    let bytes = run_dump(&req)?;
    let out = args
        .output
        .map_or_else(|| dump_output(args.ipa, args.bundle_id), Path::to_path_buf);
    std::fs::write(&out, bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("Wrote decrypted IPA: {}", out.display());
    Ok(())
}

/// Decrypt a local encrypted IPA offline with `ipadecrypt`, then verify it.
///
/// # Errors
///
/// Returns an error if `ipadecrypt` is missing or not bootstrapped, decryption
/// fails, the result does not verify, or the output cannot be written.
pub fn handle_offline(
    ipa: &Path,
    output: Option<&Path>,
    allow_on_device: bool,
) -> Result<(), String> {
    let bytes = run_offline(ipa, allow_on_device)?;
    let out = output.map_or_else(|| default_output(ipa), Path::to_path_buf);
    std::fs::write(&out, bytes).map_err(|e| format!("{}: {e}", out.display()))?;
    println!("Wrote decrypted IPA: {}", out.display());
    Ok(())
}

/// Dump an iOS app running on this Apple Silicon Mac (builtin dumper, local Frida).
///
/// # Errors
///
/// Returns an error if Frida/the app fails or the output cannot be written.
pub fn handle_dump_mac(
    bundle_id: &str,
    ipa: &Path,
    agent: Option<&Path>,
    settle: f64,
    output: Option<&Path>,
) -> Result<(), String> {
    handle_dump(&DumpArgs {
        bundle_id,
        dumper: "builtin",
        ipa: Some(ipa),
        device: "local",
        agent,
        spawn: true,
        settle,
        output,
        drop_undumped_extensions: false,
        ssh_host: "127.0.0.1",
        ssh_port: 2222,
        ssh_user: "mobile",
    })
}

/// Generate a development provisioning profile and embed it in the bundle.
///
/// # Errors
///
/// Returns an error if not logged in, provisioning fails, or files can't be written.
pub async fn handle_provision<C: CredentialRepository>(
    app: &Path,
    device_udid: &str,
    team: Option<&str>,
    app_id_id: &str,
    output: Option<&Path>,
    credentials: C,
) -> Result<(), String> {
    let account = credentials
        .load_account()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("not logged in — run `ipakeep auth login` first")?;

    let result = developer::provision(&ProvisionRequest {
        account: &account,
        team_id: team,
        device_udid,
        device_name: "ipakeep",
        app_id_id,
    })
    .await?;

    let dir = write_provisioning_files(app, output, &result)?;
    println!(
        "Provisioned team {} (cert {}). Artifacts in {}.",
        result.team_id,
        result.certificate_serial,
        dir.display()
    );
    warn_unregrantable_entitlements(app);
    println!(
        "Next: import {}/key.pem + certificate.der into your keychain, then \
         `ipakeep decrypt resign {} --identity \"<cert name>\"`.",
        dir.display(),
        app.display()
    );
    Ok(())
}

fn write_provisioning_files(
    app: &Path,
    output: Option<&Path>,
    result: &ProvisionResult,
) -> Result<PathBuf, String> {
    let dir = output.map_or_else(|| PathBuf::from("ipakeep-provision"), Path::to_path_buf);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, bytes) in [
        ("embedded.mobileprovision", &result.mobileprovision),
        ("key.pem", &result.key_pem),
        ("certificate.der", &result.certificate_der),
    ] {
        let path = dir.join(name);
        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    // Embed the profile so the bundle is ready to re-sign.
    std::fs::write(
        app.join("embedded.mobileprovision"),
        &result.mobileprovision,
    )
    .map_err(|e| format!("embedding profile: {e}"))?;
    Ok(dir)
}

fn warn_unregrantable_entitlements(app: &Path) {
    if let Ok(verdicts) = entitlements_report(app) {
        let blocked: Vec<&str> = verdicts
            .iter()
            .filter(|v| v.risk == EntitlementRisk::CannotRegrant)
            .map(|v| v.key.as_str())
            .collect();
        if !blocked.is_empty() {
            eprintln!(
                "WARNING: these entitlements cannot be granted even with a profile: {}",
                blocked.join(", ")
            );
        }
    }
}

fn dump_output(ipa: Option<&Path>, bundle_id: &str) -> PathBuf {
    match ipa {
        Some(ipa) => default_output(ipa),
        None => PathBuf::from(format!("{bundle_id}-decrypted.ipa")),
    }
}

fn default_output(ipa: &Path) -> PathBuf {
    let stem = ipa.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
    ipa.with_file_name(format!("{stem}-decrypted.ipa"))
}

fn min_os_output(ipa: &Path) -> PathBuf {
    let stem = ipa.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
    ipa.with_file_name(format!("{stem}-minos.ipa"))
}

fn render_verify(report: &VerifyReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Verified: {}", if report.ok { "OK" } else { "FAILED" });
    for macho in &report.machos {
        let _ = writeln!(out, "\n{}", macho.entry);
        if macho.slices.is_empty() {
            out.push_str("  [invalid Mach-O]\n");
        }
        for slice in &macho.slices {
            let decrypted = match slice.looks_decrypted {
                Some(true) => " looks-decrypted",
                Some(false) => " WARNING:looks-filler",
                None => "",
            };
            let _ = writeln!(
                out,
                "  [{}] cryptid_zero={} valid={}{decrypted}",
                slice.arch, slice.cryptid_zero, slice.valid
            );
        }
    }
    if !report.still_encrypted.is_empty() {
        let _ = writeln!(
            out,
            "\nstill encrypted: {}",
            report.still_encrypted.join(", ")
        );
    }
    out
}

fn render_entitlements(verdicts: &[EntitlementVerdict]) -> String {
    if verdicts.is_empty() {
        return "No entitlements (or none readable).\n".to_string();
    }
    let mut out = String::new();
    for v in verdicts {
        let tag = match v.risk {
            EntitlementRisk::Ok => "OK  ",
            EntitlementRisk::NeedsProvisioning => "PROV",
            EntitlementRisk::CannotRegrant => "FAIL",
        };
        let _ = writeln!(out, "[{tag}] {} — {}", v.key, v.note);
    }
    out
}

fn render_text(report: &InspectReport) -> String {
    let mut out = String::new();
    if let Some(exec) = &report.bundle_executable {
        let _ = writeln!(out, "Executable: {exec}");
    }
    if let Some(min) = &report.minimum_os_version {
        let _ = writeln!(out, "MinimumOSVersion: {min}");
    }
    let _ = writeln!(
        out,
        "Encrypted: {}",
        if report.encrypted { "yes" } else { "no" }
    );

    for macho in &report.machos {
        append_macho_text(&mut out, macho);
    }
    out
}

fn append_macho_text(out: &mut String, macho: &MachoReport) {
    let _ = writeln!(out, "\n{}", macho.entry);
    for slice in &macho.slices {
        let _ = write!(out, "  [{}]", slice.arch);
        if slice.encrypted {
            let _ = write!(
                out,
                " encrypted cryptid={} cryptoff={} cryptsize={}",
                slice.cryptid.unwrap_or(0),
                slice.cryptoff.unwrap_or(0),
                slice.cryptsize.unwrap_or(0),
            );
        } else {
            out.push_str(" not encrypted");
        }
        if let Some(min) = &slice.minimum_os {
            let _ = write!(out, " minos={min}");
        }
        out.push('\n');
        if let Some(name) = &slice.dump_filename {
            let _ = writeln!(out, "    dump as: {name}");
        }
        if !slice.dumpable_on.is_empty() {
            let matrix: Vec<String> = slice
                .dumpable_on
                .iter()
                .map(|t| format!("iOS{}={}", t.ios_major, if t.dumpable { "y" } else { "n" }))
                .collect();
            let _ = writeln!(out, "    dumpable: {}", matrix.join(" "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::decrypt::{MachoVerify, SliceVerify};
    use std::io::Cursor;

    fn empty_ipa() -> Vec<u8> {
        zip::ZipWriter::new(Cursor::new(Vec::new()))
            .finish()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn renderers_cover_empty_and_populated_reports() {
        let empty = VerifyReport {
            ok: false,
            machos: vec![MachoVerify {
                entry: "Bad".into(),
                slices: vec![],
            }],
            still_encrypted: vec!["App[arm64]".into()],
        };
        let text = render_verify(&empty);
        assert!(text.contains("FAILED"));
        assert!(text.contains("[invalid Mach-O]"));
        assert!(text.contains("App[arm64]"));

        let report = VerifyReport {
            ok: true,
            machos: vec![MachoVerify {
                entry: "App".into(),
                slices: vec![
                    SliceVerify {
                        arch: "arm64".into(),
                        cryptid_zero: true,
                        valid: true,
                        looks_decrypted: Some(true),
                    },
                    SliceVerify {
                        arch: "arm64e".into(),
                        cryptid_zero: false,
                        valid: false,
                        looks_decrypted: Some(false),
                    },
                    SliceVerify {
                        arch: "x86_64".into(),
                        cryptid_zero: true,
                        valid: true,
                        looks_decrypted: None,
                    },
                ],
            }],
            still_encrypted: vec![],
        };
        let text = render_verify(&report);
        assert!(text.contains("Verified: OK"));
        assert!(text.contains("looks-decrypted"));
        assert!(text.contains("WARNING:looks-filler"));
        assert!(text.contains("cryptid_zero=true"));
    }

    #[test]
    fn entitlement_renderer_covers_each_risk() {
        assert_eq!(
            render_entitlements(&[]),
            "No entitlements (or none readable).\n"
        );
        let rendered = render_entitlements(&[
            EntitlementVerdict {
                key: "safe".into(),
                risk: EntitlementRisk::Ok,
                note: "safe note".into(),
            },
            EntitlementVerdict {
                key: "profile".into(),
                risk: EntitlementRisk::NeedsProvisioning,
                note: "profile note".into(),
            },
            EntitlementVerdict {
                key: "blocked".into(),
                risk: EntitlementRisk::CannotRegrant,
                note: "blocked note".into(),
            },
        ]);
        assert!(rendered.contains("[OK  ] safe — safe note"));
        assert!(rendered.contains("[PROV] profile — profile note"));
        assert!(rendered.contains("[FAIL] blocked — blocked note"));
    }

    #[test]
    fn inspect_renderer_formats_metadata_and_slice_details() {
        let report = InspectReport {
            bundle_executable: Some("App".into()),
            minimum_os_version: Some("17.0".into()),
            encrypted: true,
            machos: vec![MachoReport {
                entry: "Payload/App.app/App".into(),
                slices: vec![
                    crate::infrastructure::decrypt::SliceReport {
                        arch: "arm64".into(),
                        encrypted: true,
                        cryptid: Some(1),
                        cryptoff: Some(4096),
                        cryptsize: Some(2048),
                        minimum_os: Some("17.0".into()),
                        dump_filename: Some("App.arm64.dump".into()),
                        dumpable_on: vec![
                            crate::infrastructure::decrypt::DumpTarget {
                                ios_major: 17,
                                dumpable: true,
                            },
                            crate::infrastructure::decrypt::DumpTarget {
                                ios_major: 18,
                                dumpable: false,
                            },
                        ],
                    },
                    crate::infrastructure::decrypt::SliceReport {
                        arch: "x86_64".into(),
                        encrypted: false,
                        cryptid: None,
                        cryptoff: None,
                        cryptsize: None,
                        minimum_os: None,
                        dump_filename: None,
                        dumpable_on: vec![],
                    },
                ],
            }],
        };
        let rendered = render_text(&report);
        assert!(rendered.contains("Executable: App"));
        assert!(rendered.contains("MinimumOSVersion: 17.0"));
        assert!(rendered.contains("Encrypted: yes"));
        assert!(rendered.contains("cryptid=1 cryptoff=4096 cryptsize=2048"));
        assert!(rendered.contains("iOS17=y iOS18=n"));
        assert!(rendered.contains("not encrypted"));
    }

    #[test]
    fn output_helpers_handle_extensions_and_missing_stems() {
        assert_eq!(
            default_output(Path::new("App.ipa")),
            PathBuf::from("App-decrypted.ipa")
        );
        assert_eq!(
            default_output(Path::new("/")),
            PathBuf::from("/app-decrypted.ipa")
        );
        assert_eq!(
            min_os_output(Path::new("App.ipa")),
            PathBuf::from("App-minos.ipa")
        );
        assert_eq!(
            dump_output(None, "com.example.app"),
            PathBuf::from("com.example.app-decrypted.ipa")
        );
        assert_eq!(
            dump_output(Some(Path::new("App.ipa")), "ignored"),
            PathBuf::from("App-decrypted.ipa")
        );
    }

    #[test]
    fn dump_rejects_invalid_device_and_backend_before_running_tools() {
        let args = DumpArgs {
            bundle_id: "com.example.app",
            dumper: "invalid",
            ipa: None,
            device: "wifi",
            agent: None,
            spawn: false,
            settle: 0.0,
            output: None,
            drop_undumped_extensions: false,
            ssh_host: "localhost",
            ssh_port: 22,
            ssh_user: "root",
        };
        assert!(handle_dump(&args).unwrap_err().contains("unknown device"));
        let args = DumpArgs {
            device: "usb",
            ..args
        };
        assert!(handle_dump(&args).unwrap_err().contains("unknown dumper"));
    }

    #[test]
    fn file_handlers_report_missing_inputs() {
        let path = Path::new("/missing/ipakeep-test.ipa");
        assert!(handle_inspect(path, &OutputFormat::Text).is_err());
        assert!(handle_patch(path, Path::new("/missing/dumps"), None).is_err());
        assert!(handle_verify(path, &OutputFormat::Json).is_err());
        assert!(handle_entitlements(Path::new("/missing/App.app"), &OutputFormat::Text).is_err());
        assert!(handle_set_min_os(path, "17.0", None).is_err());
        assert!(handle_offline(path, None, false).is_err());
        assert!(handle_resign(Path::new("/missing/App.app"), None, None).is_err());
    }

    #[test]
    fn inspect_and_verify_handle_an_empty_valid_archive() {
        let work = tempfile::tempdir().unwrap();
        let ipa = work.path().join("empty.ipa");
        std::fs::write(&ipa, empty_ipa()).unwrap();

        assert!(handle_inspect(&ipa, &OutputFormat::Json).is_ok());
        assert!(handle_inspect(&ipa, &OutputFormat::Text).is_ok());
        assert!(handle_verify(&ipa, &OutputFormat::Json).is_err());
        assert!(handle_verify(&ipa, &OutputFormat::Text).is_err());
    }
}
