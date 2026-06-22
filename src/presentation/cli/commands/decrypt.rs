//! Decrypt command handlers — inspect, patch, and re-sign.

use crate::domain::repository::CredentialRepository;
use crate::infrastructure::decrypt::{
    DumpDevice, DumpRequest, Dumper, EntitlementRisk, EntitlementVerdict, InspectReport,
    VerifyReport, entitlements_report, inspect_ipa, patch_ipa_decrypted, resign_app, run_dump,
    set_min_os, verify_ipa,
};
use crate::infrastructure::developer::{self, ProvisionRequest};
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
    /// Path to the builtin Frida runner.
    pub agent: &'a Path,
    /// Spawn rather than attach (builtin).
    pub spawn: bool,
    /// Settle seconds (builtin).
    pub settle: f64,
    /// Output IPA path.
    pub output: Option<&'a Path>,
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
        ipa: args.ipa,
        device,
        agent: args.agent,
        settle: args.settle,
        spawn: args.spawn,
    };
    let bytes = run_dump(&req)?;
    let out = args
        .output
        .map_or_else(|| dump_output(args.ipa, args.bundle_id), Path::to_path_buf);
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
    agent: &Path,
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

    println!(
        "Provisioned team {} (cert {}). Artifacts in {}.",
        result.team_id,
        result.certificate_serial,
        dir.display()
    );
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
    println!(
        "Next: import {}/key.pem + certificate.der into your keychain, then \
         `ipakeep decrypt resign {} --identity \"<cert name>\"`.",
        dir.display(),
        app.display()
    );
    Ok(())
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
    out
}
