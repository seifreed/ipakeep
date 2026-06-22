//! Decrypt command handlers — inspect, patch, and re-sign.

use crate::infrastructure::decrypt::{InspectReport, inspect_ipa, patch_ipa_decrypted, resign_app};
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

fn default_output(ipa: &Path) -> PathBuf {
    let stem = ipa.file_stem().and_then(|s| s.to_str()).unwrap_or("app");
    ipa.with_file_name(format!("{stem}-decrypted.ipa"))
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
