use super::{macho, open_archive, read_if_macho};

/// Verdict for one slice of a (supposedly) decrypted Mach-O.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SliceVerify {
    /// Architecture label.
    pub arch: String,
    /// True when no `LC_ENCRYPTION_INFO` retains a non-zero `cryptid`.
    pub cryptid_zero: bool,
    /// True when the slice parsed as a structurally valid Mach-O.
    pub valid: bool,
    /// Heuristic: the formerly-encrypted region no longer looks like filler
    /// (not all-zero, not a single repeated byte). `None` when not encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub looks_decrypted: Option<bool>,
}

/// One Mach-O entry's verification result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MachoVerify {
    /// Zip entry path.
    pub entry: String,
    /// One verdict per slice.
    pub slices: Vec<SliceVerify>,
}

/// Result of verifying a decrypted IPA.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// True when every slice is valid and fully decrypted (`cryptid == 0`).
    pub ok: bool,
    /// Per Mach-O entry.
    pub machos: Vec<MachoVerify>,
    /// `entry[arch]` of every slice still carrying `cryptid != 0`.
    pub still_encrypted: Vec<String>,
}

/// Verify that an IPA is fully decrypted: every slice has `cryptid == 0`, parses
/// cleanly, and its formerly-encrypted region no longer looks like filler.
///
/// This is a structural check; confirming the binary actually *loads* requires a
/// device or an Apple Silicon Mac.
///
/// # Errors
///
/// Returns an error if the archive cannot be read.
pub fn verify_ipa(ipa_bytes: &[u8]) -> Result<VerifyReport, String> {
    let mut archive = open_archive(ipa_bytes)?;
    let mut machos = Vec::new();
    let mut still_encrypted = Vec::new();
    let mut ok = true;

    for index in 0..archive.len() {
        let Some((name, bytes)) = read_if_macho(&mut archive, index)? else {
            continue;
        };
        let (macho, valid) = verify_macho(name, &bytes, &mut still_encrypted);
        ok &= valid;
        machos.push(macho);
    }

    Ok(VerifyReport {
        ok: ok && !machos.is_empty(),
        machos,
        still_encrypted,
    })
}

fn verify_macho(
    name: String,
    bytes: &[u8],
    still_encrypted: &mut Vec<String>,
) -> (MachoVerify, bool) {
    let Ok(slices) = macho::parse(bytes) else {
        return (
            MachoVerify {
                entry: name,
                slices: Vec::new(),
            },
            false,
        );
    };

    let mut valid = !slices.is_empty();
    let mut reports = Vec::with_capacity(slices.len());
    for slice in slices {
        reports.push(verify_slice(
            &name,
            bytes,
            &slice,
            still_encrypted,
            &mut valid,
        ));
    }
    (
        MachoVerify {
            entry: name,
            slices: reports,
        },
        valid,
    )
}

fn verify_slice(
    name: &str,
    bytes: &[u8],
    slice: &macho::Slice,
    still_encrypted: &mut Vec<String>,
    valid: &mut bool,
) -> SliceVerify {
    let cryptid_zero = slice
        .encryption
        .is_none_or(|encryption| encryption.cryptid == 0);
    let looks_decrypted = slice.encryption.map(|_| {
        slice
            .crypt_range()
            .is_some_and(|(start, end)| looks_decrypted(&bytes[start..end]))
    });
    if !cryptid_zero {
        still_encrypted.push(format!("{name}[{}]", slice.arch));
        *valid = false;
    }
    if looks_decrypted == Some(false) {
        *valid = false;
    }
    SliceVerify {
        arch: slice.arch.clone(),
        cryptid_zero,
        valid: true,
        looks_decrypted,
    }
}

/// Accept an IPA only when every Mach-O slice passes [`verify_ipa`].
pub(crate) fn ensure_decrypted(ipa_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let report = verify_ipa(&ipa_bytes)?;
    if report.ok {
        return Ok(ipa_bytes);
    }

    if report.still_encrypted.is_empty() {
        return Err("dump output failed structural verification".into());
    }
    Err(format!(
        "dump output is still encrypted: {}",
        report.still_encrypted.join(", ")
    ))
}

fn looks_decrypted(region: &[u8]) -> bool {
    match region.first() {
        None => false,
        Some(&first) => region.iter().any(|&byte| byte != first),
    }
}
