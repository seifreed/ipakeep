use std::fs;
use std::path::Path;

use crate::infrastructure::simulator::{codesign_command, run_checked};

use super::{arm64_slice_bases, convert_macho_file, is_arm64_simulator_binary};

pub(in crate::infrastructure::simulator) fn ensure_simulator_dylib(
    path: &Path,
    entitlements: Option<&Path>,
) -> Result<(), String> {
    ensure_simulator_dylib_with_signer(path, &CodesignAdHocSigner { entitlements })
}

/// Apply an ad-hoc signature to a Mach-O file. Extracted so tests can
/// substitute a no-op signer instead of shelling out to `/usr/bin/codesign`
/// (which is macOS + Xcode CLT only).
pub(in crate::infrastructure::simulator) trait AdHocSigner {
    fn sign(&self, path: &Path) -> Result<(), String>;
}

/// Default signer: shell out to `/usr/bin/codesign -f -s -`.
struct CodesignAdHocSigner<'a> {
    entitlements: Option<&'a Path>,
}

impl AdHocSigner for CodesignAdHocSigner<'_> {
    fn sign(&self, path: &Path) -> Result<(), String> {
        run_checked(codesign_command(path, self.entitlements))
    }
}

/// Thins a fat (or universal) arm64 Mach-O to a single arm64 slice in
/// place, patches its `LC_BUILD_VERSION.platform` to iOS Simulator, and
/// re-signs it. No-op when the input is already a thin arm64 Simulator
/// binary.
pub(in crate::infrastructure::simulator) fn ensure_simulator_dylib_with_signer(
    path: &Path,
    signer: &dyn AdHocSigner,
) -> Result<(), String> {
    if is_arm64_simulator_binary(path)? {
        return Ok(());
    }
    thin_to_arm64_inplace(path)?;
    convert_macho_file(path)?;
    signer.sign(path)
}

/// Reduce a fat (or universal) Mach-O to its single arm64 slice, in
/// place. Returns `Ok(true)` when the file was rewritten, `Ok(false)`
/// when the input was already a thin arm64 binary.
pub(in crate::infrastructure::simulator) fn thin_to_arm64_inplace(
    path: &Path,
) -> Result<bool, String> {
    let bases = {
        let mut file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        arm64_slice_bases(&mut file)?
    };
    match bases.as_slice() {
        [] => Err(format!("{}: no arm64 slice to thin to", path.display())),
        [0] => Ok(false),
        [base] => {
            let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let start = usize::try_from(*base)
                .map_err(|_| format!("{}: slice offset {} too large", path.display(), base))?;
            if start >= bytes.len() {
                return Err(format!("{}: slice offset past end of file", path.display()));
            }
            fs::write(path, &bytes[start..]).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(true)
        }
        _ => Err(format!("{}: multiple arm64 slices found", path.display())),
    }
}
