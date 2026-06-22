//! iOS-version dumpability matrix for the three current majors (June 2026).
//!
//! Apple's `LC_BUILD_VERSION.minos` packs the version as
//! `(major << 16) | (minor << 8) | patch`. An app whose minimum-OS major is at
//! or below a device's iOS major can load — and therefore be dumped — on it.
//! After the 18 → 26 numbering jump, the live majors are 18, 26, and 27.

/// iOS majors the Frida agent targets, newest last.
pub(super) const SUPPORTED_IOS_MAJORS: [u32; 3] = [18, 26, 27];

/// Major version encoded in a packed `LC_BUILD_VERSION` version word.
pub(super) fn major_of(packed: u32) -> u32 {
    packed >> 16
}

/// Whether an app with packed minimum-OS `minos` can run (and be dumped) on the
/// given iOS major.
pub(super) fn dumpable_on(minos: u32, ios_major: u32) -> bool {
    major_of(minos) <= ios_major
}
