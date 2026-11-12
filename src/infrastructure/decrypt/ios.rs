//! iOS-version minimum-OS compatibility matrix.
//!
//! Apple's `LC_BUILD_VERSION.minos` packs the version as
//! `(major << 16) | (minor << 8) | patch`. An app whose minimum-OS major is at
//! or below a device's iOS major passes the minimum-version check. The matrix
//! includes iOS 16, the connected hardware test device, and the current majors.

/// iOS majors shown in inspection reports, oldest first.
pub(super) const SUPPORTED_IOS_MAJORS: [u32; 4] = [16, 18, 26, 27];

/// Major version encoded in a packed `LC_BUILD_VERSION` version word.
pub(super) fn major_of(packed: u32) -> u32 {
    packed >> 16
}

/// Whether an app's packed minimum OS is at or below the given iOS major.
pub(super) fn dumpable_on(minos: u32, ios_major: u32) -> bool {
    major_of(minos) <= ios_major
}
