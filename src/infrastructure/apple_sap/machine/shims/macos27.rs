//! Build-pinned function tables for the `AppleMediaServices` image extracted
//! from the macOS 27.0.1 (26A434) arm64e shared cache.
//!
//! The extraction has its cache slide applied, so these absolute addresses
//! are stable for this exact build; the machine replaces each with the shim
//! of the same name at load time.

/// Shared-cache function addresses called by `AppleMediaServices`, by symbol.
pub const MACOS27_SHARED_CACHE_FUNCTIONS: &[(u64, &str)] = &[
    (0x0000_0001_8067_5ce8, "_malloc"),
    (0x0000_0001_8067_66f0, "_free"),
    (0x0000_0001_806c_f570, "_dispatch_once"),
    (0x0000_0001_8071_acc8, "_sysctlbyname"),
    (0x0000_0001_8071_bec4, "_gettimeofday"),
    (0x0000_0001_8072_1fb8, "_arc4random"),
    (0x0000_0001_8072_38a4, "___memset_chk"),
    (0x0000_0001_8079_03c4, "_abort"),
    (0x0000_0001_8084_9604, "___error"),
    (0x0000_0001_8088_9bc4, "_pthread_once"),
    (0x0000_0001_8088_a6f8, "_pthread_rwlock_unlock"),
    (0x0000_0001_8088_a7c0, "_pthread_rwlock_wrlock"),
    (0x0000_0001_8088_b2d8, "_pthread_rwlock_init"),
    (0x0000_0001_8089_4b40, "_strlen"),
    (0x0000_0001_808c_f540, "_CFStringCreateWithCString"),
    (0x0000_0001_808d_4200, "_CFStringGetLength"),
    (0x0000_0001_808d_44dc, "_CFStringGetCString"),
    (0x0000_0001_808d_7278, "_CFRelease"),
    (0x0000_0001_808e_89e8, "_CFDataGetLength"),
    (0x0000_0001_84d6_b4cc, "_IOServiceMatching"),
    (0x0000_0001_84d6_c168, "_IOServiceGetMatchingServices"),
    (0x0000_0001_84d6_c4fc, "_IOIteratorNext"),
    (0x0000_0001_84d6_cb50, "_IOObjectRelease"),
];

/// Shared-cache pointer slots read by `AppleMediaServices`, by symbol.
pub const MACOS27_SHARED_CACHE_SLOTS: &[(u64, &str)] = &[
    (0x0000_0001_e022_05c0, "___stack_chk_guard"),
    (0x0000_0001_e800_c958, "___chkstk_darwin"),
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn tables_have_unique_addresses_and_names() {
        for table in [MACOS27_SHARED_CACHE_FUNCTIONS, MACOS27_SHARED_CACHE_SLOTS] {
            let addresses: HashSet<_> = table.iter().map(|(address, _)| address).collect();
            let names: HashSet<_> = table.iter().map(|(_, name)| name).collect();
            assert_eq!(addresses.len(), table.len());
            assert_eq!(names.len(), table.len());
        }
        assert_eq!(MACOS27_SHARED_CACHE_FUNCTIONS.len(), 23);
    }
}
