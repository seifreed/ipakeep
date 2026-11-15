//! Guest address-space layout shared by the shim layer and the machine.

/// First address of the guest service area (shim code slots, then data).
pub const SHIM_BASE: u64 = 0x0000_7ff8_8000_0000;
/// Bytes of the service area reserved for code slots.
pub const SHIM_CODE_SIZE: u64 = 0x0008_0000;
/// Total bytes of the service area (code slots followed by data symbols).
pub const SHIM_AREA_SIZE: u64 = 0x0010_0000;
/// Distance in bytes between two consecutive shim code slots.
pub const SHIM_SLOT_SIZE: u64 = 16;

/// First address of the guest heap served by `malloc` and friends. The
/// machine maps `[HEAP_BASE, HEAP_BASE + HEAP_SIZE)` before running guests.
pub const HEAP_BASE: u64 = 0x0000_4000_0000_0000;
/// Size in bytes of the guest heap.
pub const HEAP_SIZE: u64 = 64 << 20;
/// Guest page size.
pub const PAGE_SIZE: u64 = 0x1000;
/// Largest single guest allocation or memory transfer a shim accepts.
pub const MAX_GUEST_TRANSFER: u64 = 64 << 20;
/// Opaque non-null handle returned for faked platform objects.
pub const FAKE_HANDLE: u64 = u64::MAX;

/// Rounds `value` up to a multiple of the power-of-two `alignment`, or `None`
/// on overflow.
pub(super) fn align(value: u64, alignment: u64) -> Option<u64> {
    let mask = alignment.checked_sub(1)?;

    Some(value.checked_add(mask)? & !mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_and_detects_overflow() {
        assert_eq!(align(0, 16), Some(0));
        assert_eq!(align(1, 16), Some(16));
        assert_eq!(align(16, 16), Some(16));
        assert_eq!(align(0x1001, PAGE_SIZE), Some(0x2000));
        assert_eq!(align(u64::MAX, 16), None);
        assert_eq!(align(5, 0), None);
    }

    #[test]
    fn service_area_holds_code_then_data() {
        const {
            assert!(SHIM_CODE_SIZE < SHIM_AREA_SIZE);
            assert!(SHIM_BASE.is_multiple_of(PAGE_SIZE));
            assert!(SHIM_CODE_SIZE.is_multiple_of(SHIM_SLOT_SIZE));
        }
    }
}
