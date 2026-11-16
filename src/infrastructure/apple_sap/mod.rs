//! Native Apple SAP, ADI (Anisette) and kbsync.
//!
//! Extracts Apple's `StoreServices` binaries from a pinned macOS restore image
//! and runs them on the emulator engine (`emu`, the native Rust ARM64
//! interpreter by default) to produce request signatures, machine
//! provisioning headers and keybag-sync blobs.

pub mod assets;
pub mod emu;
pub mod machine;
pub mod macho;
pub mod protocol;
pub mod signer;
pub mod storeauth;
