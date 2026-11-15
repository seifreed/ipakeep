//! Native Apple SAP, ADI (Anisette) and kbsync.
//!
//! Extracts Apple's `StoreServices` binaries from a pinned macOS restore image
//! and runs them under Unicorn to produce request signatures, machine
//! provisioning headers and keybag-sync blobs.

pub mod assets;
pub mod emu;
pub mod machine;
pub mod macho;
pub mod storeauth;
