//! Mach-O arm64e image preparation for emulation.
//!
//! Port of upstream ipatool's `internal/sap/machimage`: selects the arm64e
//! slice, strips pointer authentication from instruction sections, decodes
//! rebases/binds/chained fixups (cached on disk by image digest), applies them
//! for a chosen guest base, relocates kernel-collection pointers, and produces
//! a [`LoadPlan`] of page-aligned regions plus segment bytes for the emulator.
//!
//! Typical use mirrors upstream `machine.openRuntime`:
//! [`MachImage::open_with_cache`] → [`MachImage::export`] for entry points →
//! [`MachImage::relocate`] (or [`MachImage::prepare_prelinked`]) with a
//! resolver → optionally [`MachImage::relocate_kernel_cache_pointers`] →
//! [`MachImage::load_plan`] to map and write guest memory.

mod cache;
mod chained;
mod dyld_info;
mod error;
mod fat;
mod image;
mod layout;
mod pac;
mod relocation;
mod symbols;

#[cfg(test)]
mod golden_tests;

pub use cache::PreparationCache;
pub use error::{MachoError, MachoResult};
pub use fat::{arm64_range, arm64_slice, read_arm64};
pub use image::{LoadPlan, MachImage, MemoryRegion, SegmentData};
pub use layout::Segment;
pub use pac::{InstructionPatch, without_pointer_authentication};
pub use relocation::Relocation;
pub use symbols::Symbol;
