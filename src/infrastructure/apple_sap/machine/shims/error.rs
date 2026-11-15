//! Errors raised by emulated platform functions.

use thiserror::Error;

use crate::infrastructure::apple_sap::emu::EmuError;

/// Failure of a shim, of shim registration, or of the guest heap.
#[derive(Debug, Error)]
pub enum ShimError {
    /// The emulator rejected a register or memory access.
    #[error(transparent)]
    Emu(#[from] EmuError),
    /// The guest called an import that has no emulated implementation.
    #[error("guest called unsupported import {name}")]
    UnsupportedImport {
        /// The imported symbol name.
        name: String,
    },
    /// The guest executed a service-area address with no registered shim.
    #[error("guest entered unknown service address {address:#x}")]
    UnknownAddress {
        /// The executed address.
        address: u64,
    },
    /// Every shim code slot is in use.
    #[error("guest service code area is full")]
    CodeAreaFull,
    /// The service data area cannot hold another data symbol.
    #[error("guest service data area is full")]
    DataAreaFull,
    /// A guest allocation larger than the transfer limit was requested.
    #[error("allocation size {size} exceeds limit")]
    AllocationTooLarge {
        /// The requested size in bytes.
        size: u64,
    },
    /// The guest heap has no room for the requested allocation.
    #[error("guest heap exhausted")]
    HeapExhausted,
    /// The guest released or resized a pointer the heap never returned.
    #[error("{operation} unknown pointer {address:#x}")]
    UnknownPointer {
        /// `free` or `reallocate`.
        operation: &'static str,
        /// The rejected pointer.
        address: u64,
    },
    /// An aligned allocation asked for a non-power-of-two alignment.
    #[error("invalid allocation alignment {alignment:#x}")]
    InvalidAlignment {
        /// The rejected alignment.
        alignment: u64,
    },
    /// A size computation overflowed 64 bits.
    #[error("allocation size overflows")]
    SizeOverflow,
    /// A memory transfer larger than the transfer limit was requested.
    #[error("guest transfer size {size} exceeds limit")]
    TransferTooLarge {
        /// The requested size in bytes.
        size: u64,
    },
    /// A guest C string has no terminator within the scan limit.
    #[error("guest string exceeds {limit} bytes")]
    StringTooLong {
        /// The scan limit in bytes.
        limit: usize,
    },
    /// The guest called `abort` or a stack-protector failure routine.
    #[error("guest aborted")]
    Aborted,
    /// A shim needs an orchestration callback the machine has not installed.
    #[error("{handler} handler is unavailable")]
    MissingHandler {
        /// Which callback is missing.
        handler: &'static str,
    },
    /// The shim state was re-entered while already borrowed.
    #[error("guest service state is already in use")]
    StateBusy,
    /// A guest request violated a shim precondition.
    #[error("{0}")]
    Invalid(&'static str),
    /// A guest request carried an unsupported value.
    #[error("unsupported {what} {value:#x}")]
    Unsupported {
        /// What the value describes.
        what: &'static str,
        /// The unsupported value.
        value: u64,
    },
}
