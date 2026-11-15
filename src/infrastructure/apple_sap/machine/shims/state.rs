//! Platform state the shims read and mutate, owned by the machine layer.

use std::collections::HashMap;
use std::rc::Rc;
use std::time::SystemTime;

use crate::infrastructure::apple_sap::emu::EmuError;

use super::error::ShimError;
use super::heap::Heap;
use super::table::ShimTable;

/// Handle value given to the first faked XPC object, minus one.
const XPC_OBJECT_HANDLE_BASE: u64 = 0xffff_0000_0000_0000;

/// One `IOConnectCallStructMethod` call routed to the `FairPlay` orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FairPlayRequest {
    /// The structure input buffer.
    pub input: Vec<u8>,
    /// For selector 26, the message buffer the input points at; else empty.
    pub indirect: Vec<u8>,
    /// Capacity of the guest's structure output buffer.
    pub output_size: usize,
}

/// The orchestration's answer to a [`FairPlayRequest`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FairPlayReply {
    /// Bytes written to the structure output buffer.
    pub output: Vec<u8>,
    /// Replacement message written back over the indirect buffer, if non-empty.
    pub indirect: Vec<u8>,
    /// `IOKit` return code handed back to the guest.
    pub status: i32,
}

/// Callback serving `FairPlay` `IOKit` calls (typically by running `fairplayd` or
/// the `FairPlay` kext in another emulator).
pub type FairPlayHandler = dyn Fn(FairPlayRequest) -> Result<FairPlayReply, EmuError>;

/// Callback serving `mach_msg_rpc_from_kernel_proper`: receives the request
/// message and the receive capacity, returns the reply message.
pub type MachRpcHandler = dyn Fn(&[u8], usize) -> Result<Vec<u8>, EmuError>;

/// Source of wall-clock time and randomness for the guest.
///
/// One instance may be shared by several emulators; random draws are taken in
/// guest call order, so a deterministic implementation reproduces upstream.
pub trait HostEnvironment {
    /// The current wall-clock time.
    fn now(&self) -> SystemTime;
    /// Fills `buffer` with random bytes.
    fn fill_random(&self, buffer: &mut [u8]);
}

/// The real clock and the operating-system random generator.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemHost;

impl HostEnvironment for SystemHost {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn fill_random(&self, buffer: &mut [u8]) {
        rand::Rng::fill_bytes(&mut rand::rng(), buffer);
    }
}

/// Construction options for the shim layer.
#[derive(Clone)]
pub struct ShimConfig {
    /// `CoreFP` exports (with leading underscore) served by `dlsym`.
    pub core_exports: HashMap<String, u64>,
    /// Contents of `CoreFP.icxs`, served from `./../CoreFP.icxs`.
    pub icxs: Vec<u8>,
    /// Extra imports that simply return zero for this guest profile.
    pub zero_return_aliases: Vec<String>,
    /// Whether `CFRunLoopRun` stops the emulator instead of returning.
    pub pause_run_loop: bool,
    /// Clock and randomness served to the guest.
    pub host: Rc<dyn HostEnvironment>,
}

impl Default for ShimConfig {
    fn default() -> Self {
        Self {
            core_exports: HashMap::new(),
            icxs: Vec::new(),
            zero_return_aliases: Vec::new(),
            pause_run_loop: false,
            host: Rc::new(SystemHost),
        }
    }
}

/// Orchestration callbacks installed by the machine layer.
#[derive(Default)]
pub struct HostHandlers {
    /// Serves `IOConnectCallStructMethod`.
    pub fair_play: Option<Rc<FairPlayHandler>>,
    /// Serves `mach_msg_rpc_from_kernel_proper`.
    pub mach_rpc: Option<Rc<MachRpcHandler>>,
}

/// In-memory files: the ADI state database and the read-only `CoreFP.icxs`.
#[derive(Debug, Default)]
pub struct GuestFiles {
    /// ADI state files by absolute path (only [`ADI_STATE_PATH`] is writable).
    pub adi: HashMap<String, Vec<u8>>,
    pub(super) adi_path: String,
    pub(super) adi_offset: usize,
    pub(super) icxs: Vec<u8>,
    pub(super) icxs_offset: usize,
}

/// Path of the persistent ADI state file kept by `adid`.
pub const ADI_STATE_PATH: &str = "/var/db/fpsd/adi/adi.pb";

/// A faked XPC object: optionally carries one opaque data payload.
#[derive(Debug, Default)]
pub(super) struct XpcObject {
    pub(super) data: Option<Vec<u8>>,
    pub(super) data_address: u64,
}

/// Faked XPC connection and dictionary state for `com.apple.adid`.
#[derive(Debug)]
pub struct XpcState {
    pub(super) objects: HashMap<u64, XpcObject>,
    next_object: u64,
    /// Payload of the last `xpc_dictionary_set_data` (the client's request).
    pub data: Vec<u8>,
    /// Heap copy of the last block given to `xpc_connection_set_event_handler`.
    pub event_handler: u64,
    /// Payload of the last dictionary sent with `xpc_dictionary_send_reply`.
    pub reply: Vec<u8>,
    /// Whether `xpc_dictionary_send_reply` ran since the flag was cleared.
    pub replied: bool,
    /// Payload returned by the next `xpc_connection_send_message_with_reply_sync`.
    pub sync_reply: Option<Vec<u8>>,
}

impl Default for XpcState {
    fn default() -> Self {
        Self {
            objects: HashMap::new(),
            next_object: XPC_OBJECT_HANDLE_BASE,
            data: Vec::new(),
            event_handler: 0,
            reply: Vec::new(),
            replied: false,
            sync_reply: None,
        }
    }
}

impl XpcState {
    /// Creates a faked XPC object carrying `data` and returns its handle.
    pub fn new_object(&mut self, data: Option<&[u8]>) -> u64 {
        self.next_object += 1;
        let object = XpcObject {
            data: data.map(<[u8]>::to_vec),
            data_address: 0,
        };
        self.objects.insert(self.next_object, object);

        self.next_object
    }
}

/// Mach port registration and message capture for `fairplayd`.
#[derive(Debug, Default)]
pub struct MachState {
    /// Callback given to `CFMachPortCreateWithPort`.
    pub port_callback: u64,
    /// Context structure given to `CFMachPortCreateWithPort`.
    pub port_context: u64,
    /// The context's `info` field, passed back to the callback.
    pub port_info: u64,
    /// Message bytes the guest last sent with `mach_msg`.
    pub message_reply: Vec<u8>,
}

/// Faked `IOKit`/kernel objects created lazily by the shims.
#[derive(Debug, Default)]
pub(super) struct KernelObjects {
    pub(super) aes_service: u64,
    pub(super) buffer_vtable: u64,
}

/// Everything the shims know about the emulated platform.
pub struct ShimState {
    pub(super) table: ShimTable,
    pub(super) heap: Heap,
    /// In-memory files.
    pub files: GuestFiles,
    /// Faked XPC state.
    pub xpc: XpcState,
    /// Mach port state.
    pub mach: MachState,
    /// Orchestration callbacks.
    pub handlers: HostHandlers,
    /// Value returned by `gethostuuid`; must be set before the guest asks.
    pub host_uuid: [u8; 16],
    pub(super) core_exports: HashMap<String, u64>,
    pub(super) pause_run_loop: bool,
    pub(super) host: Rc<dyn HostEnvironment>,
    pub(super) errno: u64,
    pub(super) iterator: u32,
    pub(super) callback_returns: Vec<u64>,
    pub(super) kernel: KernelObjects,
}

impl ShimState {
    pub(super) fn new(config: ShimConfig) -> Self {
        Self {
            table: ShimTable::default(),
            heap: Heap::default(),
            files: GuestFiles {
                icxs: config.icxs,
                ..GuestFiles::default()
            },
            xpc: XpcState::default(),
            mach: MachState::default(),
            handlers: HostHandlers::default(),
            host_uuid: [0; 16],
            core_exports: config.core_exports,
            pause_run_loop: config.pause_run_loop,
            host: config.host,
            errno: 0,
            iterator: 0,
            callback_returns: Vec::new(),
            kernel: KernelObjects::default(),
        }
    }

    /// Reserves `size` bytes of guest heap (contents are not cleared).
    ///
    /// # Errors
    /// Returns [`ShimError::AllocationTooLarge`] or [`ShimError::HeapExhausted`].
    pub fn allocate(&mut self, size: u64) -> Result<u64, ShimError> {
        self.heap.allocate(size)
    }

    /// Returns the guest address of `name`, binding unknown imports to a slot
    /// that faults with [`ShimError::UnsupportedImport`] when called. This is
    /// the import resolver handed to the Mach-O loader.
    ///
    /// # Errors
    /// Returns [`ShimError::CodeAreaFull`] when no slot is left.
    pub fn resolve(&mut self, name: &str) -> Result<u64, ShimError> {
        self.table.resolve(name)
    }

    /// Returns the guest address bound to `name`, if any.
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.table.symbol(name)
    }
}
