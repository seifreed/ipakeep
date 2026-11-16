//! Guest runtime shared by every Apple machine, and the `FairPlay` SAP session.
//!
//! Port of upstream ipatool's `internal/sap/machine/machine.go` and
//! `macos27.go`: loads `CoreFP`, `AppleMediaServices` (plus one optional
//! profile image) into the emulator engine, binds their imports to the shim
//! layer and calls guest functions with the AAPCS64 convention.

use std::cell::RefMut;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use thiserror::Error;

use super::shims::{
    HEAP_BASE, HEAP_SIZE, HostEnvironment, MACOS27_SHARED_CACHE_FUNCTIONS,
    MACOS27_SHARED_CACHE_SLOTS, PAGE_SIZE, ShimConfig, ShimError, ShimState, Shims, SystemHost,
};
use crate::infrastructure::apple_sap::assets::bundle::Bundle;
use crate::infrastructure::apple_sap::emu::{ARGUMENT_REGISTER_COUNT, EmuError, Engine, Register};
use crate::infrastructure::apple_sap::macho::{MachImage, MachoError, PreparationCache};

/// Wall-clock budget of one guest call.
const GUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Address guest functions return to; it holds a `brk #0`.
const RETURN_ADDRESS: u64 = 0x0000_0001_0000_0000;
/// Little-endian `brk #0`, written at [`RETURN_ADDRESS`].
const BREAK_INSTRUCTION: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];
/// Guest base of `CoreFP`.
const CORE_FP_BASE: u64 = 0x0000_1000_0000_0000;
const SCRATCH_BASE: u64 = 0x0000_3000_0000_0000;
const SCRATCH_SIZE: u64 = 32 << 20;
const STACK_BASE: u64 = 0x0000_5000_0000_0000;
const STACK_SIZE: u64 = 8 << 20;
const STACK_END: u64 = STACK_BASE + STACK_SIZE;
const STACK_ALIGNMENT: u64 = 16;
const STACK_SLOT_SIZE: u64 = 8;
const SCRATCH_ALIGNMENT: u64 = 16;
/// Largest output buffer accepted from a guest call.
const MAX_OUTPUT_SIZE: u64 = 16 << 20;
/// `ldr x16, #8`.
const LOAD_X16_LITERAL: u32 = 0x5800_0050;
/// `br x16`.
const BRANCH_X16: u32 = 0xd61f_0200;
/// Bytes of one prelinked-function trampoline (two instructions + target).
const TRAMPOLINE_SIZE: u64 = 16;
/// Size of the hardware block handed to SAP and `FairPlay`.
const HARDWARE_BLOCK_SIZE: usize = 24;
/// Bytes of the little-endian length prefix of the hardware block.
const HARDWARE_LENGTH_SIZE: usize = 4;
/// Longest hardware identifier accepted by the guest.
const MAX_HARDWARE_ID: usize = HARDWARE_BLOCK_SIZE - HARDWARE_LENGTH_SIZE;
/// The only SAP protocol version the pinned runtime speaks.
pub const SAP_VERSION: u32 = 200;

const CORE_EXPORT_NAMES: [&str; 6] = [
    "_WIn9UJ86JKdV4dM",
    "_X46O5IeS",
    "_YlCJ3lg",
    "_dku592fbFAj",
    "_fdjkDSAFjklaf2s",
    "_lxpgvVMLd0S7uRl",
];
const SAP_INITIALIZE: &str = "_cp2g1b9ro";
const SAP_EXCHANGE: &str = "_Mib5yocT";
const SAP_SIGN: &str = "_Fc3vhtJDvr";
const SAP_TEARDOWN: &str = "_IPaI1oem5iL";
const SAP_DISPOSE: &str = "_jEHf8Xzsv8K";
const MEDIA_EXPORT_NAMES: [&str; 5] = [
    SAP_INITIALIZE,
    SAP_EXCHANGE,
    SAP_SIGN,
    SAP_TEARDOWN,
    SAP_DISPOSE,
];

/// Failure of a guest machine.
#[derive(Debug, Error)]
pub enum MachineError {
    /// The emulator failed or the guest faulted.
    #[error(transparent)]
    Emu(#[from] EmuError),
    /// A guest image could not be prepared.
    #[error(transparent)]
    Macho(#[from] MachoError),
    /// The shim layer could not be installed or used.
    #[error(transparent)]
    Shim(#[from] ShimError),
    /// A guest function reported a non-zero status.
    #[error("{operation} returned {status}")]
    Status {
        /// What the guest was asked to do.
        operation: &'static str,
        /// The signed status code.
        status: i32,
    },
    /// The guest stopped somewhere other than the return address.
    #[error("guest stopped unexpectedly at {address:#x}")]
    Stopped {
        /// The program counter when the guest stopped.
        address: u64,
    },
    /// An argument or a guest result violated a precondition.
    #[error("{0}")]
    Invalid(&'static str),
    /// A guest output buffer exceeds the accepted size.
    #[error("guest output is {length} bytes, maximum is {MAX_OUTPUT_SIZE}")]
    OutputTooLarge {
        /// The reported length.
        length: u64,
    },
    /// Another emulator call is already using this machine.
    #[error("guest machine is busy")]
    Busy,
}

/// Result alias of the machine layer.
pub type MachineResult<T> = Result<T, MachineError>;

/// Host services shared by every guest machine of one session.
#[derive(Clone)]
pub struct GuestEnvironment {
    /// Clock and randomness served to the guests.
    pub host: Rc<dyn HostEnvironment>,
    /// On-disk cache of decoded Mach-O fixups (speeds up repeated opens).
    pub preparation_cache: Option<PreparationCache>,
}

impl Default for GuestEnvironment {
    fn default() -> Self {
        Self {
            host: Rc::new(SystemHost),
            preparation_cache: PreparationCache::default_location(),
        }
    }
}

/// Where an extra image is placed in the guest.
#[derive(Debug, Clone, Copy)]
pub(super) struct ImagePlacement {
    /// Guest load base.
    pub(super) base: u64,
    /// Kernel-collection base whose pointers must be relocated, if any.
    pub(super) kernel_base: Option<u64>,
}

/// One profile image loaded next to `CoreFP` and `AppleMediaServices`.
pub(super) struct ExtraImage<'b> {
    pub(super) name: &'static str,
    pub(super) data: &'b [u8],
    pub(super) placement: ImagePlacement,
}

/// Per-profile runtime options.
#[derive(Default)]
pub(super) struct RuntimeOptions<'b> {
    pub(super) extra: Option<ExtraImage<'b>>,
    pub(super) zero_return_aliases: &'static [&'static str],
    pub(super) pause_run_loop: bool,
}

struct PreparedImage {
    image: MachImage,
    prelinked: bool,
    placement: ImagePlacement,
}

/// A loaded guest: emulator, shims, scratch arena and resolved exports.
pub(super) struct GuestRuntime {
    engine: Engine<'static>,
    shims: Shims,
    exports: HashMap<String, u64>,
    scratch_cursor: u64,
}

impl GuestRuntime {
    /// Loads the base images plus `options.extra` into a fresh emulator.
    pub(super) fn open(
        bundle: &Bundle,
        environment: &GuestEnvironment,
        options: &RuntimeOptions<'_>,
    ) -> MachineResult<Self> {
        let cache = environment.preparation_cache.as_ref();
        let mut images = open_images(bundle, options, cache)?;
        let exports = collect_exports(&images)?;
        let mut engine = Engine::new()?;
        map_fixed_regions(&mut engine)?;
        let config = shim_config(bundle, environment, options, &exports);
        let shims = Shims::install(&mut engine, config)?;
        let mut runtime = Self {
            engine,
            shims,
            exports,
            scratch_cursor: 0,
        };
        runtime.load_shared_cache_stubs()?;
        for prepared in &mut images {
            runtime.load_image(prepared)?;
        }
        Ok(runtime)
    }

    fn resolve(&self, name: &str) -> MachineResult<u64> {
        if let Some(&address) = self.exports.get(name) {
            return Ok(address);
        }
        Ok(self.shims.state().borrow_mut().resolve(name)?)
    }

    fn load_shared_cache_stubs(&mut self) -> MachineResult<()> {
        let mut slots = MACOS27_SHARED_CACHE_SLOTS.to_vec();
        slots.sort_unstable();
        map_pages(
            &mut self.engine,
            slots.iter().map(|(address, _)| (*address, 0)),
        )?;
        for (address, name) in slots {
            let value = self.resolve(name)?;
            self.engine.write_u64(address, value)?;
        }
        let mut functions = MACOS27_SHARED_CACHE_FUNCTIONS.to_vec();
        functions.sort_unstable();
        let pages = functions
            .iter()
            .map(|(address, _)| (*address, TRAMPOLINE_SIZE));
        map_pages(&mut self.engine, pages)?;
        for (address, name) in functions {
            let target = self.resolve(name)?;
            self.engine.mem_write(address, &trampoline(target))?;
        }
        Ok(())
    }

    fn load_image(&mut self, prepared: &mut PreparedImage) -> MachineResult<()> {
        let exports = self.exports.clone();
        let state = self.shims.state();
        let resolver = |name: &str| -> Result<u64, ShimError> {
            match exports.get(name) {
                Some(&address) => Ok(address),
                None => state.borrow_mut().resolve(name),
            }
        };
        let placement = prepared.placement;
        if prepared.prelinked {
            let external = shared_cache_functions();
            prepared.image.prepare_prelinked(&external, resolver)?;
        } else {
            prepared.image.relocate(placement.base, resolver)?;
        }
        if let Some(kernel_base) = placement.kernel_base {
            prepared
                .image
                .relocate_kernel_cache_pointers(placement.base, kernel_base, resolver)?;
        }
        self.write_image(&prepared.image)
    }

    fn write_image(&mut self, image: &MachImage) -> MachineResult<()> {
        let plan = image.load_plan()?;
        for region in &plan.regions {
            self.engine.mem_map(region.address, region.size)?;
        }
        for segment in &plan.segments {
            self.engine.mem_write(segment.address, segment.data)?;
        }
        Ok(())
    }

    /// Address of an export of `CoreFP` or `AppleMediaServices`.
    pub(super) fn export(&self, name: &str) -> MachineResult<u64> {
        self.exports
            .get(name)
            .copied()
            .ok_or(MachineError::Invalid("guest export is unavailable"))
    }

    /// Mutably borrows this guest's shim state.
    pub(super) fn with_state<T>(
        &self,
        action: impl FnOnce(&mut ShimState) -> T,
    ) -> MachineResult<T> {
        let state = self.shims.state();
        let mut guard: RefMut<'_, ShimState> =
            state.try_borrow_mut().map_err(|_| MachineError::Busy)?;
        Ok(action(&mut guard))
    }

    /// The emulator, for direct memory access between calls.
    pub(super) fn engine(&mut self) -> &mut Engine<'static> {
        &mut self.engine
    }

    /// Calls the guest function at `function` with integer `arguments`.
    pub(super) fn invoke(&mut self, function: u64, arguments: &[u64]) -> MachineResult<u64> {
        if function == 0 {
            return Err(MachineError::Invalid("guest entry point is unavailable"));
        }
        self.write_arguments(arguments)?;
        self.engine.run(function, RETURN_ADDRESS, GUEST_TIMEOUT)?;
        let address = self.engine.reg_read(Register::Pc)?;
        if address != RETURN_ADDRESS {
            return Err(MachineError::Stopped { address });
        }
        Ok(self.engine.reg_read(Register::X(0))?)
    }

    /// Calls `function` and fails unless it returns a zero 32-bit status.
    pub(super) fn invoke_checked(
        &mut self,
        operation: &'static str,
        function: u64,
        arguments: &[u64],
    ) -> MachineResult<()> {
        let status = status_of(self.invoke(function, arguments)?);
        if status != 0 {
            return Err(MachineError::Status { operation, status });
        }
        Ok(())
    }

    fn write_arguments(&mut self, arguments: &[u64]) -> MachineResult<()> {
        let in_registers = usize::from(ARGUMENT_REGISTER_COUNT);
        for index in 0..ARGUMENT_REGISTER_COUNT {
            let value = arguments.get(usize::from(index)).copied().unwrap_or(0);
            self.engine.reg_write(Register::X(index), value)?;
        }
        let stacked = arguments.get(in_registers..).unwrap_or(&[]);
        let mut stack_pointer = STACK_END - stacked.len() as u64 * STACK_SLOT_SIZE;
        stack_pointer -= stack_pointer % STACK_ALIGNMENT;
        for (index, value) in stacked.iter().enumerate() {
            let address = stack_pointer + index as u64 * STACK_SLOT_SIZE;
            self.engine.write_u64(address, *value)?;
        }
        self.engine.reg_write(Register::Sp, stack_pointer)?;
        self.engine.reg_write(Register::LR, RETURN_ADDRESS)?;
        Ok(())
    }

    /// Starts a new call: the scratch arena is reused from its beginning.
    pub(super) fn begin_call(&mut self) {
        self.scratch_cursor = 0;
    }

    /// Reserves `size` zeroed scratch bytes, optionally initialised with `data`.
    pub(super) fn scratch(&mut self, data: &[u8], size: u64) -> MachineResult<u64> {
        if data.len() as u64 > size {
            return Err(MachineError::Invalid("scratch data exceeds reservation"));
        }
        let reserved = align(size.max(1), SCRATCH_ALIGNMENT);
        if reserved > SCRATCH_SIZE - self.scratch_cursor.min(SCRATCH_SIZE) {
            return Err(MachineError::Invalid("guest scratch space exhausted"));
        }
        let address = SCRATCH_BASE + self.scratch_cursor;
        self.scratch_cursor += reserved;
        let length = usize::try_from(size).map_err(|_| MachineError::Invalid("scratch size"))?;
        let mut contents = vec![0; length];
        contents[..data.len()].copy_from_slice(data);
        self.engine.mem_write(address, &contents)?;
        Ok(address)
    }

    /// Copies `data` into a fresh scratch reservation of the same size.
    pub(super) fn scratch_bytes(&mut self, data: &[u8]) -> MachineResult<u64> {
        self.scratch(data, data.len() as u64)
    }

    /// Reserves a zeroed scratch field of `size` bytes.
    pub(super) fn scratch_field(&mut self, size: u64) -> MachineResult<u64> {
        self.scratch(&[], size)
    }

    /// Zeroes the scratch bytes used by the current call.
    pub(super) fn clear_scratch(&mut self) {
        if self.scratch_cursor != 0
            && let Ok(length) = usize::try_from(self.scratch_cursor)
        {
            // Clearing is hygiene only; a failure leaves stale bytes that the
            // next reservation overwrites anyway.
            let _ = self.engine.mem_write(SCRATCH_BASE, &vec![0; length]);
        }
        self.scratch_cursor = 0;
    }

    /// Reads a little-endian `u32` from guest memory.
    pub(super) fn read_u32(&self, address: u64) -> MachineResult<u32> {
        Ok(self.engine.read_u32(address)?)
    }

    /// Reads a little-endian `u64` from guest memory.
    pub(super) fn read_u64(&self, address: u64) -> MachineResult<u64> {
        Ok(self.engine.read_u64(address)?)
    }

    /// Reads `length` bytes of guest memory.
    pub(super) fn read_bytes(&self, address: u64, length: u64) -> MachineResult<Vec<u8>> {
        let length = usize::try_from(length).map_err(|_| MachineError::Invalid("read size"))?;
        Ok(self.engine.mem_read(address, length)?)
    }

    /// Reads a guest-allocated output buffer described by a pointer field and
    /// a 64-bit length field, then releases it with the SAP disposer.
    pub(super) fn consume_output(
        &mut self,
        pointer_field: u64,
        length_field: u64,
    ) -> MachineResult<Vec<u8>> {
        let pointer = self.read_u64(pointer_field)?;
        let length = self.read_u64(length_field)?;
        let output = match (length, pointer) {
            (length, _) if length > MAX_OUTPUT_SIZE => Err(MachineError::OutputTooLarge { length }),
            (0, _) => Ok(Vec::new()),
            (_, 0) => Err(MachineError::Invalid(
                "guest returned a null output pointer",
            )),
            (length, pointer) => self.read_bytes(pointer, length),
        };
        if pointer != 0 {
            let disposer = self.export(SAP_DISPOSE)?;
            self.invoke_checked("SAP storage disposal", disposer, &[pointer])?;
        }
        output
    }
}

fn open_images(
    bundle: &Bundle,
    options: &RuntimeOptions<'_>,
    cache: Option<&PreparationCache>,
) -> MachineResult<Vec<PreparedImage>> {
    let core = MachImage::open_with_cache("CoreFP", &bundle.core_fp, cache)?;
    let media =
        MachImage::open_with_cache("AppleMediaServices", &bundle.apple_media_services, cache)?;
    let media_base = media.base();
    let mut images = vec![
        PreparedImage {
            image: core,
            prelinked: false,
            placement: ImagePlacement {
                base: CORE_FP_BASE,
                kernel_base: None,
            },
        },
        PreparedImage {
            image: media,
            prelinked: true,
            placement: ImagePlacement {
                base: media_base,
                kernel_base: None,
            },
        },
    ];
    if let Some(extra) = &options.extra {
        images.push(PreparedImage {
            image: MachImage::open_with_cache(extra.name, extra.data, cache)?,
            prelinked: false,
            placement: extra.placement,
        });
    }
    Ok(images)
}

fn collect_exports(images: &[PreparedImage]) -> MachineResult<HashMap<String, u64>> {
    let mut exports = HashMap::new();
    let (core, media) = match images {
        [core, media, ..] => (&core.image, &media.image),
        _ => return Err(MachineError::Invalid("base guest images are missing")),
    };
    for name in CORE_EXPORT_NAMES {
        exports.insert(name.to_owned(), core.export(name, CORE_FP_BASE)?);
    }
    for name in MEDIA_EXPORT_NAMES {
        exports.insert(name.to_owned(), media.export(name, media.base())?);
    }
    Ok(exports)
}

fn core_exports(exports: &HashMap<String, u64>) -> HashMap<String, u64> {
    CORE_EXPORT_NAMES
        .iter()
        .filter_map(|name| {
            exports
                .get(*name)
                .map(|address| ((*name).to_owned(), *address))
        })
        .collect()
}

fn shim_config(
    bundle: &Bundle,
    environment: &GuestEnvironment,
    options: &RuntimeOptions<'_>,
    exports: &HashMap<String, u64>,
) -> ShimConfig {
    ShimConfig {
        core_exports: core_exports(exports),
        icxs: bundle.core_fp_icxs.clone(),
        zero_return_aliases: options
            .zero_return_aliases
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        pause_run_loop: options.pause_run_loop,
        host: Rc::clone(&environment.host),
    }
}

fn map_fixed_regions(engine: &mut Engine<'_>) -> MachineResult<()> {
    for (address, size) in [
        (RETURN_ADDRESS, PAGE_SIZE),
        (SCRATCH_BASE, SCRATCH_SIZE),
        (HEAP_BASE, HEAP_SIZE),
        (STACK_BASE, STACK_SIZE),
    ] {
        engine.mem_map(address, size)?;
    }
    engine.mem_write(RETURN_ADDRESS, &BREAK_INSTRUCTION)?;
    Ok(())
}

/// Maps every page touched by `(address, length)` ranges once.
fn map_pages(
    engine: &mut Engine<'_>,
    ranges: impl Iterator<Item = (u64, u64)>,
) -> MachineResult<()> {
    let mut pages: Vec<u64> = ranges
        .flat_map(|(address, length)| {
            let last = address + length.saturating_sub(1);
            [address - address % PAGE_SIZE, last - last % PAGE_SIZE]
        })
        .collect();
    pages.sort_unstable();
    pages.dedup();
    for page in pages {
        engine.mem_map(page, PAGE_SIZE)?;
    }
    Ok(())
}

fn trampoline(target: u64) -> [u8; 16] {
    let mut code = [0; 16];
    code[0..4].copy_from_slice(&LOAD_X16_LITERAL.to_le_bytes());
    code[4..8].copy_from_slice(&BRANCH_X16.to_le_bytes());
    code[8..16].copy_from_slice(&target.to_le_bytes());
    code
}

fn shared_cache_functions() -> HashMap<u64, String> {
    MACOS27_SHARED_CACHE_FUNCTIONS
        .iter()
        .map(|(address, name)| (*address, (*name).to_owned()))
        .collect()
}

/// Interprets the low 32 bits of a guest return register as a signed status.
pub(super) fn status_of(value: u64) -> i32 {
    i32::from_le_bytes(value.to_le_bytes()[..4].try_into().unwrap_or_default())
}

fn align(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// Encodes a hardware identifier as `le32(len) || id || zero padding`.
///
/// # Errors
/// Fails unless the identifier holds between 1 and 20 bytes.
pub fn hardware_block(hardware_id: &[u8]) -> MachineResult<[u8; HARDWARE_BLOCK_SIZE]> {
    if hardware_id.is_empty() || hardware_id.len() > MAX_HARDWARE_ID {
        return Err(MachineError::Invalid(
            "hardware ID must contain between 1 and 20 bytes",
        ));
    }
    let mut block = [0; HARDWARE_BLOCK_SIZE];
    let length = u32::try_from(hardware_id.len()).unwrap_or_default();
    block[..HARDWARE_LENGTH_SIZE].copy_from_slice(&length.to_le_bytes());
    block[HARDWARE_LENGTH_SIZE..HARDWARE_LENGTH_SIZE + hardware_id.len()]
        .copy_from_slice(hardware_id);
    Ok(block)
}

/// Output of one SAP exchange step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SapExchange {
    /// Message to send to Apple (empty once setup completes).
    pub output: Vec<u8>,
    /// Protocol state: 1 while a reply is expected, 0 when complete.
    pub state: i32,
}

/// The `FairPlay` SAP v200 primitives exported by `AppleMediaServices`.
pub struct SapMachine {
    runtime: GuestRuntime,
}

impl SapMachine {
    /// Loads `CoreFP` and `AppleMediaServices` into a fresh emulator.
    ///
    /// # Errors
    /// Fails when an image cannot be prepared or the emulator cannot start.
    pub fn open(bundle: &Bundle, environment: &GuestEnvironment) -> MachineResult<Self> {
        let runtime = GuestRuntime::open(bundle, environment, &RuntimeOptions::default())?;
        Ok(Self { runtime })
    }

    /// Creates a SAP context bound to `hardware_id` and returns its pointer.
    ///
    /// # Errors
    /// Fails on an invalid identifier, a guest fault or a non-zero status.
    pub fn initialize(&mut self, hardware_id: &[u8]) -> MachineResult<u64> {
        let hardware = hardware_block(hardware_id)?;
        let entry = self.runtime.export(SAP_INITIALIZE)?;
        let runtime = &mut self.runtime;
        runtime.begin_call();
        let result = (|| {
            let context_field = runtime.scratch_field(STACK_SLOT_SIZE)?;
            let hardware_address = runtime.scratch_bytes(&hardware)?;
            runtime.invoke_checked(
                "SAP initialization",
                entry,
                &[context_field, hardware_address],
            )?;
            runtime.read_u64(context_field)
        })();
        runtime.clear_scratch();
        match result? {
            0 => Err(MachineError::Invalid(
                "SAP initialization returned a null context",
            )),
            context => Ok(context),
        }
    }

    /// Runs one setup step of protocol `version` on `context` with `input`.
    ///
    /// # Errors
    /// Fails on an invalid identifier, a guest fault or a non-zero status.
    pub fn exchange(
        &mut self,
        version: u32,
        hardware_id: &[u8],
        context: u64,
        input: &[u8],
    ) -> MachineResult<SapExchange> {
        let hardware = hardware_block(hardware_id)?;
        let entry = self.runtime.export(SAP_EXCHANGE)?;
        let runtime = &mut self.runtime;
        runtime.begin_call();
        let result = (|| {
            let hardware_address = runtime.scratch_bytes(&hardware)?;
            let input_address = runtime.scratch_bytes(input)?;
            let output_field = runtime.scratch_field(STACK_SLOT_SIZE)?;
            let length_field = runtime.scratch_field(STACK_SLOT_SIZE)?;
            let state_field = runtime.scratch_field(4)?;
            let arguments = [
                u64::from(version),
                hardware_address,
                context,
                input_address,
                input.len() as u64,
                output_field,
                length_field,
                state_field,
            ];
            runtime.invoke_checked("SAP exchange", entry, &arguments)?;
            let output = runtime.consume_output(output_field, length_field)?;
            let state = status_of(u64::from(runtime.read_u32(state_field)?));
            Ok(SapExchange { output, state })
        })();
        runtime.clear_scratch();
        result
    }

    /// Signs `input` with the established `context`.
    ///
    /// # Errors
    /// Fails on a guest fault or a non-zero status.
    pub fn sign(&mut self, context: u64, input: &[u8]) -> MachineResult<Vec<u8>> {
        let entry = self.runtime.export(SAP_SIGN)?;
        let runtime = &mut self.runtime;
        runtime.begin_call();
        let result = (|| {
            let input_address = runtime.scratch_bytes(input)?;
            let output_field = runtime.scratch_field(STACK_SLOT_SIZE)?;
            let length_field = runtime.scratch_field(STACK_SLOT_SIZE)?;
            let arguments = [
                context,
                input_address,
                input.len() as u64,
                output_field,
                length_field,
            ];
            runtime.invoke_checked("SAP signing", entry, &arguments)?;
            runtime.consume_output(output_field, length_field)
        })();
        runtime.clear_scratch();
        result
    }

    /// Releases `context`.
    ///
    /// # Errors
    /// Fails on a guest fault or a non-zero status.
    pub fn teardown(&mut self, context: u64) -> MachineResult<()> {
        let entry = self.runtime.export(SAP_TEARDOWN)?;
        self.runtime
            .invoke_checked("SAP teardown", entry, &[context])
    }
}

#[cfg(test)]
pub(in crate::infrastructure::apple_sap) mod test_support {
    //! Deterministic host and golden-fixture access shared by machine tests.

    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};

    use super::{GuestEnvironment, HostEnvironment};
    use crate::infrastructure::apple_sap::assets::bundle::{Bundle, read_bundle};
    use crate::infrastructure::apple_sap::macho::PreparationCache;

    /// H0's frozen time, 2026-11-15T12:00:00Z.
    pub(in crate::infrastructure::apple_sap) const FIXED_UNIX_TIME: u64 = 1_794_744_000;
    /// H0's primary RNG seed.
    pub(in crate::infrastructure::apple_sap) const PRIMARY_SEED: &[u8] =
        b"ipakeep-h0-golden-seed-v1";
    /// H0's alternate RNG seed.
    pub(in crate::infrastructure::apple_sap) const ALTERNATE_SEED: &[u8] =
        b"ipakeep-h0-golden-seed-v2";

    /// H0's oracle host: frozen time and the `SHA-256(seed || be64(i))` stream.
    pub(in crate::infrastructure::apple_sap) struct SeededHost {
        stream: RefCell<(Vec<u8>, u64, Vec<u8>)>,
        now: RefCell<SystemTime>,
    }

    impl SeededHost {
        pub(in crate::infrastructure::apple_sap) fn new(seed: &[u8]) -> Rc<Self> {
            let host = Rc::new(Self {
                stream: RefCell::new((Vec::new(), 0, Vec::new())),
                now: RefCell::new(UNIX_EPOCH),
            });
            host.freeze(seed, FIXED_UNIX_TIME);
            host
        }

        /// Restarts the stream from `seed` and freezes time at `unix_time`.
        pub(in crate::infrastructure::apple_sap) fn freeze(&self, seed: &[u8], unix_time: u64) {
            *self.stream.borrow_mut() = (seed.to_vec(), 0, Vec::new());
            *self.now.borrow_mut() = UNIX_EPOCH + Duration::from_secs(unix_time);
        }
    }

    impl HostEnvironment for SeededHost {
        fn now(&self) -> SystemTime {
            *self.now.borrow()
        }

        fn fill_random(&self, buffer: &mut [u8]) {
            let mut stream = self.stream.borrow_mut();
            let (seed, counter, pending) = &mut *stream;
            for byte in buffer {
                if pending.is_empty() {
                    let mut hasher = Sha256::new();
                    hasher.update(&*seed);
                    hasher.update(counter.to_be_bytes());
                    *counter += 1;
                    *pending = hasher.finalize().to_vec();
                }
                *byte = pending.remove(0);
            }
        }
    }

    /// The pinned asset bundle from ipatool's cache.
    pub(in crate::infrastructure::apple_sap) fn bundle() -> Bundle {
        let directory = dirs::home_dir()
            .unwrap()
            .join("Library/Caches/ipatool/sap/apple-assets-macos-27-26A434-arm64-v5");
        read_bundle(&directory).unwrap()
    }

    /// A guest environment over `host` with the default fixup cache.
    pub(in crate::infrastructure::apple_sap) fn environment(
        host: &Rc<SeededHost>,
    ) -> GuestEnvironment {
        GuestEnvironment {
            host: Rc::clone(host) as Rc<dyn HostEnvironment>,
            preparation_cache: PreparationCache::default_location(),
        }
    }

    /// Parses `tests/fixtures/apple_sap/golden/<name>`.
    pub(in crate::infrastructure::apple_sap) fn fixture(name: &str) -> serde_json::Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/apple_sap/golden")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// Decodes the hex string at JSON `pointer`.
    pub(in crate::infrastructure::apple_sap) fn hex_at(
        value: &serde_json::Value,
        pointer: &str,
    ) -> Vec<u8> {
        hex::decode(
            value
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn seeded_stream_matches_sha256_counter_blocks() {
        let host = SeededHost::new(b"seed");
        let mut first = [0; 40];
        host.fill_random(&mut first);
        let block0 = Sha256::digest([b"seed".as_slice(), &0u64.to_be_bytes()].concat());
        let block1 = Sha256::digest([b"seed".as_slice(), &1u64.to_be_bytes()].concat());
        assert_eq!(&first[..32], block0.as_slice());
        assert_eq!(&first[32..], &block1[..8]);
        host.freeze(b"seed", FIXED_UNIX_TIME);
        let mut again = [0; 4];
        host.fill_random(&mut again);
        assert_eq!(again, first[..4]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_block_is_length_prefixed_and_padded() {
        let block = hardware_block(&[0x02, 0, 0, 0, 0, 0x01]).unwrap();
        assert_eq!(
            hex::encode(block),
            "060000000200000000010000000000000000000000000000"
        );
    }

    #[test]
    fn hardware_block_rejects_empty_and_oversized_identifiers() {
        assert!(hardware_block(&[]).is_err());
        assert!(hardware_block(&[0; MAX_HARDWARE_ID + 1]).is_err());
        assert!(hardware_block(&[0; MAX_HARDWARE_ID]).is_ok());
    }

    #[test]
    fn trampoline_loads_target_into_x16_and_branches() {
        assert_eq!(
            hex::encode(trampoline(0x1122_3344_5566_7788)),
            "50000058".to_owned() + "00021fd6" + "8877665544332211"
        );
    }

    #[test]
    fn status_uses_the_signed_low_word() {
        assert_eq!(status_of(0xffff_ffff_ffff_fffe), -2);
        assert_eq!(status_of(0x1_0000_0000), 0);
        assert_eq!(status_of(0xffff_4ffb), -45061);
    }

    #[test]
    fn shared_cache_tables_have_unique_addresses() {
        let functions = shared_cache_functions();
        assert_eq!(functions.len(), MACOS27_SHARED_CACHE_FUNCTIONS.len());
        assert_eq!(align(17, SCRATCH_ALIGNMENT), 32);
    }
}

#[cfg(test)]
mod golden_tests {
    use super::test_support::{
        ALTERNATE_SEED, PRIMARY_SEED, SeededHost, bundle, environment, fixture, hex_at,
    };
    use super::*;

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn sap_session_reproduces_golden_vectors() {
        let golden = fixture("sap.json");
        let hardware = hex_at(&golden, "/hardware_id_hex");
        let host = SeededHost::new(PRIMARY_SEED);
        let mut machine = SapMachine::open(&bundle(), &environment(&host)).unwrap();
        let context = machine.initialize(&hardware).unwrap();
        assert_eq!(
            format!("{context:#x}"),
            golden["context_pointer"].as_str().unwrap()
        );
        let first = machine
            .exchange(
                SAP_VERSION,
                &hardware,
                context,
                &hex_at(&golden, "/certificate_hex"),
            )
            .unwrap();
        assert_eq!(
            hex::encode(&first.output),
            golden["exchange1_output_hex"].as_str().unwrap()
        );
        assert_eq!(first.state, 1);
        let second = machine
            .exchange(
                SAP_VERSION,
                &hardware,
                context,
                &hex_at(&golden, "/exchange2_input_hex"),
            )
            .unwrap();
        assert_eq!(second.output, [] as [u8; 0]);
        assert_eq!(second.state, 0);
        assert_signatures(&mut machine, context, &golden);
        machine.teardown(context).unwrap();
    }

    fn assert_signatures(machine: &mut SapMachine, context: u64, golden: &serde_json::Value) {
        for entry in golden["signatures"].as_array().unwrap() {
            let signature = machine.sign(context, &hex_at(entry, "/input_hex")).unwrap();
            assert_eq!(
                hex::encode(signature),
                entry["signature_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn sap_setup_request_follows_the_alternate_seed() {
        let golden = fixture("sap.json");
        let hardware = hex_at(&golden, "/hardware_id_hex");
        let host = SeededHost::new(ALTERNATE_SEED);
        let mut machine = SapMachine::open(&bundle(), &environment(&host)).unwrap();
        let context = machine.initialize(&hardware).unwrap();
        let certificate = hex_at(&golden, "/certificate_hex");
        let first = machine
            .exchange(SAP_VERSION, &hardware, context, &certificate)
            .unwrap();
        assert_eq!(
            first.output,
            hex_at(&golden, "/exchange1_output_alt_seed_hex")
        );
    }
}
