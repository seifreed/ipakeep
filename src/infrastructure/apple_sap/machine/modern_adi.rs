//! Modern ADI (Anisette) from the pinned macOS 27 `commerce` image.
//!
//! Port of upstream ipatool's `internal/sap/machine/modern_adi.go`. Four
//! cooperating guests emulate the real process split:
//! - the `commerce` client runtime (`ADI` API entry points),
//! - the `adid` daemon (`com.apple.adid`, reached over faked XPC),
//! - `fairplayd` (reached over faked Mach ports),
//! - the `FairPlayIOKit` kernel extension (reached over faked `IOKit` calls).
//!
//! The Store "AMD" headers are the same ADI one-time password the client
//! requests for DSID `-1`, so no `AppleMediaServices` emulation is needed.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::sap::{
    ExtraImage, GuestEnvironment, GuestRuntime, ImagePlacement, MachineError, MachineResult,
    RuntimeOptions, hardware_block, status_of,
};
use super::shims::{
    ADI_STATE_PATH, FAKE_HANDLE, FairPlayHandler, FairPlayReply, FairPlayRequest, MachRpcHandler,
};
use super::storeagent::{
    STORE_AGENT_BASE, close_global, initialize_global_in_call, open_commerce_runtime,
};
use crate::infrastructure::apple_sap::assets::bundle::Bundle;
use crate::infrastructure::apple_sap::emu::EmuError;

const ADI_START_ENTRY: u64 = STORE_AGENT_BASE + 0x001b_4400;
const ADI_END_ENTRY: u64 = STORE_AGENT_BASE + 0x001d_5124;
const ADI_OTP_ENTRY: u64 = STORE_AGENT_BASE + 0x001d_ab04;
const KEY_BAG_ENTRY: u64 = STORE_AGENT_BASE + 0x0016_e0f8;
const ADID_BASE: u64 = 0x0000_2000_0000_0000;
const ADID_ENTRY: u64 = ADID_BASE + 0x0001_1180;
const FAIRPLAYD_BASE: u64 = 0x0000_6000_0000_0000;
const FAIRPLAYD_ENTRY: u64 = FAIRPLAYD_BASE + 0x0033_2040;
/// Keeps the prelinked image's original 0x510 page offset so its ADRP
/// references keep the same slide as its data segments.
const KEXT_BASE: u64 = 0x0000_7000_0000_0510;
const KEXT_START: u64 = KEXT_BASE + 0x02bc_a984;
const KEXT_SETUP: u64 = KEXT_BASE + 0x02c6_7e50;
const KEXT_INIT: u64 = KEXT_BASE + 0x02bc_a714;
const KEXT_ENTRY: u64 = KEXT_BASE + 0x02cf_978c;
const KEXT_STACK_PROBE: u64 = KEXT_BASE + 0x00b8_c028;
const KEXT_STACK_PROBE_VALUE: u64 = KEXT_BASE + 0x02c6_6248;
/// Kernel-collection base the `FairPlayIOKit` pointers are relative to.
const KERNEL_COLLECTION_BASE: u64 = 0xffff_fe00_0700_4000;
const KERNEL_TASK_SIZE: usize = 0x1000;
/// Offset of the invoke pointer inside an Objective-C block literal.
const BLOCK_INVOKE_OFFSET: u64 = 16;
const HOST_UUID_SIZE: usize = 16;
const MAX_XPC_PAYLOAD: usize = 1 << 20;
const MAX_ADI_OUTPUT: u32 = 1 << 20;
const POINTER_FIELD_SIZE: u64 = 8;
const LENGTH_FIELD_SIZE: u64 = 4;
const ADI_STATE_FILE_NAME: &str = "/adi.pb";

/// DSID of GSA machine provisioning (`-2`).
pub const MACHINE_PROVISIONING_DSID: u64 = 0xffff_ffff_ffff_fffe;
/// DSID the Store asks `adid` for when building `X-Apple-AMD` (`-1`).
pub const STORE_AMD_DSID: u64 = u64::MAX;

type SharedRuntime = Rc<RefCell<GuestRuntime>>;

/// Result of [`ModernAdi::start_provisioning`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisioningStart {
    /// Client provisioning message (`cpim`) for GSA.
    pub cpim: Vec<u8>,
    /// Session handed back to [`ModernAdi::end_provisioning`].
    pub session: u32,
}

/// A one-time password and machine identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdiOtp {
    /// Machine identifier (`X-Apple-I-MD-M` / `X-Apple-AMD-M`).
    pub mid: Vec<u8>,
    /// One-time password (`X-Apple-I-MD` / `X-Apple-AMD`).
    pub otp: Vec<u8>,
}

/// The Store machine-proof headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreAmdHeaders {
    /// `X-Apple-AMD`: base64 of the OTP.
    pub amd: String,
    /// `X-Apple-AMD-M`: base64 of the machine identifier.
    pub amd_m: String,
}

impl From<&AdiOtp> for StoreAmdHeaders {
    fn from(otp: &AdiOtp) -> Self {
        Self {
            amd: STANDARD.encode(&otp.otp),
            amd_m: STANDARD.encode(&otp.mid),
        }
    }
}

/// Routes `FairPlay` `IOKit` and Mach traffic between the guests.
struct FairPlayRouter {
    fairplay: Weak<RefCell<GuestRuntime>>,
    kernel: Option<Weak<RefCell<GuestRuntime>>>,
    kernel_context: Cell<u64>,
}

fn upgrade(runtime: &Weak<RefCell<GuestRuntime>>) -> MachineResult<SharedRuntime> {
    runtime
        .upgrade()
        .ok_or(MachineError::Invalid("FairPlay guest is closed"))
}

fn borrow(runtime: &SharedRuntime) -> MachineResult<std::cell::RefMut<'_, GuestRuntime>> {
    runtime.try_borrow_mut().map_err(|_| MachineError::Busy)
}

impl FairPlayRouter {
    fn message(&self, request: &FairPlayRequest) -> MachineResult<FairPlayReply> {
        let (indirect, status) = match &self.kernel {
            Some(kernel) => self.kernel_message(&upgrade(kernel)?, &request.indirect)?,
            None => (
                fairplay_daemon_message(&upgrade(&self.fairplay)?, &request.indirect)?,
                0,
            ),
        };
        let mut output = request.input.clone();
        output.truncate(request.output_size);
        Ok(FairPlayReply {
            output,
            indirect,
            status,
        })
    }

    fn kernel_message(
        &self,
        kernel: &SharedRuntime,
        message: &[u8],
    ) -> MachineResult<(Vec<u8>, i32)> {
        let mut kernel = borrow(kernel)?;
        if kernel.read_u64(KEXT_STACK_PROBE)? != KEXT_STACK_PROBE_VALUE {
            return Err(MachineError::Invalid(
                "FairPlay kernel stack probe is corrupt",
            ));
        }
        let context = self.kernel_context.get();
        kernel.begin_call();
        let result = (|| {
            let address = kernel.scratch_bytes(message)?;
            let length = message.len() as u64;
            let status = status_of(kernel.invoke(KEXT_ENTRY, &[address, length, context])?);
            Ok((kernel.read_bytes(address, length)?, status))
        })();
        kernel.clear_scratch();
        result
    }

    fn mach_rpc(&self, request: &[u8], receive_size: usize) -> MachineResult<Vec<u8>> {
        let fairplay = upgrade(&self.fairplay)?;
        let mut fairplay = borrow(&fairplay)?;
        let (callback, info) = port_callback(&fairplay)?;
        fairplay.begin_call();
        let result = (|| {
            let size = request.len().max(receive_size) as u64;
            let message = fairplay.scratch(request, size)?;
            fairplay.with_state(|state| state.mach.message_reply.clear())?;
            let arguments = [FAKE_HANDLE, message, request.len() as u64, info];
            fairplay.invoke(callback, &arguments)?;
            fairplay.with_state(|state| std::mem::take(&mut state.mach.message_reply))
        })();
        fairplay.clear_scratch();
        match result? {
            reply if reply.is_empty() => Err(MachineError::Invalid(
                "FairPlay daemon returned no Mach reply",
            )),
            reply => Ok(reply),
        }
    }
}

fn port_callback(fairplay: &GuestRuntime) -> MachineResult<(u64, u64)> {
    let (callback, info) =
        fairplay.with_state(|state| (state.mach.port_callback, state.mach.port_info))?;
    if callback == 0 {
        return Err(MachineError::Invalid(
            "FairPlay daemon installed no message callback",
        ));
    }
    Ok((callback, info))
}

fn fairplay_daemon_message(fairplay: &SharedRuntime, message: &[u8]) -> MachineResult<Vec<u8>> {
    let mut fairplay = borrow(fairplay)?;
    let (callback, info) = port_callback(&fairplay)?;
    fairplay.begin_call();
    let result = (|| {
        let address = fairplay.scratch_bytes(message)?;
        let length = message.len() as u64;
        fairplay.invoke(callback, &[FAKE_HANDLE, address, length, info])?;
        fairplay.read_bytes(address, length)
    })();
    fairplay.clear_scratch();
    result
}

fn fair_play_handler(router: &Rc<FairPlayRouter>) -> Rc<FairPlayHandler> {
    let router = Rc::clone(router);
    Rc::new(move |request: FairPlayRequest| router.message(&request).map_err(EmuError::guest))
}

fn mach_rpc_handler(router: &Rc<FairPlayRouter>) -> Rc<MachRpcHandler> {
    let router = Rc::clone(router);
    Rc::new(move |request: &[u8], receive_size: usize| {
        router
            .mach_rpc(request, receive_size)
            .map_err(EmuError::guest)
    })
}

fn open_profile(
    bundle: &Bundle,
    environment: &GuestEnvironment,
    image: ExtraImage<'_>,
    pause_run_loop: bool,
) -> MachineResult<SharedRuntime> {
    let options = RuntimeOptions {
        extra: Some(image),
        zero_return_aliases: &[],
        pause_run_loop,
    };
    Ok(Rc::new(RefCell::new(GuestRuntime::open(
        bundle,
        environment,
        &options,
    )?)))
}

fn placed<'b>(
    name: &'static str,
    data: &'b [u8],
    base: u64,
    kernel_base: Option<u64>,
) -> ExtraImage<'b> {
    ExtraImage {
        name,
        data,
        placement: ImagePlacement { base, kernel_base },
    }
}

/// The four ADI guests and the daemon's XPC request handler.
pub struct ModernAdi {
    runtime: SharedRuntime,
    daemon: SharedRuntime,
    fairplay: SharedRuntime,
    kernel: Option<SharedRuntime>,
    router: Rc<FairPlayRouter>,
    daemon_handler: u64,
    store_global: Option<u32>,
}

impl ModernAdi {
    /// Starts the guests for host UUID `identifier`, restoring the `adi.pb`
    /// provisioning `state` when non-empty.
    ///
    /// # Errors
    /// Fails on a malformed identifier or when a guest fails to start.
    pub fn open(
        bundle: &Bundle,
        environment: &GuestEnvironment,
        identifier: &[u8],
        state: &[u8],
    ) -> MachineResult<Self> {
        let uuid: [u8; HOST_UUID_SIZE] = identifier
            .try_into()
            .map_err(|_| MachineError::Invalid("modern ADI host UUID must be 16 bytes"))?;
        let mut adi = Self::open_guests(bundle, environment)?;
        for runtime in adi.guests() {
            borrow(&runtime)?.with_state(|shims| shims.host_uuid = uuid)?;
        }
        if !state.is_empty() {
            borrow(&adi.daemon)?.with_state(|shims| {
                shims
                    .files
                    .adi
                    .insert(ADI_STATE_PATH.to_owned(), state.to_vec());
            })?;
        }
        adi.start_services()?;
        Ok(adi)
    }

    fn open_guests(bundle: &Bundle, environment: &GuestEnvironment) -> MachineResult<Self> {
        let runtime = Rc::new(RefCell::new(open_commerce_runtime(bundle, environment)?));
        let adid = placed("adid", &bundle.adid, ADID_BASE, None);
        let daemon = open_profile(bundle, environment, adid, true)?;
        let fairplayd = placed("fairplayd", &bundle.fairplayd, FAIRPLAYD_BASE, None);
        let fairplay = open_profile(bundle, environment, fairplayd, true)?;
        let kernel = if bundle.fairplay_kext.is_empty() {
            None
        } else {
            let kext = placed(
                "FairPlayIOKit",
                &bundle.fairplay_kext,
                KEXT_BASE,
                Some(KERNEL_COLLECTION_BASE),
            );
            Some(open_profile(bundle, environment, kext, false)?)
        };
        let router = Rc::new(FairPlayRouter {
            fairplay: Rc::downgrade(&fairplay),
            kernel: kernel.as_ref().map(Rc::downgrade),
            kernel_context: Cell::new(0),
        });
        Ok(Self {
            runtime,
            daemon,
            fairplay,
            kernel,
            router,
            daemon_handler: 0,
            store_global: None,
        })
    }

    fn guests(&self) -> Vec<SharedRuntime> {
        let mut guests = vec![
            Rc::clone(&self.runtime),
            Rc::clone(&self.daemon),
            Rc::clone(&self.fairplay),
        ];
        guests.extend(self.kernel.iter().cloned());
        guests
    }

    fn start_services(&mut self) -> MachineResult<()> {
        if let Some(kernel) = &self.kernel {
            let handler = mach_rpc_handler(&self.router);
            borrow(kernel)?.with_state(|shims| shims.handlers.mach_rpc = Some(handler))?;
            self.initialize_kernel(kernel)?;
        }
        let handler = fair_play_handler(&self.router);
        let install = |runtime: &SharedRuntime| {
            let handler = Rc::clone(&handler);
            borrow(runtime)?.with_state(|shims| shims.handlers.fair_play = Some(handler))
        };
        install(&self.fairplay)?;
        borrow(&self.fairplay)?.invoke(FAIRPLAYD_ENTRY, &[0, 0, 0])?;
        install(&self.daemon)?;
        install(&self.runtime)?;
        self.initialize_daemon()
    }

    fn initialize_kernel(&self, kernel: &SharedRuntime) -> MachineResult<()> {
        let mut kernel = borrow(kernel)?;
        kernel.begin_call();
        let result = (|| {
            kernel.invoke(KEXT_START, &[])?;
            kernel.invoke_checked("set up FairPlay kernel", KEXT_SETUP, &[])?;
            let output = kernel.scratch_field(POINTER_FIELD_SIZE)?;
            let task = kernel.with_state(|shims| shims.allocate(KERNEL_TASK_SIZE as u64))??;
            kernel.engine().mem_write(task, &[0; KERNEL_TASK_SIZE])?;
            kernel.invoke_checked(
                "initialize FairPlay kernel session",
                KEXT_INIT,
                &[0, output, 0, task],
            )?;
            kernel.read_u64(output)
        })();
        kernel.clear_scratch();
        match result? {
            0 => Err(MachineError::Invalid(
                "FairPlay kernel returned no session context",
            )),
            context => {
                self.router.kernel_context.set(context);
                Ok(())
            }
        }
    }

    fn initialize_daemon(&mut self) -> MachineResult<()> {
        let entry = borrow(&self.daemon)?.invoke(ADID_ENTRY, &[0, 0, 0, 0]);
        let listener = self.daemon_state(|shims| shims.xpc.event_handler)?;
        if listener == 0 {
            entry?;
            return Err(MachineError::Invalid(
                "ADI daemon installed no XPC listener",
            ));
        }
        let connection = self.daemon_state(|shims| shims.xpc.new_object(None))?;
        self.invoke_daemon_block(listener, connection)?;
        let handler = self.daemon_state(|shims| shims.xpc.event_handler)?;
        if handler == listener {
            return Err(MachineError::Invalid(
                "ADI daemon did not install a request handler",
            ));
        }
        self.daemon_handler = handler;
        Ok(())
    }

    fn daemon_state<T>(
        &self,
        action: impl FnOnce(&mut super::shims::ShimState) -> T,
    ) -> MachineResult<T> {
        borrow(&self.daemon)?.with_state(action)
    }

    fn invoke_daemon_block(&self, block: u64, argument: u64) -> MachineResult<()> {
        let mut daemon = borrow(&self.daemon)?;
        let handler = daemon.read_u64(block + BLOCK_INVOKE_OFFSET)?;
        daemon.invoke(handler, &[block, argument])?;
        Ok(())
    }

    /// Sends an opaque `com.apple.adid` request payload to the daemon and
    /// returns its reply payload.
    ///
    /// # Errors
    /// Fails on an empty or oversized request, a daemon fault or no reply.
    pub fn exchange_xpc(&mut self, request: &[u8]) -> MachineResult<Vec<u8>> {
        if request.is_empty() || request.len() > MAX_XPC_PAYLOAD {
            return Err(MachineError::Invalid("ADI XPC request is invalid"));
        }
        let object = self.daemon_state(|shims| {
            shims.xpc.reply.clear();
            shims.xpc.replied = false;
            shims.xpc.new_object(Some(request))
        })?;
        self.invoke_daemon_block(self.daemon_handler, object)?;
        let (replied, reply) =
            self.daemon_state(|shims| (shims.xpc.replied, std::mem::take(&mut shims.xpc.reply)))?;
        if !replied || reply.is_empty() {
            return Err(MachineError::Invalid("ADI daemon returned no reply"));
        }
        Ok(reply)
    }

    /// Runs a client entry point twice: once to capture its XPC request, then
    /// again with the daemon's reply queued, returning the second result.
    fn invoke_client(&mut self, function: u64, arguments: &[u64]) -> MachineResult<u64> {
        let first = {
            let mut runtime = borrow(&self.runtime)?;
            runtime.with_state(|shims| {
                shims.xpc.data.clear();
                shims.xpc.sync_reply = None;
            })?;
            runtime.invoke(function, arguments)
        };
        let request = borrow(&self.runtime)?.with_state(|shims| shims.xpc.data.clone())?;
        if request.is_empty() {
            first?;
            return Err(MachineError::Invalid(
                "ADI client created no daemon request",
            ));
        }
        let reply = self.exchange_xpc(&request)?;
        let mut runtime = borrow(&self.runtime)?;
        runtime.with_state(|shims| shims.xpc.sync_reply = Some(reply))?;
        runtime.invoke(function, arguments)
    }

    /// Runs `body` inside one client call frame (scratch reset before and after).
    fn client_call<T>(
        &mut self,
        body: impl FnOnce(&mut Self) -> MachineResult<T>,
    ) -> MachineResult<T> {
        borrow(&self.runtime)?.begin_call();
        let result = body(self);
        borrow(&self.runtime)?.clear_scratch();
        result
    }

    fn client_status(
        &mut self,
        operation: &'static str,
        function: u64,
        arguments: &[u64],
    ) -> MachineResult<()> {
        let status = status_of(self.invoke_client(function, arguments)?);
        if status != 0 {
            return Err(MachineError::Status { operation, status });
        }
        Ok(())
    }

    /// Starts machine provisioning for `dsid` with GSA's `spim`.
    ///
    /// # Errors
    /// Fails on a guest fault or a non-zero status.
    pub fn start_provisioning(
        &mut self,
        dsid: u64,
        spim: &[u8],
    ) -> MachineResult<ProvisioningStart> {
        self.client_call(|adi| {
            let (input, pointer, length, session) = {
                let mut runtime = borrow(&adi.runtime)?;
                (
                    runtime.scratch_bytes(spim)?,
                    runtime.scratch_field(POINTER_FIELD_SIZE)?,
                    runtime.scratch_field(LENGTH_FIELD_SIZE)?,
                    runtime.scratch_field(LENGTH_FIELD_SIZE)?,
                )
            };
            let arguments = [dsid, input, spim.len() as u64, pointer, length, session];
            adi.client_status("start ADI provisioning", ADI_START_ENTRY, &arguments)?;
            let runtime = borrow(&adi.runtime)?;
            Ok(ProvisioningStart {
                cpim: read_output(&runtime, pointer, length)?,
                session: runtime.read_u32(session)?,
            })
        })
    }

    /// Finishes provisioning with GSA's `ptm` (setting info) and `tk`
    /// (transport key).
    ///
    /// # Errors
    /// Fails on a guest fault or a non-zero status.
    pub fn end_provisioning(
        &mut self,
        session: u32,
        setting_info: &[u8],
        transport_key: &[u8],
    ) -> MachineResult<()> {
        self.client_call(|adi| {
            let (setting, key) = {
                let mut runtime = borrow(&adi.runtime)?;
                (
                    runtime.scratch_bytes(setting_info)?,
                    runtime.scratch_bytes(transport_key)?,
                )
            };
            let arguments = [
                u64::from(session),
                setting,
                setting_info.len() as u64,
                key,
                transport_key.len() as u64,
            ];
            adi.client_status("finish ADI provisioning", ADI_END_ENTRY, &arguments)
        })
    }

    /// Requests the machine identifier and a one-time password for `dsid`.
    ///
    /// # Errors
    /// Fails on a guest fault or a non-zero status (`-45061` when `dsid` is
    /// not provisioned).
    pub fn request_otp(&mut self, dsid: u64) -> MachineResult<AdiOtp> {
        self.client_call(|adi| {
            let fields = {
                let mut runtime = borrow(&adi.runtime)?;
                [
                    runtime.scratch_field(POINTER_FIELD_SIZE)?,
                    runtime.scratch_field(LENGTH_FIELD_SIZE)?,
                    runtime.scratch_field(POINTER_FIELD_SIZE)?,
                    runtime.scratch_field(LENGTH_FIELD_SIZE)?,
                ]
            };
            let [mid_pointer, mid_length, otp_pointer, otp_length] = fields;
            let arguments = [dsid, mid_pointer, mid_length, otp_pointer, otp_length];
            adi.client_status("request ADI OTP", ADI_OTP_ENTRY, &arguments)?;
            let runtime = borrow(&adi.runtime)?;
            Ok(AdiOtp {
                mid: read_output(&runtime, mid_pointer, mid_length)?,
                otp: read_output(&runtime, otp_pointer, otp_length)?,
            })
        })
    }

    /// Builds `X-Apple-AMD` / `X-Apple-AMD-M` from the OTP for DSID `-1`.
    /// DSID `-1` must have been provisioned by the Store "SP" action first.
    ///
    /// # Errors
    /// See [`ModernAdi::request_otp`].
    pub fn store_amd_headers(&mut self) -> MachineResult<StoreAmdHeaders> {
        Ok(StoreAmdHeaders::from(&self.request_otp(STORE_AMD_DSID)?))
    }

    /// Imports a Store keybag into a `FairPlay` global context of the client.
    ///
    /// # Errors
    /// Fails on an invalid identifier, a guest fault or a non-zero status.
    pub fn import_key_bag(&mut self, hardware_id: &[u8], key_bag: &[u8]) -> MachineResult<()> {
        let hardware = hardware_block(hardware_id)?;
        let mut runtime = borrow(&self.runtime)?;
        runtime.begin_call();
        let result = (|| -> MachineResult<u32> {
            let global = initialize_global_in_call(&mut runtime, &hardware)?;
            let address = runtime.scratch_bytes(key_bag)?;
            let arguments = [u64::from(global), address, key_bag.len() as u64];
            runtime.invoke_checked("import FairPlay keybag", KEY_BAG_ENTRY, &arguments)?;
            Ok(global)
        })();
        runtime.clear_scratch();
        drop(runtime);
        self.store_global = Some(result?);
        Ok(())
    }

    /// The daemon's persisted `adi.pb` provisioning state.
    ///
    /// # Errors
    /// Fails when no state has been written yet.
    pub fn state(&self) -> MachineResult<Vec<u8>> {
        let state = self.daemon_state(|shims| {
            let files = &shims.files.adi;
            files
                .get(ADI_STATE_PATH)
                .filter(|state| !state.is_empty())
                .or_else(|| {
                    files
                        .iter()
                        .find(|(path, state)| {
                            path.ends_with(ADI_STATE_FILE_NAME) && !state.is_empty()
                        })
                        .map(|(_, state)| state)
                })
                .cloned()
        })?;
        state.ok_or(MachineError::Invalid("modern ADI state was not created"))
    }

    /// Releases the imported keybag context, if any.
    ///
    /// # Errors
    /// Fails when the guest destructor fails.
    pub fn close(mut self) -> MachineResult<()> {
        self.release_key_bag()
    }

    fn release_key_bag(&mut self) -> MachineResult<()> {
        match self.store_global.take() {
            Some(global) => close_global(&mut *borrow(&self.runtime)?, global),
            None => Ok(()),
        }
    }
}

impl Drop for ModernAdi {
    fn drop(&mut self) {
        // Best effort: the emulators are discarded right after.
        let _ = self.release_key_bag();
    }
}

fn read_output(
    runtime: &GuestRuntime,
    pointer_field: u64,
    length_field: u64,
) -> MachineResult<Vec<u8>> {
    let pointer = runtime.read_u64(pointer_field)?;
    let length = runtime.read_u32(length_field)?;
    if pointer == 0 || length == 0 || length > MAX_ADI_OUTPUT {
        return Err(MachineError::Invalid("modern ADI returned invalid output"));
    }
    runtime.read_bytes(pointer, u64::from(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_amd_headers_are_base64_of_otp_and_mid() {
        let otp = AdiOtp {
            mid: vec![1, 2, 3],
            otp: vec![0xff],
        };
        let headers = StoreAmdHeaders::from(&otp);
        assert_eq!(headers.amd, "/w==");
        assert_eq!(headers.amd_m, "AQID");
    }

    #[test]
    fn special_dsids_are_minus_one_and_minus_two() {
        assert_eq!(STORE_AMD_DSID.cast_signed(), -1);
        assert_eq!(MACHINE_PROVISIONING_DSID.cast_signed(), -2);
    }
}

#[cfg(test)]
mod golden_tests {
    use super::*;
    use crate::infrastructure::apple_sap::machine::sap::test_support::{
        ALTERNATE_SEED, FIXED_UNIX_TIME, PRIMARY_SEED, SeededHost, bundle, environment, fixture,
        hex_at,
    };

    fn identifier(golden: &serde_json::Value) -> Vec<u8> {
        hex_at(golden, "/identifier_hex")
    }

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn provisioning_reproduces_golden_vectors() {
        let golden = fixture("adi.json");
        let host = SeededHost::new(PRIMARY_SEED);
        let mut adi =
            ModernAdi::open(&bundle(), &environment(&host), &identifier(&golden), &[]).unwrap();
        let start = adi
            .start_provisioning(
                MACHINE_PROVISIONING_DSID,
                &hex_at(&golden, "/start_provisioning/spim_hex"),
            )
            .unwrap();
        assert_eq!(
            hex::encode(&start.cpim),
            golden["start_provisioning"]["cpim_hex"].as_str().unwrap()
        );
        assert_eq!(
            u64::from(start.session),
            golden["start_provisioning"]["session"].as_u64().unwrap()
        );
        adi.end_provisioning(
            start.session,
            &hex_at(&golden, "/end_provisioning/ptm_hex"),
            &hex_at(&golden, "/end_provisioning/tk_hex"),
        )
        .unwrap();
        let otp = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();
        assert_eq!(otp.mid, hex_at(&golden, "/request_otp/mid_hex"));
        assert_eq!(otp.otp, hex_at(&golden, "/request_otp/otp_hex"));
        assert_eq!(adi.state().unwrap(), hex_at(&golden, "/adi_state_hex"));
        adi.close().unwrap();
    }

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn store_amd_matches_golden_headers() {
        let golden = fixture("amd.json");
        let state = hex_at(&fixture("adi.json"), "/adi_state_hex");
        let host = SeededHost::new(PRIMARY_SEED);
        let mut adi =
            ModernAdi::open(&bundle(), &environment(&host), &identifier(&golden), &state).unwrap();
        host.freeze(PRIMARY_SEED, FIXED_UNIX_TIME);
        let error = adi.store_amd_headers().unwrap_err();
        assert!(
            matches!(error, MachineError::Status { status: -45061, .. }),
            "{error}"
        );
        let direct = hex_at(&golden, "/direct_reply/request_hex");
        assert_eq!(
            adi.exchange_xpc(&direct).unwrap(),
            hex_at(&golden, "/direct_reply/reply_hex")
        );
        let otp = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();
        let headers = StoreAmdHeaders::from(&otp);
        let expected = &golden["rewritten_dsid_minus2"]["headers"];
        assert_eq!(headers.amd, expected["X-Apple-AMD"].as_str().unwrap());
        assert_eq!(headers.amd_m, expected["X-Apple-AMD-M"].as_str().unwrap());
    }

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn start_provisioning_follows_the_alternate_seed() {
        let golden = fixture("adi.json");
        let host = SeededHost::new(ALTERNATE_SEED);
        let environment = environment(&host);
        let mut adi = ModernAdi::open(&bundle(), &environment, &identifier(&golden), &[]).unwrap();
        let spim = hex_at(&golden, "/start_provisioning/spim_hex");
        let start = adi
            .start_provisioning(MACHINE_PROVISIONING_DSID, &spim)
            .unwrap();
        assert_eq!(start.cpim, hex_at(&golden, "/alt_seed/cpim_hex"));
        let session = golden["alt_seed"]["session"].as_u64().unwrap();
        assert_eq!(u64::from(start.session), session);
    }

    // ---- Dynamic instrumentation probe (native-reproduction feasibility) ----
    // Question: is the ADI OTP a pure function of (adi_state, time), or does it
    // consume fresh host entropy per request? Wraps the host to count random
    // draws per phase and replays request_otp under advanced / re-frozen RNG.
    use crate::infrastructure::apple_sap::machine::shims::HostEnvironment as HostEnv;

    struct CountingHost {
        inner: Rc<SeededHost>,
        phase: Cell<&'static str>,
        draws: RefCell<Vec<(&'static str, usize)>>,
    }

    impl HostEnv for CountingHost {
        fn now(&self) -> std::time::SystemTime {
            self.inner.now()
        }
        fn fill_random(&self, buffer: &mut [u8]) {
            self.inner.fill_random(buffer);
            self.draws
                .borrow_mut()
                .push((self.phase.get(), buffer.len()));
        }
    }

    #[test]
    #[allow(clippy::many_single_char_names)]
    #[ignore = "instrumentation: needs the cached Apple SAP assets"]
    fn otp_entropy_and_determinism_probe() {
        let golden = fixture("adi.json");
        let state = hex_at(&golden, "/adi_state_hex");
        let id = identifier(&golden);

        // One FRESH ADI session per request (the OTP flow is one-shot per
        // client session). Returns (otp, mid, bytes drawn DURING the otp call,
        // bytes drawn during open).
        let run = |seed: &[u8], unix: u64| -> (Vec<u8>, Vec<u8>, usize, usize) {
            let host = Rc::new(CountingHost {
                inner: SeededHost::new(seed),
                phase: Cell::new("open"),
                draws: RefCell::new(Vec::new()),
            });
            host.inner.freeze(seed, unix);
            let env = GuestEnvironment {
                host: Rc::clone(&host) as Rc<dyn HostEnv>,
                preparation_cache:
                    crate::infrastructure::apple_sap::macho::PreparationCache::default_location(),
            };
            let mut adi = ModernAdi::open(&bundle(), &env, &id, &state).unwrap();
            host.phase.set("otp");
            let otp = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();
            let _ = adi.close();
            let d = host.draws.borrow();
            let sum = |p: &str| {
                d.iter()
                    .filter(|(ph, _)| *ph == p)
                    .map(|(_, n)| *n)
                    .sum::<usize>()
            };
            (otp.otp, otp.mid, sum("otp"), sum("open"))
        };

        let t = FIXED_UNIX_TIME;
        let a = run(PRIMARY_SEED, t); // baseline
        let b = run(PRIMARY_SEED, t); // same seed+time  -> determinism control
        let c = run(ALTERNATE_SEED, t); // different RNG  -> random dependence
        let e = run(PRIMARY_SEED, t + 86_400); // +1 day   -> time dependence

        eprintln!("=== OTP ENTROPY / DETERMINISM PROBE (fresh session per run) ===");
        eprintln!(
            "  entropy DURING otp call: a={} b={} c={} e={} bytes",
            a.2, b.2, c.2, e.2
        );
        eprintln!("  entropy during open:     a={} bytes", a.3);
        eprintln!("  otp(seed1,t)    = {}", hex::encode(&a.0));
        eprintln!("  otp(seed1,t)    = {}  [repeat]", hex::encode(&b.0));
        eprintln!("  otp(seed2,t)    = {}  [diff RNG]", hex::encode(&c.0));
        eprintln!("  otp(seed1,t+1d) = {}  [diff time]", hex::encode(&e.0));
        eprintln!("  mid(seed1,t)    = {}", hex::encode(&a.1));
        eprintln!("  --- interpretation ---");
        eprintln!("  deterministic (same inputs -> same otp): {}", a.0 == b.0);
        eprintln!("  depends on RNG draw (seed changes otp):  {}", a.0 != c.0);
        eprintln!("  depends on time     (time changes otp):  {}", a.0 != e.0);
        eprintln!("  otp consumes host entropy per request:   {}", a.2 > 0);

        assert_eq!(
            a.0, b.0,
            "OTP must be deterministic for identical (state, seed, time)"
        );
    }

    #[test]
    #[ignore = "instrumentation: needs the cached Apple SAP assets"]
    fn otp_time_window_probe() {
        let golden = fixture("adi.json");
        let state = hex_at(&golden, "/adi_state_hex");
        let id = identifier(&golden);
        let otp_at = |unix: u64| -> Vec<u8> {
            let host = SeededHost::new(PRIMARY_SEED);
            host.freeze(PRIMARY_SEED, unix);
            let env = GuestEnvironment {
                host: Rc::clone(&host) as Rc<dyn HostEnv>,
                preparation_cache:
                    crate::infrastructure::apple_sap::macho::PreparationCache::default_location(),
            };
            let mut adi = ModernAdi::open(&bundle(), &env, &id, &state).unwrap();
            let otp = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();
            let _ = adi.close();
            otp.otp[8..24].to_vec() // the 16 raw OTP bytes
        };
        let base = FIXED_UNIX_TIME;
        eprintln!("=== OTP TIME-WINDOW PROBE (base={base}) ===");
        let mut prev: Option<(u64, Vec<u8>)> = None;
        for off in [0u64, 10, 15, 20, 25, 29, 30, 45, 59, 60] {
            let t = base + off;
            let otp = otp_at(t);
            let same_as_base = off != 0 && otp == otp_at(base);
            eprintln!(
                "  t=base+{off:<5} (floor/300={:>8}, floor/60={:>9}) otp16={} same_as_base={same_as_base}",
                t / 300,
                t / 60,
                hex::encode(&otp)
            );
            if let Some((po, ref pv)) = prev
                && *pv != otp
            {
                eprintln!("    ^ CHANGED vs t=base+{po}");
            }
            prev = Some((off, otp));
        }
    }

    #[test]
    #[ignore = "instrumentation: needs the cached Apple SAP assets"]
    fn otp_leaf_size_probe() {
        let golden = fixture("adi.json");
        let state = hex_at(&golden, "/adi_state_hex");
        let id = identifier(&golden);
        let host = SeededHost::new(PRIMARY_SEED);
        let env = GuestEnvironment {
            host: Rc::clone(&host) as Rc<dyn HostEnv>,
            preparation_cache:
                crate::infrastructure::apple_sap::macho::PreparationCache::default_location(),
        };
        let mut adi = ModernAdi::open(&bundle(), &env, &id, &state).unwrap();

        let commerce = Rc::new(Cell::new(0u64));
        let daemon = Rc::new(Cell::new(0u64));
        let fairplay = Rc::new(Cell::new(0u64));
        let kernel = Rc::new(Cell::new(0u64));
        let span = Rc::new(Cell::new((u64::MAX, 0u64))); // commerce code extent

        let reg = |rt: &SharedRuntime, c: Rc<Cell<u64>>, sp: Option<Rc<Cell<(u64, u64)>>>| {
            rt.borrow_mut()
                .engine()
                .add_code_hook(0, u64::MAX, move |_e, addr, _s| {
                    c.set(c.get() + 1);
                    if let Some(ref sp) = sp {
                        let (lo, hi) = sp.get();
                        sp.set((lo.min(addr), hi.max(addr)));
                    }
                    Ok(())
                })
                .unwrap();
        };
        reg(&adi.runtime, Rc::clone(&commerce), Some(Rc::clone(&span)));
        reg(&adi.daemon, Rc::clone(&daemon), None);
        reg(&adi.fairplay, Rc::clone(&fairplay), None);
        if let Some(ref k) = adi.kernel {
            reg(k, Rc::clone(&kernel), None);
        }

        let otp = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();

        let (lo, hi) = span.get();
        let total = commerce.get() + daemon.get() + fairplay.get() + kernel.get();
        eprintln!("=== OTP LEAF-SIZE PROBE (instructions per guest during ONE request_otp) ===");
        eprintln!(
            "  commerce : {:>9} insns   code span [{lo:#x}..{hi:#x}] = {} bytes",
            commerce.get(),
            hi.saturating_sub(lo)
        );
        eprintln!("  adid     : {:>9} insns", daemon.get());
        eprintln!("  fairplayd: {:>9} insns", fairplay.get());
        eprintln!("  kext     : {:>9} insns", kernel.get());
        eprintln!("  TOTAL    : {total:>9} insns");
        eprintln!("  otp16 = {}", hex::encode(&otp.otp[8..24]));
    }

    #[test]
    #[allow(clippy::similar_names)]
    #[ignore = "instrumentation: needs the cached Apple SAP assets"]
    fn otp_opcode_histogram_probe() {
        use std::collections::HashMap;
        let golden = fixture("adi.json");
        let state = hex_at(&golden, "/adi_state_hex");
        let id = identifier(&golden);
        let host = SeededHost::new(PRIMARY_SEED);
        let env = GuestEnvironment {
            host: Rc::clone(&host) as Rc<dyn HostEnv>,
            preparation_cache:
                crate::infrastructure::apple_sap::macho::PreparationCache::default_location(),
        };
        let mut adi = ModernAdi::open(&bundle(), &env, &id, &state).unwrap();

        // Decode each executed instruction into its mnemonic and histogram it —
        // the dynamic opcode distribution of the real ~6.7M-insn OTP hot path,
        // confirming the static r2 histogram and bounding the interpreter's ISA.
        let hist: Rc<RefCell<HashMap<&'static str, u64>>> = Rc::new(RefCell::new(HashMap::new()));
        let reg = |rt: &SharedRuntime| {
            let h = Rc::clone(&hist);
            rt.borrow_mut()
                .engine()
                .add_code_hook(0, u64::MAX, move |engine, addr, _size| {
                    if let Ok(word) = engine.read_u32(addr) {
                        let mnem = crate::infrastructure::apple_sap::emu::decode::mnemonic(word);
                        *h.borrow_mut().entry(mnem).or_insert(0) += 1;
                    }
                    Ok(())
                })
                .unwrap();
        };
        reg(&adi.runtime);
        reg(&adi.daemon);
        reg(&adi.fairplay);
        if let Some(ref k) = adi.kernel {
            reg(k);
        }

        let _ = adi.request_otp(MACHINE_PROVISIONING_DSID).unwrap();

        let map = hist.borrow();
        let total: u64 = map.values().sum();
        let mut rows: Vec<(&&'static str, &u64)> = map.iter().collect();
        rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        eprintln!("=== OTP DYNAMIC OPCODE HISTOGRAM (one request_otp) ===");
        eprintln!(
            "  total instructions: {total}  distinct mnemonics: {}",
            map.len()
        );
        for (mnem, count) in rows.iter().take(70) {
            eprintln!("  {count:>10}  {mnem}");
        }
    }
}
