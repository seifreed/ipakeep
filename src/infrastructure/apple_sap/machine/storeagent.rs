//! `FairPlay` `StoreAgent` profile of the `commerce` daemon: global context,
//! decryption sessions and chunked stream decryption.
//!
//! Port of upstream ipatool's `internal/sap/machine/storeagent.go`.

use std::io::{ErrorKind, Read, Write};

use super::sap::{
    ExtraImage, GuestEnvironment, GuestRuntime, ImagePlacement, MachineError, MachineResult,
    RuntimeOptions, hardware_block,
};
use crate::infrastructure::apple_sap::assets::bundle::Bundle;

/// Guest base of the `commerce` image.
pub(super) const STORE_AGENT_BASE: u64 = 0x0000_1000_c000_0000;
/// `FairPlay` global-context constructor.
pub(super) const STORE_AGENT_GLOBAL_INIT: u64 = STORE_AGENT_BASE + 0x0013_12fc;
/// kbsync generator.
pub(super) const STORE_AGENT_KBSYNC_ENTRY: u64 = STORE_AGENT_BASE + 0x0019_ae34;
const STORE_AGENT_SESSION_INIT: u64 = STORE_AGENT_BASE + 0x0013_ac60;
const STORE_AGENT_DECRYPT_ENTRY: u64 = STORE_AGENT_BASE + 0x0017_5390;
/// `FairPlay` global-context destructor.
pub(super) const STORE_AGENT_GLOBAL_CLOSE: u64 = STORE_AGENT_BASE + 0x0013_0eb4;
/// Bytes decrypted per guest call.
const STORE_AGENT_CHUNK_SIZE: usize = 0x8000;
/// Virtual path of the `SC Info` keybag directory.
pub(super) const STORE_AGENT_SC_INFO_PATH: &str = "/Users/Shared/SC Info";
/// Imports the `commerce` profile turns into `return 0`.
pub(super) const STORE_AGENT_ZERO_RETURN_ALIASES: &[&str] = &[
    "_pthread_rwlock_rdlock",
    "_pthread_rwlock_rdlock$UNIX2003",
    "_pthread_mutex_init",
    "_pthread_mutex_destroy",
    "_pthread_rwlock_destroy",
];
const CONTEXT_FIELD_SIZE: u64 = 4;
const POINTER_FIELD_SIZE: u64 = 8;

/// Opens a guest running `commerce` in its `StoreAgent` profile.
pub(super) fn open_commerce_runtime(
    bundle: &Bundle,
    environment: &GuestEnvironment,
) -> MachineResult<GuestRuntime> {
    let options = RuntimeOptions {
        extra: Some(ExtraImage {
            name: "commerce",
            data: &bundle.commerce,
            placement: ImagePlacement {
                base: STORE_AGENT_BASE,
                kernel_base: None,
            },
        }),
        zero_return_aliases: STORE_AGENT_ZERO_RETURN_ALIASES,
        pause_run_loop: false,
    };
    GuestRuntime::open(bundle, environment, &options)
}

/// Creates the `FairPlay` global context for `hardware_id` over the virtual
/// `SC Info` directory and returns its handle.
pub(super) fn initialize_global(
    runtime: &mut GuestRuntime,
    hardware_id: &[u8],
) -> MachineResult<u32> {
    let hardware = hardware_block(hardware_id)?;
    runtime.begin_call();
    let result = initialize_global_in_call(runtime, &hardware);
    runtime.clear_scratch();
    result
}

/// Like [`initialize_global`], inside a call frame the caller manages.
pub(super) fn initialize_global_in_call(
    runtime: &mut GuestRuntime,
    hardware: &[u8],
) -> MachineResult<u32> {
    let hardware_address = runtime.scratch_bytes(hardware)?;
    let mut path = STORE_AGENT_SC_INFO_PATH.as_bytes().to_vec();
    path.push(0);
    let path_address = runtime.scratch_bytes(&path)?;
    let context_field = runtime.scratch_field(CONTEXT_FIELD_SIZE)?;
    let arguments = [0, hardware_address, path_address, context_field];
    runtime.invoke_checked(
        "StoreAgent global initialization",
        STORE_AGENT_GLOBAL_INIT,
        &arguments,
    )?;
    match runtime.read_u32(context_field)? {
        0 => Err(MachineError::Invalid(
            "StoreAgent global initialization returned a null context",
        )),
        global => Ok(global),
    }
}

/// Releases a `FairPlay` global context.
pub(super) fn close_global(runtime: &mut GuestRuntime, global: u32) -> MachineResult<()> {
    runtime.invoke_checked(
        "StoreAgent global context close",
        STORE_AGENT_GLOBAL_CLOSE,
        &[u64::from(global)],
    )
}

/// A `commerce` guest with an open `FairPlay` global context and, once
/// [`StoreAgent::open`] succeeds, a decryption session.
pub struct StoreAgent {
    runtime: GuestRuntime,
    global: Option<u32>,
    session: u64,
}

impl StoreAgent {
    /// Opens a decryption session for the app's `dpInfo` (its `sinf` data).
    ///
    /// # Errors
    /// Fails on empty `dp_info`, an invalid identifier or a guest failure.
    pub fn open(
        bundle: &Bundle,
        environment: &GuestEnvironment,
        hardware_id: &[u8],
        dp_info: &[u8],
    ) -> MachineResult<Self> {
        if dp_info.is_empty() {
            return Err(MachineError::Invalid("StoreAgent dpInfo is empty"));
        }
        let mut agent = Self::open_global(bundle, environment, hardware_id)?;
        agent.session = agent.initialize_session(dp_info)?;
        Ok(agent)
    }

    /// Opens the guest and its global context without a session.
    pub(super) fn open_global(
        bundle: &Bundle,
        environment: &GuestEnvironment,
        hardware_id: &[u8],
    ) -> MachineResult<Self> {
        hardware_block(hardware_id)?;
        let mut runtime = open_commerce_runtime(bundle, environment)?;
        let global = initialize_global(&mut runtime, hardware_id)?;
        Ok(Self {
            runtime,
            global: Some(global),
            session: 0,
        })
    }

    /// The guest and its global-context handle.
    pub(super) fn runtime_and_global(&mut self) -> (&mut GuestRuntime, u32) {
        (&mut self.runtime, self.global.unwrap_or_default())
    }

    fn initialize_session(&mut self, dp_info: &[u8]) -> MachineResult<u64> {
        let global = u64::from(self.global.unwrap_or_default());
        let runtime = &mut self.runtime;
        runtime.begin_call();
        let result = (|| {
            let dp_info_address = runtime.scratch_bytes(dp_info)?;
            let session_field = runtime.scratch_field(POINTER_FIELD_SIZE)?;
            let arguments = [global, dp_info_address, dp_info.len() as u64, session_field];
            runtime.invoke_checked(
                "StoreAgent session initialization",
                STORE_AGENT_SESSION_INIT,
                &arguments,
            )?;
            runtime.read_u64(session_field)
        })();
        runtime.clear_scratch();
        match result? {
            0 => Err(MachineError::Invalid(
                "StoreAgent session initialization returned a null session",
            )),
            session => Ok(session),
        }
    }

    /// Decrypts `source` into `destination` in 32 KiB chunks and returns the
    /// number of bytes written.
    ///
    /// # Errors
    /// Fails on I/O errors or a guest failure.
    pub fn decrypt(
        &mut self,
        destination: &mut impl Write,
        source: &mut impl Read,
    ) -> Result<u64, StoreAgentStreamError> {
        let mut buffer = vec![0; STORE_AGENT_CHUNK_SIZE];
        let mut written = 0;
        loop {
            let count = read_full(source, &mut buffer)?;
            if count == 0 {
                return Ok(written);
            }
            let chunk = &mut buffer[..count];
            self.decrypt_chunk(chunk)?;
            destination.write_all(chunk)?;
            written += count as u64;
            if count < STORE_AGENT_CHUNK_SIZE {
                return Ok(written);
            }
        }
    }

    fn decrypt_chunk(&mut self, data: &mut [u8]) -> MachineResult<()> {
        let session = self.session;
        let runtime = &mut self.runtime;
        runtime.begin_call();
        let result = (|| {
            let address = runtime.scratch_bytes(data)?;
            let arguments = [session, address, data.len() as u64, address, 0];
            runtime.invoke_checked(
                "StoreAgent decryption",
                STORE_AGENT_DECRYPT_ENTRY,
                &arguments,
            )?;
            let decrypted = runtime.read_bytes(address, data.len() as u64)?;
            data.copy_from_slice(&decrypted);
            Ok(())
        })();
        runtime.clear_scratch();
        result
    }

    /// Releases the global context.
    ///
    /// # Errors
    /// Fails when the guest destructor fails.
    pub fn close(mut self) -> MachineResult<()> {
        self.close_context()
    }

    fn close_context(&mut self) -> MachineResult<()> {
        self.session = 0;
        match self.global.take() {
            Some(global) => close_global(&mut self.runtime, global),
            None => Ok(()),
        }
    }
}

impl Drop for StoreAgent {
    fn drop(&mut self) {
        // Best effort: the emulator is discarded right after.
        let _ = self.close_context();
    }
}

/// Failure of [`StoreAgent::decrypt`].
#[derive(Debug, thiserror::Error)]
pub enum StoreAgentStreamError {
    /// Reading the source or writing the destination failed.
    #[error("StoreAgent stream I/O: {0}")]
    Io(#[from] std::io::Error),
    /// The guest failed to decrypt a chunk.
    #[error(transparent)]
    Machine(#[from] MachineError),
}

/// Fills `buffer` as far as `source` allows; returns the byte count.
fn read_full(source: &mut impl Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match source.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Yields its data a few bytes at a time.
    struct Trickle(Vec<u8>);

    impl Read for Trickle {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = buffer.len().min(self.0.len()).min(3);
            buffer[..count].copy_from_slice(&self.0[..count]);
            self.0.drain(..count);
            Ok(count)
        }
    }

    #[test]
    fn read_full_collects_short_reads() {
        let mut source = Trickle((0..10).collect());
        let mut buffer = [0; 8];
        assert_eq!(read_full(&mut source, &mut buffer).unwrap(), 8);
        assert_eq!(buffer, [0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(read_full(&mut source, &mut buffer).unwrap(), 2);
        assert_eq!(read_full(&mut source, &mut buffer).unwrap(), 0);
    }

    #[test]
    fn commerce_entry_points_are_inside_the_image_profile() {
        assert_eq!(STORE_AGENT_GLOBAL_INIT, 0x0000_1000_c013_12fc);
        assert_eq!(STORE_AGENT_KBSYNC_ENTRY, 0x0000_1000_c019_ae34);
        assert_eq!(STORE_AGENT_GLOBAL_CLOSE, 0x0000_1000_c013_0eb4);
    }
}
