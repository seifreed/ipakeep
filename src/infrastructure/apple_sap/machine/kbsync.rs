//! Account- and hardware-bound kbsync blob required by the bag's
//! `ent/download` endpoint.
//!
//! Port of upstream ipatool's `internal/sap/machine/kbsync.go`.

use super::sap::{GuestEnvironment, GuestRuntime, MachineError, MachineResult, status_of};
use super::storeagent::{STORE_AGENT_KBSYNC_ENTRY, StoreAgent};
use crate::infrastructure::apple_sap::assets::bundle::Bundle;

const POINTER_FIELD_SIZE: u64 = 8;
/// The guest writes a 32-bit length; a zeroed 64-bit field lets the shared
/// output reader apply its bounds and disposal.
const LENGTH_FIELD_SIZE: u64 = 8;
const KBSYNC_FLAGS: u64 = 0;
const KBSYNC_MODE: u64 = 1;

/// Generates kbsync for account `dsid` on the device `hardware_id`, without
/// opening a decryption session.
///
/// # Errors
/// Fails on a zero DSID, an invalid identifier or a guest failure.
pub fn generate_kbsync(
    bundle: &Bundle,
    environment: &GuestEnvironment,
    hardware_id: &[u8],
    dsid: u64,
) -> MachineResult<Vec<u8>> {
    if dsid == 0 {
        return Err(MachineError::Invalid(
            "kbsync requires a nonzero account DSID",
        ));
    }
    let mut agent = StoreAgent::open_global(bundle, environment, hardware_id)?;
    let blob = {
        let (runtime, global) = agent.runtime_and_global();
        runtime.begin_call();
        let result = request_kbsync(runtime, global, dsid);
        runtime.clear_scratch();
        result?
    };
    agent.close()?;
    if blob.is_empty() {
        return Err(MachineError::Invalid(
            "StoreAgent kbsync returned an empty buffer",
        ));
    }
    Ok(blob)
}

fn request_kbsync(runtime: &mut GuestRuntime, global: u32, dsid: u64) -> MachineResult<Vec<u8>> {
    let pointer_field = runtime.scratch_field(POINTER_FIELD_SIZE)?;
    let length_field = runtime.scratch_field(LENGTH_FIELD_SIZE)?;
    let arguments = [
        u64::from(global),
        dsid,
        KBSYNC_FLAGS,
        KBSYNC_MODE,
        pointer_field,
        length_field,
    ];
    let status = status_of(runtime.invoke(STORE_AGENT_KBSYNC_ENTRY, &arguments)?);
    let output = runtime.consume_output(pointer_field, length_field);
    if status != 0 {
        return Err(MachineError::Status {
            operation: "StoreAgent kbsync",
            status,
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::apple_sap::machine::sap::test_support::{
        ALTERNATE_SEED, PRIMARY_SEED, SeededHost, bundle, environment, fixture, hex_at,
    };

    #[test]
    fn zero_dsid_is_rejected_before_loading_images() {
        let bundle = Bundle {
            apple_media_services: Vec::new(),
            commerce: Vec::new(),
            adid: Vec::new(),
            core_fp: Vec::new(),
            core_fp_icxs: Vec::new(),
            fairplayd: Vec::new(),
            fairplay_kext: Vec::new(),
        };
        let error = generate_kbsync(&bundle, &GuestEnvironment::default(), &[1], 0).unwrap_err();
        assert!(matches!(error, MachineError::Invalid(_)));
    }

    #[test]
    #[ignore = "needs the cached Apple SAP assets"]
    fn kbsync_reproduces_golden_vectors() {
        let golden = fixture("kbsync.json");
        let hardware = hex_at(&golden, "/hardware_id_hex");
        let dsid = golden["dsid"].as_u64().unwrap();
        let bundle = bundle();
        let host = SeededHost::new(PRIMARY_SEED);
        let blob = generate_kbsync(&bundle, &environment(&host), &hardware, dsid).unwrap();
        assert_eq!(hex::encode(blob), golden["kbsync_hex"].as_str().unwrap());
        let alternate = SeededHost::new(ALTERNATE_SEED);
        let blob = generate_kbsync(&bundle, &environment(&alternate), &hardware, dsid).unwrap();
        assert_eq!(
            hex::encode(blob),
            golden["kbsync_alt_seed_hex"].as_str().unwrap()
        );
    }
}
