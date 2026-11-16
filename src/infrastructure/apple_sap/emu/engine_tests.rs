//! Unit tests for the Unicorn status-code mapping.

use unicorn_engine::uc_error;

use super::{EngineErrorCode, code_of, native};

#[test]
fn every_classified_unicorn_status_maps_to_its_code() {
    for (source, code) in [
        (uc_error::MAP, EngineErrorCode::Map),
        (uc_error::READ_UNMAPPED, EngineErrorCode::ReadUnmapped),
        (uc_error::WRITE_UNMAPPED, EngineErrorCode::WriteUnmapped),
        (uc_error::FETCH_UNMAPPED, EngineErrorCode::FetchUnmapped),
        (uc_error::EXCEPTION, EngineErrorCode::Exception),
        (uc_error::INSN_INVALID, EngineErrorCode::InvalidInstruction),
    ] {
        assert_eq!(code_of(source), code, "{source:?}");
    }
}

#[test]
fn unclassified_unicorn_statuses_map_to_other() {
    for source in [uc_error::NOMEM, uc_error::ARG, uc_error::HOOK] {
        assert_eq!(code_of(source), EngineErrorCode::Other, "{source:?}");
    }
    let error = native("emu_start")(uc_error::NOMEM);
    assert_eq!(error.engine_code(), Some(EngineErrorCode::Other));
    assert_eq!(error.to_string(), "engine emu_start failed: engine error");
}
