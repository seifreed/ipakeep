//! In-memory file system: the ADI state file and the read-only `CoreFP.icxs`.

use super::call::{ShimCall, checked_size};
use super::error::ShimError;
use super::memory::MINUS_ONE;
use super::state::{ADI_STATE_PATH, GuestFiles};

/// Descriptor of the open `CoreFP.icxs`.
const CORE_FP_DESCRIPTOR: u64 = 3;
/// Descriptor returned for the virtual directories.
const DIRECTORY_DESCRIPTOR: u64 = 4;
/// Descriptor of the open ADI state file.
const ADI_DESCRIPTOR: u64 = 5;
/// Path `CoreFP` opens its `ICXS` blob from.
const ICXS_PATH: &[u8] = b"./../CoreFP.icxs";
/// Directories that exist in the virtual file system.
const DIRECTORIES: [&[u8]; 3] = [b"/var/db/fpsd/adi", b"/var/db", b"/var/setup"];
/// Directories `open` succeeds on.
const OPENABLE_DIRECTORIES: [&[u8]; 2] = [b"/var/db", b"/var/setup"];
/// Darwin `O_CREAT`.
const O_CREAT: u64 = 0x200;
/// Offset of `st_mode` in Darwin's `struct stat`.
const STAT_MODE_OFFSET: u64 = 4;
/// Offset of `st_size` in Darwin's `struct stat`.
const STAT_SIZE_OFFSET: u64 = 96;
/// Size of Darwin's `struct stat`.
const STAT_SIZE: u64 = 144;
/// `S_IFDIR | 0755`.
const DIRECTORY_MODE: u16 = 0o40755;
/// `S_IFREG | 0600`.
const FILE_MODE: u16 = 0o100_600;
/// Largest length `ftruncate` accepts.
const TRUNCATE_LIMIT: u64 = 1 << 20;

fn is_adi_state_path(path: &[u8]) -> bool {
    path == ADI_STATE_PATH.as_bytes()
}

fn path_key(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}

pub(super) fn lstat(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let path = call.read_c_string(call.arg(0)?)?;
    let is_directory = DIRECTORIES.contains(&path.as_slice());
    let is_file = call.state()?.files.adi.contains_key(&path_key(&path));
    let exists = is_directory || (is_adi_state_path(&path) && is_file);
    if !exists {
        return call.set_result(MINUS_ONE);
    }
    let mode = if is_file { FILE_MODE } else { DIRECTORY_MODE };
    let result = call.arg(1)?;
    call.write_bytes(result + STAT_MODE_OFFSET, &mode.to_le_bytes())?;

    call.set_result(0)
}

pub(super) fn open(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let path = call.read_c_string(call.arg(0)?)?;
    let flags = call.arg(1)?;
    if OPENABLE_DIRECTORIES.contains(&path.as_slice()) {
        return call.set_result(DIRECTORY_DESCRIPTOR);
    }
    let descriptor = {
        let mut state = call.state()?;
        open_file(&mut state.files, &path, flags)
    };

    call.set_result(descriptor)
}

fn open_file(files: &mut GuestFiles, path: &[u8], flags: u64) -> u64 {
    if is_adi_state_path(path) {
        let key = path_key(path);
        if !files.adi.contains_key(&key) {
            if flags & O_CREAT == 0 {
                return MINUS_ONE;
            }
            files.adi.insert(key.clone(), Vec::new());
        }
        files.adi_path = key;
        files.adi_offset = 0;
        return ADI_DESCRIPTOR;
    }
    if path == ICXS_PATH {
        files.icxs_offset = 0;
        return CORE_FP_DESCRIPTOR;
    }

    MINUS_ONE
}

pub(super) fn fstat(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [descriptor, result] = call.args()?;
    if descriptor != ADI_DESCRIPTOR {
        return call.set_result(MINUS_ONE);
    }
    let size = {
        let state = call.state()?;
        let files = &state.files;
        files.adi.get(&files.adi_path).map_or(0, Vec::len) as u64
    };
    call.fill(result, 0, STAT_SIZE)?;
    call.write_bytes(result + STAT_MODE_OFFSET, &FILE_MODE.to_le_bytes())?;
    call.write_u64(result + STAT_SIZE_OFFSET, size)?;

    call.set_result(0)
}

pub(super) fn ftruncate(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [descriptor, length] = call.args()?;
    if descriptor != ADI_DESCRIPTOR || length > TRUNCATE_LIMIT {
        return call.set_result(MINUS_ONE);
    }
    {
        let mut state = call.state()?;
        let files = &mut state.files;
        let length = checked_size(length)?;
        let data = files.adi.entry(files.adi_path.clone()).or_default();
        data.resize(length, 0);
        files.adi_offset = files.adi_offset.min(length);
    }

    call.set_result(0)
}

pub(super) fn read(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [descriptor, buffer, requested] = call.args()?;
    if descriptor != ADI_DESCRIPTOR && descriptor != CORE_FP_DESCRIPTOR {
        return call.set_result(MINUS_ONE);
    }
    let requested = checked_size(requested)?;
    let chunk = {
        let mut state = call.state()?;
        take_chunk(&mut state.files, descriptor == ADI_DESCRIPTOR, requested)
    };
    call.write_bytes(buffer, &chunk)?;

    call.set_result(chunk.len() as u64)
}

/// Reads up to `requested` bytes at the file's offset and advances it.
fn take_chunk(files: &mut GuestFiles, adi: bool, requested: usize) -> Vec<u8> {
    let (data, offset) = if adi {
        let data = files
            .adi
            .get(&files.adi_path)
            .map_or(&[][..], Vec::as_slice);
        (data, &mut files.adi_offset)
    } else {
        (files.icxs.as_slice(), &mut files.icxs_offset)
    };
    let start = (*offset).min(data.len());
    let end = start + requested.min(data.len() - start);
    *offset = end;

    data[start..end].to_vec()
}

pub(super) fn write(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let [descriptor, buffer, requested] = call.args()?;
    if descriptor != ADI_DESCRIPTOR {
        return call.set_result(MINUS_ONE);
    }
    let data = call.read_bytes(buffer, requested)?;
    {
        let mut state = call.state()?;
        let files = &mut state.files;
        let start = files.adi_offset;
        let end = start + data.len();
        let file = files.adi.entry(files.adi_path.clone()).or_default();
        if end > file.len() {
            file.resize(end, 0);
        }
        file[start..end].copy_from_slice(&data);
        files.adi_offset = end;
    }

    call.set_result(data.len() as u64)
}

pub(super) fn unlink(call: &mut ShimCall<'_, '_>) -> Result<(), ShimError> {
    let path = call.read_c_string(call.arg(0)?)?;
    if !is_adi_state_path(&path) {
        return call.set_result(MINUS_ONE);
    }
    {
        let mut state = call.state()?;
        state.files.adi.remove(&path_key(&path));
        state.files.adi_offset = 0;
    }

    call.set_result(0)
}
