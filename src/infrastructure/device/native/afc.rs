//! Apple File Conduit (`com.apple.afc`) client, enough to stage an app bundle
//! under `PublicStaging`.
//!
//! Packet layout (libimobiledevice `afc.h`): 40-byte little-endian header
//! `{magic "CFA6LPAA", entire_length, this_length, packet_num, operation}`,
//! then the operation's header data (`this_length - 40` bytes), then an
//! optional payload (`entire_length - this_length` bytes). Failures come back
//! as an `AFC_OP_STATUS` packet whose data is a `u64` error code.

use super::BoxStream;
use super::codec::{MAX_MESSAGE, io_error, read_bytes};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

/// Prefixes a local file system error with the `path` it concerns.
fn path_error(path: &Path) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |error| format!("{}: {error}", path.display())
}

/// lockdownd service name.
pub(crate) const SERVICE: &str = "com.apple.afc";
pub(super) const MAGIC: &[u8; 8] = b"CFA6LPAA";
pub(super) const HEADER_LEN: usize = 40;
/// Bytes per `FILE_WRITE`.
const CHUNK: usize = 1 << 20;

/// AFC operation codes.
pub(super) mod op {
    pub(crate) const STATUS: u64 = 0x01;
    pub(crate) const MAKE_DIR: u64 = 0x09;
    pub(crate) const FILE_OPEN: u64 = 0x0D;
    pub(crate) const FILE_OPEN_RESULT: u64 = 0x0E;
    pub(crate) const FILE_WRITE: u64 = 0x10;
    pub(crate) const FILE_CLOSE: u64 = 0x14;
    pub(crate) const MAKE_LINK: u64 = 0x1C;
    pub(crate) const REMOVE_PATH_AND_CONTENTS: u64 = 0x22;
}

/// `AFC_FOPEN_WRONLY`: create/truncate for writing.
const OPEN_WRITE_ONLY: u64 = 3;
/// `AFC_SYMLINK`.
const LINK_SYMBOLIC: u64 = 2;
pub(super) const OBJECT_NOT_FOUND: u64 = 8;

/// Names of AFC error codes (libimobiledevice `afc_error_t`).
const ERRORS: &[(u64, &str)] = &[
    (1, "unknown error"),
    (7, "invalid argument"),
    (OBJECT_NOT_FOUND, "object not found"),
    (9, "object is a directory"),
    (10, "permission denied"),
    (11, "service not connected"),
    (16, "object exists"),
    (18, "no space left on device"),
    (20, "I/O error"),
];

/// One decoded AFC packet.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Packet {
    pub(super) number: u64,
    pub(super) operation: u64,
    pub(super) data: Vec<u8>,
    pub(super) payload: Vec<u8>,
}

impl Packet {
    pub(super) fn encode(&self) -> Vec<u8> {
        let this_len = (HEADER_LEN + self.data.len()) as u64;
        let mut frame = MAGIC.to_vec();
        for word in [
            this_len + self.payload.len() as u64,
            this_len,
            self.number,
            self.operation,
        ] {
            frame.extend(word.to_le_bytes());
        }
        frame.extend(&self.data);
        frame.extend(&self.payload);
        frame
    }

    pub(super) fn read(stream: &mut dyn Read) -> Result<Self, String> {
        let header = read_bytes(stream, HEADER_LEN, "reading an AFC reply")?;
        let word = |index: usize| {
            let start = 8 + index * 8;
            u64::from_le_bytes(header[start..start + 8].try_into().expect("8-byte field"))
        };
        let (entire, this) = (word(0), word(1));
        let valid = &header[..8] == MAGIC
            && this >= HEADER_LEN as u64
            && entire >= this
            && entire <= MAX_MESSAGE as u64;
        if !valid {
            return Err("malformed AFC packet from the device".to_string());
        }
        Ok(Self {
            number: word(2),
            operation: word(3),
            data: read_bytes(stream, bounded(this) - HEADER_LEN, "reading an AFC reply")?,
            payload: read_bytes(stream, bounded(entire - this), "reading an AFC reply")?,
        })
    }

    /// Status code of an `AFC_OP_STATUS` packet.
    pub(super) fn status(&self) -> Option<u64> {
        let code = self.data.get(..8)?;
        (self.operation == op::STATUS)
            .then(|| u64::from_le_bytes(code.try_into().expect("8 bytes")))
    }
}

/// Lengths already checked against [`MAX_MESSAGE`].
fn bounded(len: u64) -> usize {
    usize::try_from(len).expect("AFC length bounded by MAX_MESSAGE")
}

fn describe(code: u64, what: &str) -> String {
    let name = ERRORS
        .iter()
        .find(|(known, _)| *known == code)
        .map_or("unexpected error", |(_, name)| name);
    format!("AFC {what} failed: {name} (code {code})")
}

fn c_path(path: &str) -> Vec<u8> {
    let mut bytes = path.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

/// An AFC connection.
pub(crate) struct Afc {
    stream: BoxStream,
    packets: u64,
}

impl Afc {
    pub(crate) fn new(stream: BoxStream) -> Self {
        Self { stream, packets: 0 }
    }

    /// Send one request packet and read the device's reply.
    pub(super) fn transact(
        &mut self,
        operation: u64,
        data: Vec<u8>,
        payload: &[u8],
    ) -> Result<Packet, String> {
        let request = Packet {
            number: self.packets,
            operation,
            data,
            payload: payload.to_vec(),
        };
        self.packets += 1;
        self.stream
            .write_all(&request.encode())
            .map_err(|error| io_error("sending an AFC request", &error))?;
        Packet::read(&mut self.stream)
    }

    /// Perform `operation` and return its status code.
    fn status(
        &mut self,
        operation: u64,
        data: Vec<u8>,
        payload: &[u8],
        what: &str,
    ) -> Result<u64, String> {
        self.transact(operation, data, payload)?
            .status()
            .ok_or_else(|| format!("AFC {what}: unexpected reply"))
    }

    fn expect_ok(
        &mut self,
        operation: u64,
        data: Vec<u8>,
        payload: &[u8],
        what: &str,
    ) -> Result<(), String> {
        match self.status(operation, data, payload, what)? {
            0 => Ok(()),
            code => Err(describe(code, what)),
        }
    }

    /// Create `path` (succeeds if it already exists).
    pub(crate) fn make_dir(&mut self, path: &str) -> Result<(), String> {
        self.expect_ok(op::MAKE_DIR, c_path(path), &[], &format!("mkdir {path}"))
    }

    /// Remove `path` recursively; a missing path is not an error.
    pub(crate) fn remove_all(&mut self, path: &str) -> Result<(), String> {
        let what = format!("remove {path}");
        match self.status(op::REMOVE_PATH_AND_CONTENTS, c_path(path), &[], &what)? {
            0 | OBJECT_NOT_FOUND => Ok(()),
            code => Err(describe(code, &what)),
        }
    }

    fn symlink(&mut self, target: &str, link: &str) -> Result<(), String> {
        let mut data = LINK_SYMBOLIC.to_le_bytes().to_vec();
        data.extend(c_path(target));
        data.extend(c_path(link));
        self.expect_ok(op::MAKE_LINK, data, &[], &format!("symlink {link}"))
    }

    /// Copy the local file `local` to `remote` (created or truncated).
    pub(super) fn write_file(&mut self, local: &Path, remote: &str) -> Result<(), String> {
        let mut file = fs::File::open(local).map_err(path_error(local))?;
        let mut data = OPEN_WRITE_ONLY.to_le_bytes().to_vec();
        data.extend(c_path(remote));
        let what = format!("open {remote}");
        let reply = self.transact(op::FILE_OPEN, data, &[])?;
        let handle = match (reply.operation, reply.data.get(..8)) {
            (op::FILE_OPEN_RESULT, Some(handle)) => handle.to_vec(),
            _ => {
                return Err(reply.status().map_or_else(
                    || format!("AFC {what}: unexpected reply"),
                    |code| describe(code, &what),
                ));
            }
        };
        let mut buffer = vec![0; CHUNK];
        loop {
            let read = file.read(&mut buffer).map_err(path_error(local))?;
            if read == 0 {
                break;
            }
            self.expect_ok(
                op::FILE_WRITE,
                handle.clone(),
                &buffer[..read],
                &format!("write {remote}"),
            )?;
        }
        self.expect_ok(op::FILE_CLOSE, handle, &[], &format!("close {remote}"))
    }

    /// Mirror the local directory `local` (files, directories, symlinks) to `remote`.
    pub(crate) fn upload_dir(&mut self, local: &Path, remote: &str) -> Result<(), String> {
        self.make_dir(remote)?;
        let mut entries = fs::read_dir(local)
            .and_then(Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(path_error(local))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let target = format!("{remote}/{}", entry.file_name().to_string_lossy());
            let kind = entry.file_type().map_err(path_error(&path))?;
            if kind.is_symlink() {
                let link = fs::read_link(&path).map_err(path_error(&path))?;
                self.symlink(&link.to_string_lossy(), &target)?;
            } else if kind.is_dir() {
                self.upload_dir(&path, &target)?;
            } else {
                self.write_file(&path, &target)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    /// A device stream that rejects every write.
    struct UnwritableStream;

    impl Read for UnwritableStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for UnwritableStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A device stream that accepts writes and replays canned replies.
    #[cfg(unix)]
    struct ScriptedStream {
        replies: Cursor<Vec<u8>>,
    }

    #[cfg(unix)]
    impl Read for ScriptedStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.replies.read(buffer)
        }
    }

    #[cfg(unix)]
    impl Write for ScriptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn request_write_failures_are_reported() {
        let mut afc = Afc::new(Box::new(UnwritableStream));
        assert_eq!(
            afc.make_dir("PublicStaging").unwrap_err(),
            "I/O error while sending an AFC request: broken pipe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_read_failures_name_the_local_path() {
        // Opening a directory succeeds on Unix, but reading it fails.
        let local = tempfile::tempdir().unwrap();
        let opened = Packet {
            number: 0,
            operation: op::FILE_OPEN_RESULT,
            data: 1_u64.to_le_bytes().to_vec(),
            payload: Vec::new(),
        };
        let mut afc = Afc::new(Box::new(ScriptedStream {
            replies: Cursor::new(opened.encode()),
        }));

        let error = afc.write_file(local.path(), "PublicStaging/x").unwrap_err();

        assert!(
            error.starts_with(&format!("{}: ", local.path().display())),
            "{error}"
        );
    }

    #[test]
    fn packets_round_trip_with_header_data_and_payload() {
        let packet = Packet {
            number: 4,
            operation: op::FILE_WRITE,
            data: 9_u64.to_le_bytes().to_vec(),
            payload: b"abc".to_vec(),
        };
        let wire = packet.encode();
        assert_eq!(&wire[..8], MAGIC);
        assert_eq!(u64::from_le_bytes(wire[8..16].try_into().unwrap()), 51);
        assert_eq!(u64::from_le_bytes(wire[16..24].try_into().unwrap()), 48);
        assert_eq!(Packet::read(&mut Cursor::new(&wire)).unwrap(), packet);
        assert_eq!(packet.status(), None);
    }

    #[test]
    fn malformed_packets_are_rejected() {
        let good = Packet {
            number: 0,
            operation: op::STATUS,
            data: 0_u64.to_le_bytes().to_vec(),
            payload: Vec::new(),
        }
        .encode();
        assert_eq!(
            Packet::read(&mut Cursor::new(&good)).unwrap().status(),
            Some(0)
        );
        for (offset, value) in [(0, 0_u64), (16, 8), (8, 41), (8, u64::MAX)] {
            let mut bad = good.clone();
            bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                Packet::read(&mut Cursor::new(&bad))
                    .unwrap_err()
                    .contains("malformed")
            );
        }
        let short_status = Packet {
            number: 0,
            operation: op::STATUS,
            data: vec![1],
            payload: Vec::new(),
        };
        assert_eq!(short_status.status(), None);
    }

    #[test]
    fn error_codes_are_named() {
        assert_eq!(
            describe(10, "open x"),
            "AFC open x failed: permission denied (code 10)"
        );
        assert_eq!(
            describe(99, "y"),
            "AFC y failed: unexpected error (code 99)"
        );
    }
}
