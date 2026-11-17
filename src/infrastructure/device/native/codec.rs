//! Plist encoding and the 4-byte big-endian length framing shared by
//! lockdownd and `installation_proxy` (libimobiledevice's
//! `property_list_service`).

use plist::{Dictionary, Value};
use std::io::{self, Cursor, Read, Write};

/// Upper bound for one plist message; real replies are a few KiB.
pub(super) const MAX_MESSAGE: usize = 16 << 20;

/// Serialize `dict` as an XML plist (the encoding libimobiledevice sends).
pub(super) fn to_xml(dict: Dictionary) -> Vec<u8> {
    let mut out = Vec::new();
    Value::Dictionary(dict)
        .to_writer_xml(&mut out)
        .expect("serializing a plist into memory cannot fail");
    out
}

/// Parse an XML or binary plist whose root must be a dictionary.
pub(super) fn from_plist(bytes: &[u8]) -> Result<Dictionary, String> {
    Value::from_reader(Cursor::new(bytes))
        .map_err(|error| format!("invalid plist from device: {error}"))?
        .into_dictionary()
        .ok_or_else(|| "device sent a plist whose root is not a dictionary".to_string())
}

/// Describe an I/O failure; an EOF means the peer dropped the connection.
pub(super) fn io_error(context: &str, error: &io::Error) -> String {
    // A reset/aborted peer is a dropped connection too (macOS and Windows often
    // report RST instead of EOF when the device side closes first).
    if matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    ) {
        format!("connection to the device closed unexpectedly while {context}")
    } else {
        format!("I/O error while {context}: {error}")
    }
}

/// Read exactly `len` bytes.
pub(super) fn read_bytes(
    stream: &mut dyn Read,
    len: usize,
    context: &str,
) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0; len];
    stream
        .read_exact(&mut buffer)
        .map_err(|error| io_error(context, &error))?;
    Ok(buffer)
}

/// Send one length-prefixed XML plist.
pub(super) fn send_plist(stream: &mut dyn Write, dict: Dictionary) -> Result<(), String> {
    let body = to_xml(dict);
    let mut frame = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    frame.extend(body);
    stream
        .write_all(&frame)
        .and_then(|()| stream.flush())
        .map_err(|error| io_error("sending a request", &error))
}

/// Receive one length-prefixed plist (XML or binary).
pub(super) fn recv_plist(stream: &mut dyn Read) -> Result<Dictionary, String> {
    let header = read_bytes(stream, 4, "reading a reply")?;
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if len > MAX_MESSAGE {
        return Err(format!("device reply of {len} bytes exceeds the limit"));
    }
    from_plist(&read_bytes(stream, len, "reading a reply")?)
}

/// Build a dictionary from string/value pairs.
pub(super) fn dict<const N: usize>(entries: [(&str, Value); N]) -> Dictionary {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

/// String field of a reply, if present.
pub(super) fn string<'a>(dict: &'a Dictionary, key: &str) -> Option<&'a str> {
    dict.get(key).and_then(Value::as_string)
}

/// Unsigned integer field of a reply, if present.
pub(super) fn unsigned(dict: &Dictionary, key: &str) -> Option<u64> {
    dict.get(key).and_then(Value::as_unsigned_integer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefixed_plists_round_trip_and_reject_bad_frames() {
        let mut wire = Vec::new();
        send_plist(&mut wire, dict([("Request", "QueryType".into())])).unwrap();
        let len = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(len, wire.len() - 4);
        assert!(String::from_utf8_lossy(&wire[4..]).contains("<key>Request</key>"));
        let reply = recv_plist(&mut Cursor::new(&wire)).unwrap();
        assert_eq!(string(&reply, "Request"), Some("QueryType"));
        assert_eq!(unsigned(&reply, "Request"), None);

        let oversized = u32::MAX.to_be_bytes();
        assert!(
            recv_plist(&mut &oversized[..])
                .unwrap_err()
                .contains("exceeds")
        );
        let truncated = [0, 0, 0, 9, b'<'];
        assert!(
            recv_plist(&mut &truncated[..])
                .unwrap_err()
                .contains("closed unexpectedly")
        );
    }

    #[test]
    fn plist_decoding_accepts_binary_and_rejects_non_dictionaries() {
        let mut binary = Vec::new();
        Value::Dictionary(dict([("Number", 7_u64.into())]))
            .to_writer_binary(&mut binary)
            .unwrap();
        assert_eq!(unsigned(&from_plist(&binary).unwrap(), "Number"), Some(7));
        assert!(
            from_plist(b"garbage")
                .unwrap_err()
                .contains("invalid plist")
        );
        let mut array = Vec::new();
        Value::Array(Vec::new()).to_writer_xml(&mut array).unwrap();
        assert!(from_plist(&array).unwrap_err().contains("not a dictionary"));
    }

    #[test]
    fn io_errors_distinguish_dropped_connections() {
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert!(io_error("x", &eof).contains("closed unexpectedly while x"));
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
        ] {
            let reset = io::Error::from(kind);
            assert!(io_error("x", &reset).contains("closed unexpectedly while x"));
        }
        let other = io::Error::other("boom");
        assert_eq!(io_error("x", &other), "I/O error while x: boom");
    }

    #[test]
    fn write_failures_are_reported() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("broken pipe"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(Broken.flush().is_ok());
        let error = send_plist(&mut Broken, Dictionary::new()).unwrap_err();
        assert!(error.contains("sending a request: broken pipe"));
    }
}
