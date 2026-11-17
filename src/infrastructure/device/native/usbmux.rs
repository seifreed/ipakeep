//! usbmuxd client: device discovery, pair records, and TCP-over-USB tunnels.
//!
//! Wire format (as in libusbmuxd/pymobiledevice3): a 16-byte little-endian
//! header `{length, version = 1, message = 8 (plist), tag}` followed by an XML
//! plist. A successful `Connect` turns the socket into a raw byte tunnel to
//! the device port, so every service needs its own usbmuxd connection.

use super::BoxStream;
use super::codec::{dict, from_plist, io_error, read_bytes, string, to_xml, unsigned};
use plist::{Dictionary, Value};
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

const HEADER_LEN: usize = 16;
const PLIST_VERSION: u32 = 1;
const PLIST_MESSAGE: u32 = 8;
/// A stalled device must not hang the CLI forever.
const IO_TIMEOUT: Duration = Duration::from_secs(300);

/// usbmuxd `Result` codes (libusbmuxd `usbmuxd_result`).
const RESULT_CODES: &[(u64, &str)] = &[
    (1, "bad command"),
    (2, "unknown device (unplugged?)"),
    (3, "connection refused by the device service"),
    (6, "unsupported protocol version"),
];

/// Where usbmuxd listens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Address {
    /// UNIX domain socket (macOS and Linux).
    Unix(PathBuf),
    /// TCP `host:port` (Windows' Apple Mobile Device Service).
    Tcp(String),
}

impl Address {
    /// Honour `USBMUXD_SOCKET_ADDRESS` like libusbmuxd, else the platform default.
    pub(crate) fn from_env() -> Self {
        Self::parse(std::env::var("USBMUXD_SOCKET_ADDRESS").ok().as_deref())
    }

    /// `UNIX:/path` or `host:port`; empty or unset selects the platform default.
    pub(crate) fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => default_address(),
            Some(value) => value.strip_prefix("UNIX:").map_or_else(
                || Self::Tcp(value.to_string()),
                |path| Self::Unix(PathBuf::from(path)),
            ),
        }
    }

    fn connect(&self) -> Result<BoxStream, String> {
        let unavailable = |error: std::io::Error| {
            format!("cannot reach usbmuxd at {self}: {error} (is the device service running?)")
        };
        match self {
            Self::Unix(path) => connect_unix(path).map_err(unavailable),
            Self::Tcp(address) => std::net::TcpStream::connect(address)
                .and_then(|stream| {
                    stream.set_read_timeout(Some(IO_TIMEOUT))?;
                    Ok(Box::new(stream) as BoxStream)
                })
                .map_err(unavailable),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unix(path) => write!(f, "UNIX:{}", path.display()),
            Self::Tcp(address) => f.write_str(address),
        }
    }
}

#[cfg(unix)]
fn default_address() -> Address {
    Address::Unix(PathBuf::from("/var/run/usbmuxd"))
}

#[cfg(not(unix))]
fn default_address() -> Address {
    Address::Tcp("127.0.0.1:27015".to_string())
}

#[cfg(unix)]
fn connect_unix(path: &std::path::Path) -> std::io::Result<BoxStream> {
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
fn connect_unix(_: &std::path::Path) -> std::io::Result<BoxStream> {
    Err(std::io::Error::other(
        "UNIX sockets are unavailable on this platform",
    ))
}

/// A device attached to usbmuxd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Device {
    /// usbmuxd's handle used by `Connect`.
    pub(crate) id: u64,
    /// UDID as reported by usbmuxd (also the pair record ID).
    pub(crate) serial: String,
    /// `USB` or `Network`.
    pub(crate) connection: String,
}

/// Encode one usbmuxd request frame.
pub(super) fn encode(tag: u32, message: Dictionary) -> Vec<u8> {
    let body = to_xml(message);
    let len = u32::try_from(HEADER_LEN + body.len()).unwrap_or(u32::MAX);
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    for word in [len, PLIST_VERSION, PLIST_MESSAGE, tag] {
        frame.extend(word.to_le_bytes());
    }
    frame.extend(body);
    frame
}

/// Read one usbmuxd frame, returning its tag and plist payload.
pub(super) fn read_frame(stream: &mut dyn std::io::Read) -> Result<(u32, Dictionary), String> {
    let header = read_bytes(stream, HEADER_LEN, "reading a usbmuxd reply")?;
    let word = |index: usize| {
        u32::from_le_bytes([
            header[index * 4],
            header[index * 4 + 1],
            header[index * 4 + 2],
            header[index * 4 + 3],
        ])
    };
    let len = word(0) as usize;
    if word(1) != PLIST_VERSION
        || word(2) != PLIST_MESSAGE
        || !(HEADER_LEN..=super::codec::MAX_MESSAGE).contains(&len)
    {
        return Err("usbmuxd sent an unsupported (non-plist) reply".to_string());
    }
    let body = read_bytes(stream, len - HEADER_LEN, "reading a usbmuxd reply")?;
    Ok((word(3), from_plist(&body)?))
}

/// One request/reply exchange on a fresh connection; returns the open stream.
fn request(
    address: &Address,
    message_type: &str,
    extra: Dictionary,
) -> Result<(BoxStream, Dictionary), String> {
    let mut stream = address.connect()?;
    let mut message = dict([
        ("MessageType", message_type.into()),
        ("ClientVersionString", "ipakeep".into()),
        ("ProgName", "ipakeep".into()),
        ("kLibUSBMuxVersion", 3_u64.into()),
    ]);
    message.extend(extra);
    stream
        .write_all(&encode(1, message))
        .map_err(|error| io_error("sending a usbmuxd request", &error))?;
    let (tag, reply) = read_frame(&mut stream)?;
    if tag != 1 {
        return Err(format!("usbmuxd replied with unexpected tag {tag}"));
    }
    Ok((stream, reply))
}

/// Fail unless a `Result` reply carries `Number = 0`.
fn check_result(reply: &Dictionary, action: &str) -> Result<(), String> {
    match unsigned(reply, "Number") {
        Some(0) => Ok(()),
        code => {
            let code = code.unwrap_or(u64::MAX);
            let reason = RESULT_CODES
                .iter()
                .find(|(known, _)| *known == code)
                .map_or("unexpected reply", |(_, reason)| reason);
            Err(format!("usbmuxd {action} failed: {reason} (code {code})"))
        }
    }
}

/// List the devices usbmuxd currently sees.
pub(crate) fn list_devices(address: &Address) -> Result<Vec<Device>, String> {
    let (_, reply) = request(address, "ListDevices", Dictionary::new())?;
    let list = reply
        .get("DeviceList")
        .and_then(Value::as_array)
        .ok_or("usbmuxd ListDevices reply has no DeviceList")?;
    Ok(list
        .iter()
        .filter_map(|entry| {
            let properties = entry.as_dictionary()?.get("Properties")?.as_dictionary()?;
            Some(Device {
                id: unsigned(properties, "DeviceID")?,
                serial: string(properties, "SerialNumber")?.to_string(),
                connection: string(properties, "ConnectionType")
                    .unwrap_or("USB")
                    .to_string(),
            })
        })
        .collect())
}

/// UDIDs compared without dashes or case (usbmuxd on macOS drops the dash
/// of 25-character UDIDs).
fn normalize(udid: &str) -> String {
    udid.chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Pick the device matching `udid`, preferring a USB connection.
pub(crate) fn find_device(devices: &[Device], udid: &str) -> Result<Device, String> {
    let wanted = normalize(udid);
    devices
        .iter()
        .filter(|device| normalize(&device.serial) == wanted)
        .min_by_key(|device| device.connection != "USB")
        .cloned()
        .ok_or_else(|| {
            let attached: Vec<&str> = devices.iter().map(|device| device.serial.as_str()).collect();
            format!(
                "device {udid} not found via usbmuxd (attached: {}); connect it over USB, unlock it and pass its UDID",
                if attached.is_empty() { "none".to_string() } else { attached.join(", ") }
            )
        })
}

/// Fetch the host's pair record for `serial` from usbmuxd.
pub(crate) fn read_pair_record(address: &Address, serial: &str) -> Result<Vec<u8>, String> {
    let (_, reply) = request(
        address,
        "ReadPairRecord",
        dict([("PairRecordID", serial.into())]),
    )?;
    match reply.get("PairRecordData") {
        Some(Value::Data(data)) => Ok(data.clone()),
        _ => Err(format!(
            "no pair record for {serial}: unlock the device, tap \"Trust This Computer\" and retry \
             (on Linux/Windows pair it once with the platform's device service)"
        )),
    }
}

/// Open a tunnel to TCP `port` on the device.
pub(crate) fn connect(address: &Address, device_id: u64, port: u16) -> Result<BoxStream, String> {
    let (stream, reply) = request(
        address,
        "Connect",
        dict([
            ("DeviceID", device_id.into()),
            // usbmuxd expects the port in network byte order (`htons`).
            (
                "PortNumber",
                u64::from(u16::from_ne_bytes(port.to_be_bytes())).into(),
            ),
        ]),
    )?;
    check_result(&reply, &format!("connect to device port {port}"))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn device(id: u64, serial: &str, connection: &str) -> Device {
        Device {
            id,
            serial: serial.into(),
            connection: connection.into(),
        }
    }

    #[test]
    fn frames_round_trip_and_reject_foreign_headers() {
        let frame = encode(7, dict([("MessageType", "ListDevices".into())]));
        assert_eq!(
            u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len()
        );
        assert_eq!(frame[4..12], [1, 0, 0, 0, 8, 0, 0, 0]);
        let (tag, message) = read_frame(&mut Cursor::new(&frame)).unwrap();
        assert_eq!(tag, 7);
        assert_eq!(string(&message, "MessageType"), Some("ListDevices"));

        let mut binary = frame.clone();
        binary[8] = 1;
        assert!(
            read_frame(&mut Cursor::new(&binary))
                .unwrap_err()
                .contains("non-plist")
        );
        let mut short = frame.clone();
        short[..4].copy_from_slice(&3_u32.to_le_bytes());
        assert!(read_frame(&mut Cursor::new(&short)).is_err());
        let mut version = frame;
        version[4] = 0;
        assert!(read_frame(&mut Cursor::new(&version)).is_err());
    }

    #[test]
    fn addresses_follow_libusbmuxd_conventions() {
        assert_eq!(Address::parse(None), default_address());
        assert_eq!(Address::parse(Some("  ")), default_address());
        assert_eq!(
            Address::parse(Some("UNIX:/tmp/mux")),
            Address::Unix(PathBuf::from("/tmp/mux"))
        );
        let tcp = Address::parse(Some("127.0.0.1:27015"));
        assert_eq!(tcp, Address::Tcp("127.0.0.1:27015".into()));
        assert_eq!(tcp.to_string(), "127.0.0.1:27015");
        assert_eq!(Address::Unix("/x".into()).to_string(), "UNIX:/x");
        let _ = Address::from_env();
    }

    #[test]
    fn device_lookup_normalizes_udids_and_prefers_usb() {
        let devices = [
            device(1, "00008030001A2B3C4D5E6F70", "Network"),
            device(2, "00008030001A2B3C4D5E6F70", "USB"),
            device(3, "abcdef", "USB"),
        ];
        assert_eq!(
            find_device(&devices, "00008030-001a2b3c4d5e6f70")
                .unwrap()
                .id,
            2
        );
        assert_eq!(
            find_device(&devices[..1], "00008030-001A2B3C4D5E6F70")
                .unwrap()
                .id,
            1
        );
        let missing = find_device(&devices, "nope").unwrap_err();
        assert!(
            missing
                .contains("attached: 00008030001A2B3C4D5E6F70, 00008030001A2B3C4D5E6F70, abcdef")
        );
        assert!(
            find_device(&[], "nope")
                .unwrap_err()
                .contains("attached: none")
        );
    }

    #[test]
    fn result_codes_are_named() {
        assert!(check_result(&dict([("Number", 0_u64.into())]), "x").is_ok());
        let refused = check_result(&dict([("Number", 3_u64.into())]), "connect").unwrap_err();
        assert_eq!(
            refused,
            "usbmuxd connect failed: connection refused by the device service (code 3)"
        );
        let unknown = check_result(&Dictionary::new(), "x").unwrap_err();
        assert!(unknown.contains("unexpected reply"));
    }

    #[test]
    fn replies_to_another_request_tag_are_rejected() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = Address::Tcp(listener.local_addr().unwrap().to_string());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_frame(&mut stream).unwrap();
            stream
                .write_all(&encode(9, dict([("DeviceList", Value::Array(Vec::new()))])))
                .unwrap();
        });
        let error = list_devices(&address).unwrap_err();
        assert_eq!(error, "usbmuxd replied with unexpected tag 9");
        server.join().unwrap();
    }

    #[test]
    fn unreachable_usbmuxd_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let missing = Address::Unix(dir.path().join("absent.sock"));
        assert!(
            list_devices(&missing)
                .unwrap_err()
                .contains("cannot reach usbmuxd at UNIX:")
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = Address::Tcp(listener.local_addr().unwrap().to_string());
        drop(listener);
        assert!(
            list_devices(&closed)
                .unwrap_err()
                .contains("cannot reach usbmuxd")
        );
    }
}
