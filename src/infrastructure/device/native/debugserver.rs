//! Client for iOS `debugserver` speaking the GDB remote serial protocol, used
//! to launch an installed app and detach (`idevicedebug --detach run`).
//!
//! # Wire format
//!
//! Every packet is `$<payload>#<checksum>`, the checksum being the modulo-256
//! sum of the payload bytes as two lowercase hex digits. Until
//! `QStartNoAckMode` is accepted, the receiver of each packet answers `+`
//! (good) or `-` (bad checksum, retransmit). Reply payloads escape `#`, `$`,
//! `}` and `*` as `}` followed by the byte XOR `0x20`.
//!
//! The launch sequence is `QStartNoAckMode`, `QSetMaxPacketSize:<hex>`,
//! `QSetWorkingDir:<hex path>`, one `QEnvironmentHexEncoded:<hex KEY=VALUE>`
//! per variable, `A<hexlen>,<index>,<hex arg>,...`, `qLaunchSuccess` and
//! finally `D`, which detaches and leaves the app running.
//!
//! # Sources
//!
//! Reimplemented from public documentation and behaviour, no code copied: the
//! GDB manual's "Remote Protocol" appendix (packet framing, acknowledgement,
//! escaping, `A`, `D`), LLVM's `lldb/docs/lldb-gdb-remote.txt`
//! (`QStartNoAckMode`, `QSetMaxPacketSize`, `QSetWorkingDir`,
//! `QEnvironmentHexEncoded`, `qLaunchSuccess`), libimobiledevice (LGPL-2.1:
//! `src/debugserver.c`, `tools/idevicedebug.c`) and pymobiledevice3 (GPL-3.0:
//! `services/debugserver_applist.py`, `cli/developer.py`), read as protocol
//! references only.

use super::BoxStream;
use super::codec::io_error;
use std::fmt::Write as _;

/// Lockdown service of iOS 14+ debugserver (service TLS).
pub(crate) const SECURE_SERVICE: &str = "com.apple.debugserver.DVTSecureSocketProxy";
/// Lockdown service of debugserver before iOS 14 (plain socket).
pub(crate) const LEGACY_SERVICE: &str = "com.apple.debugserver";

const ACK: u8 = b'+';
const NAK: u8 = b'-';
const START: u8 = b'$';
const END: u8 = b'#';
const ESCAPE: u8 = b'}';
const ESCAPE_XOR: u8 = 0x20;
/// Packet size ipakeep announces (`QSetMaxPacketSize`), as idevicedebug does.
const MAX_PACKET_SIZE: usize = 1024;
/// Upper bound for one reply payload; launch replies are a few bytes.
const MAX_REPLY: usize = 1 << 20;
/// Attempts per packet when the peer answers `-` (or a corrupted reply).
const MAX_ATTEMPTS: usize = 3;
/// debugserver's reply for success.
const OK: &str = "OK";

/// Text debugserver returns when it may not attach to the launched process.
const NOT_DEBUGGABLE: &[&str] = &["failed to get the task", "get-task-allow"];
/// Text debugserver returns when `SpringBoard` refuses a launch on a locked device.
const LOCKED: &[&str] = &["Locked", "locked"];

/// Modulo-256 sum of `payload`.
pub(crate) fn checksum(payload: &[u8]) -> u8 {
    payload
        .iter()
        .fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
}

/// Frame `payload` as `$payload#cs`.
pub(crate) fn encode(payload: &str) -> Vec<u8> {
    format!("${payload}#{:02x}", checksum(payload.as_bytes())).into_bytes()
}

/// Lowercase hex of `bytes` (the encoding of every string argument).
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Undo `}`-escaping in a reply payload.
pub(crate) fn unescape(body: &[u8]) -> String {
    let mut out = Vec::with_capacity(body.len());
    let mut bytes = body.iter();
    while let Some(byte) = bytes.next() {
        if let (ESCAPE, Some(next)) = (*byte, bytes.as_slice().first()) {
            out.push(next ^ ESCAPE_XOR);
            bytes.next();
        } else {
            out.push(*byte);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What to launch: the executable, its working directory and environment.
pub(crate) struct Launch<'a> {
    /// Absolute on-device path of the main executable (argv\[0\]).
    pub(crate) executable: &'a str,
    /// Working directory for the process.
    pub(crate) working_dir: &'a str,
    /// `KEY=VALUE` environment additions.
    pub(crate) environment: &'a [String],
}

/// The `A` packet: `A<hexlen>,<index>,<hex>` for each argument.
pub(crate) fn arguments_packet(arguments: &[&str]) -> String {
    let fields: Vec<String> = arguments
        .iter()
        .enumerate()
        .map(|(index, argument)| argument_field(index, argument))
        .collect();
    format!("A{}", fields.join(","))
}

fn argument_field(index: usize, argument: &str) -> String {
    let encoded = hex(argument.as_bytes());
    format!("{},{index},{encoded}", encoded.len())
}

/// Map an `E...` reply to an actionable message.
pub(crate) fn describe(step: &str, executable: &str, reply: &str) -> String {
    let matches = |needles: &[&str]| needles.iter().any(|needle| reply.contains(needle));
    if matches(NOT_DEBUGGABLE) {
        format!(
            "debugserver could not launch {executable}: the app is not debuggable — its \
             signature lacks the get-task-allow entitlement (App Store and distribution-signed \
             apps cannot be launched this way); re-sign it with a development profile \
             (debugserver: {reply})"
        )
    } else if matches(LOCKED) {
        format!(
            "debugserver could not launch {executable}: the device is locked; unlock it and retry ({reply})"
        )
    } else {
        format!("debugserver {step} failed for {executable}: {reply}")
    }
}

/// A GDB remote protocol session with debugserver.
pub(crate) struct Client {
    stream: BoxStream,
    ack: bool,
}

impl Client {
    /// Start a session in acknowledgement mode.
    pub(crate) fn new(stream: BoxStream) -> Self {
        Self { stream, ack: true }
    }

    fn read_byte(&mut self, context: &str) -> Result<u8, String> {
        let mut byte = [0];
        std::io::Read::read_exact(&mut self.stream, &mut byte)
            .map_err(|error| io_error(context, &error))?;
        Ok(byte[0])
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        std::io::Write::write_all(&mut self.stream, bytes)
            .and_then(|()| std::io::Write::flush(&mut self.stream))
            .map_err(|error| io_error("sending to debugserver", &error))
    }

    /// Send one packet, retransmitting while the peer answers `-`.
    pub(crate) fn send(&mut self, payload: &str) -> Result<(), String> {
        let packet = encode(payload);
        for _ in 0..MAX_ATTEMPTS {
            self.write(&packet)?;
            if !self.ack || self.read_byte("waiting for debugserver's acknowledgement")? == ACK {
                return Ok(());
            }
        }
        Err(format!(
            "debugserver rejected packet {} {MAX_ATTEMPTS} times",
            command_name(payload)
        ))
    }

    /// Read one packet body; `None` when its checksum does not match.
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>, String> {
        const CONTEXT: &str = "reading a debugserver reply";
        while self.read_byte(CONTEXT)? != START {}
        let mut body = Vec::new();
        loop {
            match self.read_byte(CONTEXT)? {
                END => break,
                byte if body.len() < MAX_REPLY => body.push(byte),
                _ => return Err(format!("debugserver reply exceeds {MAX_REPLY} bytes")),
            }
        }
        let digits = [self.read_byte(CONTEXT)?, self.read_byte(CONTEXT)?];
        let expected = std::str::from_utf8(&digits)
            .ok()
            .and_then(|digits| u8::from_str_radix(digits, 16).ok());
        Ok((expected == Some(checksum(&body))).then_some(body))
    }

    /// Receive one reply, asking for retransmission of corrupted packets.
    pub(crate) fn receive(&mut self) -> Result<String, String> {
        for _ in 0..MAX_ATTEMPTS {
            let packet = self.read_packet()?;
            if self.ack {
                self.write(&[if packet.is_some() { ACK } else { NAK }])?;
            }
            if let Some(body) = packet {
                return Ok(unescape(&body));
            }
        }
        Err(format!(
            "debugserver sent {MAX_ATTEMPTS} replies with bad checksums"
        ))
    }

    /// Send `payload` and return the reply.
    pub(crate) fn request(&mut self, payload: &str) -> Result<String, String> {
        self.send(payload)?;
        self.receive()
    }

    /// Send `payload` and require `OK`.
    fn expect_ok(&mut self, payload: &str, executable: &str) -> Result<(), String> {
        let reply = self.request(payload)?;
        tracing::debug!(
            event = "device.native.debugserver.packet",
            command = command_name(payload),
            ok = reply == OK
        );
        if reply == OK {
            Ok(())
        } else {
            Err(describe(command_name(payload), executable, &reply))
        }
    }

    /// Run the launch sequence, then detach so the app keeps running.
    pub(crate) fn launch(&mut self, launch: &Launch<'_>) -> Result<(), String> {
        let executable = launch.executable;
        if self.request("QStartNoAckMode")? == OK {
            self.ack = false;
        }
        self.expect_ok(
            &format!("QSetMaxPacketSize:{MAX_PACKET_SIZE:x}"),
            executable,
        )?;
        let working_dir = hex(launch.working_dir.as_bytes());
        self.expect_ok(&format!("QSetWorkingDir:{working_dir}"), executable)?;
        for variable in launch.environment {
            let encoded = hex(variable.as_bytes());
            self.expect_ok(&format!("QEnvironmentHexEncoded:{encoded}"), executable)?;
        }
        self.expect_ok(&arguments_packet(&[executable]), executable)?;
        self.expect_ok("qLaunchSuccess", executable)?;
        self.expect_ok("D", executable)
    }
}

/// The command part of a packet (before `:`, or `A` for the argument packet).
pub(crate) fn command_name(payload: &str) -> &str {
    if payload.starts_with('A') {
        return "A";
    }
    payload.split(':').next().unwrap_or(payload)
}
