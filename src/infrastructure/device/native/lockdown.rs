//! lockdownd client (device port 62078): `QueryType`, `StartSession` with the
//! pair record and its TLS upgrade, then `StartService`.

use super::BoxStream;
use super::codec::{dict, recv_plist, send_plist, string, unsigned};
use super::tls::{PairRecord, upgrade};
use plist::{Dictionary, Value};

/// lockdownd's TCP port on the device.
pub(crate) const PORT: u16 = 62078;

/// Actionable hints for lockdownd `Error` values.
const ERROR_HINTS: &[(&str, &str)] = &[
    (
        "InvalidHostID",
        "the device no longer trusts this computer's pair record; unplug it, tap \"Trust This Computer\" again and retry",
    ),
    ("PasswordProtected", "unlock the device and retry"),
    (
        "PairingDialogResponsePending",
        "answer the \"Trust This Computer\" prompt on the device and retry",
    ),
    (
        "UserDeniedPairing",
        "the device user declined to trust this computer",
    ),
    ("SessionInactive", "the lockdown session ended; retry"),
    ("InvalidService", "the device does not offer this service"),
    (
        "ServiceProhibited",
        "the device refused this service (Developer Mode or a restriction may be required)",
    ),
];

/// A service endpoint returned by `StartService`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Service {
    pub(crate) port: u16,
    pub(crate) ssl: bool,
}

/// An authenticated lockdownd session.
pub(crate) struct Lockdown {
    stream: BoxStream,
}

fn describe(request: &str, error: &str) -> String {
    let hint = ERROR_HINTS
        .iter()
        .find(|(code, _)| *code == error)
        .map_or("unexpected lockdownd error", |(_, hint)| hint);
    format!("lockdownd {request} failed with {error}: {hint}")
}

fn exchange(
    stream: &mut BoxStream,
    request: &str,
    extra: Dictionary,
) -> Result<Dictionary, String> {
    let mut message = dict([("Label", "ipakeep".into()), ("Request", request.into())]);
    message.extend(extra);
    send_plist(stream, message)?;
    let reply = recv_plist(stream).map_err(|error| format!("lockdownd {request}: {error}"))?;
    match string(&reply, "Error") {
        Some(error) => Err(describe(request, error)),
        None => Ok(reply),
    }
}

impl Lockdown {
    /// Verify the peer is lockdownd and start a (TLS) session.
    pub(crate) fn open(mut stream: BoxStream, pair: &PairRecord) -> Result<Self, String> {
        let kind = exchange(&mut stream, "QueryType", Dictionary::new())?;
        if string(&kind, "Type") != Some("com.apple.mobile.lockdown") {
            return Err("device port 62078 did not answer as lockdownd".to_string());
        }
        let session = exchange(
            &mut stream,
            "StartSession",
            dict([
                ("HostID", pair.host_id.as_str().into()),
                ("SystemBUID", pair.system_buid.as_str().into()),
            ]),
        )?;
        if session.get("EnableSessionSSL").and_then(Value::as_boolean) == Some(true) {
            stream = upgrade(stream, pair)?;
        }
        Ok(Self { stream })
    }

    /// Read `key` from lockdownd's global domain (`GetValue`).
    pub(crate) fn get_value(&mut self, key: &str) -> Result<Value, String> {
        let reply = exchange(&mut self.stream, "GetValue", dict([("Key", key.into())]))?;
        reply
            .get("Value")
            .cloned()
            .ok_or_else(|| format!("lockdownd GetValue {key} returned no value"))
    }

    /// Ask lockdownd to spawn `service` and return its port.
    pub(crate) fn start_service(&mut self, service: &str) -> Result<Service, String> {
        let reply = exchange(
            &mut self.stream,
            "StartService",
            dict([("Service", service.into())]),
        )?;
        let port = unsigned(&reply, "Port")
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| format!("lockdownd StartService {service} returned no port"))?;
        Ok(Service {
            port,
            ssl: reply.get("EnableServiceSSL").and_then(Value::as_boolean) == Some(true),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_actionable_hints() {
        assert!(describe("StartSession", "InvalidHostID").contains("Trust This Computer"));
        assert_eq!(
            describe("StartService", "Mystery"),
            "lockdownd StartService failed with Mystery: unexpected lockdownd error"
        );
    }
}
