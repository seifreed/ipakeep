//! End-to-end tests of the native launch against an in-process fake device:
//! usbmuxd, lockdownd (session and service TLS), `installation_proxy`
//! `Lookup`, `mobile_image_mounter` `LookupImage` and a GDB remote stub that
//! validates framing, checksums and the packet sequence.

use super::codec::{dict, recv_plist, send_plist, string, unsigned};
use super::debugserver::{self, encode, hex};
use super::fake::{Scenario, UDID, server_tls};
use super::launch::*;
use super::{Address, BoxStream, instproxy, lockdown, usbmux};
use plist::{Dictionary, Value};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const INSTPROXY_PORT: u16 = 1;
const MOUNTER_PORT: u16 = 2;
const DEBUGSERVER_PORT: u16 = 3;
const BUNDLE: &str = "com.example.debuggable";
const PATH: &str = "/private/var/containers/Bundle/Application/UUID/Test.app";
const CONTAINER: &str = "/private/var/mobile/Containers/Data/Application/DATA";

/// What the fake device answers.
#[derive(Clone)]
struct Device {
    base: Scenario,
    version: Value,
    lookup: Dictionary,
    image: Dictionary,
    /// Error for `StartService` of the iOS 14+ debugserver, if any.
    secure_error: Option<&'static str>,
    /// Whether the pre-iOS 14 debugserver is missing too.
    legacy_missing: bool,
    /// `(expected payload prefix, reply)` the GDB stub plays in order.
    gdb: Vec<(String, &'static str)>,
}

/// What the fake device received.
#[derive(Default)]
struct Log {
    services: Vec<String>,
    requests: Vec<Dictionary>,
    packets: Vec<String>,
}

fn app(entitlements: Option<bool>) -> Dictionary {
    let mut app = dict([
        ("Path", PATH.into()),
        ("CFBundleExecutable", "Test".into()),
        ("Container", CONTAINER.into()),
    ]);
    if let Some(allow) = entitlements {
        let entitlements = dict([("get-task-allow", allow.into())]);
        app.insert("Entitlements".into(), Value::Dictionary(entitlements));
    }
    app
}

fn lookup_reply(app: Dictionary) -> Dictionary {
    let result = dict([(BUNDLE, Value::Dictionary(app))]);
    dict([
        ("LookupResult", Value::Dictionary(result)),
        ("Status", "Complete".into()),
    ])
}

fn launch_script() -> Vec<(String, &'static str)> {
    let executable = hex(format!("{PATH}/Test").as_bytes());
    [
        "QStartNoAckMode".to_string(),
        "QSetMaxPacketSize:400".to_string(),
        format!("QSetWorkingDir:{}", hex(CONTAINER.as_bytes())),
        format!("A{},0,{executable}", executable.len()),
        "qLaunchSuccess".to_string(),
        "D".to_string(),
    ]
    .into_iter()
    .map(|packet| (packet, "OK"))
    .collect()
}

impl Device {
    fn working() -> Self {
        let signature = Value::Array(vec![Value::Data(vec![1, 2, 3])]);
        Self {
            base: Scenario::working(),
            version: "16.7.16".into(),
            lookup: lookup_reply(app(Some(true))),
            image: dict([("ImageSignature", signature), ("Status", "Complete".into())]),
            secure_error: None,
            legacy_missing: false,
            gdb: launch_script(),
        }
    }
}

fn run(device: Device) -> (Result<(), String>, Log) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = Address::Tcp(listener.local_addr().unwrap().to_string());
    let log = Arc::new(Mutex::new(Log::default()));
    let shared = (Arc::new(device), log.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (device, log) = (shared.0.clone(), shared.1.clone());
            std::thread::spawn(move || serve_usbmux(Box::new(stream), &device, &log));
        }
    });
    let result = launch_app(&address, UDID, BUNDLE);
    let log = std::mem::take(&mut *log.lock().unwrap());
    (result, log)
}

fn serve_usbmux(mut stream: BoxStream, device: &Device, log: &Mutex<Log>) {
    let (tag, request) = usbmux::read_frame(&mut stream).unwrap();
    let message = string(&request, "MessageType").unwrap();
    let reply = match message {
        "ListDevices" => {
            let properties = dict([
                ("DeviceID", 7_u64.into()),
                ("SerialNumber", "00008030001A2B3C4D5E6F70".into()),
                ("ConnectionType", "USB".into()),
            ]);
            let entry = dict([("Properties", Value::Dictionary(properties))]);
            dict([("DeviceList", Value::Array(vec![Value::Dictionary(entry)]))])
        }
        "ReadPairRecord" => dict([(
            "PairRecordData",
            Value::Data(device.base.pair_record.clone().unwrap()),
        )]),
        _ => dict([("MessageType", "Result".into()), ("Number", 0_u64.into())]),
    };
    stream.write_all(&usbmux::encode(tag, reply)).unwrap();
    if message == "Connect" {
        let raw = u16::try_from(unsigned(&request, "PortNumber").unwrap()).unwrap();
        serve_port(stream, u16::from_be_bytes(raw.to_ne_bytes()), device, log);
    }
}

fn serve_port(stream: BoxStream, port: u16, device: &Device, log: &Mutex<Log>) {
    match port {
        lockdown::PORT => serve_lockdown(stream, device, log),
        INSTPROXY_PORT => serve_plist(stream, &device.lookup, log),
        MOUNTER_PORT => serve_plist(stream, &device.image, log),
        DEBUGSERVER_PORT => serve_gdb(server_tls(stream, &device.base), device, log),
        _ => serve_gdb(stream, device, log),
    }
}

fn start_service(name: &str, device: &Device) -> Dictionary {
    let (port, ssl) = match name {
        instproxy::SERVICE => (INSTPROXY_PORT, false),
        IMAGE_MOUNTER => (MOUNTER_PORT, false),
        debugserver::SECURE_SERVICE => (DEBUGSERVER_PORT, true),
        _ => (DEBUGSERVER_PORT + 1, false),
    };
    let legacy_missing = device.legacy_missing && !ssl && port > DEBUGSERVER_PORT;
    match device.secure_error.filter(|_| ssl || legacy_missing) {
        Some(error) => dict([("Error", error.into())]),
        None => dict([
            ("Port", u64::from(port).into()),
            ("EnableServiceSSL", ssl.into()),
        ]),
    }
}

fn serve_lockdown(mut stream: BoxStream, device: &Device, log: &Mutex<Log>) {
    while let Ok(request) = recv_plist(&mut stream) {
        let kind = string(&request, "Request").unwrap();
        let reply = match kind {
            "QueryType" => dict([("Type", "com.apple.mobile.lockdown".into())]),
            "StartSession" => dict([("EnableSessionSSL", true.into())]),
            "GetValue" => dict([("Value", device.version.clone())]),
            _ => {
                let name = string(&request, "Service").unwrap();
                log.lock().unwrap().services.push(name.to_string());
                start_service(name, device)
            }
        };
        send_plist(&mut stream, reply).unwrap();
        if kind == "StartSession" {
            stream = server_tls(stream, &device.base);
        }
    }
}

fn serve_plist(mut stream: BoxStream, reply: &Dictionary, log: &Mutex<Log>) {
    let request = recv_plist(&mut stream).unwrap();
    log.lock().unwrap().requests.push(request);
    send_plist(&mut stream, reply.clone()).unwrap();
}

fn byte(stream: &mut BoxStream) -> Option<u8> {
    let mut byte = [0];
    stream.read_exact(&mut byte).ok().map(|()| byte[0])
}

/// Read one packet, asserting its framing and checksum.
fn read_packet(stream: &mut BoxStream) -> Option<String> {
    assert_eq!(byte(stream)?, b'$');
    let mut body = Vec::new();
    loop {
        match byte(stream)? {
            b'#' => break,
            other => body.push(other),
        }
    }
    let digits = [byte(stream)?, byte(stream)?];
    let payload = String::from_utf8(body).unwrap();
    assert_eq!(encode(&payload)[payload.len() + 2..], digits);
    Some(payload)
}

fn serve_gdb(mut stream: BoxStream, device: &Device, log: &Mutex<Log>) {
    let mut ack = true;
    for (expected, reply) in &device.gdb {
        let Some(payload) = read_packet(&mut stream) else {
            return;
        };
        log.lock().unwrap().packets.push(payload.clone());
        assert!(
            payload.starts_with(expected.as_str()),
            "{payload} vs {expected}"
        );
        let mut out = if ack { b"+".to_vec() } else { Vec::new() };
        out.extend(encode(reply));
        stream.write_all(&out).unwrap();
        if ack {
            assert_eq!(byte(&mut stream), Some(b'+'));
        }
        ack &= !(payload == "QStartNoAckMode" && *reply == "OK");
    }
}

#[test]
fn launches_over_the_secure_debugserver_and_detaches() {
    let (result, log) = run(Device::working());
    result.unwrap();
    assert_eq!(
        log.services,
        [
            instproxy::SERVICE,
            IMAGE_MOUNTER,
            debugserver::SECURE_SERVICE
        ]
    );
    let expected: Vec<String> = launch_script()
        .into_iter()
        .map(|(packet, _)| packet)
        .collect();
    assert_eq!(log.packets, expected);
    let lookup = &log.requests[0];
    assert_eq!(string(lookup, "Command"), Some("Lookup"));
    let options = lookup["ClientOptions"].as_dictionary().unwrap();
    assert_eq!(options["BundleIDs"], Value::Array(vec![BUNDLE.into()]));
    assert_eq!(string(&log.requests[1], "Command"), Some("LookupImage"));
    assert_eq!(string(&log.requests[1], "ImageType"), Some("Developer"));
}

#[test]
fn falls_back_to_the_plain_debugserver_before_ios_14() {
    let mut device = Device::working();
    device.secure_error = Some("InvalidService");
    device.version = "13.7".into();
    device.lookup = lookup_reply(dict([
        ("Path", PATH.into()),
        ("CFBundleExecutable", "Test".into()),
    ]));
    device.image = dict([("ImagePresent", true.into())]);
    device.gdb[2].0 = format!("QSetWorkingDir:{}", hex(PATH.as_bytes()));
    let (result, log) = run(device);
    result.unwrap();
    assert_eq!(
        log.services[2..],
        [debugserver::SECURE_SERVICE, debugserver::LEGACY_SERVICE]
    );
    assert_eq!(log.packets.len(), 6);
}

fn failure(device: Device) -> (String, Log) {
    let (result, log) = run(device);
    (result.unwrap_err(), log)
}

#[test]
fn ios_17_and_unparseable_versions_are_rejected_before_any_service() {
    let mut device = Device::working();
    device.version = "17.0".into();
    let (error, log) = failure(device.clone());
    assert!(error.contains("devicectl"), "{error}");
    assert_eq!(log.services, Vec::<String>::new());
    device.version = true.into();
    assert!(failure(device).0.contains("unexpected iOS version"));
}

#[test]
fn missing_and_undebuggable_apps_are_reported_before_debugserver() {
    let mut device = Device::working();
    device.lookup = dict([("LookupResult", Value::Dictionary(Dictionary::new()))]);
    let (error, log) = failure(device.clone());
    assert!(
        error.contains("com.example.debuggable is not installed"),
        "{error}"
    );
    assert_eq!(log.services, [instproxy::SERVICE]);

    device.lookup = lookup_reply(app(Some(false)));
    let error = failure(device.clone()).0;
    assert!(error.contains("not debuggable"), "{error}");

    device.lookup = lookup_reply(dict([("Path", PATH.into())]));
    assert!(failure(device.clone()).0.contains("no CFBundleExecutable"));

    device.lookup = dict([("Error", "APIInternalError".into())]);
    assert!(
        failure(device)
            .0
            .contains("Lookup failed: APIInternalError")
    );
}

#[test]
fn a_missing_developer_disk_image_is_reported() {
    let mut device = Device::working();
    device.image = dict([("ImageSignature", Value::Array(Vec::new()))]);
    let (error, log) = failure(device.clone());
    assert!(
        error.contains("Developer Disk Image is not mounted"),
        "{error}"
    );
    assert_eq!(log.services, [instproxy::SERVICE, IMAGE_MOUNTER]);

    device.image = dict([("Error", "DeviceLocked".into())]);
    assert!(
        failure(device)
            .0
            .contains("LookupImage failed: DeviceLocked")
    );
}

#[test]
fn refused_debugserver_service_points_at_the_ddi() {
    let mut device = Device::working();
    device.secure_error = Some("ServiceProhibited");
    let error = failure(device).0;
    assert!(error.contains("ServiceProhibited"), "{error}");
    assert!(error.contains("Developer Disk Image"), "{error}");

    let mut device = Device::working();
    device.secure_error = Some("InvalidService");
    device.legacy_missing = true;
    let (error, log) = failure(device);
    assert!(error.contains("Developer Disk Image"), "{error}");
    assert_eq!(log.services.len(), 4);
}

#[test]
fn debugserver_refusals_and_dropped_connections_fail_cleanly() {
    let mut device = Device::working();
    device.gdb[4].1 = "Efailed to get the task for process 321";
    let (error, log) = failure(device.clone());
    assert!(error.contains("get-task-allow"), "{error}");
    assert_eq!(log.packets.last().unwrap(), "qLaunchSuccess");

    device.gdb.truncate(3);
    let error = failure(device).0;
    assert!(error.contains("closed unexpectedly"), "{error}");
}

#[test]
fn unknown_devices_fail_before_lockdown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = Address::Tcp(listener.local_addr().unwrap().to_string());
    drop(listener);
    assert!(launch_app(&address, UDID, BUNDLE).is_err());
}
