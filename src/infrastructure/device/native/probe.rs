//! Non-destructive probe of every protocol layer against a **real** device.
//!
//! Ignored by default; run it by exact name with the device's UDID:
//!
//! ```text
//! IPAKEEP_DEVICE_UDID=<udid> cargo test --lib -- --ignored --exact \
//!     infrastructure::device::native::probe::real_device_protocol_stack --nocapture
//! ```
//!
//! It reads device state (usbmuxd, lockdownd, AFC, `installation_proxy`) and
//! only writes one temporary `PublicStaging/ipakeep-probe-<random>` file,
//! which it deletes again. Results are printed so they can be compared with
//! libimobiledevice (`ideviceinfo`, `afcclient`, `ideviceinstaller`).

use super::afc::Afc;
use super::codec::{dict, recv_plist, send_plist, string};
use super::tls::{PairRecord, upgrade};
use super::{Address, BoxStream, STAGING, afc, instproxy, lockdown, usbmux};
use plist::{Dictionary, Value};
use std::io::{Read, Write};

const AFC_READ_DIR: u64 = 0x03;
const AFC_DATA: u64 = 0x02;
const AFC_GET_FILE_INFO: u64 = 0x0A;
const AFC_REMOVE_PATH: u64 = 0x08;
const DEBUGSERVER: &str = "com.apple.debugserver.DVTSecureSocketProxy";
const PROBE_APP: &str = "com.superking.ludo.star";

/// NUL-separated strings of an AFC data reply.
fn strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn afc_strings(files: &mut Afc, operation: u64, path: &str) -> Vec<String> {
    let mut data = path.as_bytes().to_vec();
    data.push(0);
    let reply = files.transact(operation, data, &[]).unwrap();
    assert_eq!(
        reply.operation,
        AFC_DATA,
        "{path}: status {:?}",
        reply.status()
    );
    strings(&reply.payload)
}

fn service(
    address: &Address,
    device: u64,
    lockdown: &mut lockdown::Lockdown,
    pair: &PairRecord,
    name: &str,
) -> BoxStream {
    let service = lockdown.start_service(name).unwrap();
    eprintln!(
        "[4] StartService {name}: port {} ssl {}",
        service.port, service.ssl
    );
    let stream = usbmux::connect(address, device, service.port).unwrap();
    if service.ssl {
        upgrade(stream, pair).unwrap()
    } else {
        stream
    }
}

fn probe_afc(mut files: Afc) {
    let root = afc_strings(&mut files, AFC_READ_DIR, "/");
    eprintln!("[5] AFC readdir /: {root:?}");
    let staging = afc_strings(&mut files, AFC_GET_FILE_INFO, STAGING);
    eprintln!("[5] AFC stat {STAGING}: {staging:?}");
    let name = format!("{STAGING}/ipakeep-probe-{:016x}", rand::random::<u64>());
    let local = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(local.path(), b"ipakeep probe\n").unwrap();
    files.write_file(local.path(), &name).unwrap();
    let info = afc_strings(&mut files, AFC_GET_FILE_INFO, &name);
    eprintln!("[5] AFC created {name}: {info:?}");
    assert!(info.windows(2).any(|pair| pair == ["st_size", "14"]));
    let mut data = name.as_bytes().to_vec();
    data.push(0);
    let removed = files.transact(AFC_REMOVE_PATH, data, &[]).unwrap();
    assert_eq!(removed.status(), Some(0), "remove {name}");
    let gone = files
        .transact(AFC_GET_FILE_INFO, [name.as_bytes(), &[0]].concat(), &[])
        .unwrap();
    assert_eq!(gone.status(), Some(afc::OBJECT_NOT_FOUND));
    eprintln!("[5] AFC removed {name}");
}

fn instproxy_request(
    stream: &mut BoxStream,
    command: &str,
    options: Dictionary,
) -> Vec<Dictionary> {
    send_plist(
        stream,
        dict([
            ("Command", command.into()),
            ("ClientOptions", Value::Dictionary(options)),
        ]),
    )
    .unwrap();
    let mut replies = Vec::new();
    loop {
        let reply = recv_plist(stream).unwrap();
        assert!(string(&reply, "Error").is_none(), "{command}: {reply:?}");
        let done =
            string(&reply, "Status") == Some("Complete") || reply.contains_key("LookupResult");
        replies.push(reply);
        if done {
            return replies;
        }
    }
}

fn attributes() -> Value {
    Value::Array(vec![
        "CFBundleIdentifier".into(),
        "CFBundleShortVersionString".into(),
        "Path".into(),
    ])
}

fn probe_instproxy(
    address: &Address,
    device: u64,
    lockdown: &mut lockdown::Lockdown,
    pair: &PairRecord,
) {
    let mut stream = service(address, device, lockdown, pair, instproxy::SERVICE);
    let replies = instproxy_request(
        &mut stream,
        "Browse",
        dict([
            ("ApplicationType", "User".into()),
            ("ReturnAttributes", attributes()),
        ]),
    );
    let mut apps: Vec<String> = replies
        .iter()
        .filter_map(|reply| reply.get("CurrentList")?.as_array())
        .flatten()
        .filter_map(|app| {
            let app = app.as_dictionary()?;
            Some(format!(
                "{}, \"{}\"",
                string(app, "CFBundleIdentifier")?,
                string(app, "CFBundleShortVersionString").unwrap_or("")
            ))
        })
        .collect();
    apps.sort();
    eprintln!(
        "[6] instproxy Browse User ({} apps, {} replies):",
        apps.len(),
        replies.len()
    );
    for app in &apps {
        eprintln!("      {app}");
    }
    drop(stream);
    let mut stream = service(address, device, lockdown, pair, instproxy::SERVICE);
    let lookup = instproxy_request(
        &mut stream,
        "Lookup",
        dict([
            ("BundleIDs", Value::Array(vec![PROBE_APP.into()])),
            ("ReturnAttributes", attributes()),
        ]),
    );
    let result = lookup
        .last()
        .unwrap()
        .get("LookupResult")
        .unwrap()
        .as_dictionary()
        .unwrap();
    let app = result.get(PROBE_APP).unwrap().as_dictionary().unwrap();
    eprintln!("[6] instproxy Lookup {PROBE_APP}: {app:?}");
}

/// Services that may demand service TLS (`EnableServiceSSL`). Each is only
/// started, TLS-upgraded when asked, and closed again; debugserver (needs
/// the mounted Developer Disk Image) additionally answers `QStartNoAckMode`.
const SSL_CANDIDATES: &[&str] = &[
    DEBUGSERVER,
    "com.apple.webinspector",
    "com.apple.mobile.heartbeat",
    "com.apple.syslog_relay",
];

fn probe_service_tls(
    address: &Address,
    device: u64,
    lockdown: &mut lockdown::Lockdown,
    pair: &PairRecord,
) {
    for name in SSL_CANDIDATES {
        let service = match lockdown.start_service(name) {
            Ok(service) => service,
            Err(error) => {
                eprintln!("[4] StartService {name}: {error}");
                continue;
            }
        };
        let stream = usbmux::connect(address, device, service.port).unwrap();
        eprintln!(
            "[4] StartService {name}: port {} ssl {}",
            service.port, service.ssl
        );
        if !service.ssl {
            continue;
        }
        let mut stream = upgrade(stream, pair).unwrap();
        eprintln!("[4] {name}: service TLS handshake ok");
        if *name == DEBUGSERVER {
            stream.write_all(b"$QStartNoAckMode#b0").unwrap();
            stream.flush().unwrap();
            let mut reply = [0; 7];
            stream.read_exact(&mut reply).unwrap();
            eprintln!("[4] {name}: {:?}", String::from_utf8_lossy(&reply));
        }
    }
}

#[test]
#[ignore = "needs a real, unlocked, paired device: set IPAKEEP_DEVICE_UDID"]
fn real_device_protocol_stack() {
    let Ok(udid) = std::env::var("IPAKEEP_DEVICE_UDID") else {
        eprintln!("IPAKEEP_DEVICE_UDID is not set; skipping");
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let address = Address::from_env();
    let devices = usbmux::list_devices(&address).unwrap();
    eprintln!("[1] usbmuxd ListDevices: {devices:?}");
    let device = usbmux::find_device(&devices, &udid).unwrap();
    let record = usbmux::read_pair_record(&address, &device.serial).unwrap();
    let pair = PairRecord::parse(&record).unwrap();
    eprintln!(
        "[2] ReadPairRecord: {} bytes, HostID {}, SystemBUID {}",
        record.len(),
        pair.host_id,
        pair.system_buid
    );
    let stream = usbmux::connect(&address, device.id, lockdown::PORT).unwrap();
    let mut lockdown = lockdown::Lockdown::open(stream, &pair).unwrap();
    eprintln!("[3] lockdownd QueryType + StartSession + TLS: ok");
    for key in [
        "ProductVersion",
        "ProductType",
        "UniqueDeviceID",
        "DeviceName",
    ] {
        eprintln!("[3] GetValue {key}: {:?}", lockdown.get_value(key).unwrap());
    }
    probe_service_tls(&address, device.id, &mut lockdown, &pair);
    let files = Afc::new(service(
        &address,
        device.id,
        &mut lockdown,
        &pair,
        afc::SERVICE,
    ));
    probe_afc(files);
    probe_instproxy(&address, device.id, &mut lockdown, &pair);
}
