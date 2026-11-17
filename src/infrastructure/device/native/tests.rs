//! End-to-end tests of the native install stack against the in-process fake
//! device in [`super::fake`].

use super::afc::op;
use super::fake::{Fake, Identity, Scenario, UDID, install_error, pair_record, serve_tcp};
use super::tls::PairRecord;
use super::*;
use plist::Value;
use std::fs;
use std::sync::Arc;

const BIG: usize = (1 << 20) + 17;

/// A signed-looking bundle: nested directories, an empty file, a file larger
/// than one AFC write chunk, and (on UNIX) a symlink.
fn app_bundle(root: &Path) -> std::path::PathBuf {
    let app = root.join("Test.app");
    fs::create_dir_all(app.join("Frameworks/Kit.framework")).unwrap();
    fs::write(app.join("Info.plist"), b"info").unwrap();
    fs::write(app.join("Empty"), b"").unwrap();
    fs::write(app.join("Frameworks/Kit.framework/Kit"), vec![0xab; BIG]).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("Info.plist", app.join("Link")).unwrap();
    app
}

fn run(fake: &Fake, app: &Path) -> (Result<(), String>, Vec<Progress>) {
    let mut updates = Vec::new();
    let result = install_app(&fake.address, UDID, app, &mut |update| {
        updates.push(update.clone());
    });
    (result, updates)
}

fn install_with(scenario: Scenario) -> (Fake, Result<(), String>, Vec<Progress>) {
    let dir = tempfile::tempdir().unwrap();
    let app = app_bundle(dir.path());
    let fake = serve_tcp(scenario);
    let (result, updates) = run(&fake, &app);
    (fake, result, updates)
}

fn failure(scenario: Scenario) -> String {
    install_with(scenario).1.unwrap_err()
}

fn assert_installed(fake: &Fake, updates: &[Progress]) {
    let recorded = fake.recorded();
    assert_eq!(recorded.pair_record_ids, ["00008030001A2B3C4D5E6F70"]);
    assert_eq!(
        recorded.connected_ports,
        [lockdown::PORT, fake::INSTPROXY_PORT, fake::AFC_PORT]
    );
    assert_eq!(
        recorded.dirs,
        [
            "PublicStaging",
            "PublicStaging/Test.app",
            "PublicStaging/Test.app/Frameworks",
            "PublicStaging/Test.app/Frameworks/Kit.framework",
        ]
    );
    assert_eq!(recorded.removed, ["PublicStaging/Test.app"]);
    assert_eq!(recorded.files["PublicStaging/Test.app/Info.plist"], b"info");
    assert_eq!(recorded.files["PublicStaging/Test.app/Empty"], b"");
    assert_eq!(
        recorded.files["PublicStaging/Test.app/Frameworks/Kit.framework/Kit"],
        vec![0xab; BIG]
    );
    #[cfg(unix)]
    assert_eq!(
        recorded.links,
        [(
            "PublicStaging/Test.app/Link".to_string(),
            "Info.plist".to_string()
        )]
    );
    let install = recorded.install.as_ref().unwrap();
    assert_eq!(
        install.get("Command").and_then(Value::as_string),
        Some("Install")
    );
    assert_eq!(
        install.get("PackagePath").and_then(Value::as_string),
        Some("PublicStaging/Test.app")
    );
    let options = install
        .get("ClientOptions")
        .and_then(Value::as_dictionary)
        .unwrap();
    assert_eq!(
        options.get("PackageType").and_then(Value::as_string),
        Some("Developer")
    );
    let statuses: Vec<_> = updates
        .iter()
        .map(|update| (update.status.as_str(), update.percent))
        .collect();
    assert_eq!(
        statuses,
        [
            ("CreatingStagingDirectory", Some(5)),
            ("InstallingApplication", Some(60)),
            ("Complete", None),
        ]
    );
}

#[test]
fn installs_over_tcp_with_a_tls12_lockdown_session() {
    let (fake, result, updates) = install_with(Scenario {
        tls12_only: true,
        ..Scenario::working()
    });
    result.unwrap();
    assert_installed(&fake, &updates);
}

#[cfg(unix)]
#[test]
fn installs_over_a_unix_socket_with_tls13_and_service_tls() {
    let dir = tempfile::tempdir().unwrap();
    let app = app_bundle(dir.path());
    let fake = fake::serve_unix(
        Scenario {
            service_ssl: true,
            ..Scenario::working()
        },
        &dir.path().join("usbmuxd"),
    );
    let (result, updates) = run(&fake, &app);
    result.unwrap();
    assert_installed(&fake, &updates);
}

#[test]
fn installs_without_session_tls_and_prefers_usb_over_network() {
    let (fake, result, _) = install_with(Scenario {
        session_ssl: false,
        devices: vec![
            (3, "00008030001A2B3C4D5E6F70", "Network"),
            (7, "00008030001A2B3C4D5E6F70", "USB"),
        ],
        ..Scenario::working()
    });
    result.unwrap();
    assert_eq!(fake.recorded().connected_ports.len(), 3);
}

#[test]
fn missing_device_lists_what_usbmuxd_sees() {
    let error = failure(Scenario {
        devices: vec![(1, "OTHER-UDID", "USB")],
        ..Scenario::working()
    });
    assert!(
        error.contains("device 00008030-001A2B3C4D5E6F70 not found"),
        "{error}"
    );
    assert!(error.contains("attached: OTHER-UDID"), "{error}");
}

#[test]
fn unpaired_device_asks_to_trust_the_computer() {
    let error = failure(Scenario {
        pair_record: None,
        ..Scenario::working()
    });
    assert!(
        error.contains("no pair record") && error.contains("Trust This Computer"),
        "{error}"
    );
}

#[test]
fn invalid_pairing_is_reported_by_lockdown_and_by_the_tls_pin() {
    let error = failure(Scenario {
        session_error: Some("InvalidHostID"),
        ..Scenario::working()
    });
    assert!(
        error.contains("StartSession failed with InvalidHostID"),
        "{error}"
    );

    let impostor = Scenario {
        device: Arc::new(Identity::new(3, "impostor")),
        ..Scenario::working()
    };
    let error = failure(impostor);
    assert!(
        error.contains("TLS handshake with the device failed"),
        "{error}"
    );
}

#[test]
fn malformed_pair_records_are_rejected() {
    let host = Identity::new(1, "host");
    let device = Identity::new(2, "device");
    let mut record = Value::from_reader(std::io::Cursor::new(pair_record(&host, &device)))
        .unwrap()
        .into_dictionary()
        .unwrap();
    let encode = |record: &plist::Dictionary| {
        let mut out = Vec::new();
        Value::Dictionary(record.clone())
            .to_writer_xml(&mut out)
            .unwrap();
        out
    };
    let parsed = PairRecord::parse(&encode(&record)).unwrap();
    assert_eq!(
        (parsed.host_id.as_str(), parsed.system_buid.as_str()),
        ("HOST-ID", "SYSTEM-BUID")
    );
    assert!(format!("{parsed:?}").contains("HOST-ID"));
    assert!(
        PairRecord::parse(b"junk")
            .unwrap_err()
            .starts_with("pair record: invalid plist")
    );

    let mut broken = record.clone();
    broken.remove("HostID");
    assert!(
        PairRecord::parse(&encode(&broken))
            .unwrap_err()
            .contains("no HostID")
    );
    broken = record.clone();
    broken.insert("HostCertificate".into(), "text".into());
    assert!(
        PairRecord::parse(&encode(&broken))
            .unwrap_err()
            .contains("no HostCertificate")
    );
    broken = record.clone();
    broken.insert("HostCertificate".into(), Value::Data(b"no pem".to_vec()));
    assert!(
        PairRecord::parse(&encode(&broken))
            .unwrap_err()
            .contains("not a PEM certificate")
    );
    broken = record.clone();
    broken.insert("HostPrivateKey".into(), Value::Data(b"no pem".to_vec()));
    assert!(
        PairRecord::parse(&encode(&broken))
            .unwrap_err()
            .contains("not a PEM key")
    );
    broken = record.clone();
    broken.insert(
        "DeviceCertificate".into(),
        Value::Data(fake::pem("CERTIFICATE", b"xx")),
    );
    assert!(
        PairRecord::parse(&encode(&broken))
            .unwrap_err()
            .contains("not an X.509")
    );

    record.insert(
        "HostPrivateKey".into(),
        Value::Data(fake::pem("PRIVATE KEY", b"garbage")),
    );
    let fake = serve_tcp(Scenario {
        pair_record: Some(encode(&record)),
        ..Scenario::working()
    });
    let dir = tempfile::tempdir().unwrap();
    let error = run(&fake, &app_bundle(dir.path())).0.unwrap_err();
    assert!(error.contains("host key is unusable"), "{error}");
}

#[test]
fn lockdown_protocol_failures_are_explained() {
    let error = failure(Scenario {
        lockdown_type: "com.example.other",
        ..Scenario::working()
    });
    assert!(error.contains("did not answer as lockdownd"), "{error}");
    let error = failure(Scenario {
        service_error: Some("InvalidService"),
        ..Scenario::working()
    });
    assert!(
        error.contains("StartService failed with InvalidService"),
        "{error}"
    );
    let error = failure(Scenario {
        omit_service_port: true,
        ..Scenario::working()
    });
    assert!(error.contains("returned no port"), "{error}");
    let error = failure(Scenario {
        refuse_connect: true,
        ..Scenario::working()
    });
    assert!(error.contains("connection refused"), "{error}");
}

#[test]
fn install_errors_and_dropped_streams_fail_cleanly() {
    let (_, result, updates) = install_with(Scenario {
        install_replies: vec![
            plist::Dictionary::new(),
            install_error("ApplicationVerificationFailed", "0xe8008015"),
        ],
        ..Scenario::working()
    });
    let error = result.unwrap_err();
    assert!(
        error.contains("ApplicationVerificationFailed — 0xe8008015 — the device rejected"),
        "{error}"
    );
    assert_eq!(
        updates,
        [Progress {
            status: String::new(),
            percent: None
        }]
    );

    let error = failure(Scenario {
        install_replies: vec![dict_status("InstallingApplication")],
        ..Scenario::working()
    });
    assert!(
        error.contains("installation_proxy: connection to the device closed unexpectedly"),
        "{error}"
    );
}

fn dict_status(status: &str) -> plist::Dictionary {
    codec::dict([("Status", status.into())])
}

#[test]
fn afc_failures_name_the_path_and_error() {
    let cases = [
        (
            (op::FILE_OPEN, Some(10)),
            "AFC open PublicStaging/Test.app/Empty failed: permission denied",
        ),
        (
            (op::FILE_OPEN, None),
            "AFC open PublicStaging/Test.app/Empty: unexpected reply",
        ),
        (
            (op::FILE_WRITE, Some(18)),
            "write PublicStaging/Test.app/Frameworks/Kit.framework/Kit failed: no space left",
        ),
        (
            (op::FILE_CLOSE, Some(20)),
            "close PublicStaging/Test.app/Empty failed: I/O error",
        ),
        (
            (op::MAKE_DIR, None),
            "AFC mkdir PublicStaging: unexpected reply",
        ),
        (
            (op::REMOVE_PATH_AND_CONTENTS, Some(10)),
            "AFC remove PublicStaging/Test.app failed",
        ),
        (
            (op::MAKE_LINK, Some(16)),
            "symlink PublicStaging/Test.app/Link failed: object exists",
        ),
    ];
    for (failure_mode, expected) in cases {
        if cfg!(not(unix)) && failure_mode.0 == op::MAKE_LINK {
            continue;
        }
        let error = failure(Scenario {
            afc_failure: Some(failure_mode),
            ..Scenario::working()
        });
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn unreadable_local_bundles_fail_before_or_during_upload() {
    let fake = serve_tcp(Scenario::working());
    let dir = tempfile::tempdir().unwrap();
    let error = run(&fake, &dir.path().join("Missing.app")).0.unwrap_err();
    assert!(error.contains("Missing.app"), "{error}");
}

#[test]
fn progress_lines_show_percentages_when_known() {
    let mut update = Progress {
        status: "Complete".into(),
        percent: None,
    };
    assert_eq!(progress_line(&update), "  Complete");
    update.percent = Some(40);
    assert_eq!(progress_line(&update), "  Complete (40%)");
    print_progress(&update);
}
