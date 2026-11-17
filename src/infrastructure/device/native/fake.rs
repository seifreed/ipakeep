//! In-process fake usbmuxd + lockdownd + AFC + `installation_proxy`, speaking
//! the real wire protocols (including the lockdown TLS upgrade) over loopback
//! TCP or a UNIX socket.

use super::afc::{OBJECT_NOT_FOUND, Packet, op};
use super::codec::{dict, recv_plist, send_plist, string, unsigned};
use super::{Address, BoxStream, afc, lockdown, usbmux};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use plist::{Dictionary, Value};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, ServerConfig, ServerConnection, SignatureScheme,
    StreamOwned,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

pub(super) const AFC_PORT: u16 = 49_152;
pub(super) const INSTPROXY_PORT: u16 = 49_153;

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 0x80 {
        out.push(u8::try_from(content.len()).unwrap());
    } else {
        let len: Vec<u8> = content
            .len()
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(len.len()).unwrap());
        out.extend(len);
    }
    out.extend(content);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}

/// A P-256 key with a minimal self-issued X.509 v3 certificate. The
/// certificate signature is a placeholder: lockdown TLS never validates the
/// chain, only the handshake signature made with the key.
pub(super) struct Identity {
    pub(super) certificate: Vec<u8>,
    pub(super) key: Vec<u8>,
}

impl Identity {
    pub(super) fn new(seed: u8, common_name: &str) -> Self {
        let secret = p256::SecretKey::from_bytes(&[seed; 32].into()).unwrap();
        let spki = secret.public_key().to_public_key_der().unwrap().into_vec();
        let algorithm = sequence(&[der(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
        let name = sequence(&[der(
            0x31,
            &sequence(&[
                der(0x06, &[0x55, 0x04, 0x03]),
                der(0x0c, common_name.as_bytes()),
            ]),
        )]);
        let validity = sequence(&[der(0x17, b"200101000000Z"), der(0x17, b"491231235959Z")]);
        let tbs = sequence(&[
            der(0xa0, &der(0x02, &[2])),
            der(0x02, &[seed]),
            algorithm.clone(),
            name.clone(),
            validity,
            name,
            spki,
        ]);
        let signature = der(0x03, &[0, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        Self {
            certificate: sequence(&[tbs, algorithm, signature]),
            key: secret.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        }
    }

    pub(super) fn certificate_pem(&self) -> Vec<u8> {
        pem("CERTIFICATE", &self.certificate)
    }

    pub(super) fn key_pem(&self) -> Vec<u8> {
        pem("PRIVATE KEY", &self.key)
    }
}

pub(super) fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    x509_cert::der::pem::encode_string(label, x509_cert::der::pem::LineEnding::LF, der)
        .unwrap()
        .into_bytes()
}

/// Binary-plist pair record as usbmuxd stores it.
pub(super) fn pair_record(host: &Identity, device: &Identity) -> Vec<u8> {
    let record = dict([
        ("HostID", "HOST-ID".into()),
        ("SystemBUID", "SYSTEM-BUID".into()),
        ("HostCertificate", Value::Data(host.certificate_pem())),
        ("HostPrivateKey", Value::Data(host.key_pem())),
        ("RootCertificate", Value::Data(host.certificate_pem())),
        ("DeviceCertificate", Value::Data(device.certificate_pem())),
    ]);
    let mut out = Vec::new();
    Value::Dictionary(record)
        .to_writer_binary(&mut out)
        .unwrap();
    out
}

/// What the fake device does.
#[derive(Clone)]
pub(super) struct Scenario {
    pub(super) devices: Vec<(u64, &'static str, &'static str)>,
    pub(super) pair_record: Option<Vec<u8>>,
    pub(super) host_certificate: Vec<u8>,
    pub(super) device: Arc<Identity>,
    pub(super) session_ssl: bool,
    pub(super) service_ssl: bool,
    pub(super) tls12_only: bool,
    pub(super) lockdown_type: &'static str,
    pub(super) session_error: Option<&'static str>,
    pub(super) service_error: Option<&'static str>,
    pub(super) omit_service_port: bool,
    pub(super) refuse_connect: bool,
    /// `(operation, Some(status))` fails that AFC operation; `None` replies
    /// with a non-status packet instead.
    pub(super) afc_failure: Option<(u64, Option<u64>)>,
    pub(super) install_replies: Vec<Dictionary>,
}

pub(super) const UDID: &str = "00008030-001A2B3C4D5E6F70";

impl Scenario {
    /// A paired device that installs successfully.
    pub(super) fn working() -> Self {
        let host = Identity::new(1, "ipakeep test host");
        let device = Identity::new(2, "ipakeep test device");
        Self {
            devices: vec![(7, "00008030001A2B3C4D5E6F70", "USB")],
            pair_record: Some(pair_record(&host, &device)),
            host_certificate: host.certificate,
            device: Arc::new(device),
            session_ssl: true,
            service_ssl: false,
            tls12_only: false,
            lockdown_type: "com.apple.mobile.lockdown",
            session_error: None,
            service_error: None,
            omit_service_port: false,
            refuse_connect: false,
            afc_failure: None,
            install_replies: vec![
                dict([
                    ("Status", "CreatingStagingDirectory".into()),
                    ("PercentComplete", 5_u64.into()),
                ]),
                dict([
                    ("Status", "InstallingApplication".into()),
                    ("PercentComplete", 60_u64.into()),
                ]),
                dict([("Status", "Complete".into())]),
            ],
        }
    }
}

/// Everything the fake device received.
#[derive(Default, Debug)]
pub(super) struct Recorded {
    pub(super) pair_record_ids: Vec<String>,
    pub(super) connected_ports: Vec<u16>,
    pub(super) dirs: Vec<String>,
    pub(super) removed: Vec<String>,
    pub(super) files: BTreeMap<String, Vec<u8>>,
    pub(super) links: Vec<(String, String)>,
    pub(super) install: Option<Dictionary>,
}

/// A running fake device.
pub(super) struct Fake {
    pub(super) address: Address,
    pub(super) recorded: Arc<Mutex<Recorded>>,
}

impl Fake {
    pub(super) fn recorded(&self) -> std::sync::MutexGuard<'_, Recorded> {
        self.recorded.lock().unwrap()
    }
}

/// Serve `scenario` on loopback TCP (the Windows usbmuxd transport).
pub(super) fn serve_tcp(scenario: Scenario) -> Fake {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = Address::Tcp(listener.local_addr().unwrap().to_string());
    serve(address, scenario, move || {
        listener
            .accept()
            .map(|(stream, _)| Box::new(stream) as BoxStream)
    })
}

/// Serve `scenario` on a UNIX socket at `path` (the macOS/Linux transport).
#[cfg(unix)]
pub(super) fn serve_unix(scenario: Scenario, path: &std::path::Path) -> Fake {
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    serve(Address::Unix(path.to_path_buf()), scenario, move || {
        listener
            .accept()
            .map(|(stream, _)| Box::new(stream) as BoxStream)
    })
}

fn serve(
    address: Address,
    scenario: Scenario,
    mut accept: impl FnMut() -> std::io::Result<BoxStream> + Send + 'static,
) -> Fake {
    let recorded = Arc::new(Mutex::new(Recorded::default()));
    let shared = (Arc::new(scenario), recorded.clone());
    std::thread::spawn(move || {
        while let Ok(stream) = accept() {
            let (scenario, recorded) = (shared.0.clone(), shared.1.clone());
            std::thread::spawn(move || handle_usbmux(stream, &scenario, &recorded));
        }
    });
    Fake { address, recorded }
}

fn handle_usbmux(mut stream: BoxStream, scenario: &Scenario, recorded: &Mutex<Recorded>) {
    let Ok((tag, request)) = usbmux::read_frame(&mut stream) else {
        return;
    };
    let reply = |stream: &mut BoxStream, message: Dictionary| {
        let _ = stream.write_all(&usbmux::encode(tag, message));
    };
    match string(&request, "MessageType").unwrap() {
        "ListDevices" => {
            let list = scenario
                .devices
                .iter()
                .map(|(id, serial, connection)| {
                    Value::Dictionary(dict([
                        ("MessageType", "Attached".into()),
                        (
                            "Properties",
                            Value::Dictionary(dict([
                                ("DeviceID", (*id).into()),
                                ("SerialNumber", (*serial).into()),
                                ("ConnectionType", (*connection).into()),
                            ])),
                        ),
                    ]))
                })
                .chain([Value::String("not a device".into())])
                .collect();
            reply(&mut stream, dict([("DeviceList", Value::Array(list))]));
        }
        "ReadPairRecord" => {
            let id = string(&request, "PairRecordID").unwrap().to_string();
            recorded.lock().unwrap().pair_record_ids.push(id);
            reply(
                &mut stream,
                scenario.pair_record.clone().map_or_else(
                    || dict([("MessageType", "Result".into()), ("Number", 2_u64.into())]),
                    |data| dict([("PairRecordData", Value::Data(data))]),
                ),
            );
        }
        _ => {
            let raw = u16::try_from(unsigned(&request, "PortNumber").unwrap()).unwrap();
            let port = u16::from_be_bytes(raw.to_ne_bytes());
            recorded.lock().unwrap().connected_ports.push(port);
            let code = if scenario.refuse_connect { 3_u64 } else { 0 };
            reply(
                &mut stream,
                dict([("MessageType", "Result".into()), ("Number", code.into())]),
            );
            match port {
                lockdown::PORT => serve_lockdown(stream, scenario),
                AFC_PORT => serve_afc(service_stream(stream, scenario), scenario, recorded),
                _ => serve_instproxy(service_stream(stream, scenario), scenario, recorded),
            }
        }
    }
}

fn service_stream(stream: BoxStream, scenario: &Scenario) -> BoxStream {
    if scenario.service_ssl {
        server_tls(stream, scenario)
    } else {
        stream
    }
}

fn serve_lockdown(mut stream: BoxStream, scenario: &Scenario) {
    while let Ok(request) = recv_plist(&mut stream) {
        let kind = string(&request, "Request").unwrap();
        let error = match kind {
            "QueryType" => None,
            "StartSession" => scenario.session_error,
            _ => scenario.service_error,
        };
        let reply = match (kind, error) {
            (_, Some(error)) => dict([("Error", error.into())]),
            ("QueryType", None) => dict([("Type", scenario.lockdown_type.into())]),
            ("GetValue", None) => get_value(&request),
            ("StartSession", None) => dict([
                ("SessionID", "SESSION".into()),
                ("EnableSessionSSL", scenario.session_ssl.into()),
            ]),
            _ => {
                let port = if string(&request, "Service") == Some(afc::SERVICE) {
                    AFC_PORT
                } else {
                    INSTPROXY_PORT
                };
                let mut reply = dict([("EnableServiceSSL", scenario.service_ssl.into())]);
                if !scenario.omit_service_port {
                    reply.insert("Port".into(), u64::from(port).into());
                }
                reply
            }
        };
        let _ = send_plist(&mut stream, reply);
        if kind == "StartSession" && error.is_none() && scenario.session_ssl {
            stream = server_tls(stream, scenario);
        }
    }
}

/// `GetValue` replies with the iPhone 8 / iOS 16.7.16 values the real-device
/// probe recorded; unknown keys come back without a `Value`, as lockdownd does.
fn get_value(request: &Dictionary) -> Dictionary {
    let mut reply = dict([("Request", "GetValue".into())]);
    let value = match string(request, "Key") {
        Some("ProductVersion") => Some("16.7.16"),
        Some("ProductType") => Some("iPhone10,1"),
        _ => None,
    };
    if let Some(value) = value {
        reply.insert("Value".into(), value.into());
    }
    reply
}

fn c_string(bytes: &[u8]) -> (String, &[u8]) {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap();
    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        &bytes[end + 1..],
    )
}

fn serve_afc(mut stream: BoxStream, scenario: &Scenario, recorded: &Mutex<Recorded>) {
    let mut handles: Vec<String> = Vec::new();
    while let Ok(request) = Packet::read(&mut stream) {
        let mut operation = op::STATUS;
        let mut data = 0_u64.to_le_bytes().to_vec();
        let mut recorded = recorded.lock().unwrap();
        match scenario
            .afc_failure
            .filter(|(failed, _)| *failed == request.operation)
        {
            Some((_, Some(status))) => data = status.to_le_bytes().to_vec(),
            Some((_, None)) => operation = 0x02,
            None => match request.operation {
                op::MAKE_DIR => recorded.dirs.push(c_string(&request.data).0),
                op::REMOVE_PATH_AND_CONTENTS => {
                    recorded.removed.push(c_string(&request.data).0);
                    data = OBJECT_NOT_FOUND.to_le_bytes().to_vec();
                }
                op::FILE_OPEN => {
                    handles.push(c_string(&request.data[8..]).0);
                    operation = op::FILE_OPEN_RESULT;
                    data = (handles.len() as u64 - 1).to_le_bytes().to_vec();
                }
                op::FILE_WRITE | op::FILE_CLOSE => {
                    let handle = u64::from_le_bytes(request.data[..8].try_into().unwrap());
                    let path = handles[usize::try_from(handle).unwrap()].clone();
                    recorded
                        .files
                        .entry(path)
                        .or_default()
                        .extend(&request.payload);
                }
                _ => {
                    let (target, rest) = c_string(&request.data[8..]);
                    recorded.links.push((c_string(rest).0, target));
                }
            },
        }
        drop(recorded);
        let reply = Packet {
            number: request.number,
            operation,
            data,
            payload: Vec::new(),
        };
        let _ = stream.write_all(&reply.encode());
    }
}

fn serve_instproxy(mut stream: BoxStream, scenario: &Scenario, recorded: &Mutex<Recorded>) {
    if let Ok(request) = recv_plist(&mut stream) {
        recorded.lock().unwrap().install = Some(request);
        for reply in &scenario.install_replies {
            let _ = send_plist(&mut stream, reply.clone());
        }
    }
}

/// Device side of the TLS upgrade, requiring the pair record's host certificate.
pub(super) fn server_tls(stream: BoxStream, scenario: &Scenario) -> BoxStream {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if scenario.tls12_only {
        &[&rustls::version::TLS12]
    } else {
        rustls::DEFAULT_VERSIONS
    };
    let config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .unwrap()
        .with_client_cert_verifier(Arc::new(ExpectHost {
            certificate: scenario.host_certificate.clone(),
            provider,
        }))
        .with_single_cert(
            vec![CertificateDer::from(scenario.device.certificate.clone())],
            PrivateKeyDer::Pkcs8(scenario.device.key.clone().into()),
        )
        .unwrap();
    Box::new(StreamOwned::new(
        ServerConnection::new(Arc::new(config)).unwrap(),
        stream,
    ))
}

#[derive(Debug)]
struct ExpectHost {
    certificate: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ExpectHost {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        assert_eq!(end_entity.as_ref(), self.certificate.as_slice());
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Install-error reply as `installation_proxy` sends it.
pub(super) fn install_error(code: &str, description: &str) -> Dictionary {
    dict([
        ("Error", code.into()),
        ("ErrorDescription", description.into()),
    ])
}
