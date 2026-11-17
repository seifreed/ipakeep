//! Pair records and the lockdown TLS upgrade (rustls, `ring` provider).
//!
//! The host authenticates with the pair record's `HostCertificate` /
//! `HostPrivateKey`. The device presents the `DeviceCertificate` that was
//! issued during pairing (its chain uses the record's private root, often
//! SHA-1 signed, so `WebPKI` validation does not apply). Instead of accepting
//! any certificate as libimobiledevice does, the device certificate's public
//! key is pinned to the pair record; the TLS handshake signature is still
//! verified against that key.

use super::BoxStream;
use super::codec::from_plist;
use plist::{Dictionary, Value};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme,
    StreamOwned,
};
use std::sync::Arc;

/// The parts of a usbmuxd pair record lockdownd needs.
#[derive(Debug)]
pub(crate) struct PairRecord {
    pub(crate) host_id: String,
    pub(crate) system_buid: String,
    host_certificate: CertificateDer<'static>,
    host_key: PrivateKeyDer<'static>,
    device_public_key: Vec<u8>,
}

impl PairRecord {
    /// Parse the plist usbmuxd returns from `ReadPairRecord`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let record = from_plist(bytes).map_err(|error| format!("pair record: {error}"))?;
        let device_certificate = certificate(&record, "DeviceCertificate")?;
        Ok(Self {
            host_id: text(&record, "HostID")?,
            system_buid: text(&record, "SystemBUID")?,
            host_certificate: certificate(&record, "HostCertificate")?,
            host_key: PrivateKeyDer::from_pem_slice(pem(&record, "HostPrivateKey")?)
                .map_err(|error| format!("pair record HostPrivateKey is not a PEM key: {error}"))?,
            device_public_key: subject_public_key_info(&device_certificate)
                .ok_or("pair record DeviceCertificate is not an X.509 certificate")?
                .to_vec(),
        })
    }
}

fn text(record: &Dictionary, key: &str) -> Result<String, String> {
    super::codec::string(record, key)
        .map(str::to_string)
        .ok_or_else(|| format!("pair record has no {key}; re-pair the device"))
}

fn pem<'a>(record: &'a Dictionary, key: &str) -> Result<&'a [u8], String> {
    record
        .get(key)
        .and_then(Value::as_data)
        .ok_or_else(|| format!("pair record has no {key}; re-pair the device"))
}

fn certificate(record: &Dictionary, key: &str) -> Result<CertificateDer<'static>, String> {
    CertificateDer::from_pem_slice(pem(record, key)?)
        .map_err(|error| format!("pair record {key} is not a PEM certificate: {error}"))
}

/// Split one DER TLV, returning `(header_len, content_len)`.
fn tlv(der: &[u8]) -> Option<(usize, usize)> {
    let first = *der.get(1)?;
    if first < 0x80 {
        return Some((2, usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let len = der
        .get(2..2 + count)?
        .iter()
        .fold(0, |len, byte| (len << 8) | usize::from(*byte));
    Some((2 + count, len))
}

/// Content of the leading TLV and the bytes following it.
fn split(der: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let (header, len) = tlv(der)?;
    let end = header.checked_add(len).filter(|end| *end <= der.len())?;
    Some((&der[..end], &der[header..end], &der[end..]))
}

/// DER `SubjectPublicKeyInfo` of a certificate, located leniently (no
/// profile checks, so unusual pairing certificates still parse).
pub(super) fn subject_public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    let (_, certificate, _) = split(certificate)?;
    let (_, mut fields, _) = split(certificate)?;
    if fields.first() == Some(&0xa0) {
        fields = split(fields)?.2;
    }
    // serial, signature algorithm, issuer, validity, subject
    for _ in 0..5 {
        fields = split(fields)?.2;
    }
    split(fields).map(|(whole, _, _)| whole)
}

/// Accepts only the device certificate recorded at pairing time.
#[derive(Debug)]
struct PinnedDevice {
    public_key: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedDevice {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if subject_public_key_info(end_entity) == Some(self.public_key.as_slice()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
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

fn client_config(pair: &PairRecord) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedDevice {
            public_key: pair.device_public_key.clone(),
            provider,
        }))
        .with_client_auth_cert(
            vec![pair.host_certificate.clone()],
            pair.host_key.clone_key(),
        )
        .map_err(|error| format!("pair record host key is unusable: {error}"))
}

/// Run the TLS handshake over `stream` and return the encrypted stream.
pub(crate) fn upgrade(mut stream: BoxStream, pair: &PairRecord) -> Result<BoxStream, String> {
    let mut connection = ClientConnection::new(
        Arc::new(client_config(pair)?),
        ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
    )
    .expect("a TLS client for an IP server name always builds");
    connection.complete_io(&mut stream).map_err(|error| {
        format!(
            "TLS handshake with the device failed: {error} \
             (a certificate error means the pair record is stale; re-pair the device)"
        )
    })?;
    Ok(Box::new(StreamOwned::new(connection, stream)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_walker_handles_long_form_lengths_and_truncation() {
        assert_eq!(tlv(&[0x30, 0x03]), Some((2, 3)));
        assert_eq!(tlv(&[0x30, 0x82, 0x01, 0x00]), Some((4, 256)));
        assert_eq!(tlv(&[0x30, 0x80]), None);
        assert_eq!(tlv(&[0x30, 0x85, 1, 1, 1, 1, 1]), None);
        assert_eq!(tlv(&[0x30]), None);
        assert_eq!(split(&[0x30, 0x05, 0x00]), None);
        assert_eq!(subject_public_key_info(&[0x30, 0x02, 0x30, 0x00]), None);
        assert_eq!(subject_public_key_info(b""), None);
    }
}
