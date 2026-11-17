//! RSA key + PKCS#10 Certificate Signing Request generation.
//!
//! Apple's Developer Services issues a development certificate in exchange for a
//! CSR signed by a 2048-bit RSA key. The key is generated and the request is
//! encoded and signed (`sha256WithRSAEncryption`) in pure Rust.

use rsa::PrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, SignatureEncoding, Signer};
use std::fmt::Display;
use std::time::Instant;
use x509_cert::der::asn1::{Any, BitString, PrintableStringRef, SetOfVec, Utf8StringRef};
use x509_cert::der::{Decode, Encode, EncodePem};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::request::{CertReq, CertReqInfo, Version};
use x509_cert::spki::{DynSignatureAlgorithmIdentifier, ObjectIdentifier, SubjectPublicKeyInfo};

/// RSA modulus size Apple requires for development certificates.
const RSA_KEY_BITS: usize = 2048;
/// RFC 5280 `ub-common-name`; `openssl req` enforces the same limit.
const MAX_COMMON_NAME_CHARS: usize = 64;
const ORGANIZATION: &str = "ipakeep";
const COUNTRY: &str = "US";
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
const OID_COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");

/// A freshly generated private key (PEM) and its CSR (PEM).
#[derive(Debug, Clone)]
pub struct KeyAndCsr {
    /// PKCS#8 private key, PEM-encoded.
    pub key_pem: Vec<u8>,
    /// Certificate signing request, PEM-encoded.
    pub csr_pem: Vec<u8>,
}

/// Generate a 2048-bit RSA key and a CSR for `CN=<common_name>, O=ipakeep, C=US`.
///
/// # Errors
///
/// Returns an error if `common_name` contains control characters or exceeds
/// 64 characters, or if key generation or encoding fails.
pub fn generate_key_and_csr(common_name: &str) -> Result<KeyAndCsr, String> {
    generate_with_key_bits(common_name, RSA_KEY_BITS)
}

/// [`generate_key_and_csr`] with a `key_bits` RSA key, logging the outcome.
fn generate_with_key_bits(common_name: &str, key_bits: usize) -> Result<KeyAndCsr, String> {
    let started = Instant::now();
    let result = validate_common_name(common_name)
        .map_err(|error| ("invalid_common_name", error))
        .and_then(|()| build_key_and_csr(common_name, key_bits).map_err(generation_failed));
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match result {
        Ok(pair) => {
            tracing::info!(
                service = "ipakeep",
                component = "developer",
                operation = "generate_csr",
                event_name = "developer.csr.generated",
                outcome = "success",
                key_bits = RSA_KEY_BITS,
                duration_ms,
                "developer key and CSR generated"
            );
            Ok(pair)
        }
        Err((error_type, error)) => {
            tracing::warn!(
                service = "ipakeep",
                component = "developer",
                operation = "generate_csr",
                event_name = "developer.csr.failed",
                outcome = "failure",
                error_type,
                duration_ms,
                "developer key and CSR generation failed"
            );
            Err(error)
        }
    }
}

/// Tags a key or CSR generation failure for the outcome log.
fn generation_failed(error: String) -> (&'static str, String) {
    ("generation_failed", error)
}

/// Generate a `key_bits` RSA key and a CSR signed by it for `common_name`.
fn build_key_and_csr(common_name: &str, key_bits: usize) -> Result<KeyAndCsr, String> {
    let subject = subject_name(common_name).map_err(csr_error("CSR subject"))?;
    let private_key = PrivateKey::new(&mut rand::rng(), key_bits)
        .map_err(csr_error("RSA key generation failed"))?;
    let key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(csr_error("PKCS#8 encoding failed"))?;
    let csr = signed_request(subject, &SigningKey::<Sha256>::new(private_key))?;
    let csr_pem = csr
        .to_pem(LineEnding::LF)
        .map_err(csr_error("CSR encoding failed"))?;
    Ok(KeyAndCsr {
        key_pem: key_pem.as_bytes().to_vec(),
        csr_pem: csr_pem.into_bytes(),
    })
}

/// Maps the failure of a CSR generation `stage` to its error message.
fn csr_error<E: Display>(stage: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{stage}: {error}")
}

fn validate_common_name(common_name: &str) -> Result<(), String> {
    if common_name.chars().any(char::is_control) {
        return Err("certificate common name must not contain control characters".into());
    }
    if common_name.chars().count() > MAX_COMMON_NAME_CHARS {
        return Err(format!(
            "certificate common name exceeds {MAX_COMMON_NAME_CHARS} characters"
        ));
    }
    Ok(())
}

fn subject_name(common_name: &str) -> x509_cert::der::Result<Name> {
    let rdns = vec![
        rdn(
            OID_COMMON_NAME,
            Any::encode_from(&Utf8StringRef::new(common_name)?)?,
        )?,
        rdn(
            OID_ORGANIZATION,
            Any::encode_from(&Utf8StringRef::new(ORGANIZATION)?)?,
        )?,
        rdn(
            OID_COUNTRY,
            Any::encode_from(&PrintableStringRef::new(COUNTRY)?)?,
        )?,
    ];
    Name::from_der(&RdnSequence::from(rdns).to_der()?)
}

fn rdn(oid: ObjectIdentifier, value: Any) -> x509_cert::der::Result<RelativeDistinguishedName> {
    RelativeDistinguishedName::try_from(vec![x509_cert::attr::AttributeTypeAndValue { oid, value }])
}

fn signed_request(subject: Name, signer: &SigningKey<Sha256>) -> Result<CertReq, String> {
    let info = CertReqInfo {
        version: Version::V1,
        subject,
        public_key: SubjectPublicKeyInfo::from_key(&signer.verifying_key())
            .map_err(csr_error("CSR public key"))?,
        attributes: SetOfVec::new(),
    };
    let tbs = info.to_der().map_err(csr_error("CSR encoding"))?;
    let signature = signer
        .try_sign(&tbs)
        .map_err(csr_error("CSR signing failed"))?;
    Ok(CertReq {
        info,
        algorithm: signer
            .signature_algorithm_identifier()
            .map_err(csr_error("CSR signature algorithm"))?,
        signature: BitString::from_bytes(&signature.to_bytes())
            .map_err(csr_error("CSR signature"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::observability::log_capture::LogCapture;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::Verifier;
    use rsa::traits::PublicKeyParts;
    use x509_cert::der::DecodePem;
    use x509_cert::spki::DecodePublicKey;

    const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

    fn parse(pair: &KeyAndCsr) -> (PrivateKey, CertReq) {
        let key = PrivateKey::from_pkcs8_pem(std::str::from_utf8(&pair.key_pem).unwrap())
            .expect("PKCS#8 PEM key");
        let csr = CertReq::from_pem(&pair.csr_pem).expect("PEM CSR");
        (key, csr)
    }

    #[test]
    fn generates_a_2048_bit_pkcs8_key_and_a_self_signed_csr() {
        let pair = generate_key_and_csr("ipakeep-test").unwrap();
        assert!(String::from_utf8_lossy(&pair.key_pem).starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(
            String::from_utf8_lossy(&pair.csr_pem)
                .starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        );
        let (key, csr) = parse(&pair);
        assert_eq!(key.n().bit_width(), 2048);
        assert_eq!(csr.info.version, Version::V1);
        assert!(csr.info.attributes.is_empty());
        assert_eq!(csr.algorithm.oid.to_string(), SHA256_WITH_RSA);

        let spki_der = csr.info.public_key.to_der().unwrap();
        let verifier = VerifyingKey::<Sha256>::from_public_key_der(&spki_der).unwrap();
        assert_eq!(verifier.as_ref(), &key.to_public_key());
        let signature = Signature::try_from(csr.signature.raw_bytes()).unwrap();
        verifier
            .verify(&csr.info.to_der().unwrap(), &signature)
            .expect("CSR self-signature verifies");
    }

    #[test]
    fn reports_rsa_key_generation_failure_for_an_undersized_modulus() {
        // The RSA crate refuses moduli below 1024 bits before generating primes.
        const UNDERSIZED_KEY_BITS: usize = 512;
        let error = generate_with_key_bits("ipakeep-test", UNDERSIZED_KEY_BITS).unwrap_err();
        assert!(
            error.starts_with("RSA key generation failed:"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn subject_is_common_name_organization_country_in_order() {
        let (_, csr) = parse(&generate_key_and_csr("Test iPhone, 15 Pro").unwrap());
        let subject = &csr.info.subject;
        assert_eq!(
            subject.to_string(),
            "C=US,O=ipakeep,CN=Test iPhone\\, 15 Pro"
        );
        let oids: Vec<String> = subject.iter().map(|atv| atv.oid.to_string()).collect();
        assert_eq!(oids, ["2.5.4.3", "2.5.4.10", "2.5.4.6"]);
    }

    #[test]
    fn rejects_control_characters_in_the_common_name() {
        assert!(generate_key_and_csr("invalid\0name").is_err());
        assert!(generate_key_and_csr("line\nbreak").is_err());
    }

    #[test]
    fn rejects_common_names_longer_than_64_characters() {
        assert!(generate_key_and_csr(&"a".repeat(65)).is_err());
        assert!(validate_common_name(&"é".repeat(64)).is_ok());
    }

    #[test]
    fn generation_logs_outcome_without_the_name_or_key_material() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        let pair = generate_key_and_csr("private-device-name").unwrap();
        let logs = capture.contents();

        assert!(logs.contains("developer.csr.generated"));
        assert!(logs.contains("outcome=\"success\""));
        assert!(logs.contains("key_bits=2048"));
        assert!(logs.contains("duration_ms="));
        assert!(!logs.contains("private-device-name"));
        assert!(!logs.contains("PRIVATE KEY"));
        let key_body = String::from_utf8_lossy(&pair.key_pem);
        let first_key_line = key_body.lines().nth(1).unwrap();
        assert!(!logs.contains(first_key_line));
    }

    #[test]
    fn invalid_names_log_a_failure_event() {
        let capture = LogCapture::default();
        let _guard = capture.install();
        assert!(generate_key_and_csr("secret\0name").is_err());
        let logs = capture.contents();

        assert!(logs.contains("developer.csr.failed"));
        assert!(logs.contains("WARN"));
        assert!(logs.contains("outcome=\"failure\""));
        assert!(logs.contains("error_type=\"invalid_common_name\""));
        assert!(!logs.contains("secret"));
    }
}
