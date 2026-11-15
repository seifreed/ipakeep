//! Native `FairPlay` SAP request signer.
//!
//! Port of upstream ipatool's `internal/sap/signer.go` and `signer_local.go`:
//! starts a SAP session in the emulated `AppleMediaServices`, completes the
//! setup handshake with Apple and then signs request payloads.
//!
//! The signer owns a Unicorn emulator, so it is `!Send`; drive it from one
//! thread (for example inside `spawn_blocking` with a current-thread runtime).

use reqwest::Url;
use thiserror::Error;

use super::assets::bundle::Bundle;
use super::machine::sap::{GuestEnvironment, MachineError, SAP_VERSION, SapMachine};
use super::protocol::{ProtocolError, SetupTransport, exchange_setup, fetch_certificate};

const SECURE_SCHEME: &str = "https";
const MAX_HARDWARE_ID: usize = 20;
const SETUP_PENDING_STATE: i32 = 1;
const SETUP_COMPLETE_STATE: i32 = 0;

/// Failure of the SAP signer.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The configuration is invalid.
    #[error("{0}")]
    Config(String),
    /// The emulated SAP runtime failed.
    #[error(transparent)]
    Machine(#[from] MachineError),
    /// The setup handshake with Apple failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// A setup step left the session in an unexpected state.
    #[error("SAP {phase} entered unexpected state {state}")]
    UnexpectedState {
        /// Which setup step.
        phase: &'static str,
        /// The reported state.
        state: i32,
    },
    /// The runtime produced an empty setup message or signature.
    #[error("SAP {0} is empty")]
    Empty(&'static str),
}

/// Where and how to establish the SAP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerConfig {
    /// The bag's `sign-sap-setup` URL.
    pub setup_url: String,
    /// The bag's `sign-sap-setup-cert` URL.
    pub certificate_url: String,
    /// SAP protocol version; only [`SAP_VERSION`] is supported.
    pub version: u32,
    /// Device hardware identifier (1–20 bytes, e.g. the MAC address).
    pub hardware_id: Vec<u8>,
}

impl SignerConfig {
    /// Validates the version, identifier length and both endpoints.
    ///
    /// # Errors
    /// Returns [`SignerError::Config`] describing the first violation.
    pub fn validate(&self) -> Result<(), SignerError> {
        if self.version != SAP_VERSION {
            return Err(SignerError::Config(format!(
                "unsupported SAP version {}",
                self.version
            )));
        }
        if self.hardware_id.is_empty() || self.hardware_id.len() > MAX_HARDWARE_ID {
            return Err(SignerError::Config(
                "SAP hardware ID must contain between 1 and 20 bytes".to_owned(),
            ));
        }
        validate_endpoint("setup", &self.setup_url)?;
        validate_endpoint("certificate", &self.certificate_url)
    }
}

fn validate_endpoint(label: &str, value: &str) -> Result<(), SignerError> {
    let valid = Url::parse(value).is_ok_and(|url| {
        url.scheme() == SECURE_SCHEME
            && url.host_str().is_some_and(|host| !host.is_empty())
            && url.username().is_empty()
            && url.password().is_none()
    });
    if valid {
        Ok(())
    } else {
        Err(SignerError::Config(format!(
            "SAP {label} URL must be an absolute HTTPS URL"
        )))
    }
}

/// A SAP session that completed setup and signs Apple requests.
pub struct SapSigner {
    machine: SapMachine,
    context: Option<u64>,
}

impl SapSigner {
    /// Starts the runtime, initialises a session and completes the setup
    /// handshake over `transport`.
    ///
    /// # Errors
    /// Fails on invalid configuration, a runtime failure, a protocol failure
    /// or an unexpected setup state.
    pub async fn connect(
        bundle: &Bundle,
        environment: &GuestEnvironment,
        config: &SignerConfig,
        transport: &impl SetupTransport,
    ) -> Result<Self, SignerError> {
        config.validate()?;
        let mut machine = SapMachine::open(bundle, environment)?;
        let context = machine.initialize(&config.hardware_id)?;
        let mut signer = Self {
            machine,
            context: Some(context),
        };
        let certificate = fetch_certificate(transport, &config.certificate_url).await?;
        let request = signer.setup_step(config, &certificate, "setup", SETUP_PENDING_STATE)?;
        if request.is_empty() {
            return Err(SignerError::Empty("setup message"));
        }
        let reply = exchange_setup(transport, &config.setup_url, &request).await?;
        signer.setup_step(config, &reply, "setup completion", SETUP_COMPLETE_STATE)?;
        Ok(signer)
    }

    fn setup_step(
        &mut self,
        config: &SignerConfig,
        input: &[u8],
        phase: &'static str,
        expected: i32,
    ) -> Result<Vec<u8>, SignerError> {
        let context = self.context.unwrap_or_default();
        let step = self
            .machine
            .exchange(config.version, &config.hardware_id, context, input)?;
        if step.state != expected {
            return Err(SignerError::UnexpectedState {
                phase,
                state: step.state,
            });
        }
        Ok(step.output)
    }

    /// Signs `input` (for example a request body or the action string).
    ///
    /// # Errors
    /// Fails on a runtime failure or an empty signature.
    pub fn sign(&mut self, input: &[u8]) -> Result<Vec<u8>, SignerError> {
        let context = self.context.unwrap_or_default();
        let signature = self.machine.sign(context, input)?;
        if signature.is_empty() {
            return Err(SignerError::Empty("signature"));
        }
        Ok(signature)
    }

    /// Tears the session down, reporting a guest failure.
    ///
    /// # Errors
    /// Fails when the guest teardown fails.
    pub fn close(mut self) -> Result<(), SignerError> {
        self.teardown()
    }

    fn teardown(&mut self) -> Result<(), SignerError> {
        match self.context.take() {
            Some(context) => Ok(self.machine.teardown(context)?),
            None => Ok(()),
        }
    }
}

impl Drop for SapSigner {
    fn drop(&mut self) {
        // Best-effort release when the caller did not call `close`; the
        // emulator is discarded right after, so a failure has no effect.
        let _ = self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::apple_sap::machine::sap::test_support::{
        PRIMARY_SEED, SeededHost, bundle, environment, fixture, hex_at,
    };
    use crate::infrastructure::apple_sap::protocol::{SetupMethod, SetupRequest, SetupResponse};

    fn config() -> SignerConfig {
        SignerConfig {
            setup_url: "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy".to_owned(),
            certificate_url: "https://s.mzstatic.com/sap/setupCert.plist".to_owned(),
            version: SAP_VERSION,
            hardware_id: vec![2, 0, 0, 0, 0, 1],
        }
    }

    #[test]
    fn validate_accepts_https_endpoints() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_versions_identifiers_and_urls() {
        let cases = [
            SignerConfig {
                version: 100,
                ..config()
            },
            SignerConfig {
                hardware_id: Vec::new(),
                ..config()
            },
            SignerConfig {
                hardware_id: vec![0; 21],
                ..config()
            },
            SignerConfig {
                setup_url: "http://example.com/".to_owned(),
                ..config()
            },
            SignerConfig {
                setup_url: "/relative".to_owned(),
                ..config()
            },
            SignerConfig {
                certificate_url: "https://user:pw@example.com/".to_owned(),
                ..config()
            },
        ];
        for case in cases {
            assert!(
                matches!(case.validate(), Err(SignerError::Config(_))),
                "{case:?}"
            );
        }
    }

    /// Replays the recorded Apple responses of `sap.json`.
    struct Replay(serde_json::Value);

    impl SetupTransport for Replay {
        async fn send(&self, request: SetupRequest) -> Result<SetupResponse, ProtocolError> {
            let record = match request.method {
                SetupMethod::Get => "/certificate_http",
                SetupMethod::Post => "/setup_http",
            };
            let recorded = &self.0[&record[1..]];
            assert_eq!(request.url, recorded["url"].as_str().unwrap());
            assert_eq!(
                request.body,
                hex_at(&self.0, &format!("{record}/request_body_hex"))
            );
            Ok(SetupResponse {
                status: 200,
                body: hex_at(&self.0, &format!("{record}/response_body_hex")),
            })
        }
    }

    #[tokio::test]
    #[ignore = "needs the cached Apple SAP assets"]
    async fn connect_and_sign_reproduce_golden_signatures() {
        let golden = fixture("sap.json");
        let host = SeededHost::new(PRIMARY_SEED);
        let replay = Replay(golden.clone());
        let mut signer = SapSigner::connect(&bundle(), &environment(&host), &config(), &replay)
            .await
            .unwrap();
        for entry in golden["signatures"].as_array().unwrap() {
            let signature = signer.sign(&hex_at(entry, "/input_hex")).unwrap();
            assert_eq!(
                hex::encode(signature),
                entry["signature_hex"].as_str().unwrap()
            );
        }
        signer.close().unwrap();
    }
}
