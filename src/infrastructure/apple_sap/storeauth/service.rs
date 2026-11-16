//! [`SapService`]: the `Send + Sync` handle to the machine worker thread.

use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use super::anisette::{
    AnisetteHeaders, GsaEndpoints, LOCAL_TIME_ZONE, finish_machine, start_machine,
};
use super::error::{StoreAuthError, StoreAuthResult};
use super::state::StateStore;
use super::store_provisioning::{StoreProvisioningRequest, decode_challenge, finish_store};
use super::worker::{
    BundleSource, EnvironmentFactory, IdentifierSource, Job, Worker, WorkerConfig, run,
};
use crate::infrastructure::apple_sap::machine::modern_adi::{
    MACHINE_PROVISIONING_DSID, StoreAmdHeaders,
};
use crate::infrastructure::apple_sap::machine::sap::GuestEnvironment;
use crate::infrastructure::apple_sap::signer::SignerConfig;
use crate::infrastructure::observability::elapsed_ms;

const WORKER_THREAD_NAME: &str = "apple-sap";
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// `gsa.apple.com` chains to Apple's own root, absent from non-Apple trust
/// stores (upstream downloads it on demand; ipakeep pins it).
const APPLE_ROOT_CA: &[u8] = include_bytes!("../../http/apple_root_ca.pem");

static SHARED: Mutex<Option<SapService>> = Mutex::new(None);

/// Construction options of a [`SapService`].
pub struct ServiceConfig {
    /// The `anisette-v4.json` location.
    pub state: StateStore,
    /// Where the Apple images come from.
    pub bundle: BundleSource,
    /// GSA `MidService` endpoints.
    pub gsa: GsaEndpoints,
    /// `X-Apple-I-TimeZone` value.
    pub time_zone: String,
    /// Guest clock and randomness, built on the worker thread.
    pub environment: EnvironmentFactory,
    /// Host identifier choice for from-scratch provisioning.
    pub identifiers: IdentifierSource,
}

impl ServiceConfig {
    /// The production setup: state in the user config directory, the shared
    /// asset cache, Apple's endpoints and the real clock and RNG.
    ///
    /// # Errors
    /// Fails when there is no user configuration directory.
    pub fn standard() -> StoreAuthResult<Self> {
        Ok(Self {
            state: StateStore::in_config_directory()?,
            bundle: BundleSource::Shared,
            gsa: GsaEndpoints::default(),
            time_zone: LOCAL_TIME_ZONE.to_owned(),
            environment: Box::new(GuestEnvironment::default),
            identifiers: IdentifierSource::Random,
        })
    }
}

struct Inner {
    jobs: Sender<Job>,
    http: reqwest::Client,
    gsa: GsaEndpoints,
    /// Serialises the multi-step provisioning flows and caches the anisette
    /// headers for the life of the process.
    anisette: tokio::sync::Mutex<Option<AnisetteHeaders>>,
}

/// In-process Apple SAP / ADI service.
///
/// One worker thread owns the asset bundle, the live modern ADI, kbsync
/// generation and the SAP signer (all `!Send`); this handle is cheap to clone
/// and safe to share. `*_blocking` variants serve the synchronous closures of
/// the native Store commerce clients and may be called from async code (they
/// park the calling thread, never the worker).
#[derive(Clone)]
pub struct SapService {
    inner: Arc<Inner>,
}

/// An HTTP client for Apple authentication: Apple root trusted, TLS 1.2+,
/// 30 s timeout, redirects not followed (upstream `NewHTTPClient`).
///
/// # Errors
/// Fails when the TLS backend cannot be initialised.
pub fn apple_auth_client() -> StoreAuthResult<reqwest::Client> {
    let root = reqwest::Certificate::from_pem(APPLE_ROOT_CA).map_err(client_error)?;
    crate::infrastructure::http::client_builder()
        .add_root_certificate(root)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(client_error)
}

fn client_error(source: reqwest::Error) -> StoreAuthError {
    StoreAuthError::Http {
        context: "build Apple authentication client",
        source,
    }
}

impl SapService {
    /// Starts the worker thread. Assets load lazily on first use.
    ///
    /// # Errors
    /// Fails when the HTTP clients or the thread cannot be created.
    pub fn spawn(config: ServiceConfig) -> StoreAuthResult<Self> {
        let (jobs, receiver) = mpsc::channel::<Job>();
        let worker = WorkerConfig {
            state: config.state,
            bundle: config.bundle,
            environment: config.environment,
            identifiers: config.identifiers,
            time_zone: config.time_zone,
            http: apple_auth_client()?,
        };
        std::thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || run(worker, &receiver))
            .map_err(|source| StoreAuthError::Io {
                action: "start the Apple SAP worker thread",
                source,
            })?;
        let inner = Inner {
            jobs,
            http: apple_auth_client()?,
            gsa: config.gsa,
            anisette: tokio::sync::Mutex::new(None),
        };
        tracing::debug!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "spawn",
            event_name = "apple_sap.worker.started",
            outcome = "success",
            "Apple SAP worker thread started"
        );
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The process-wide service over [`ServiceConfig::standard`], so every
    /// caller shares one provisioning and one set of anisette headers.
    ///
    /// # Errors
    /// See [`ServiceConfig::standard`] and [`Self::spawn`].
    pub fn shared() -> StoreAuthResult<Self> {
        let mut shared = SHARED.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(service) = shared.as_ref() {
            return Ok(service.clone());
        }
        let service = Self::spawn(ServiceConfig::standard()?)?;
        *shared = Some(service.clone());
        Ok(service)
    }

    fn submit<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Worker) -> StoreAuthResult<T> + Send + 'static,
        reply: impl FnOnce(StoreAuthResult<T>) + Send + 'static,
    ) -> StoreAuthResult<()> {
        // Run the job under the caller's subscriber and span so worker
        // events stay correlated with the command that requested them.
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let span = tracing::Span::current();
        let job: Job = Box::new(move |worker| {
            tracing::dispatcher::with_default(&dispatch, || {
                let _entered = span.enter();
                reply(job(worker));
            });
        });
        self.inner
            .jobs
            .send(job)
            .map_err(|_| StoreAuthError::WorkerStopped)
    }

    async fn call<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Worker) -> StoreAuthResult<T> + Send + 'static,
    ) -> StoreAuthResult<T> {
        let (sender, receiver) = oneshot::channel();
        self.submit(job, move |result| {
            // The caller may have been cancelled; the result is then unused.
            let _ = sender.send(result);
        })?;
        receiver.await.map_err(|_| StoreAuthError::WorkerStopped)?
    }

    fn call_blocking<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Worker) -> StoreAuthResult<T> + Send + 'static,
    ) -> StoreAuthResult<T> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.submit(job, move |result| {
            // The caller is parked on `recv`; it only fails if it went away.
            let _ = sender.send(result);
        })?;
        receiver.recv().map_err(|_| StoreAuthError::WorkerStopped)?
    }

    /// GSA anisette headers (`X-Apple-I-MD`, `-M`, `-RINFO`, `-LU`, client
    /// time, time zone, locale, `X-Mme-Device-Id`, `X-MMe-Client-Info`,
    /// `X-Apple-I-SRL-NO`).
    ///
    /// The first call reuses the persisted provisioning, or provisions a
    /// fresh identifier with GSA when there is none or it no longer works;
    /// the result is then returned unchanged for the rest of the process,
    /// because Apple binds the `GrandSlam` session to the `X-Apple-I-MD-M` it
    /// saw and rejects 2FA requests carrying another one.
    ///
    /// # Errors
    /// Asset, guest, GSA HTTP or state-file failures.
    pub async fn anisette_headers(&self) -> StoreAuthResult<AnisetteHeaders> {
        let mut cached = self.inner.anisette.lock().await;
        if let Some(headers) = cached.as_ref() {
            return Ok(headers.clone());
        }
        let started = Instant::now();
        let result = self.resolve_anisette().await;
        let headers = observed("anisette_headers", started, result)?;
        *cached = Some(headers.clone());
        Ok(headers)
    }

    async fn resolve_anisette(&self) -> StoreAuthResult<AnisetteHeaders> {
        if let Some(headers) = self.call(Worker::reuse_headers).await? {
            tracing::debug!(
                service = "ipakeep",
                component = "apple_sap",
                operation = "anisette_headers",
                event_name = "apple_sap.anisette.reused",
                outcome = "success",
                "reused the persisted anisette provisioning"
            );
            return Ok(headers);
        }
        tracing::info!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "provision_machine",
            event_name = "apple_sap.anisette.provisioning_started",
            "no reusable anisette provisioning; provisioning with GSA"
        );
        let started = Instant::now();
        let headers = self.provision_machine().await?;
        tracing::info!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "provision_machine",
            event_name = "apple_sap.anisette.provisioned",
            outcome = "success",
            duration_ms = elapsed_ms(started),
            "anisette machine provisioning completed"
        );
        Ok(headers)
    }

    async fn provision_machine(&self) -> StoreAuthResult<AnisetteHeaders> {
        let (http, gsa) = (&self.inner.http, &self.inner.gsa);
        let identifier = self.call(Worker::begin_machine).await?;
        let spim = start_machine(http, gsa, &identifier).await?;
        let start = self
            .call(move |worker| worker.start_pending(MACHINE_PROVISIONING_DSID, &spim))
            .await?;
        let finish = finish_machine(http, gsa, &identifier, &start.cpim).await?;
        self.call(move |worker| worker.finish_machine(start.session, &finish))
            .await
    }

    /// Runs the Store "SP" action: ADI provisioning of DSID `-1` against
    /// `otp/1.5/finish`, keybag import and persistence.
    ///
    /// # Errors
    /// Invalid challenge, guest, Store HTTP or state-file failures.
    pub async fn provision_store(
        &self,
        request: &StoreProvisioningRequest<'_>,
    ) -> StoreAuthResult<()> {
        let _flow = self.inner.anisette.lock().await;
        let started = Instant::now();
        let result = self.run_store_provisioning(request).await;
        observed("provision_store", started, result)?;
        tracing::info!(
            service = "ipakeep",
            component = "apple_sap",
            operation = "provision_store",
            event_name = "apple_sap.store.provisioned",
            outcome = "success",
            duration_ms = elapsed_ms(started),
            "Store AMD provisioning completed"
        );
        Ok(())
    }

    async fn run_store_provisioning(
        &self,
        request: &StoreProvisioningRequest<'_>,
    ) -> StoreAuthResult<()> {
        let spim = decode_challenge(request.challenge)?;
        let start = self.call(move |worker| worker.begin_store(&spim)).await?;
        let finish = finish_store(request, &start.cpim).await?;
        let hardware_id = request.hardware_id.to_vec();
        self.call(move |worker| worker.finish_store(start.session, &finish, &hardware_id))
            .await
    }

    /// `X-Apple-AMD` / `X-Apple-AMD-M` (base64 ADI OTP and MID of DSID `-1`).
    ///
    /// # Errors
    /// [`StoreAuthError::StoreNotProvisioned`] before the Store "SP" action;
    /// guest or state-file failures otherwise.
    pub async fn store_amd_headers(&self) -> StoreAuthResult<StoreAmdHeaders> {
        let started = Instant::now();
        let result = self.call(Worker::store_amd).await;
        observed("store_amd_headers", started, result)
    }

    /// Blocking [`Self::store_amd_headers`].
    ///
    /// # Errors
    /// See [`Self::store_amd_headers`].
    pub fn store_amd_headers_blocking(&self) -> StoreAuthResult<StoreAmdHeaders> {
        let started = Instant::now();
        let result = self.call_blocking(Worker::store_amd);
        observed("store_amd_headers", started, result)
    }

    /// Raw kbsync for account `dsid` on `hardware_id`.
    ///
    /// # Errors
    /// Asset or guest failures (including a zero DSID).
    pub async fn kbsync(&self, hardware_id: &[u8], dsid: u64) -> StoreAuthResult<Vec<u8>> {
        let started = Instant::now();
        let hardware_id = hardware_id.to_vec();
        let result = self
            .call(move |worker| worker.kbsync(&hardware_id, dsid))
            .await;
        observed("kbsync", started, result)
    }

    /// Blocking [`Self::kbsync`].
    ///
    /// # Errors
    /// See [`Self::kbsync`].
    pub fn kbsync_blocking(&self, hardware_id: &[u8], dsid: u64) -> StoreAuthResult<Vec<u8>> {
        let started = Instant::now();
        let hardware_id = hardware_id.to_vec();
        let result = self.call_blocking(move |worker| worker.kbsync(&hardware_id, dsid));
        observed("kbsync", started, result)
    }

    /// Opens a fresh SAP session for the bag's `sign-sap-setup` endpoints,
    /// replacing any open one; later [`Self::sign`] calls use it.
    ///
    /// # Errors
    /// Invalid configuration, asset, guest or setup-handshake failures.
    pub async fn connect_sap(&self, config: SignerConfig) -> StoreAuthResult<()> {
        let started = Instant::now();
        let result = self.call(move |worker| worker.connect_sap(config)).await;
        observed("connect_sap", started, result)
    }

    /// `X-Apple-ActionSignature` bytes for `input`.
    ///
    /// # Errors
    /// [`StoreAuthError::NoSapSession`] before [`Self::connect_sap`]; guest
    /// failures otherwise.
    pub async fn sign(&self, input: &[u8]) -> StoreAuthResult<Vec<u8>> {
        let started = Instant::now();
        let input = input.to_vec();
        let result = self.call(move |worker| worker.sign(&input)).await;
        observed("sign", started, result)
    }

    /// Blocking [`Self::sign`].
    ///
    /// # Errors
    /// See [`Self::sign`].
    pub fn sign_blocking(&self, input: &[u8]) -> StoreAuthResult<Vec<u8>> {
        let started = Instant::now();
        let input = input.to_vec();
        let result = self.call_blocking(move |worker| worker.sign(&input));
        observed("sign", started, result)
    }
}

/// Records the outcome of a service operation and passes `result` through.
///
/// Only the operation name, outcome, duration and a stable error category
/// are logged: never inputs, outputs (OTP, MID, kbsync, signatures) or error
/// text, which may carry server-provided detail or local paths.
fn observed<T>(
    operation: &'static str,
    started: Instant,
    result: StoreAuthResult<T>,
) -> StoreAuthResult<T> {
    let duration_ms = elapsed_ms(started);
    match &result {
        Ok(_) => tracing::debug!(
            service = "ipakeep",
            component = "apple_sap",
            operation,
            event_name = "apple_sap.operation.completed",
            outcome = "success",
            duration_ms,
            "Apple SAP operation completed"
        ),
        Err(StoreAuthError::StoreNotProvisioned) => tracing::debug!(
            service = "ipakeep",
            component = "apple_sap",
            operation,
            event_name = "apple_sap.operation.completed",
            outcome = "not_provisioned",
            duration_ms,
            "Store AMD state is not provisioned yet"
        ),
        Err(error) => tracing::warn!(
            service = "ipakeep",
            component = "apple_sap",
            operation,
            event_name = "apple_sap.operation.failed",
            outcome = "failure",
            error_type = error.kind(),
            duration_ms,
            "Apple SAP operation failed"
        ),
    }
    result
}
