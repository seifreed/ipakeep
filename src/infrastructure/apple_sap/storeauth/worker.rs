//! The dedicated thread that owns every `!Send` machine (Unicorn engines).
//!
//! Jobs arrive as boxed closures and run one at a time against [`Worker`],
//! which lazily loads the asset bundle and keeps one live modern ADI (the
//! persisted provisioning), at most one in-flight provisioning, and the SAP
//! signer.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use super::anisette::{AnisetteHeaders, MachineFinish, build_headers};
use super::error::{StoreAuthError, StoreAuthResult};
use super::state::{AnisetteState, IDENTIFIER_SIZE, StateStore};
use super::store_provisioning::StoreFinish;
use crate::infrastructure::apple_sap::assets::bundle::{self, Bundle};
use crate::infrastructure::apple_sap::machine::kbsync::generate_kbsync;
use crate::infrastructure::apple_sap::machine::modern_adi::{
    MACHINE_PROVISIONING_DSID, ModernAdi, ProvisioningStart, STORE_AMD_DSID, StoreAmdHeaders,
};
use crate::infrastructure::apple_sap::machine::sap::{GuestEnvironment, MachineError};
use crate::infrastructure::apple_sap::protocol::ReqwestTransport;
use crate::infrastructure::apple_sap::signer::{SapSigner, SignerConfig};

/// adid status for a DSID that was never provisioned.
const NOT_PROVISIONED_STATUS: i32 = -45061;

/// A unit of work for the worker thread.
pub(super) type Job = Box<dyn FnOnce(&mut Worker) + Send>;

/// Builds the guest environment on the worker thread (it holds an `Rc`).
pub type EnvironmentFactory = Box<dyn FnOnce() -> GuestEnvironment + Send>;

/// Where the pinned Apple framework images come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleSource {
    /// The process-wide [`bundle::load`] cache (extracting on first use).
    Shared,
    /// An already extracted bundle directory ([`bundle::read_bundle`]).
    Directory(PathBuf),
}

/// How a from-scratch machine provisioning picks its host identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierSource {
    /// A fresh random identifier: GSA rejects re-provisioning a known one.
    Random,
    /// Always this identifier (replays of recorded provisioning).
    #[cfg(test)]
    Fixed([u8; IDENTIFIER_SIZE]),
}

impl IdentifierSource {
    fn next(self) -> [u8; IDENTIFIER_SIZE] {
        match self {
            Self::Random => {
                let mut identifier = [0; IDENTIFIER_SIZE];
                rand::Rng::fill_bytes(&mut rand::rng(), &mut identifier);
                identifier
            }
            #[cfg(test)]
            Self::Fixed(identifier) => identifier,
        }
    }
}

/// Everything the worker needs besides its job queue.
pub(super) struct WorkerConfig {
    pub(super) state: StateStore,
    pub(super) bundle: BundleSource,
    pub(super) environment: EnvironmentFactory,
    pub(super) identifiers: IdentifierSource,
    pub(super) time_zone: String,
    pub(super) http: reqwest::Client,
}

/// A modern ADI and the state it was opened from.
struct MachineSession {
    state: AnisetteState,
    adi: ModernAdi,
}

/// The `!Send` side of the service.
pub(super) struct Worker {
    state: StateStore,
    bundle_source: BundleSource,
    identifiers: IdentifierSource,
    time_zone: String,
    http: reqwest::Client,
    environment: GuestEnvironment,
    bundle: Option<Arc<Bundle>>,
    machine: Option<MachineSession>,
    pending: Option<MachineSession>,
    signer: Option<(SignerConfig, SapSigner)>,
    runtime: Option<tokio::runtime::Runtime>,
}

/// Runs jobs until every handle is dropped.
pub(super) fn run(config: WorkerConfig, jobs: &Receiver<Job>) {
    let mut worker = Worker {
        state: config.state,
        bundle_source: config.bundle,
        identifiers: config.identifiers,
        time_zone: config.time_zone,
        http: config.http,
        environment: (config.environment)(),
        bundle: None,
        machine: None,
        pending: None,
        signer: None,
        runtime: None,
    };
    for job in jobs {
        job(&mut worker);
    }
}

fn is_not_provisioned(error: &MachineError) -> bool {
    matches!(
        error,
        MachineError::Status {
            status: NOT_PROVISIONED_STATUS,
            ..
        }
    )
}

impl Worker {
    fn bundle(&mut self) -> StoreAuthResult<Arc<Bundle>> {
        if let Some(bundle) = &self.bundle {
            return Ok(Arc::clone(bundle));
        }
        let bundle = match &self.bundle_source {
            BundleSource::Shared => bundle::load()?,
            BundleSource::Directory(directory) => Arc::new(bundle::read_bundle(directory)?),
        };
        self.bundle = Some(Arc::clone(&bundle));
        Ok(bundle)
    }

    fn open_session(&mut self, state: AnisetteState) -> StoreAuthResult<MachineSession> {
        let bundle = self.bundle()?;
        let adi = ModernAdi::open(
            &bundle,
            &self.environment,
            &state.identifier,
            &state.provisioning,
        )?;
        Ok(MachineSession { state, adi })
    }

    fn read_state(&self) -> StoreAuthResult<Option<AnisetteState>> {
        let lock = self.state.lock()?;
        self.state.read(&lock)
    }

    fn persist(&self, state: &AnisetteState) -> StoreAuthResult<()> {
        let lock = self.state.lock()?;
        self.state.write(&lock, state)
    }

    /// Opens the persisted provisioning once; `false` when there is none.
    fn load_machine(&mut self) -> StoreAuthResult<bool> {
        if self.machine.is_some() {
            return Ok(true);
        }
        let Some(state) = self.read_state()?.filter(AnisetteState::is_provisioned) else {
            return Ok(false);
        };
        self.machine = Some(self.open_session(state)?);
        Ok(true)
    }

    /// Re-reads `adi.pb` after an ADI call and persists it when it changed.
    fn sync_machine_state(&mut self) -> StoreAuthResult<()> {
        let Some(session) = self.machine.as_mut() else {
            return Ok(());
        };
        let provisioning = session.adi.state()?;
        if provisioning == session.state.provisioning {
            return Ok(());
        }
        session.state.provisioning = provisioning;
        let state = session.state.clone();
        self.persist(&state)
    }

    /// Anisette headers from the persisted GSA provisioning, or `None` when
    /// it is missing or no longer valid.
    ///
    /// # Errors
    /// Fails on state, asset or persistence errors.
    pub(super) fn reuse_headers(&mut self) -> StoreAuthResult<Option<AnisetteHeaders>> {
        if !self.load_machine()? {
            return Ok(None);
        }
        let Some(session) = self.machine.as_mut() else {
            return Ok(None);
        };
        if session.state.routing_info == 0 {
            return Ok(None);
        }
        let otp = match session.adi.request_otp(MACHINE_PROVISIONING_DSID) {
            Ok(otp) => otp,
            Err(error) => {
                tracing::debug!(%error, "persisted anisette provisioning is not reusable");
                return Ok(None);
            }
        };
        let now = self.environment.host.now();
        let headers = build_headers(&session.state, &otp, now, &self.time_zone);
        self.sync_machine_state()?;
        Ok(Some(headers))
    }

    /// Opens a blank ADI under a fresh identifier and returns the identifier.
    ///
    /// # Errors
    /// Fails when the guests cannot start.
    pub(super) fn begin_machine(&mut self) -> StoreAuthResult<Vec<u8>> {
        self.pending = None;
        let state = AnisetteState::new(self.identifiers.next());
        let identifier = state.identifier.clone();
        self.pending = Some(self.open_session(state)?);
        Ok(identifier)
    }

    /// Starts provisioning `dsid` on the pending ADI with the server `spim`.
    ///
    /// # Errors
    /// Fails without a pending ADI or on a guest failure.
    pub(super) fn start_pending(
        &mut self,
        dsid: u64,
        spim: &[u8],
    ) -> StoreAuthResult<ProvisioningStart> {
        let pending = self
            .pending
            .as_mut()
            .ok_or(StoreAuthError::NotStarted("ADI provisioning"))?;
        Ok(pending.adi.start_provisioning(dsid, spim)?)
    }

    fn take_pending(&mut self) -> StoreAuthResult<MachineSession> {
        self.pending
            .take()
            .ok_or(StoreAuthError::NotStarted("ADI provisioning"))
    }

    /// Completes GSA machine provisioning, persists it and makes it the live
    /// machine.
    ///
    /// # Errors
    /// Fails on a guest failure or when the state cannot be saved.
    pub(super) fn finish_machine(
        &mut self,
        session: u32,
        finish: &MachineFinish,
    ) -> StoreAuthResult<AnisetteHeaders> {
        let mut pending = self.take_pending()?;
        let adi = &mut pending.adi;
        adi.end_provisioning(session, &finish.setting_info, &finish.transport_key)?;
        let otp = adi.request_otp(MACHINE_PROVISIONING_DSID)?;
        pending.state.provisioning = adi.state()?;
        pending.state.routing_info = finish.routing_info;
        self.persist(&pending.state)?;
        let now = self.environment.host.now();
        let headers = build_headers(&pending.state, &otp, now, &self.time_zone);
        self.machine = Some(pending);
        Ok(headers)
    }

    /// Like upstream, opens a blank ADI under the current identifier and
    /// starts provisioning the Store DSID `-1` with `spim`.
    ///
    /// # Errors
    /// Fails without any machine identity or on a guest failure.
    pub(super) fn begin_store(&mut self, spim: &[u8]) -> StoreAuthResult<ProvisioningStart> {
        self.pending = None;
        let current = match &self.machine {
            Some(session) => Some(session.state.clone()),
            None => self.read_state()?,
        };
        let current = current.ok_or(StoreAuthError::NotStarted("anisette provisioning"))?;
        let state = AnisetteState {
            provisioning: Vec::new(),
            ..current
        };
        self.pending = Some(self.open_session(state)?);
        self.start_pending(STORE_AMD_DSID, spim)
    }

    /// Completes the Store provisioning, imports the keybag and persists the
    /// new `adi.pb`, which replaces the live machine.
    ///
    /// # Errors
    /// Fails on a guest failure or when the state cannot be saved.
    pub(super) fn finish_store(
        &mut self,
        session: u32,
        finish: &StoreFinish,
        hardware_id: &[u8],
    ) -> StoreAuthResult<()> {
        let mut pending = self.take_pending()?;
        let adi = &mut pending.adi;
        adi.end_provisioning(session, &finish.setting_info, &finish.transport_key)?;
        if !finish.key_bag.is_empty() {
            adi.import_key_bag(hardware_id, &finish.key_bag)?;
        }
        pending.state.provisioning = adi.state()?;
        self.persist(&pending.state)?;
        self.machine = Some(pending);
        Ok(())
    }

    /// `X-Apple-AMD` / `-M` from the live machine's DSID `-1`.
    ///
    /// # Errors
    /// [`StoreAuthError::StoreNotProvisioned`] until the Store "SP" action
    /// ran; guest and persistence failures otherwise.
    pub(super) fn store_amd(&mut self) -> StoreAuthResult<StoreAmdHeaders> {
        if !self.load_machine()? {
            return Err(StoreAuthError::StoreNotProvisioned);
        }
        let session = self
            .machine
            .as_mut()
            .ok_or(StoreAuthError::StoreNotProvisioned)?;
        let headers = match session.adi.store_amd_headers() {
            Err(error) if is_not_provisioned(&error) => {
                return Err(StoreAuthError::StoreNotProvisioned);
            }
            other => other?,
        };
        self.sync_machine_state()?;
        Ok(headers)
    }

    /// A kbsync blob for `dsid` on `hardware_id`.
    ///
    /// # Errors
    /// Fails on asset or guest failures.
    pub(super) fn kbsync(&mut self, hardware_id: &[u8], dsid: u64) -> StoreAuthResult<Vec<u8>> {
        let bundle = self.bundle()?;
        Ok(generate_kbsync(
            &bundle,
            &self.environment,
            hardware_id,
            dsid,
        )?)
    }

    /// Opens a SAP session for `config` unless one is already open for it.
    ///
    /// # Errors
    /// Fails on asset, guest or setup-handshake failures.
    pub(super) fn connect_sap(&mut self, config: SignerConfig) -> StoreAuthResult<()> {
        if self
            .signer
            .as_ref()
            .is_some_and(|(open, _)| *open == config)
        {
            return Ok(());
        }
        self.signer = None;
        let bundle = self.bundle()?;
        let transport = ReqwestTransport::new(self.http.clone());
        self.ensure_runtime()?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or(StoreAuthError::NotStarted("Apple SAP worker runtime"))?;
        let signer = runtime.block_on(SapSigner::connect(
            &bundle,
            &self.environment,
            &config,
            &transport,
        ))?;
        self.signer = Some((config, signer));
        Ok(())
    }

    fn ensure_runtime(&mut self) -> StoreAuthResult<()> {
        if self.runtime.is_none() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|source| StoreAuthError::Io {
                    action: "start the Apple SAP worker runtime",
                    source,
                })?;
            self.runtime = Some(runtime);
        }
        Ok(())
    }

    /// Signs `input` with the open SAP session.
    ///
    /// # Errors
    /// [`StoreAuthError::NoSapSession`] before [`Self::connect_sap`].
    pub(super) fn sign(&mut self, input: &[u8]) -> StoreAuthResult<Vec<u8>> {
        let (_, signer) = self.signer.as_mut().ok_or(StoreAuthError::NoSapSession)?;
        Ok(signer.sign(input)?)
    }
}
