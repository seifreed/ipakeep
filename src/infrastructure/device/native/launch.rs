//! Launch an installed app on iOS ≤ 16 without libimobiledevice
//! (`idevicedebug --detach run <bundle>`).
//!
//! 1. lockdownd `GetValue ProductVersion`: iOS 17+ no longer offers
//!    debugserver over lockdown, so it is rejected up front.
//! 2. `installation_proxy` `Lookup` returns the app's `Path`,
//!    `CFBundleExecutable`, `Container` and `Entitlements`; an app whose
//!    entitlements lack `get-task-allow` is rejected before debugserver
//!    refuses it.
//! 3. `mobile_image_mounter` `LookupImage` (`ImageType = Developer`) confirms
//!    the Developer Disk Image is mounted; mounting it is out of scope.
//! 4. debugserver is started (`DVTSecureSocketProxy` with service TLS on iOS
//!    14+, plain `com.apple.debugserver` before) and driven by
//!    [`super::debugserver`] to launch the executable and detach.
//!
//! Request and reply shapes were taken from libimobiledevice (LGPL-2.1:
//! `src/installation_proxy.c`, `src/mobile_image_mounter.c`,
//! `tools/idevicedebug.c`) and pymobiledevice3 (GPL-3.0:
//! `services/installation_proxy.py`, `services/mobile_image_mounter.py`) as
//! protocol references only; no code was copied.

use super::codec::{dict, recv_plist, send_plist, string};
use super::debugserver::{self, Client, Launch};
use super::tls::{self, PairRecord};
use super::{Address, BoxStream, instproxy, lockdown, usbmux};
use plist::{Dictionary, Value};
use std::time::Instant;

/// lockdown service that reports mounted disk images.
pub(crate) const IMAGE_MOUNTER: &str = "com.apple.mobile.mobile_image_mounter";
/// First iOS major release whose debugserver is reachable only via `CoreDevice`.
const FIRST_COREDEVICE_MAJOR: u64 = 17;
/// Entitlement debugserver requires to attach to an app.
const GET_TASK_ALLOW: &str = "get-task-allow";
/// `installation_proxy` attributes the launch needs.
const ATTRIBUTES: [&str; 5] = [
    "CFBundleIdentifier",
    "CFBundleExecutable",
    "Path",
    "Container",
    "Entitlements",
];

/// What `installation_proxy` reports about an installed app.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct InstalledApp {
    /// Bundle directory on the device.
    pub(crate) path: String,
    /// `CFBundleExecutable`.
    pub(crate) executable: String,
    /// Data container, the working directory when present.
    pub(crate) container: Option<String>,
    /// `get-task-allow`, when the entitlements were reported.
    pub(crate) debuggable: Option<bool>,
}

/// A lockdown session that can open service connections.
struct Session {
    address: Address,
    device_id: u64,
    pair: PairRecord,
    lockdown: lockdown::Lockdown,
}

impl Session {
    fn open(address: &Address, udid: &str) -> Result<Self, String> {
        let device = usbmux::find_device(&usbmux::list_devices(address)?, udid)?;
        let pair = PairRecord::parse(&usbmux::read_pair_record(address, &device.serial)?)?;
        let stream = usbmux::connect(address, device.id, lockdown::PORT)?;
        let lockdown = lockdown::Lockdown::open(stream, &pair)?;
        Ok(Self {
            address: address.clone(),
            device_id: device.id,
            pair,
            lockdown,
        })
    }

    fn connect(&mut self, service: &lockdown::Service) -> Result<BoxStream, String> {
        let stream = usbmux::connect(&self.address, self.device_id, service.port)?;
        if service.ssl {
            tls::upgrade(stream, &self.pair)
        } else {
            Ok(stream)
        }
    }

    fn service(&mut self, name: &str) -> Result<BoxStream, String> {
        let service = self.lockdown.start_service(name)?;
        self.connect(&service)
    }

    /// debugserver, preferring the iOS 14+ TLS service.
    fn debugserver(&mut self) -> Result<BoxStream, String> {
        match self.lockdown.start_service(debugserver::SECURE_SERVICE) {
            Ok(service) => self.connect(&service),
            Err(error) if error.contains("InvalidService") => {
                tracing::debug!(event = "device.native.launch.legacy_debugserver");
                self.service(debugserver::LEGACY_SERVICE)
                    .map_err(|error| missing_debugserver(&error))
            }
            Err(error) => Err(missing_debugserver(&error)),
        }
    }
}

fn missing_debugserver(error: &str) -> String {
    format!(
        "{error}; debugserver needs the Developer Disk Image mounted (and Developer Mode on iOS 16)"
    )
}

/// Reject iOS releases whose debugserver lockdown cannot reach.
pub(crate) fn check_version(version: &Value) -> Result<(), String> {
    let text = version.as_string().unwrap_or_default();
    let major = text
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok());
    match major {
        Some(major) if major < FIRST_COREDEVICE_MAJOR => Ok(()),
        Some(_) => Err(format!(
            "native launch supports iOS 16 and earlier; this device runs iOS {text}, whose \
             debugserver is only reachable through CoreDevice — install without --native \
             (devicectl) to launch on iOS 17+"
        )),
        None => Err(format!(
            "device reported an unexpected iOS version {version:?}"
        )),
    }
}

/// `installation_proxy` `Lookup` of one bundle identifier.
pub(crate) fn lookup(mut stream: BoxStream, bundle_id: &str) -> Result<InstalledApp, String> {
    let attributes = ATTRIBUTES.into_iter().map(Value::from).collect();
    let options = dict([
        ("BundleIDs", Value::Array(vec![bundle_id.into()])),
        ("ReturnAttributes", Value::Array(attributes)),
    ]);
    send_plist(
        &mut stream,
        dict([
            ("Command", "Lookup".into()),
            ("ClientOptions", Value::Dictionary(options)),
        ]),
    )?;
    let reply = recv_plist(&mut stream).map_err(|error| format!("installation_proxy: {error}"))?;
    if let Some(error) = string(&reply, "Error") {
        return Err(format!("installation_proxy Lookup failed: {error}"));
    }
    reply
        .get("LookupResult")
        .and_then(Value::as_dictionary)
        .and_then(|apps| apps.get(bundle_id))
        .and_then(Value::as_dictionary)
        .map_or_else(
            || Err(not_installed(bundle_id)),
            |app| installed_app(app, bundle_id),
        )
}

fn not_installed(bundle_id: &str) -> String {
    format!("{bundle_id} is not installed on the device; install it first")
}

fn installed_app(app: &Dictionary, bundle_id: &str) -> Result<InstalledApp, String> {
    let field = |key: &str| {
        string(app, key)
            .map(str::to_string)
            .ok_or_else(|| format!("installation_proxy reported no {key} for {bundle_id}"))
    };
    Ok(InstalledApp {
        path: field("Path")?,
        executable: field("CFBundleExecutable")?,
        container: string(app, "Container").map(str::to_string),
        debuggable: app
            .get("Entitlements")
            .and_then(Value::as_dictionary)
            .map(|entitlements| {
                entitlements.get(GET_TASK_ALLOW).and_then(Value::as_boolean) == Some(true)
            }),
    })
}

/// Fail early for an app whose entitlements lack `get-task-allow`.
pub(crate) fn require_debuggable(app: &InstalledApp, bundle_id: &str) -> Result<(), String> {
    if app.debuggable == Some(false) {
        return Err(debugserver::describe(
            "launch",
            bundle_id,
            &format!("{GET_TASK_ALLOW} is not set in the installed app's entitlements"),
        ));
    }
    Ok(())
}

/// `mobile_image_mounter` `LookupImage`: require a mounted Developer image.
pub(crate) fn require_developer_image(mut stream: BoxStream) -> Result<(), String> {
    send_plist(
        &mut stream,
        dict([
            ("Command", "LookupImage".into()),
            ("ImageType", "Developer".into()),
        ]),
    )?;
    let reply =
        recv_plist(&mut stream).map_err(|error| format!("mobile_image_mounter: {error}"))?;
    if let Some(error) = string(&reply, "Error") {
        return Err(format!("mobile_image_mounter LookupImage failed: {error}"));
    }
    let signed = reply
        .get("ImageSignature")
        .and_then(Value::as_array)
        .is_some_and(|signatures| !signatures.is_empty());
    let present = reply.get("ImagePresent").and_then(Value::as_boolean) == Some(true);
    if signed || present {
        Ok(())
    } else {
        Err(
            "the Developer Disk Image is not mounted on the device; mount the DDI matching its \
             iOS version (e.g. `ideviceimagemounter` or by connecting it to Xcode once) and retry"
                .to_string(),
        )
    }
}

/// Launch `bundle_id` on device `udid` and detach, leaving it running.
pub(crate) fn launch_app(address: &Address, udid: &str, bundle_id: &str) -> Result<(), String> {
    let started = Instant::now();
    let mut session = Session::open(address, udid)?;
    check_version(&session.lockdown.get_value("ProductVersion")?)?;
    let app = lookup(session.service(instproxy::SERVICE)?, bundle_id)?;
    require_debuggable(&app, bundle_id)?;
    require_developer_image(session.service(IMAGE_MOUNTER)?)?;
    let executable = format!("{}/{}", app.path, app.executable);
    let launch = Launch {
        executable: &executable,
        working_dir: app.container.as_deref().unwrap_or(&app.path),
        environment: &[],
    };
    Client::new(session.debugserver()?).launch(&launch)?;
    tracing::info!(
        event = "device.native.launch",
        bundle_id,
        outcome = "launched",
        duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    );
    Ok(())
}
