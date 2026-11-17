//! **Experimental** in-process device install (`device install-ipa --native`):
//! a pure-Rust replacement for `ideviceinstaller install <app>` that needs
//! neither Xcode nor libimobiledevice.
//!
//! # Protocol stack
//!
//! | Layer | Module | Transport |
//! |---|---|---|
//! | usbmuxd (`ListDevices`, `ReadPairRecord`, `Connect`) | [`usbmux`] | `/var/run/usbmuxd` (macOS/Linux), `127.0.0.1:27015` (Windows), or `USBMUXD_SOCKET_ADDRESS` |
//! | lockdownd (`QueryType`, `StartSession`, `StartService`) | [`lockdown`] | device port 62078, upgraded to TLS by [`tls`] with the pair record |
//! | AFC upload to `PublicStaging/<App>.app` | [`afc`] | service port from lockdownd |
//! | `installation_proxy` `Install` + status stream | [`instproxy`] | service port from lockdownd |
//!
//! The flow mirrors `ideviceinstaller` for an unpacked `.app`: start and
//! connect `installation_proxy`, start and connect AFC, mirror the signed
//! bundle into `PublicStaging`, then `Install` it with `PackageType =
//! Developer` and stream its progress.
//!
//! Only TLS 1.2/1.3 are offered (rustls), which every iOS release this tool
//! targets supports; very old iOS versions that only speak TLS 1.0 are not.
//! The device must already be paired (trusted) with this host: pairing itself
//! is not implemented, the pair record is read from usbmuxd.
//!
//! # Sources
//!
//! Reimplemented from public behaviour, no code copied: libimobiledevice
//! (LGPL-2.1: `src/lockdown.c`, `src/afc.c`/`afc.h`,
//! `src/installation_proxy.c`, `src/property_list_service.c`), libusbmuxd
//! (LGPL-2.1: `src/libusbmuxd.c`), `ideviceinstaller` (GPL-2.0) and
//! pymobiledevice3 (GPL-3.0: `usbmux.py`, `lockdown.py`,
//! `services/afc.py`, `services/installation_proxy.py`), plus The iPhone Wiki
//! pages on usbmux and AFC. They were read as protocol references only.
//!
//! # Launch feasibility (`idevicedebug` replacement) — not implemented
//!
//! * **iOS ≤ 16** (the `--legacy-device` audience): mount the Developer Disk
//!   Image for that iOS version through `com.apple.mobile.mobile_image_mounter`
//!   (`UploadImage` + `MountImage` with the `.signature`), start
//!   `com.apple.debugserver` over lockdown (iOS 14+:
//!   `com.apple.debugserver.DVTSecureSocketProxy`, with service TLS), look up
//!   the app's install path via `installation_proxy` `Lookup`, and speak the
//!   GDB remote serial protocol (`QSetMaxPacketSize`, `A<argv>`,
//!   `qLaunchSuccess`, then `D` to detach). That reuses every layer here and
//!   is a moderate addition (DDI files must be supplied by the user from an
//!   Xcode install).
//! * **iOS 17+**: the DDI is *personalized* (a per-device ticket from Apple's
//!   TSS server signs a `PersonalizationManifest` before `MountImage`), and
//!   debugserver is no longer offered by lockdown. It is reached only through
//!   `CoreDevice`: `RemotePairing` (SRP-6a + Ed25519/X25519 over the untrusted
//!   tunnel service), a QUIC (17.0–17.3) or TLS-PSK TCP (17.4+) tunnel
//!   carrying IPv6 packets — which needs a TUN device (root) or a userspace
//!   TCP/IP stack — then `RemoteServiceDiscovery` (HTTP/2 + XPC on port 58783)
//!   to reach `com.apple.coredevice.appservice` or the remote debugproxy.
//!   That is a separate, large project (XPC, HTTP/2, QUIC/TLS-PSK and a
//!   network stack) and is deliberately out of scope; use the default
//!   `devicectl` path on macOS for iOS 17+ launches.

pub(crate) mod afc;
pub(crate) mod codec;
pub(crate) mod instproxy;
pub(crate) mod lockdown;
pub(crate) mod tls;
pub(crate) mod usbmux;


use std::io::{Read, Write};
use std::path::Path;

pub(crate) use instproxy::Progress;
pub(crate) use usbmux::Address;

/// A bidirectional byte stream (socket or TLS session).
pub(crate) trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}
/// Owned, type-erased [`Stream`].
pub(crate) type BoxStream = Box<dyn Stream>;

/// Staging directory installd consumes uploads from.
const STAGING: &str = "PublicStaging";

/// Upload the signed `.app` at `app` to device `udid` and install it.
pub(crate) fn install_app(
    address: &Address,
    udid: &str,
    app: &Path,
    progress: &mut dyn FnMut(&Progress),
) -> Result<(), String> {
    let device = usbmux::find_device(&usbmux::list_devices(address)?, udid)?;
    let pair = tls::PairRecord::parse(&usbmux::read_pair_record(address, &device.serial)?)?;
    let mut lockdown =
        lockdown::Lockdown::open(usbmux::connect(address, device.id, lockdown::PORT)?, &pair)?;
    let mut open = |name: &str| -> Result<BoxStream, String> {
        let service = lockdown.start_service(name)?;
        let stream = usbmux::connect(address, device.id, service.port)?;
        if service.ssl {
            tls::upgrade(stream, &pair)
        } else {
            Ok(stream)
        }
    };
    let installer = open(instproxy::SERVICE)?;
    let mut files = afc::Afc::new(open(afc::SERVICE)?);
    let package = format!(
        "{STAGING}/{}",
        app.file_name().unwrap_or_default().to_string_lossy()
    );
    files.make_dir(STAGING)?;
    files.remove_all(&package)?;
    files.upload_dir(app, &package)?;
    drop(files);
    instproxy::install(installer, &package, progress)
}

/// Print install progress to stderr.
pub(crate) fn print_progress(progress: &Progress) {
    eprintln!("{}", progress_line(progress));
}

fn progress_line(progress: &Progress) -> String {
    match progress.percent {
        Some(percent) => format!("  {} ({percent}%)", progress.status),
        None => format!("  {}", progress.status),
    }
}
