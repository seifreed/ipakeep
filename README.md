<p align="center">
  <img src="https://img.shields.io/badge/ipakeep-App%20Store%20IPA%20Downloader-blue?style=for-the-badge" alt="ipakeep">
</p>

<h1 align="center">ipakeep</h1>

<p align="center">
  <strong>Production-grade CLI and library to download IPA files from the Apple App Store</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-edition%202024-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust Edition"></a>
  <a href="https://github.com/seifreed/ipakeep/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/ipakeep"><img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?style=flat-square" alt="Platforms"></a>
  <a href="https://github.com/seifreed/ipakeep#architecture"><img src="https://img.shields.io/badge/architecture-clean-brightgreen?style=flat-square" alt="Clean Architecture"></a>
</p>

<p align="center">
  <a href="https://github.com/seifreed/ipakeep/stargazers"><img src="https://img.shields.io/github/stars/seifreed/ipakeep?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/ipakeep/issues"><img src="https://img.shields.io/github/issues/seifreed/ipakeep?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**ipakeep** is a Rust toolkit to authenticate with Apple, search the App Store, acquire app licenses, and download IPA files — patched with their DRM `sinf` blobs and `iTunesMetadata.plist` while retaining Apple’s FairPlay encryption. It ships both a command-line tool and a library crate, and runs on macOS, Linux, and Windows.

> **ipakeep does not decrypt a downloaded IPA by itself.** A downloaded IPA is
> still FairPlay-encrypted. Decryption needs either the app running on a real
> device that you can attach Frida to (ipakeep drives that dump and patches the
> result), or `decrypt offline`, which decrypts the IPA on the computer
> natively — no app run, no external tool — given a one-time 16-byte
> per-account FairPlay credential minted once from a jailbroken device.

### Workflow: Who Does What

| Stage | What happens | Needs |
|-------|--------------|-------|
| **1. Download & patch** | `auth login`, license (`purchase` / automatic), `download`. The IPA is what Apple serves, plus `sinf` blobs and `iTunesMetadata.plist`. **Still FairPlay-encrypted.** | An Apple ID; any OS |
| **2. Decrypt** | The app runs on a device, iOS decrypts its code in memory, and a dumper reads it. ipakeep orchestrates `decrypt dump` (builtin Frida dumper, or `--dumper frida-ios-dump`, `bagbak`, `r2flutch`) or `decrypt dump-mac`, or decrypts offline with `decrypt offline` (native, no app run, needs a per-account credential), patches the plaintext back (`decrypt patch`), and checks it (`decrypt verify`) | See below |
| **3. Install / run decrypted** | Physical non-jailbroken device: `device install-ipa` re-signs with your development profile. Simulator: `simulator install-ipa` / `simulator run --inject-dylib` | Signing identity + profile (device), or Apple Silicon Mac (Simulator) |

Stage 2 requirements for the on-device dumpers (`decrypt offline` instead needs
only a 16-byte per-account credential minted once from a jailbroken device):

- A **jailbroken device** (or another route that gives `frida-server` access to the
  app's memory, such as TrollStore). A stock, non-jailbroken iPhone cannot be
  used to decrypt App Store apps. `decrypt dump-mac` is the alternative on an
  Apple Silicon Mac with SIP disabled, for apps available as iOS-on-Mac.
- Device iOS **≥ the app's `MinimumOSVersion`**, and the app must launch there.
- The version **installed on the device must match the encrypted IPA** you pass
  with `--ipa`; ipakeep rejects mismatched slice sizes.

### Limitations

- **Minimum iOS vs. jailbreakable devices.** Current apps often require an iOS
  newer than any device you can jailbreak. `decrypt inspect` reports which iOS
  majors satisfy each slice's minimum. ipakeep's builtin dumper reads decrypted
  code from a *running* app, so it needs the app to launch on the device; an
  older App Store version (`list-versions`, `download --external-version-id`)
  is the simplest workaround when one exists. Otherwise use `decrypt offline`:
  it decrypts the encrypted IPA natively on the computer without running the
  app, so the app's minimum iOS does not matter. That needs a 16-byte
  per-account FairPlay credential minted once from a jailbroken device (see
  [Offline decryption](#offline-decryption)); supported license formats are
  the standard SINF + SUPF/SUPP page-key files, and fat binaries are thinned to
  one slice. `decrypt set-min-os` lowers the declared minimum, but it does not
  backport APIs, so the app may still crash at launch.
- **Which decrypt path.** `decrypt dump` reads any app installed on the device,
  regardless of which Apple ID bought it, but needs the app to launch.
  `decrypt offline` never launches the app but its credential is
  **per Apple account**: it only decrypts apps owned by the account you minted
  with. So for an app bought on a *different* account, use `decrypt dump` on a
  device where it is installed. The native decryptor handles the SUPF (f-class,
  `.supf`/`.v5.supf`) and SUPP (p-class, `.supp`/`.v4.supp`) page-key formats;
  a page-key generation it does not recognize errors out and you fall back to
  the on-device path.
- **No-jailbreak decryption.** On iOS, decryption always needs a jailbreak (the
  kernel read/write `decrypt dump` and `mremap_encrypted`-style static tools
  rely on). The only no-jailbreak route is an older Apple Silicon Mac
  (macOS 11.2.3 or earlier) running the iOS app, which is a niche setup.
- **Entitlements.** A development re-sign can only grant what your profile
  authorizes. App Groups, keychain access groups, push notifications,
  associated domains, iCloud containers, and Apple-restricted entitlements from
  the original team are not available to you, so features depending on them may
  fail. `decrypt entitlements <App.app>` reports which ones will break.
  TrollStore is the exception: it keeps arbitrary entitlements, but only on
  iOS 14.0b2–16.6.1, the 16.7 RC (build 20H18) and 17.0 — not 16.7.x final or
  17.0.1+ — so to keep an app's original entitlements, install the decrypted IPA
  with TrollStore on a supported build instead of re-signing. LiveContainer and
  SideStore can emulate shared keychain groups for sideloaded apps but not push
  or the original team's capabilities.

### Key Features

| Feature | Description |
|---------|-------------|
| **Native Store sign-in** | In-process Apple ADI/SAP (Store AMD proof, kbsync, action signatures) on macOS, Linux and Windows, with trusted-device 2FA |
| **GrandSlam auth** | `--grandslam` SRP login with trusted-device/SMS 2FA over the same native anisette |
| **Trusted-phone enumeration** | Lists the account's trusted phone numbers for SMS 2FA instead of guessing |
| **Search & lookup** | Public iTunes Search/Lookup by term or bundle identifier |
| **Purchase** | Acquire a free-app license via `buyProduct` |
| **Owned apps** | `purchases` lists the apps the authenticated account already owns (signed Store session) |
| **Download & patch** | Fetches the IPA and injects `sinf` DRM blobs + `iTunesMetadata.plist`; output is **still FairPlay-encrypted** |
| **Device decryption** | Orchestrates a Frida dump of the app **running on a jailbroken device** (or Apple Silicon Mac with SIP off), then patches and verifies; cannot decrypt the file alone |
| **Offline decryption** | `decrypt offline` decrypts a local encrypted IPA natively (no running app, no external tool, any minimum iOS) with a per-account credential, and verifies the result |
| **Physical-device install** | Match provisioning profiles per bundle, preserve authorized capabilities, sign and install decrypted IPAs |
| **Version pinning** | List and download specific external version IDs |
| **Simulator prep** | Patch extracted arm64 Mach-O app bundles/dylibs for Apple Silicon Simulator |
| **Secure credentials** | macOS Keychain or `0600` file keychain at `~/.ipakeep/auth.json` |
| **Cross-platform Anisette** | Native in-process anisette on every platform, run on ipakeep's own Rust ARM64 interpreter ([Native ARM64 Emulation Engine](#native-arm64-emulation-engine)); no Docker, Go, remote server or C toolchain |
| **MCP server** | `mcp` runs ipakeep as a Model Context Protocol server over stdio, exposing `search`, `list_versions`, `auth_info`, `download` and `purchases` as tools for AI agents |
| **CLI + Library** | Use as a command-line tool or as a Rust crate |

### Supported Outputs

```text
Account / results   Text tables, JSON
IPA artifacts       Patched .ipa (sinf + iTunesMetadata injected, still encrypted)
                    Decrypted .ipa (via `decrypt dump` on a running device, or
                    `decrypt offline`, native, with a per-account credential)
Logging             tracing to stderr (`RUST_LOG`, `--verbose`, optional JSON)
```

### Logging

Logs are written to stderr so command results, including `--format json`, stay
clean on stdout. The default level is `info`; `--verbose` defaults to `debug`,
and `RUST_LOG` can set a more specific filter. Set
`IPAKEEP_LOG_FORMAT=json` for structured JSON and `IPAKEEP_ENV` to label the
deployment environment. HTTP events include method, host, status, and elapsed
time; they omit paths, query strings, headers, and bodies. See
[`docs/observability.md`](docs/observability.md) for the event policy and
diagnostics guide.

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/seifreed/ipakeep.git
cd ipakeep
cargo build --release
# binary at target/release/ipakeep
```

The default build needs only the Rust toolchain: the Apple guest code runs on
ipakeep's native Rust ARM64 interpreter (`native-cpu` feature). Apple's signed
framework assets are downloaded and verified on the first sign-in.

Optional profile-guided (PGO) build: `scripts/pgo.sh` builds
`target/pgo/release/ipakeep`. On the current interpreter it is slower than
the default build (see [Performance](#performance)), so the default build
does not use it.

The legacy Unicorn backend is still available but **deprecated**:
`cargo build --release --no-default-features --features unicorn`. It builds
`unicorn-engine-sys` from source and needs a C toolchain, CMake and libclang:
`cmake libclang-dev pkg-config` on Debian/Ubuntu, Xcode command line tools plus
`cmake` on macOS, and MSVC with CMake, Ninja and LLVM (`LIBCLANG_PATH`) on
Windows. Enabling `unicorn` makes the binary GPL-2.0 (see [License](#license)).

### Install the binary

```bash
cargo install --path .
```

### Sign-in state

ipakeep provisions an emulated Apple machine in-process on every platform and
keeps its state in the user config directory (`ipakeep/` under
`~/Library/Application Support` on macOS, `~/.config` on Linux, `%APPDATA%` on
Windows): `anisette-v4.json` (machine provisioning), `store-cookies.json`
(Store session cookies, shared by the code-less and the 2FA sign-in attempts)
and `kbsync-v1.json`. Delete them to start from a fresh identity.

---

## Quick Start

```bash
# Sign in for purchase/download. macOS uses local ADI-backed GrandSlam auth.
ipakeep auth login --email you@example.com --country es

# Search the store
ipakeep search "twitter"

# Download an app by name — the id is resolved and the free license acquired automatically
ipakeep download ludo-star
```

## Common Use Cases

### Archive an App Store IPA

Use this when you want a local copy of an app already available through the
App Store account.

```bash
ipakeep auth login --email you@example.com --country es
ipakeep search "ludo star" --country es
ipakeep download ludo-star --country es --output ./ipas/
```

The downloaded `.ipa` is a ZIP archive with Apple IPA layout. ipakeep patches it
with the account `sinf` blobs and `iTunesMetadata.plist`.

This step does **not** decrypt FairPlay. The downloaded executable is still
encrypted, because the App Store response does not contain the plaintext.

### Decrypt a FairPlay IPA

The on-device dumpers need the app to run on a compatible target so its code
is decrypted in memory. ipakeep coordinates that dump and patches the dumped
bytes back into the IPA; it does not decrypt an IPA from the downloaded file
alone. For apps that cannot run on your device, see
[Offline decryption](#offline-decryption).

```bash
# Inspect encrypted slices and the exact dump filenames.
ipakeep decrypt inspect MyApp.ipa

# Dump the installed app through Frida. Without --ipa, the installed (still
# encrypted) bundle is pulled from the device, so versions always match.
ipakeep decrypt dump com.example.MyApp --spawn

# App extensions are started automatically; if iOS refuses one, drop it
# instead of failing.
ipakeep decrypt dump com.example.MyApp --spawn --drop-undumped-extensions

# Validate that every Mach-O slice is structurally decrypted.
ipakeep decrypt verify MyApp-decrypted.ipa
```

The builtin dumper needs `frida-server` reachable over USB (jailbreak,
TrollStore, or another supported Frida deployment) and
`python3 -m pip install frida frida-tools` for the Python on your PATH. The
runner and JavaScript agent are bundled in the binary, including `cargo install`
builds; `--agent` overrides the runner. The app must be installed and runnable on the
target; `decrypt inspect` reports which iOS majors satisfy each slice's minimum
OS. `--dumper frida-ios-dump`, `bagbak`, and `r2flutch` can drive an installed
third-party dumper instead.

If you pass `--ipa`, it must be the encrypted IPA for the exact app version
installed on the target. A matching bundle ID is not enough: ipakeep compares
each dumped slice's `LC_UUID` and size with the IPA and refuses a different
build. Omitting `--ipa` avoids the problem: ipakeep copies the installed bundle
off the device through Frida's system session (no SSH needed) and patches that.

Tested end to end on a jailbroken iPhone 8 (iOS 16.7.16, Dopamine, Frida 17):
the main executable, all embedded frameworks and the notification-service
extension were dumped and verified with `cryptid 0`. App extensions are started
through `NSExtension` from SpringBoard while spawn gating is active, so
event-driven extensions are dumped too; `--drop-undumped-extensions` remains a
fallback for any extension iOS still refuses to start. The device must be
unlocked so iOS can launch the app.

A normal, non-jailbroken iPhone can install a properly re-signed **decrypted**
IPA, but pairing it or enabling Developer Mode does not grant access to an
App Store app's decrypted memory. Frida's stock-device mode is for debuggable
apps; it is not a general FairPlay decryption route. See the
[Frida iOS requirements](https://frida.re/docs/ios/).

The iOS-major matrix in `inspect` only compares declared minimum versions at
major-version granularity. Compare the full `minimum_os` (including minor/patch)
with the target OS as well. It does not establish Frida availability, entitlement
compatibility, or that the app will launch. Changing the minimum version cannot
supply missing APIs or grant entitlements.

The dumper reads code loaded in the selected process. During `--settle`, the
builtin dumper also watches for extension executables found in the supplied IPA
and attaches when iOS runs them. Trigger the extension's normal action during
that window (for example, deliver a notification push). Unloaded frameworks and
extensions that never run cannot be recovered by waiting alone. If encrypted
slices remain, the command fails rather than publishing an incomplete IPA. For
those slices, collect additional process dumps into the same directory with the
[Frida bridge](scripts/frida/README.md), then use `decrypt patch` and
`decrypt verify`.

### Offline decryption

`decrypt offline` decrypts a local encrypted IPA on this computer **natively** —
no external tool, no emulator, and the app never runs, so its `MinimumOSVersion`
can exceed every device you have. It is a Rust reimplementation of the
credential-based FairPlay decrypt (verified byte-identical to londek/ipadecrypt
on real App Store data).

```bash
ipakeep download com.example.MyApp --output MyApp.ipa
IPAKEEP_FAIRPLAY_CREDENTIAL=~/path/to/credential.bin \
  ipakeep decrypt offline MyApp.ipa -o MyApp-decrypted.ipa
```

It unwraps each binary's SINF license with the credential, derives the per-page
keys from the IPA's SUPF/SUPP records, AES-decrypts every FairPlay page, clears
`cryptid`, thins each fat binary to one slice, strips `SC_Info` /
`iTunesMetadata.plist` / the Watch app, then runs its own `decrypt verify` and
refuses an IPA that still has an encrypted slice. Only local `.ipa` paths are
accepted; decrypting needs no network or App Store login.

It needs a **16-byte per-account FairPlay credential**, resolved from
`$IPAKEEP_FAIRPLAY_CREDENTIAL` or the sole `*.bin` under
`~/Library/Application Support/ipakeep/credentials/` (or `~/.ipadecrypt/credentials/`).
The credential belongs to the Apple ID that owns the app (download the IPA with
that same account); a credential from a different account is rejected up front.
`$IPAKEEP_FAIRPLAY_ARCADE_CREDENTIAL` supplies the separate Apple Arcade
credential when decrypting an Arcade title. The credential is minted once from a
jailbroken device; `--no-on-device` is accepted for compatibility but is a no-op
(the native path is always offline and never touches a device).

`decrypt verify` proves that `cryptid` is cleared and the dumped regions are
not obvious filler. It cannot prove that the app will launch on another device.
The resulting IPA still needs to be re-signed with a certificate and matching
provisioning profile before installation on a non-jailbroken iPhone.

### Install on a physical iPhone

On macOS with Xcode and a paired device, `device install-ipa` verifies the IPA,
matches supplied development profiles to the app and each extension, re-signs
nested code in dependency order, and installs through `devicectl`:

```bash
ipakeep device install-ipa MyApp-decrypted.ipa \
  --device <device-udid> \
  --identity "Apple Development: Your Name (TEAMID)" \
  --provisioning-profile ./App.mobileprovision \
  --run
```

For iOS 16 devices that `devicectl` cannot address, add `--legacy-device`
and use the USB UDID reported by `idevice_id -l`:

```bash
brew install ideviceinstaller libimobiledevice
ipakeep device install-ipa MyApp-decrypted.ipa \
  --legacy-device --device <usb-udid> \
  --identity "Apple Development: Your Name (TEAMID)" \
  --provisioning-profile ./App.mobileprovision
```

This route uses `ideviceinstaller` 1.2+ for installation and, when `--run` is
requested, `idevicedebug --detach` for launch. Launch requires a compatible
Developer Disk Image mounted on the device and a debuggable development
signature. Signing and entitlement checks are the same as the default route.

#### Experimental: `--native` (no Xcode, no libimobiledevice)

> **Experimental.** Implemented against an in-process fake device only; it has
> not yet been validated on real hardware. The default `devicectl` route and
> `--legacy-device` are unchanged.

`--native` installs in-process with ipakeep's own Rust implementation of the
device protocols: it talks to **usbmuxd** (`/var/run/usbmuxd` on macOS/Linux,
`127.0.0.1:27015` on Windows, or `USBMUXD_SOCKET_ADDRESS`), reads the host's
pair record, opens a **lockdownd** session upgraded to TLS with that record
(the device certificate is pinned to the record), uploads the signed bundle to
`PublicStaging` over **AFC**, and installs it through **installation_proxy**,
printing its progress:

```bash
ipakeep device install-ipa MyApp-decrypted.ipa \
  --native --device <usb-udid> \
  --identity "Apple Development: Your Name (TEAMID)" \
  --provisioning-profile ./App.mobileprovision
```

Limits: the device must already be paired ("Trust This Computer"); `--device`
must be its UDID; `--run` is not supported (launching on iOS 17+ needs the
personalized Developer Disk Image and a CoreDevice tunnel); TLS 1.2+ only.
Re-signing still uses `/usr/bin/codesign`, so the command as a whole still
needs macOS even though the install protocols themselves are cross-platform.

Repeat `--provisioning-profile` for extensions with different bundle IDs. An
explicit App ID profile takes priority over a wildcard profile; missing or
ambiguous matches fail before signing.

Without `--entitlements`, ipakeep preserves each bundle's original capabilities
and validates their values against its selected profile. It regenerates the
application/team identity and the default app keychain group for the new team.
Shared keychain groups, app groups, iCloud containers, and other custom values
are preserved and must be authorized by the profile. Changing teams does not
transfer access to the original team's data or services. A main-app
`--entitlements` override is an explicit choice to change those capabilities.

Apple-private or incompatible entitlements produce an error naming the key;
ipakeep does not silently remove them. The device still validates certificates,
profile expiry, device registration, and runtime compatibility. A valid signing
identity, matching development profiles, and a registered device are required.
The command uses `/usr/bin/codesign` and `xcrun devicectl`, so it requires
macOS/Xcode. See Apple's [entitlements troubleshooting guide](https://developer.apple.com/library/archive/technotes/tn2415/).

Lowering `MinimumOSVersion` with `decrypt set-min-os` may make installation
possible on an older OS, but it does not backport APIs and commonly causes a
launch crash. Prefer downloading an older App Store version when one exists.

### Download a Specific Version

```bash
ipakeep list-versions 1198143062 --country es
ipakeep download 1198143062 --external-version-id <external-version-id> --output ./ipas/
```

### Acquire a Free License Without Downloading

```bash
ipakeep purchase --bundle-identifier com.example.app --country us
```

### Run Non-Interactively

Use this for automation, CI probes, or scripts where prompts would hang.

```bash
ipakeep --non-interactive --file-keychain auth login \
  --email you@example.com \
  --password "$APPLE_ID_PASSWORD" \
  --country es
```

### Use the File Keychain

```bash
ipakeep --file-keychain auth info
ipakeep --file-keychain auth revoke
```

The file keychain stores credentials at `~/.ipakeep/auth.json` with private file
permissions. On macOS, the native Keychain is the default; if it does not
respond within 5 seconds, unlock it or use `--file-keychain`.

### Prepare an App for Apple Silicon Simulator

```bash
unzip app.ipa -d /tmp/app
ipakeep simulator prepare /tmp/app/Payload/App.app
xcrun simctl install booted /tmp/app/Payload/App.app
ipakeep simulator run --bundle-id com.example.app --device "iPhone 16"
```

### Install and Launch a Simulator-Compatible IPA

```bash
ipakeep simulator install-ipa /path/to/app-decrypted.ipa --run --udid <simulator-udid>
ipakeep simulator install-ipa /path/to/app-decrypted.ipa --run --console --device "iPhone 16"
```

`install-ipa` rejects encrypted App Store IPAs. A normal downloaded store IPA may
still refuse to run in Simulator if the app enforces secure-device checks or
uses device-only frameworks.

### Inject a Dylib While Launching

```bash
ipakeep simulator run \
  --bundle-id com.example.app \
  --inject-dylib /path/to/tweak.dylib \
  --entitlements /path/to/entitlements.plist \
  --console
```

Repeated `--inject-dylib` flags are supported.

---

## Usage

### Command Line Interface

```bash
# Search, JSON output
ipakeep --format json search "vpn" --limit 10 --country us

# Download by name, bundle id, or numeric id (all resolve automatically)
ipakeep download ludo-star
ipakeep download com.gameberry.ludostarbis
ipakeep download 1198143062

# Download a specific version into a directory (ids come from list-versions)
ipakeep download 1198143062 --external-version-id <id> --output ./ipas/

# Download only, without acquiring the license
ipakeep download 1198143062 --no-purchase

# Download and try to install in the first booted iOS Simulator
ipakeep download ludo-star --country es --simulator-install

# Download, install, and launch in the first booted iOS Simulator
ipakeep download ludo-star --country es --simulator-run

# List available versions
ipakeep list-versions ludo-star

# Prepare an extracted .app for Apple Silicon iOS Simulator
ipakeep simulator prepare /path/to/Payload/App.app

# Launch an installed Simulator app with a dylib injected
ipakeep simulator run --bundle-id com.example.app --inject-dylib /path/to/tweak.dylib --device "iPhone 16"

# Install and launch a decrypted IPA in a specific Simulator
ipakeep simulator install-ipa /path/to/app-decrypted.ipa --run --udid <simulator-udid>

# Attach console output and wait until the app exits
ipakeep simulator run --bundle-id com.example.app --console
ipakeep simulator install-ipa /path/to/app-decrypted.ipa --run --console

# Inspect / revoke stored credentials
ipakeep auth info
ipakeep auth revoke
```

### Commands

| Command | Description |
|--------|-------------|
| `ipakeep auth login` | Sign in (`--email`, `--password`, `--code`, `--country`); macOS uses local ADI-backed GrandSlam auth |
| `ipakeep auth info` | Show the stored account summary |
| `ipakeep auth revoke` | Delete stored credentials |
| `ipakeep search <term>` | Search the App Store (`--limit`, `--country`) |
| `ipakeep purchase` | Acquire a license (`--bundle-identifier`, `--country`) |
| `ipakeep download <app>` | Download & patch an IPA; `<app>` is an id, bundle id, or name. License acquired automatically (`--country`, `--external-version-id`, `--output`, `--no-purchase`, `--simulator-install`, `--simulator-run`) |
| `ipakeep list-versions <app>` | List versions; `<app>` is an id, bundle id, or name (`--country`) |
| `ipakeep simulator prepare <path>` | Patch extracted `.app` bundles, binaries, and dylibs for Apple Silicon iOS Simulator |
| `ipakeep simulator run --bundle-id <id> [--inject-dylib <path>] [--udid <id> \| --device <name>] [--entitlements <plist>] [--console]` | Launch an installed app on a selected booted Simulator, optionally injecting signed dylibs |
| `ipakeep simulator install-ipa <ipa> [--run] [--udid <id> \| --device <name>] [--entitlements <plist>] [--console]` | Extract, reject encrypted App Store IPAs, prepare, sign, install, and optionally launch a Simulator-compatible IPA. `--console` requires `--run` |
| `ipakeep simulator unlock-runtime [path]` | Create a read-write overlay for a path inside an iOS `.simruntime`; defaults to the booted Simulator runtime root |
| `ipakeep decrypt <inspect\|dump\|dump-mac\|patch\|verify\|entitlements\|set-min-os>` | Inspect encryption, dump a running app, patch dumped slices, verify, report entitlements that break after re-signing, lower the minimum OS |
| `ipakeep device install-ipa <ipa>` | Verify, re-sign, install, and optionally launch a decrypted IPA on a connected iOS device (`--device`, `--identity`, `--provisioning-profile`, `--entitlements`, `--legacy-device`, experimental `--native`, `--run`) |

### Global Flags

| Option | Description |
|--------|-------------|
| `--format <text\|json>` | Output format (default `text`) |
| `--legacy` | Use the Store login flow (the default; kept for compatibility) |
| `--grandslam` | Use GrandSlam SRP login instead of the Store login |
| `--non-interactive` | Fail instead of prompting |
| `--file-keychain` | Force the file keychain instead of the macOS Keychain |
| `--verbose` | Enable debug-level logging |

### Input Validation

- `--country` must be a two-letter ISO 3166-1 alpha-2 code and is normalized to lowercase.
- `search --limit` must be at least `1`.
- Empty app references, search terms, bundle identifiers, simulator UDIDs, and simulator device names are rejected.
- `--legacy` and `--grandslam` conflict.
- `simulator install-ipa --console` requires `--run`.

### Authentication Notes

- Every platform signs in through the native Store login: the first login
  downloads Apple's signed framework assets and provisions a local device
  identity. Without `--code`, Apple pushes a code to your trusted devices; the
  coded attempt reuses the saved Store cookie session.
- `--grandslam` selects SRP and uses the same native anisette.
- Use `--non-interactive` with `--email`, `--password`, and optionally `--code`
  when no prompts are allowed.

### Simulator Notes

- Simulator support targets Apple Silicon iOS Simulator workflows.
- A `.ipa` file is a ZIP archive. `simulator install-ipa` expects a `Payload/*.app`
  bundle inside it.
- Encrypted App Store IPAs are rejected for direct Simulator installation.
- Some apps show secure-device or jailbreak/device-integrity errors in Simulator.
  ipakeep can patch Mach-O platform metadata, sign bundles, inject dylibs, and
  mount runtime overlays; it does not guarantee that every production app will
  bypass its own runtime checks.
- `simulator unlock-runtime` is macOS-only and requires root because it mounts a
  read-write overlay over a Simulator runtime path.

---

## Library

ipakeep is also a crate following Clean Architecture. Add it as a path/git
dependency and drive the use cases directly:

```rust
use ipakeep::domain::usecase::Search;
use ipakeep::infrastructure::appstore::AppleAppStoreRepository;
use ipakeep::infrastructure::http::AppleHttpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AppleHttpClient::new()?;
    let repo = AppleAppStoreRepository::new(client);
    let search = Search::new(repo);

    let results = search.execute("twitter", "us", 5).await?;
    for app in &results {
        println!("{} ({}) - {}", app.name, app.bundle_id, app.version);
    }
    Ok(())
}
```

### Architecture

The crate is split into four dependency-isolated layers (inner layers never
depend on outer ones):

```text
domain/          Entities, repository traits (ports), use cases, errors — zero external deps
infrastructure/  HTTP client, plist codec, App Store API, IPA patching, keychains, GrandSlam,
                 and apple_sap/ (Apple asset extraction, Mach-O loader, shims, ARM64 emulator)
presentation/    Clap CLI commands and output formatting
main.rs          Wires concrete infrastructure into the presentation handlers
```

---

## Native ARM64 Emulation Engine

Signing in to the App Store and downloading apps depends on three Apple
algorithms that Apple doesn't document: **FairPlay SAP** (request
signatures), **ADI** (machine provisioning and the anisette / Store AMD
one-time passwords) and **kbsync** (the account- and hardware-bound blob that
`ent/download` requires). These algorithms are obfuscated white-box code, so
ipakeep doesn't try to reimplement them. Instead it runs **Apple's own macOS
27.0.1 arm64e binaries** in-process, on every OS, on an ARM64 interpreter
written in Rust as part of this project. It needs no Mac, no Docker, no Go
helper, no remote anisette server and no C toolchain.

### From restore image to running guest

```text
macOS 27.0.1 restore image (IPSW, ~26 GB)   pinned; read lazily over HTTP byte ranges, never downloaded whole
 └─ AEA1 archive                             key HPKE-wrapped (P-256 / HKDF-SHA256 / AES-256-GCM) to Apple's FCS key;
     │                                       segments HMAC-SHA256-checked, AES-256-CTR-decrypted, LZFSE-decoded
     └─ APFS cryptex (sealed volume)         object maps, file-system B-tree, decmpfs (LZVN / LZFSE / LZBITMAP)
         ├─ dyld shared cache                slide info v5; images exported as standalone thin Mach-O
         ├─ CoreFP, AppleMediaServices, CommerceKit `commerce`, CoreADI `adid`, `fairplayd`, CoreFP.icxs
         └─ IM4P kernel collection           LZFSE; FairPlayIOKit kext exported as a standalone Mach-O
→ Mach-O loader     arm64e slice, PAC stripped from code, rebases / binds / chained fixups, guest base
→ shim layer        ~200 libc, CoreFoundation, IOKit, XPC, Mach, pthread and dispatch functions in Rust
→ emulator engine   runs the guest code (native interpreter by default)
```

Every extracted file is cached and pinned to its size and SHA-256 digest.
The dyld and kext exports are byte-identical to upstream ipatool's.

| Machine | Apple code it runs | What it produces |
|---------|-------------------|------------------|
| SAP | `CoreFP` + `AppleMediaServices` | FairPlay SAP session and `X-Apple-ActionSignature` request signatures |
| Modern ADI | four cooperating guests: the `commerce` client runtime, the `adid` daemon (via faked XPC), `fairplayd` (via faked Mach ports) and the `FairPlayIOKit` kext (via faked IOKit) | machine provisioning, `X-Apple-I-MD*` anisette and Store `X-Apple-AMD` headers |
| StoreAgent / kbsync | the `commerce` daemon's FairPlay StoreAgent profile | the kbsync blob, FairPlay decryption sessions |

### The interpreter (`src/infrastructure/apple_sap/emu/native/`)

- **What it is:** a fetch / decode / execute A64 interpreter in safe Rust,
  with no `unsafe`, no JIT and no C dependencies. It implements the same
  `Engine` API as the old Unicorn wrapper: memory map/read/write, X and V
  registers, NZCV, code hooks, stop/fail, and runs bounded by a timeout or
  an instruction count. The machine layer above it is unchanged.
- **Decoding:** it dispatches on the top-level encoding class (`op0`,
  bits\[28:25\]) into one module per ARM ARM group:

  | Module | Coverage |
  |--------|----------|
  | `dpimm.rs` | PC-relative, add/sub and logical immediate, move wide, bitfield, extract |
  | `dpreg.rs` | shifted/extended add/sub, logical, ADC/SBC, conditional compare/select, 1- and 2-source, multiply / multiply-long / divide |
  | `branch.rs` | B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET, BRK; hints and barriers are no-ops |
  | `ldst.rs` | integer loads/stores (unsigned-offset, unscaled, pre/post-indexed, register-offset), pairs, literals, exclusive / acquire-release, `CAS*`, `SWP` |
  | `simd.rs` | the NEON / scalar-FP / `EOR3` subset Apple's white-boxes use (~0.01% of executed instructions): three-same, two-register-misc, across-lanes, shifts, permutes, EXT, INS/DUP/UMOV/SMOV, TBL/TBX, vector loads/stores, FP compare and convert |

  An encoding outside the modelled set stops the guest with
  `Unsupported { pc, word, what }`. The interpreter never guesses a
  neighbouring instruction.
- **Execution model:** single-threaded, so the exclusive monitor always
  succeeds. Pointer authentication is stripped at load time, so only the
  plain branch forms reach the decoder. The guest touches no system
  registers, so `MRS`/`MSR` are rejected. An access to unmapped memory
  reports both the faulting address and the PC.
- **Memory:** sparse 4 KiB pages kept in a frame vector, indexed by a
  Fibonacci-hashed page map. Data accesses go through a 1024-entry
  direct-mapped software TLB (a hit is one tag compare), and an access that
  stays inside one page (every aligned A64 load or store) is a fixed-width
  1/2/4/8/16-byte copy with no `memcpy` call. Instruction fetch keeps its own
  one-entry page cache. Page-straddling copies are page-wise, not byte-wise.
- **Block cache:** the first time the run loop reaches a PC, it pre-decodes a
  straight-line basic block (up to the first branch, 64 instructions, the end
  of the page, or the next hooked address) into compact 16-byte ops with
  fields, immediates and masks already extracted and register 31 resolved to
  XZR or SP. Later visits run the ops without fetching or decoding. Each
  block remembers the blocks its exits last reached (chaining), so the next
  block is usually found without a hash lookup. Encodings without a fast
  form run through the full decoder, so every op behaves exactly as the
  decoder does, and `Unsupported` errors are unchanged.
- **Self-modifying code:** a page holding cached code is flagged in `Memory`.
  The first write to it (a guest store on any path, including the TLB fast
  path, a host write, or an unmap) clears the flag and records the page, and
  the engine drops that page's blocks. A guest store into the running block
  ends the block after that instruction, so the modified code runs next.
- **Host functions (shims):** every emulated symbol gets a `ret` stub, and
  one code hook covers the shim area. The Rust handler runs before the
  `ret`: it reads arguments from `X0`–`X7`, writes `X0`, and the stub
  returns to `LR`. This is the same model Unicorn used, so all shims carried
  over unchanged.
- **Hot loop:** the wall-clock deadline is checked every 4096 instructions,
  not on every instruction. A two-compare range check skips hook dispatch
  for addresses no hook covers. Code hooks fire only at block entry, because
  a block never contains a hooked address after its first instruction.

### How it is verified

- **Golden vectors:** 13 `#[ignore]`d tests run the real Apple binaries and
  must reproduce, byte for byte, the outputs recorded from upstream ipatool:
  SAP setup and signatures, ADI provisioning (two seeds), Store AMD headers,
  kbsync, persisted provisioning, and the dyld, kext and APFS exports. See
  [Contributing](#contributing) for how to run them.
- **Differential testing against Unicorn:** with the `unicorn` feature
  enabled, every instruction group's tests run each encoding on both engines
  and compare X0–X30, SP, PC, NZCV and V0–V31.
- **Decode oracle:** every size, Q and U combination of the
  two-register-misc, across-lanes, EXT and INS (element) groups (1,360
  encodings) is classified with `llvm-mc`. Encodings LLVM rejects or that
  ipakeep doesn't model must be rejected; every modelled one must match
  Unicorn.
- **100% line coverage** is enforced in CI (`tarpaulin.toml`), including the
  rejection path of every unsupported encoding.

Writing these tests found real interpreter bugs that the golden vectors had
not exposed: `CASAL` executed as `LDAXP`, `UZP`/`ZIP`/`TRN` and `EXT`
executed as `TBL`, `FRECPE` executed as `SCVTF`, and reserved element sizes
accepted. All of them are fixed and covered by regression tests.

### Performance

These are the CPU user times of the golden tests (`/usr/bin/time -l`), not
wall times, because the measuring machine was heavily loaded. Each is the
median of 3 interleaved runs of a release build with `--test-threads=1` on an
Apple M5 Max, including loading and relocating the guest images:

| Workload | Native interpreter | Unicorn (legacy, being removed) |
|----------|--------------------|---------------------------------|
| SAP session and signatures (`connect_and_sign_reproduce_golden_signatures`) | 0.44 s | 0.44 s |
| ADI provisioning (`provisioning_reproduces_golden_vectors`) | 0.99 s | 1.09 s |
| kbsync, two blobs (`kbsync_reproduces_golden_vectors`) | 3.56 s | 2.59 s |

Unicorn translates guest code to host code with a JIT (QEMU TCG). The
interpreter stays a pure, safe-Rust interpreter, but the block cache and the
software TLB remove most of its per-instruction cost: it now matches Unicorn
on SAP, beats it on ADI provisioning, and is about 1.4× slower on kbsync, the
longest guest run. kbsync is generated once per account and device and cached
in `kbsync-v1.json`, so a normal download doesn't pay that cost anyway.
Earlier optimisation work (page-wise memory, page caches, the hook and
deadline fast paths) had already made the SAP signing test about 5× faster in
release and 13× faster in debug.

**PGO (optional).** The interpreter is branch-heavy decode and dispatch code,
which is what profile-guided optimisation helps most. `scripts/pgo.sh` trains
an instrumented build on the kbsync, SAP session and ADI provisioning golden
tests, merges the profiles and builds `target/pgo/release/ipakeep`. It needs
the cached Apple assets and `rustup component add llvm-tools`.
`scripts/pgo.sh --verify` builds the PGO-optimised test binary and runs the
kbsync golden test instead. Before the block cache, PGO cut the
interpreter's kbsync CPU time by ~18%. On the current interpreter it no
longer helps: measured the same way as the table above, the PGO test binary
took 4.12 s of CPU time for kbsync against 3.32 s for the plain release
build, so PGO is currently not recommended. The default build and CI do not
use PGO.

### Backends

| Build | Engine | License of the binary |
|-------|--------|-----------------------|
| default (`native-cpu`) | native interpreter | MIT |
| `--features unicorn` / `--all-features` | native interpreter, with Unicorn compiled as the differential oracle | GPL-2.0 |
| `--no-default-features --features unicorn` | Unicorn (deprecated legacy backend) | GPL-2.0 |

---

## Requirements

- Rust toolchain (edition 2024)
- Only for the deprecated `unicorn` feature: CMake, libclang and a C toolchain
  (see Installation)
- See [Cargo.toml](Cargo.toml) for dependencies

## SBOM

Generate and verify the committed CycloneDX SBOM:

```bash
./scripts/sbom.sh
```

The gate scores the SBOM with the project `sbomqs` profile and `sbom-tools`,
verifies NTIA minimum elements, and scans it with `osv-scanner` and `grype`.

CI runs the Rust formatting, compile, Clippy, dependency, license and SBOM
checks, and the test suite on Linux, macOS and Windows, all with the default
features and no C toolchain. A separate Linux job installs CMake and libclang
and runs the `unicorn` configurations: Clippy and tests with `--all-features`
(which run the native interpreter's differential tests against Unicorn), the
legacy `--no-default-features --features unicorn` backend, and coverage.
CodeQL analyzes the Rust crate.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Run the gates: `cargo fmt --all -- --check`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`, `cargo machete`, `cargo +nightly udeps --workspace --all-targets`, `cargo audit`, `cargo deny check`, `cargo tarpaulin --all-features --workspace`, `cargo license --json`, `./scripts/sbom.sh`
   - The `--all-features` gates build the deprecated `unicorn` feature, so they need CMake and libclang (see Installation). With it enabled, `cargo test --all-features` also runs the native interpreter's differential tests against Unicorn. Changes to the emulator should pass them, plus `cargo clippy --all-targets --no-default-features --features unicorn -- -D warnings`.
   - The golden tests against Apple's real binaries are `#[ignore]`d because they need the cached Apple assets. Run them by name, for example `cargo test --release --lib -- --ignored --test-threads=1 connect_and_sign_reproduce_golden_signatures`. A bare `--ignored` also runs tests that download the multi-gigabyte macOS restore image.
5. Open a Pull Request

---

## Support the Project

If this project is useful in your workflows, you can support development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT license. See [Cargo.toml](Cargo.toml).

The ipakeep source code is MIT-licensed (see [LICENSE](LICENSE)). Binaries
built with the default features run the Apple SAP/anisette stack on the native
Rust ARM64 interpreter and are MIT-licensed as well.

The optional, deprecated `unicorn` feature statically links the
[Unicorn](https://www.unicorn-engine.org/) emulator through the `unicorn-engine`
crate, which is licensed under the
[GPL-2.0](https://github.com/unicorn-engine/unicorn/blob/master/COPYING). A
binary built with `unicorn` enabled (including `--all-features`) is a combined
work: distributing it is governed by the GPL-2.0 (including its
source-availability and license-text requirements), while the MIT terms still
apply to the ipakeep source on its own. The full dependency license list is in
the CycloneDX SBOM at [sbom/ipakeep.cdx.json](sbom/ipakeep.cdx.json).

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/ipakeep](https://github.com/seifreed/ipakeep)

---

<p align="center">
  <sub>Built for practical iOS app archival and security research</sub>
</p>
