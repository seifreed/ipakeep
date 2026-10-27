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

### Key Features

| Feature | Description |
|---------|-------------|
| **Modern GrandSlam auth** | Optional SRP-6a login against `gsa.apple.com` with full 2FA |
| **Trusted-phone enumeration** | Lists the account's trusted phone numbers for SMS 2FA instead of guessing |
| **Legacy auth** | Classic App Store authentication flow with `-5000` retry handling |
| **Search & lookup** | Public iTunes Search/Lookup by term or bundle identifier |
| **Purchase** | Acquire a free-app license via `buyProduct` |
| **Download & patch** | Fetches the IPA and injects `sinf` DRM blobs + `iTunesMetadata.plist` |
| **Device decryption** | Builtin Frida dump orchestration, patching, and structural verification; requires access to the running app |
| **Physical-device install** | Match provisioning profiles per bundle, preserve authorized capabilities, sign and install decrypted IPAs |
| **Version pinning** | List and download specific external version IDs |
| **Simulator prep** | Patch extracted arm64 Mach-O app bundles/dylibs for Apple Silicon Simulator |
| **Secure credentials** | macOS Keychain or `0600` file keychain at `~/.ipakeep/auth.json` |
| **Cross-platform Anisette** | Local `AOSKit` on macOS, auto-managed Docker anisette server elsewhere |
| **CLI + Library** | Use as a command-line tool or as a Rust crate |

### Supported Outputs

```text
Account / results   Text tables, JSON
IPA artifacts       Patched .ipa (sinf + iTunesMetadata injected)
Logging             tracing (set --verbose for debug detail)
```

---

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/seifreed/ipakeep.git
cd ipakeep
cargo build --release
# binary at target/release/ipakeep
```

### Install the binary

```bash
cargo install --path .
```

### Anisette on Linux / Windows

Apple's `AOSKit` is macOS-only, so off-macOS ipakeep launches a Docker anisette
server automatically. **Docker must be installed and running.** Override the
provider if you already run one:

```bash
export IPAKEEP_ANISETTE_URL=http://127.0.0.1:6969   # use an existing server
export IPAKEEP_ANISETTE_IMAGE=my/anisette:tag        # use a custom image
```

---

## Quick Start

```bash
# Sign in for purchase/download. Configurator auth is the default commerce path.
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

FairPlay decryption requires the app to run on a compatible target so its code
is decrypted in memory. ipakeep coordinates that dump and patches the dumped
bytes back into the IPA; it does not decrypt an IPA from the downloaded file
alone.

```bash
# Inspect encrypted slices and the exact dump filenames.
ipakeep decrypt inspect MyApp.ipa

# Dump the running app through Frida, then patch the plaintext slices.
ipakeep decrypt dump com.example.MyApp --ipa MyApp.ipa --spawn

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

The dumper reads code loaded in the selected process. Extensions run separately,
and unloaded frameworks cannot be recovered by waiting alone. If encrypted
slices remain, the command fails rather than publishing an incomplete IPA.
For such apps, collect the additional process dumps into the same directory
with the [Frida bridge](scripts/frida/README.md), then use `decrypt patch` and
`decrypt verify`.

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
| `ipakeep auth login` | Sign in via Configurator by default (`--email`, `--password`, `--code`, `--country`; `--grandslam` for SRP auth) |
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
| `ipakeep device install-ipa <ipa>` | Verify, re-sign, install, and optionally launch a decrypted IPA on a connected iOS device (`--device`, `--identity`, `--provisioning-profile`, `--entitlements`, `--legacy-device`, `--run`) |

### Global Flags

| Option | Description |
|--------|-------------|
| `--format <text\|json>` | Output format (default `text`) |
| `--legacy` | Kept for compatibility; Configurator login is already the default |
| `--grandslam` | Use GrandSlam SRP login instead of Configurator |
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

- Configurator/legacy auth is the default because purchase and download require
  an App Store purchase token.
- `--grandslam` uses Apple's SRP flow and supports trusted-device/SMS 2FA, but
  GrandSlam-only account state may not be enough for App Store purchases. If
  purchase or download says the purchase token is missing, log in again without
  `--grandslam`.
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
infrastructure/  HTTP client, plist codec, App Store API, IPA patching, keychains, GrandSlam
presentation/    Clap CLI commands and output formatting
main.rs          Wires concrete infrastructure into the presentation handlers
```

---

## Requirements

- Rust toolchain (edition 2024)
- macOS for local `AOSKit` Anisette; otherwise Docker for the anisette server
- See [Cargo.toml](Cargo.toml) for dependencies

## SBOM

Generate and verify the committed CycloneDX SBOM:

```bash
./scripts/sbom.sh
```

The gate scores the SBOM with the project `sbomqs` profile, verifies NTIA
minimum elements, and scans it with `osv-scanner` and `grype`.

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Run the gates: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo audit`, `cargo deny check`, `./scripts/sbom.sh`
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

**Attribution**
- Author: **Marc Rivero López** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/ipakeep](https://github.com/seifreed/ipakeep)

---

<p align="center">
  <sub>Built for practical iOS app archival and security research</sub>
</p>
