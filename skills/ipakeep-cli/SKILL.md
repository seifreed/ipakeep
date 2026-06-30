---
name: ipakeep-cli
description: Use ipakeep to authenticate with the Apple App Store, search apps, acquire free-app licenses, download and patch IPA files, list historical versions, prepare apps for iOS Simulator, and inspect, patch, re-sign, provision, or verify decrypted IPAs. Trigger this skill when a user asks how to install, configure, run, automate, troubleshoot, or choose commands/options for this ipakeep project.
---

# ipakeep CLI

Use the installed `ipakeep` binary when available. In this repository, use `cargo run -- ...` for local verification and `cargo run -- <command> --help` when command behavior may have changed.

## Install

Prefer the smallest install path that matches the user's source:

```bash
cargo install ipakeep
cargo install --git https://github.com/seifreed/ipakeep
cargo install --path .
```

On Linux or Windows, ensure Docker is running unless `IPAKEEP_ANISETTE_URL` points to an existing anisette server. macOS uses local `AOSKit` when available.

Useful environment overrides:

```bash
export IPAKEEP_ANISETTE_URL=http://127.0.0.1:6969
export IPAKEEP_ANISETTE_IMAGE=my/anisette:tag
```

## Global Options

Use these before or after the subcommand:

- `--format text|json`: choose human or machine output.
- `--verbose`: enable debug logging.
- `--non-interactive`: fail instead of prompting; use for scripts.
- `--file-keychain`: use `~/.ipakeep/auth.json` instead of macOS Keychain.
- `--legacy`: Configurator auth flow; default and required for purchase/download commerce token.
- `--grandslam`: SRP login flow; conflicts with `--legacy`.

Country values must be two-letter ISO codes and are normalized to lowercase. Avoid putting Apple ID passwords in shell history; prefer prompts or environment variables.

## Core Flow

For normal IPA archival:

```bash
ipakeep auth login --email you@example.com --country es
ipakeep search "app name" --country es --limit 10
ipakeep download 123456789 --country es --output ./ipas/
```

`download <app>` accepts a numeric App Store id, bundle identifier, or app name. It acquires the free license automatically unless `--no-purchase` is set.

For automation:

```bash
ipakeep --non-interactive --file-keychain auth login \
  --email you@example.com \
  --password "$APPLE_ID_PASSWORD" \
  --country es
```

## Auth

Commands:

- `auth login --email <email> --password <password> --code <2fa> --country <cc>`
- `auth info`
- `auth revoke`

Use `auth info` before download/purchase tasks if credentials may already exist. Use `auth revoke` to clear stored account state.

## Store Operations

Search:

```bash
ipakeep --format json search "vpn" --country us --limit 10
```

Purchase a free-app license without downloading:

```bash
ipakeep purchase --bundle-identifier com.example.app --country us
```

List versions and download a specific external version:

```bash
ipakeep list-versions 1198143062 --country es
ipakeep download 1198143062 --external-version-id <external-version-id> --output ./ipas/
```

Download without license acquisition:

```bash
ipakeep download 1198143062 --no-purchase
```

Download can also use `--simulator-install` or `--simulator-run` to act on the first booted iOS Simulator after the IPA is fetched.

## Simulator

Prepare an extracted app, framework, binary, or dylib for Apple Silicon iOS Simulator:

```bash
unzip app.ipa -d /tmp/app
ipakeep simulator prepare /tmp/app/Payload/App.app
```

Install and optionally run a Simulator-compatible IPA:

```bash
ipakeep simulator install-ipa app-decrypted.ipa --run --device "iPhone 16"
ipakeep simulator install-ipa app-decrypted.ipa --run --console --udid <sim-udid>
```

Launch an installed app:

```bash
ipakeep simulator run --bundle-id com.example.app --device "iPhone 16"
ipakeep simulator run --bundle-id com.example.app --inject-dylib tweak.dylib --console
```

Selection options are `--udid <id>` or `--device <name>`. `--console` on `install-ipa` requires `--run`. Normal encrypted App Store IPAs are rejected by `install-ipa`; decrypt first.

Use `simulator unlock-runtime [path]` only when a read-write overlay over a `.simruntime` path is intentionally needed.

## Decrypt And Signing

Inspect encryption state:

```bash
ipakeep decrypt inspect app.ipa
ipakeep --format json decrypt inspect app.ipa
```

Dump and patch with the builtin Frida runner:

```bash
ipakeep decrypt dump com.example.app --ipa encrypted.ipa --device usb --output decrypted.ipa
ipakeep decrypt dump com.example.app --ipa encrypted.ipa --spawn --settle 8
```

Other dumper backends are selected with `--dumper frida-ios-dump`, `--dumper bagbak`, or `--dumper r2flutch`.

For iOS-on-Mac apps on Apple Silicon:

```bash
ipakeep decrypt dump-mac com.example.app --ipa encrypted.ipa --output decrypted.ipa
```

Patch already dumped plaintext slices:

```bash
ipakeep decrypt patch encrypted.ipa --from ./dumped-slices --output decrypted.ipa
```

Verify and re-sign:

```bash
ipakeep decrypt verify decrypted.ipa
ipakeep decrypt entitlements Payload/App.app
ipakeep decrypt resign Payload/App.app --identity -
```

Provision a decrypted app for a registered device:

```bash
ipakeep decrypt provision Payload/App.app --device-udid <udid> --team <team-id>
```

`decrypt provision` requires a logged-in account with a paid Apple Developer membership. It writes `embedded.mobileprovision`, `key.pem`, and `certificate.der`, and embeds the profile into the app bundle.

Lowering the minimum OS version only changes install eligibility and often still crashes at launch:

```bash
ipakeep decrypt set-min-os app.ipa --version 16.0 --output app-minos.ipa
```

## Option Reference

Core commands:

- `auth login`: `--email`, `--password`, `--code`, `--country`.
- `auth info`: no command-specific options.
- `auth revoke`: no command-specific options.
- `search <term>`: `--limit`, `--country`.
- `purchase`: `--bundle-identifier`, `--country`.
- `download <app>`: `--country`, `--external-version-id`, `--output`, `--no-purchase`, `--simulator-install`, `--simulator-run`.
- `list-versions <app>`: `--country`.

Simulator commands:

- `simulator prepare <path>`: accepts an extracted `.app`, framework, binary, or dylib.
- `simulator run`: `--bundle-id`, repeatable `--inject-dylib`, `--udid` or `--device`, `--entitlements`, `--console`.
- `simulator install-ipa <ipa>`: `--run`, `--console`, `--udid` or `--device`, `--entitlements`.
- `simulator unlock-runtime [path]`: optional runtime path; defaults to the booted Simulator runtime root.

Decrypt commands:

- `decrypt inspect <ipa>`: no command-specific options.
- `decrypt patch <ipa>`: `--from`, `--output`.
- `decrypt resign <app>`: `--identity`, `--entitlements`.
- `decrypt verify <ipa>`: no command-specific options.
- `decrypt entitlements <path>`: no command-specific options.
- `decrypt set-min-os <ipa>`: `--version`, `--output`.
- `decrypt dump <bundle-id>`: `--dumper`, `--ipa`, `--device`, `--agent`, `--spawn`, `--settle`, `--output`.
- `decrypt dump-mac <bundle-id>`: `--ipa`, `--agent`, `--settle`, `--output`.
- `decrypt provision <app>`: `--device-udid`, `--team`, `--app-id-id`, `--output`.

## Troubleshooting

- If purchase/download fails after GrandSlam login, retry with the default legacy flow because commerce requires an App Store purchase token.
- If macOS Keychain hangs, unlock it or rerun with `--file-keychain`.
- If off-macOS auth fails before reaching Apple, check Docker or set `IPAKEEP_ANISETTE_URL`.
- If a command shape is uncertain, run `ipakeep <command> --help` or `cargo run -- <command> --help` in the repo before answering.
