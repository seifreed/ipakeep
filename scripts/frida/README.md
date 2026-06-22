# ipakeep on-device decrypt bridge

ipakeep never decrypts FairPlay binaries itself. Instead it pinpoints exactly
what is encrypted and where, an on-device dumper reads the decrypted bytes out of
live memory, and ipakeep patches them back into the IPA. The bridge is a fixed
filename convention, so any dumper that honours it works — these scripts are the
reference implementation.

## Flow

```
# 1. See what's encrypted and the filenames the dumper must produce.
ipakeep decrypt inspect MyApp.ipa

# 2. On a device with the app installed, dump the decrypted slices.
python scripts/frida/ipakeep_dump.py --out dump/ com.example.MyApp
#   (use --spawn to launch the app instead of attaching to a running one)

# 3. Patch the dumped plaintext back in (cryptid -> 0, region replaced).
ipakeep decrypt patch MyApp.ipa --from dump/ -o MyApp-decrypted.ipa

# 4. Re-sign, preserving the binary's own entitlements.
ipakeep decrypt resign Payload/MyApp.app                 # ad-hoc (-)
ipakeep decrypt resign Payload/MyApp.app --identity "Apple Development: you"
```

## Filename convention

For every encrypted slice, `inspect` prints `dump as: <module-basename>.<arch>.bin`
(e.g. `MyApp.arm64.bin`). The Frida agent writes files with the same name; `patch`
matches them back by basename + arch and verifies each file is exactly `cryptsize`
bytes before overlaying `[cryptoff, cryptoff+cryptsize)`.

## iOS support (June 2026)

Targets the three live majors: **iOS 18, 26, 27**. `inspect` reports each slice's
`MinimumOSVersion` and a per-major dumpable matrix — an app only dumps on a device
whose iOS major is ≥ the app's minimum. arm64e (PAC) is handled: PAC signs code
pointers, not data, so reading the mapped `__TEXT` region is unaffected.

## Requirements

- A jailbroken or developer-provisioned device with `frida-server` reachable over USB.
- `pip install frida frida-tools`.
