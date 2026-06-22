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
python scripts/frida/ipakeep_dump.py --out dump/ --spawn com.example.MyApp
#   --spawn launches the app; the agent hooks dlopen so lazily-loaded
#   frameworks are dumped too. --settle <sec> waits for them before the final
#   sweep. Only the app bundle's own Mach-Os are dumped.

# 3. Patch the dumped plaintext back in (cryptid -> 0, region replaced).
ipakeep decrypt patch MyApp.ipa --from dump/ -o MyApp-decrypted.ipa

# 4. Confirm it's fully decrypted (every slice cryptid=0, not filler).
ipakeep decrypt verify MyApp-decrypted.ipa

# 5. See which entitlements will break before re-signing.
ipakeep decrypt entitlements Payload/MyApp.app

# 6. Re-sign, preserving the binary's own entitlements.
ipakeep decrypt resign Payload/MyApp.app                 # ad-hoc (-)
ipakeep decrypt resign Payload/MyApp.app --identity "Apple Development: you"
```

The agent exposes two RPC calls the runner drives: `arm()` installs the dlopen
hook and does the initial sweep; `sweep()` is the final pass after `--settle`.

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

## Getting frida-server onto the device (no full jailbreak needed)

The runner attaches the same way regardless of how `frida-server` got there:

- **Jailbroken**: install the Frida package from the Cydia/Sileo repo.
- **TrollStore**: install a Frida-server `.tipa`, or embed the Frida gadget.
- **Rootless jailbreak** (Dopamine etc.): the rootless Frida package.

## Apple Silicon Mac route (`--device local` / `decrypt dump-mac`)

An iOS App Store app installed on an M-series Mac ("iPhone & iPad Apps" tab) runs
with its binary FairPlay-encrypted and decrypted in memory at launch — so it can
be dumped with no iOS device and no jailbreak. **But it requires SIP disabled.**

Why: Frida on macOS cannot instrument a process it did not spawn unless SIP is
off. With SIP enabled, `task_for_pid` on another app is denied even to root
(the app lacks `get-task-allow`, and Frida lacks Apple's private
`com.apple.system-task-ports` entitlement). And iOS-on-Mac apps can't be spawned
directly by Frida — launched outside their launchd container they exit instantly.

So the Mac route needs, once:

1. Disable SIP: reboot to Recovery → Terminal → `csrutil disable` → reboot.
2. Launch the app normally (`open -b <bundle-id>`), then attach as root:
   `sudo python3 ipakeep_dump.py --device local --out dump/ "<App Name or PID>"`.

This is "no jailbreak" but not "no system changes" — SIP-off lowers the Mac's
security globally; re-enable it (`csrutil enable`) when done. If you'd rather not
touch SIP, use the USB-device route above (jailbreak / TrollStore / rootless).

## Requirements

- A device with `frida-server` reachable over USB (any of the above) **or** an
  Apple Silicon Mac with SIP disabled running the iOS app (`--device local`).
- `pip install frida frida-tools`.
