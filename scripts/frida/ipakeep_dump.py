#!/usr/bin/env python3
"""Thin Frida runner for ipakeep's on-device FairPlay slice dumper.

Attaches (or spawns) the target app on a USB device, loads ipakeep_dump.js, and
writes each decrypted slice to <out>/<name>, where <name> is exactly what
`ipakeep decrypt inspect` prints. Feed <out> to `ipakeep decrypt patch --from`.

Usage:
    python ipakeep_dump.py --out dump/ <bundle-id-or-name>
    python ipakeep_dump.py --out dump/ --spawn <bundle-id>

Requires: pip install frida frida-tools  (and a jailbroken / dev device).
"""

import argparse
import os
import sys

import frida

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump FairPlay-decrypted Mach-O slices.")
    parser.add_argument("target", help="Bundle id, app name, or PID to attach to.")
    parser.add_argument("--out", required=True, help="Output directory for dumped slices.")
    parser.add_argument("--spawn", action="store_true", help="Spawn the app instead of attaching.")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    device = frida.get_usb_device(timeout=10)

    if args.spawn:
        pid = device.spawn([args.target])
        session = device.attach(pid)
    else:
        session = device.attach(args.target)
        pid = None

    with open(os.path.join(HERE, "ipakeep_dump.js"), "r", encoding="utf-8") as handle:
        script = session.create_script(handle.read())

    written = []

    def on_message(message, data):
        if message["type"] != "send":
            print(message, file=sys.stderr)
            return
        payload = message["payload"]
        if payload.get("event") == "slice" and data is not None:
            path = os.path.join(args.out, payload["name"])
            with open(path, "wb") as out:
                out.write(data)
            written.append(payload["name"])
            print(f"dumped {payload['name']} ({payload['cryptsize']} bytes)")
        elif payload.get("event") == "done":
            print(f"scanned {payload['scanned']} modules")

    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)

    script.exports_sync.dump()
    session.detach()

    print(f"\nwrote {len(written)} slice(s) to {args.out}")
    print("next: ipakeep decrypt patch <ipa> --from", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
