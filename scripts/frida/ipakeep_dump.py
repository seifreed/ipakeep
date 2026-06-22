#!/usr/bin/env python3
"""Thin Frida runner for ipakeep's on-device FairPlay slice dumper.

Loads ipakeep_dump.js into the target app, lets it settle (so lazily `dlopen`'d
frameworks map and get dumped), and writes each decrypted slice to <out>/<name>,
where <name> is exactly what `ipakeep decrypt inspect` prints. Feed <out> to
`ipakeep decrypt patch --from`.

Works against a USB iOS device (jailbroken / TrollStore / rootless frida-server)
or the local machine — `--device local` is what `ipakeep decrypt dump-mac` uses
to dump an iOS app running on an Apple Silicon Mac, no jailbreak needed.

Usage:
    python ipakeep_dump.py --out dump/ <bundle-id-or-name>
    python ipakeep_dump.py --out dump/ --spawn <bundle-id>
    python ipakeep_dump.py --out dump/ --device local --spawn <bundle-id>

Requires: pip install frida frida-tools
"""

import argparse
import os
import sys
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))


def get_device(kind: str):
    if kind == "local":
        return frida.get_local_device()
    return frida.get_usb_device(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump FairPlay-decrypted Mach-O slices.")
    parser.add_argument("target", help="Bundle id, app name, or PID.")
    parser.add_argument("--out", required=True, help="Output directory for dumped slices.")
    parser.add_argument("--device", choices=["usb", "local"], default="usb", help="Frida device.")
    parser.add_argument("--spawn", action="store_true", help="Spawn the app instead of attaching.")
    parser.add_argument(
        "--settle",
        type=float,
        default=5.0,
        help="Seconds to wait for lazily-loaded frameworks before the final sweep.",
    )
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    device = get_device(args.device)

    pid = None
    try:
        if args.spawn:
            pid = device.spawn([args.target])
            session = device.attach(pid)
        else:
            # Accept a numeric PID or a process/app name.
            target = int(args.target) if args.target.isdigit() else args.target
            session = device.attach(target)
    except frida.PermissionDeniedError:
        # macOS with SIP enabled won't let a normal user attach to another app
        # (no get-task-allow). Re-run as root, or boot with SIP disabled.
        print(
            "permission denied attaching to the target.\n"
            "On a SIP-enabled Mac, run this as root:\n"
            f"    sudo {sys.executable} {os.path.abspath(__file__)} "
            f"--device {args.device} --out {args.out} {args.target}",
            file=sys.stderr,
        )
        return 2

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
            print(f"final sweep: {payload['dumped']} slice(s) total")

    script.on("message", on_message)
    script.load()
    if pid is not None:
        device.resume(pid)

    root = script.exports_sync.arm()
    print(f"armed; bundle root: {root}")
    time.sleep(args.settle)
    script.exports_sync.sweep()
    session.detach()

    print(f"\nwrote {len(written)} slice(s) to {args.out}")
    print("next: ipakeep decrypt patch <ipa> --from", args.out)
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
