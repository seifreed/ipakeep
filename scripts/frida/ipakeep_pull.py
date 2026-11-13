#!/usr/bin/env python3
"""Pull an installed app bundle off a jailbroken device into an encrypted IPA.

The bundle on disk is still FairPlay-encrypted, but it is guaranteed to be the
exact build that `ipakeep_dump.py` will dump from memory, so the patch step
never has to match an App Store download to the installed version.

Usage:
    python ipakeep_pull.py --out App.ipa <bundle-id>

Requires: pip install frida frida-tools, and frida-server on the device.
"""

import argparse
import logging
import os
import posixpath
import sys
import zipfile

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger("ipakeep.frida")
CHUNK = 4 * 1024 * 1024


def app_bundle_path(device, bundle_id: str) -> str:
    apps = device.enumerate_applications(identifiers=[bundle_id], scope="full")
    if not apps or not apps[0].parameters.get("path"):
        raise ValueError(f"{bundle_id} is not installed on the device")
    return apps[0].parameters["path"].rstrip("/")


def walk(api, root: str, relative: str = ""):
    """Yield bundle-relative file paths, depth first; non-regular files are skipped."""
    for entry in sorted(api.list_directory(posixpath.join(root, relative)), key=lambda e: e["name"]):
        child = posixpath.join(relative, entry["name"]) if relative else entry["name"]
        if entry["kind"] == "dir":
            yield from walk(api, root, child)
        elif entry["kind"] == "file":
            yield child
        else:
            LOGGER.warning(
                "service=ipakeep component=frida event_name=frida.pull.skipped path=%r", child
            )


def archive_name(bundle_path: str, relative: str) -> str:
    return posixpath.join("Payload", posixpath.basename(bundle_path), relative)


def copy_file(api, source: str, sink) -> int:
    size = api.file_size(source)
    offset = 0
    while offset < size:
        chunk = api.read_chunk(source, offset, min(CHUNK, size - offset))
        if not chunk:
            raise IOError(f"short read at {offset} of {source}")
        sink.write(chunk)
        offset += len(chunk)
    return size


def pull(device, bundle_id: str, out: str) -> int:
    bundle = app_bundle_path(device, bundle_id)
    session = device.attach(0)
    try:
        with open(os.path.join(HERE, "ipakeep_pull.js"), encoding="utf-8") as handle:
            script = session.create_script(handle.read())
        script.load()
        api = script.exports_sync
        files = total = 0
        with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED, allowZip64=True) as archive:
            for relative in walk(api, bundle):
                with archive.open(archive_name(bundle, relative), "w", force_zip64=True) as sink:
                    total += copy_file(api, posixpath.join(bundle, relative), sink)
                files += 1
    finally:
        session.detach()
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.pull.completed files=%d bytes=%d",
        files,
        total,
    )
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description="Pull an installed app bundle into an IPA.")
    parser.add_argument("bundle_id", help="Bundle id of the installed app.")
    parser.add_argument("--out", required=True, help="IPA path to write.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)sZ %(levelname)s %(name)s %(message)s")
    try:
        pull(frida.get_usb_device(timeout=10), args.bundle_id, args.out)
    except (ValueError, frida.InvalidOperationError, frida.NotSupportedError, frida.TransportError) as error:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.pull.failed error=%r", str(error)
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
