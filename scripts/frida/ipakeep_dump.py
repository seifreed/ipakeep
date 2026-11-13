#!/usr/bin/env python3
"""Thin Frida runner for ipakeep's on-device FairPlay slice dumper.

Loads ipakeep_dump.js into the target app, lets it settle (so lazily `dlopen`'d
frameworks map and get dumped), and watches for app extensions from the IPA to
run in their own process. It writes each decrypted slice to <out>/<name>, where
<name> is exactly what `ipakeep decrypt inspect` prints. Feed <out> to
`ipakeep decrypt patch --from`.

Works against a USB iOS device (jailbroken / TrollStore / rootless frida-server)
or the local machine — `--device local` is what `ipakeep decrypt dump-mac` uses
to dump an iOS app running on an Apple Silicon Mac, no jailbreak needed.

Usage:
    python ipakeep_dump.py --out dump/ --ipa App.ipa <bundle-id-or-name>
    python ipakeep_dump.py --out dump/ --ipa App.ipa --spawn <bundle-id>
    python ipakeep_dump.py --out dump/ --ipa App.ipa --device local --spawn <bundle-id>

Requires: pip install frida frida-tools
"""

import argparse
import logging
import os
import plistlib
import threading
import time
import zipfile
from pathlib import PurePosixPath

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
LOGGER = logging.getLogger("ipakeep.frida")


def configure_logging() -> None:
    level_name = os.environ.get("IPAKEEP_FRIDA_LOG_LEVEL", "INFO").upper()
    level = logging.getLevelName(level_name)
    valid_level = isinstance(level, int)
    if not valid_level:
        level = logging.INFO

    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logging.basicConfig(level=level, handlers=[handler], force=True)
    if not valid_level:
        LOGGER.warning(
            "service=ipakeep component=frida event_name=logging.invalid_level; using INFO"
        )


def get_device(kind: str):
    if kind == "local":
        return frida.get_local_device()
    return frida.get_usb_device(timeout=10)


def attach_target(device, target: str):
    if target.isdecimal():
        return int(target)
    application = next(
        (app for app in device.enumerate_applications() if app.identifier == target), None
    )
    if application is None:
        return target
    if application.pid == 0:
        raise ValueError(f"{target} is not running; open it or pass --spawn")
    return application.pid


def extension_process_names(ipa_path: str) -> set[str]:
    process_names = set()
    with zipfile.ZipFile(ipa_path) as ipa:
        for entry in ipa.infolist():
            parts = PurePosixPath(entry.filename).parts
            plugin = next(
                (
                    parts[index + 2]
                    for index, part in enumerate(parts[:-3])
                    if part.endswith(".app")
                    and parts[index + 1] == "PlugIns"
                    and parts[index + 2].endswith(".appex")
                    and parts[index + 3] == "Info.plist"
                ),
                None,
            )
            if plugin is None:
                continue
            try:
                metadata = plistlib.loads(ipa.read(entry))
            except Exception as error:
                raise ValueError(f"invalid extension plist {entry.filename}: {error}") from error
            if isinstance(metadata, dict):
                process_names.update(
                    value
                    for key in ("CFBundleExecutable", "CFBundleIdentifier")
                    if isinstance((value := metadata.get(key)), str) and value
                )
    return process_names


def is_extension_process(process_name: str, extension_names: set[str]) -> bool:
    return any(
        process_name == executable or process_name.endswith(f".{executable}")
        for executable in extension_names
    )


def load_agent(session, agent_path: str, out_dir: str, written: list[str]):
    with open(agent_path, "r", encoding="utf-8") as handle:
        script = session.create_script(handle.read())

    def on_message(message, data):
        if message["type"] != "send":
            LOGGER.error(
                "service=ipakeep component=frida event_name=frida.script.message_failed message_type=%r",
                message.get("type"),
            )
            return
        payload = message["payload"]
        if payload.get("event") == "slice" and data is not None:
            path = os.path.join(out_dir, payload["name"])
            with open(path, "wb") as output:
                output.write(data)
            written.append(payload["name"])
            LOGGER.info(
                "service=ipakeep component=frida event_name=frida.slice.dumped artifact=%r bytes=%d",
                payload["name"],
                payload["cryptsize"],
            )
        elif payload.get("event") == "done":
            LOGGER.info(
                "service=ipakeep component=frida event_name=frida.sweep.completed slices=%d",
                payload["dumped"],
            )

    script.on("message", on_message)
    script.load()
    return script


def attach_extension(device, pid: int, agent_path: str, out_dir: str, written: list[str]):
    session = device.attach(pid)
    try:
        script = load_agent(session, agent_path, out_dir, written)
        root = script.exports_sync.arm()
        LOGGER.info(
            "service=ipakeep component=frida event_name=frida.extension.attached pid=%d",
            pid,
        )
        return session, script
    except Exception:
        detach_session(session)
        raise


def sweep_extension(script) -> bool:
    try:
        script.exports_sync.sweep()
        return True
    except (frida.InvalidOperationError, frida.ProcessNotFoundError, frida.TransportError):
        return False


def detach_session(session) -> None:
    try:
        session.detach()
    except frida.InvalidOperationError:
        pass


def resume_spawn(device, pid: int) -> None:
    try:
        device.resume(pid)
    except (frida.InvalidOperationError, frida.ProcessNotFoundError):
        pass


def watch_extensions(device, process_names, agent_path, out_dir, written, seconds: float):
    if not process_names:
        time.sleep(seconds)
        return

    deadline = time.monotonic() + seconds
    seen_pids = set()
    attaching_pids = set()
    sessions = {}
    state_changed = threading.Condition()

    def on_spawn(spawn):
        with state_changed:
            duplicate = spawn.pid in seen_pids
            if not duplicate:
                seen_pids.add(spawn.pid)
                attaching_pids.add(spawn.pid)
            while duplicate and spawn.pid in attaching_pids:
                state_changed.wait()
        if duplicate:
            resume_spawn(device, spawn.pid)
            return
        attached = None
        try:
            if is_extension_process(spawn.identifier, process_names):
                attached = attach_extension(device, spawn.pid, agent_path, out_dir, written)
        except (frida.ProcessNotFoundError, frida.PermissionDeniedError) as error:
            LOGGER.warning(
                "service=ipakeep component=frida event_name=frida.extension.attach_failed pid=%d error_type=%s",
                spawn.pid,
                type(error).__name__,
            )
        except Exception as error:
            LOGGER.error(
                "service=ipakeep component=frida event_name=frida.extension.instrumentation_failed pid=%d error_type=%s",
                spawn.pid,
                type(error).__name__,
            )
        finally:
            with state_changed:
                if attached is not None:
                    sessions[spawn.pid] = attached
                attaching_pids.discard(spawn.pid)
                state_changed.notify_all()
            resume_spawn(device, spawn.pid)

    device.on("spawn-added", on_spawn)
    try:
        device.enable_spawn_gating()
    except Exception:
        device.off("spawn-added", on_spawn)
        raise
    try:
        for process in device.enumerate_processes():
            if not is_extension_process(process.name, process_names):
                continue
            with state_changed:
                if process.pid in seen_pids:
                    while process.pid in attaching_pids:
                        state_changed.wait()
                    continue
                seen_pids.add(process.pid)
                attaching_pids.add(process.pid)
            attached = None
            try:
                attached = attach_extension(device, process.pid, agent_path, out_dir, written)
            except (frida.ProcessNotFoundError, frida.PermissionDeniedError) as error:
                LOGGER.warning(
                    "service=ipakeep component=frida event_name=frida.extension.attach_failed pid=%d error_type=%s",
                    process.pid,
                    type(error).__name__,
                )
            finally:
                with state_changed:
                    if attached is not None:
                        sessions[process.pid] = attached
                    attaching_pids.discard(process.pid)
                    state_changed.notify_all()

        while time.monotonic() < deadline:
            with state_changed:
                active_sessions = list(sessions.items())
            for pid, (session, script) in active_sessions:
                if not sweep_extension(script):
                    detach_session(session)
                    with state_changed:
                        sessions.pop(pid, None)
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    finally:
        try:
            device.disable_spawn_gating()
        finally:
            device.off("spawn-added", on_spawn)
            with state_changed:
                remaining_sessions = list(sessions.values())
            for session, script in remaining_sessions:
                sweep_extension(script)
                detach_session(session)


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump FairPlay-decrypted Mach-O slices.")
    parser.add_argument("target", help="Bundle id, app name, or PID.")
    parser.add_argument("--out", required=True, help="Output directory for dumped slices.")
    parser.add_argument("--ipa", required=True, help="Encrypted IPA used to find app extensions.")
    parser.add_argument("--device", choices=["usb", "local"], default="usb", help="Frida device.")
    parser.add_argument("--spawn", action="store_true", help="Spawn the app instead of attaching.")
    parser.add_argument(
        "--settle",
        type=float,
        default=5.0,
        help="Seconds to wait for frameworks and running app extensions before the final sweep.",
    )
    args = parser.parse_args()
    configure_logging()
    started = time.monotonic()
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.command.started operation=dump"
    )
    try:
        status = run_dump(args)
    except KeyboardInterrupt:
        status = 130
        LOGGER.warning(
            "service=ipakeep component=frida event_name=frida.command.cancelled operation=dump"
        )
    except Exception as error:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.command.failed operation=dump error_type=%s duration_ms=%d",
            type(error).__name__,
            round((time.monotonic() - started) * 1000),
        )
        raise
    duration_ms = round((time.monotonic() - started) * 1000)
    LOGGER.log(
        logging.INFO if status == 0 else logging.ERROR,
        "service=ipakeep component=frida event_name=frida.command.completed operation=dump outcome=%s status=%d duration_ms=%d",
        "success" if status == 0 else "failure",
        status,
        duration_ms,
    )
    return status


def run_dump(args) -> int:

    try:
        process_names = extension_process_names(args.ipa)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.ipa.inspect_failed error_type=%s",
            type(error).__name__,
        )
        return 2

    os.makedirs(args.out, exist_ok=True)
    device = get_device(args.device)

    pid = None
    try:
        if args.spawn:
            pid = device.spawn([args.target])
            session = device.attach(pid)
        else:
            session = device.attach(attach_target(device, args.target))
    except frida.PermissionDeniedError:
        # macOS with SIP enabled won't let a normal user attach to another app
        # (no get-task-allow). Re-run as root, or boot with SIP disabled.
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.attach.permission_denied retry_as_root=true"
        )
        return 2
    except (ValueError, frida.ProcessNotFoundError) as exc:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.attach.failed error_type=%s",
            type(exc).__name__,
        )
        return 2

    written = []
    agent_path = os.path.join(HERE, "ipakeep_dump.js")
    script = load_agent(session, agent_path, args.out, written)
    if pid is not None:
        device.resume(pid)

    root = script.exports_sync.arm()
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.target.armed target_type=%s",
        type(root).__name__,
    )
    if process_names:
        LOGGER.info(
            "service=ipakeep component=frida event_name=frida.extensions.watch_started settle_seconds=%.3f",
            args.settle,
        )
    watch_extensions(device, process_names, agent_path, args.out, written, args.settle)
    script.exports_sync.sweep()
    session.detach()

    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.dump.completed slices=%d",
        len(written),
    )
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.next_step command=decrypt.patch"
    )
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
