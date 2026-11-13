#!/usr/bin/env python3
"""Thin Frida runner for ipakeep's on-device FairPlay slice dumper.

Loads ipakeep_dump.js into the target app, lets it settle (so lazily `dlopen`'d
frameworks map and get dumped), and watches for app extensions from the IPA to
run in their own process. Extensions that did not run on their own are then
spawned by bundle id and dumped; any that cannot be launched are reported. It writes each decrypted slice to <out>/<name>, where
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
import queue
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


def extension_bundles(ipa_path: str) -> list[tuple[str, str]]:
    """(CFBundleIdentifier, CFBundleExecutable) of every .appex; missing values are ''."""
    bundles = []
    with zipfile.ZipFile(ipa_path) as ipa:
        for entry in ipa.infolist():
            if not is_extension_info_plist(entry.filename):
                continue
            try:
                metadata = plistlib.loads(ipa.read(entry))
            except Exception as error:
                raise ValueError(f"invalid extension plist {entry.filename}: {error}") from error
            if isinstance(metadata, dict):
                bundles.append(
                    tuple(
                        value if isinstance((value := metadata.get(key)), str) else ""
                        for key in ("CFBundleIdentifier", "CFBundleExecutable")
                    )
                )
    return bundles


def is_extension_info_plist(filename: str) -> bool:
    parts = PurePosixPath(filename).parts
    return any(
        part.endswith(".app")
        and parts[index + 1] == "PlugIns"
        and parts[index + 2].endswith(".appex")
        and parts[index + 3] == "Info.plist"
        for index, part in enumerate(parts[:-3])
    )


def extension_process_names(ipa_path: str) -> set[str]:
    return bundle_process_names(extension_bundles(ipa_path))


def bundle_process_names(bundles) -> set[str]:
    return {value for bundle in bundles for value in bundle if value}


def is_extension_process(process_name: str, extension_names: set[str]) -> bool:
    candidates = {process_name, os.path.basename(process_name)}
    return any(
        candidate == executable or candidate.endswith(f".{executable}")
        for candidate in candidates
        for executable in extension_names
        if executable
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
        script.exports_sync.arm()
        LOGGER.info(
            "service=ipakeep component=frida event_name=frida.extension.attached pid=%d",
            pid,
        )
        return session, script
    except Exception:
        detach_session(session)
        raise


def try_attach_extension(device, pid: int, agent_path: str, out_dir: str, written: list[str]):
    try:
        return attach_extension(device, pid, agent_path, out_dir, written)
    except Exception as error:
        LOGGER.warning(
            "service=ipakeep component=frida event_name=frida.extension.attach_failed pid=%d error_type=%s error=%r",
            pid,
            type(error).__name__,
            str(error),
        )
        return None


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


def kill_process(device, pid: int) -> None:
    try:
        device.kill(pid)
    except Exception as error:
        LOGGER.warning(
            "service=ipakeep component=frida event_name=frida.process.kill_failed pid=%d error_type=%s error=%r",
            pid,
            type(error).__name__,
            str(error),
        )


def watch_extensions(
    device, process_names, agent_path, out_dir, written, seconds: float, on_gated=None
) -> set[str]:
    """Attach to extension processes for `seconds`; returns the matched process names.

    Frida delivers `spawn-added` on its own thread, where blocking device calls can
    deadlock, so the callback only enqueues. This thread attaches, arms and resumes.
    """
    matched = set()
    if not process_names:
        time.sleep(seconds)
        return matched

    deadline = time.monotonic() + seconds
    pending_spawns = queue.Queue()
    seen_pids = set()
    sessions = {}

    def on_spawn(spawn):
        pending_spawns.put(spawn)

    def track(pid: int, name: str) -> None:
        seen_pids.add(pid)
        attached = try_attach_extension(device, pid, agent_path, out_dir, written)
        if attached is not None:
            sessions[pid] = attached
            matched.add(name)

    def handle_spawn(spawn) -> None:
        try:
            if spawn.pid not in seen_pids and is_extension_process(
                spawn.identifier, process_names
            ):
                track(spawn.pid, spawn.identifier)
        finally:
            resume_spawn(device, spawn.pid)

    def drain_spawns(timeout: float) -> None:
        try:
            spawn = pending_spawns.get(timeout=timeout) if timeout > 0 else pending_spawns.get_nowait()
        except queue.Empty:
            return
        while True:
            handle_spawn(spawn)
            try:
                spawn = pending_spawns.get_nowait()
            except queue.Empty:
                return

    device.on("spawn-added", on_spawn)
    try:
        device.enable_spawn_gating()
    except Exception:
        device.off("spawn-added", on_spawn)
        raise
    try:
        if on_gated is not None:
            on_gated()
        drain_spawns(0)
        for process in device.enumerate_processes():
            if process.pid not in seen_pids and is_extension_process(process.name, process_names):
                track(process.pid, process.name)

        while (remaining := deadline - time.monotonic()) > 0:
            drain_spawns(min(0.1, remaining))
            for pid, (session, script) in list(sessions.items()):
                if not sweep_extension(script):
                    detach_session(session)
                    sessions.pop(pid, None)
    finally:
        try:
            device.disable_spawn_gating()
        finally:
            device.off("spawn-added", on_spawn)
            while True:
                try:
                    resume_spawn(device, pending_spawns.get_nowait().pid)
                except queue.Empty:
                    break
            for session, script in sessions.values():
                sweep_extension(script)
                detach_session(session)
    return matched


def bundles_to_launch(bundles, matched_names: set[str]) -> list[str]:
    """Bundle ids of extensions that were not already dumped from a running process."""
    return [
        identifier
        for identifier, executable in bundles
        if identifier
        and not any(
            is_extension_process(name, {identifier, executable}) for name in matched_names
        )
    ]


def dump_launched_extension(device, identifier: str, agent_path, out_dir, written, settle: float):
    pid = device.spawn(identifier)
    try:
        session = device.attach(pid)
        try:
            script = load_agent(session, agent_path, out_dir, written)
            script.exports_sync.arm()
            resume_spawn(device, pid)
            LOGGER.info(
                "service=ipakeep component=frida event_name=frida.extension.launched bundle_id=%r pid=%d",
                identifier,
                pid,
            )
            time.sleep(settle)
            sweep_extension(script)
        finally:
            detach_session(session)
    finally:
        kill_process(device, pid)


def launch_extensions(device, identifiers, agent_path, out_dir, written, settle: float) -> list[str]:
    """Spawn each extension by bundle id and dump it; returns the ids that failed."""
    failed = []
    for identifier in identifiers:
        try:
            dump_launched_extension(device, identifier, agent_path, out_dir, written, settle)
        except Exception as error:
            failed.append(identifier)
            LOGGER.warning(
                "service=ipakeep component=frida event_name=frida.extension.launch_failed bundle_id=%r error_type=%s error=%r",
                identifier,
                type(error).__name__,
                str(error),
            )
    if failed:
        LOGGER.warning(
            "service=ipakeep component=frida event_name=frida.extensions.not_dumped bundle_ids=%r hint=%r",
            failed,
            "trigger these extensions on the device and re-run while they are active",
        )
    return failed


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
        bundles = extension_bundles(args.ipa)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.ipa.inspect_failed error_type=%s",
            type(error).__name__,
        )
        return 2
    process_names = bundle_process_names(bundles)

    os.makedirs(args.out, exist_ok=True)
    device = get_device(args.device)

    pid = None
    try:
        if args.spawn:
            pid = device.spawn([args.target])
            session = device.attach(pid)
        else:
            session = device.attach(attach_target(device, args.target))
    except frida.PermissionDeniedError as error:
        # macOS with SIP enabled won't let a normal user attach to another app
        # (no get-task-allow). Re-run as root, or boot with SIP disabled.
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.attach.permission_denied retry_as_root=true error=%r",
            str(error),
        )
        if pid is not None:
            kill_process(device, pid)
        return 2
    except frida.NotSupportedError as error:
        # FrontBoard refuses to launch apps while the device is locked.
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.spawn.failed hint=%r error=%r",
            "unlock the device and keep the screen on while dumping",
            str(error),
        )
        if pid is not None:
            kill_process(device, pid)
        return 2
    except (ValueError, frida.ProcessNotFoundError, frida.ExecutableNotFoundError) as error:
        LOGGER.error(
            "service=ipakeep component=frida event_name=frida.attach.failed error_type=%s error=%r",
            type(error).__name__,
            str(error),
        )
        if pid is not None:
            kill_process(device, pid)
        return 2

    written = []
    agent_path = os.path.join(HERE, "ipakeep_dump.js")
    try:
        matched = dump_main_app(device, session, pid, bundles, agent_path, args, written)
    except BaseException:
        if pid is not None:
            kill_process(device, pid)
        raise
    finally:
        detach_session(session)

    launch_extensions(
        device, bundles_to_launch(bundles, matched), agent_path, args.out, written, args.settle
    )

    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.dump.completed slices=%d",
        len(written),
    )
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.next_step command=decrypt.patch"
    )
    return 0 if written else 1


def request_extension_launches(device, host_session, identifiers) -> None:
    """Ask iOS to start each extension via NSExtension.

    SpringBoard is the preferred host: it is always running and can start
    event-driven extensions (e.g. notification services) even while the device
    is locked. The dumped app is the fallback host (e.g. on a Mac).
    """
    if not identifiers:
        return
    with open(os.path.join(HERE, "ipakeep_extensions.js"), "r", encoding="utf-8") as handle:
        source = handle.read()
    springboard = None
    try:
        springboard = device.attach("SpringBoard")
    except (frida.ProcessNotFoundError, frida.NotSupportedError, frida.PermissionDeniedError):
        pass
    try:
        launcher = (springboard or host_session).create_script(source)
        launcher.load()
        for identifier in identifiers:
            try:
                requested = launcher.exports_sync.launch(identifier)
            except frida.core.RPCException as error:
                requested = False
                LOGGER.warning(
                    "service=ipakeep component=frida event_name=frida.extension.request_failed bundle_id=%r error=%r",
                    identifier,
                    str(error),
                )
            LOGGER.info(
                "service=ipakeep component=frida event_name=frida.extension.requested bundle_id=%r host=%s requested=%s",
                identifier,
                "SpringBoard" if springboard else "app",
                requested,
            )
    finally:
        if springboard is not None:
            detach_session(springboard)


def dump_main_app(device, session, pid, bundles, agent_path, args, written) -> set[str]:
    script = load_agent(session, agent_path, args.out, written)
    if pid is not None:
        device.resume(pid)

    root = script.exports_sync.arm()
    LOGGER.info(
        "service=ipakeep component=frida event_name=frida.target.armed target_type=%s",
        type(root).__name__,
    )
    process_names = bundle_process_names(bundles)
    identifiers = [identifier for identifier, _ in bundles if identifier]
    if process_names:
        LOGGER.info(
            "service=ipakeep component=frida event_name=frida.extensions.watch_started settle_seconds=%.3f",
            args.settle,
        )
    matched = watch_extensions(
        device,
        process_names,
        agent_path,
        args.out,
        written,
        args.settle,
        on_gated=lambda: request_extension_launches(device, session, identifiers),
    )
    script.exports_sync.sweep()
    return matched


if __name__ == "__main__":
    raise SystemExit(main())
