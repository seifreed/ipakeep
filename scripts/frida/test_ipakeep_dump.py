"""Tests for the dependency-free target selection in the Frida runner."""

from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.modules["frida"] = ModuleType("frida")
from ipakeep_dump import (
    LOGGER,
    attach_target,
    bundles_to_launch,
    configure_logging,
    extension_bundles,
    extension_process_names,
    is_extension_process,
    launch_extensions,
    load_agent,
    main,
    watch_extensions,
)


class FakeDevice:
    def __init__(self, applications):
        self.applications = applications

    def enumerate_applications(self):
        return self.applications


class FakeScript:
    def __init__(self):
        self.sweeps = 0
        self.message_handler = None
        self.exports_sync = SimpleNamespace(arm=lambda: "bundle-root", sweep=self.sweep)

    def on(self, _event, callback):
        self.message_handler = callback

    def load(self):
        pass

    def sweep(self):
        self.sweeps += 1


class FakeSession:
    def __init__(self):
        self.script = FakeScript()
        self.detached = False

    def create_script(self, _source):
        return self.script

    def detach(self):
        self.detached = True


class FakeProcessDevice:
    def __init__(self):
        self.processes = [SimpleNamespace(pid=42, name="Notify")]
        self.session = FakeSession()
        self.attached = []
        self.resumed = []
        self.spawn_handler = None
        self.gating = False
        self.attached_during_callback = None

    def on(self, _event, callback):
        self.spawn_handler = callback

    def off(self, _event, callback):
        self.spawn_handler = None

    def enable_spawn_gating(self):
        self.gating = True
        self.spawn_handler(SimpleNamespace(pid=43, identifier="com.example.Notify"))
        self.spawn_handler(SimpleNamespace(pid=44, identifier="com.other.App"))
        self.attached_during_callback = list(self.attached)

    def disable_spawn_gating(self):
        self.gating = False

    def resume(self, pid):
        self.resumed.append(pid)

    def enumerate_processes(self):
        return self.processes

    def attach(self, pid):
        self.attached.append(pid)
        return self.session


class AttachTargetTests(unittest.TestCase):
    def test_configured_logger_writes_utc_text_to_stderr(self):
        stderr = StringIO()
        with (
            patch.dict("os.environ", {"IPAKEEP_FRIDA_LOG_LEVEL": "INFO"}),
            redirect_stderr(stderr),
        ):
            configure_logging()
            LOGGER.info("service=ipakeep component=frida event_name=test.stderr")

        self.assertRegex(
            stderr.getvalue(),
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z INFO ipakeep\.frida .*event_name=test\.stderr",
        )

    def test_log_level_is_configurable_from_environment(self):
        with patch.dict("os.environ", {"IPAKEEP_FRIDA_LOG_LEVEL": "DEBUG"}):
            with self.assertLogs("ipakeep.frida", level="DEBUG") as capture:
                configure_logging()
                LOGGER.debug("event_name=test.debug")

        self.assertIn("event_name=test.debug", capture.output[0])

    def test_invalid_log_level_falls_back_to_info(self):
        with patch.dict("os.environ", {"IPAKEEP_FRIDA_LOG_LEVEL": "invalid"}):
            with self.assertLogs("ipakeep.frida", level="WARNING") as capture:
                configure_logging()

        self.assertIn("logging.invalid_level", capture.output[0])

    def test_bundle_id_resolves_to_running_process_id(self):
        device = FakeDevice(
            [SimpleNamespace(identifier="com.example.app", name="Example", pid=1234)]
        )
        self.assertEqual(attach_target(device, "com.example.app"), 1234)

    def test_non_running_bundle_id_suggests_spawn(self):
        device = FakeDevice(
            [SimpleNamespace(identifier="com.example.app", name="Example", pid=0)]
        )
        with self.assertRaisesRegex(ValueError, "pass --spawn"):
            attach_target(device, "com.example.app")

    def test_name_and_numeric_pid_are_preserved(self):
        device = FakeDevice([])
        self.assertEqual(attach_target(device, "Example"), "Example")
        self.assertEqual(attach_target(device, "1234"), 1234)

    def test_ipa_extension_executables_are_discovered(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ipa_path = Path(temp_dir) / "app.ipa"
            with zipfile.ZipFile(ipa_path, "w") as ipa:
                ipa.writestr(
                    "Payload/Example.app/PlugIns/Notify.appex/Info.plist",
                    plistlib.dumps(
                        {
                            "CFBundleExecutable": "NotificationService",
                            "CFBundleIdentifier": "com.example.NotificationService",
                        }
                    ),
                )
                ipa.writestr(
                    "Payload/Example.app/Info.plist",
                    plistlib.dumps({"CFBundleExecutable": "Example"}),
                )

            self.assertEqual(
                extension_process_names(str(ipa_path)),
                {"NotificationService", "com.example.NotificationService"},
            )

    def test_agent_messages_use_safe_structured_logging(self):
        session = FakeSession()
        with tempfile.TemporaryDirectory() as temp_dir:
            agent = Path(temp_dir) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            script = load_agent(session, str(agent), temp_dir, [])

            with self.assertLogs("ipakeep.frida", level="INFO") as capture:
                session.script.message_handler(
                    {
                        "type": "send",
                        "payload": {
                            "event": "slice",
                            "name": "slice\nname.bin",
                            "cryptsize": 3,
                        },
                    },
                    b"abc",
                )

            self.assertEqual(Path(temp_dir, "slice\nname.bin").read_bytes(), b"abc")
            self.assertIs(session.script, script)
            self.assertIn("event_name=frida.slice.dumped", capture.output[0])
            self.assertIn("artifact='slice\\nname.bin'", capture.output[0])
            self.assertNotIn("\nslice name.bin", capture.output[0])

    def test_command_failure_records_safe_lifecycle_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_ipa = str(Path(temp_dir) / "private-path.ipa")
            args = SimpleNamespace(
                target="com.example.app",
                out=temp_dir,
                ipa=missing_ipa,
                device="usb",
                spawn=False,
                settle=0.0,
            )
            with (
                patch.dict("os.environ", {"IPAKEEP_FRIDA_LOG_LEVEL": "INFO"}),
                patch("ipakeep_dump.argparse.ArgumentParser.parse_args", return_value=args),
                self.assertLogs("ipakeep.frida", level="INFO") as capture,
            ):
                self.assertEqual(main(), 2)

            self.assertIn("event_name=frida.command.started", capture.output[0])
            self.assertIn("event_name=frida.ipa.inspect_failed", "\n".join(capture.output))
            self.assertIn("event_name=frida.command.completed", capture.output[-1])
            self.assertIn("duration_ms=", capture.output[-1])
            self.assertNotIn("private-path.ipa", "\n".join(capture.output))

    def test_unexpected_failure_is_logged_without_losing_original_cause(self):
        args = SimpleNamespace(
            target="com.example.app",
            out="dump",
            ipa="private-path.ipa",
            device="usb",
            spawn=False,
            settle=0.0,
        )
        with (
            patch.dict("os.environ", {"IPAKEEP_FRIDA_LOG_LEVEL": "INFO"}),
            patch("ipakeep_dump.argparse.ArgumentParser.parse_args", return_value=args),
            patch("ipakeep_dump.run_dump", side_effect=ValueError("private error details")),
            self.assertLogs("ipakeep.frida", level="INFO") as capture,
        ):
            with self.assertRaisesRegex(ValueError, "private error details"):
                main()

        failure = next(line for line in capture.output if "frida.command.failed" in line)
        self.assertIn("error_type=ValueError", failure)
        self.assertIn("duration_ms=", failure)
        self.assertNotIn("private error details", "\n".join(capture.output))

    def test_extension_process_matches_executable_or_qualified_name(self):
        executables = {"NotificationService"}
        self.assertTrue(is_extension_process("NotificationService", executables))
        self.assertTrue(is_extension_process("com.example.NotificationService", executables))
        self.assertFalse(is_extension_process("Example", executables))

    def test_invalid_extension_plist_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ipa_path = Path(temp_dir) / "app.ipa"
            with zipfile.ZipFile(ipa_path, "w") as ipa:
                ipa.writestr(
                    "Payload/Example.app/PlugIns/Notify.appex/Info.plist", "not a plist"
                )

            with self.assertRaisesRegex(ValueError, "invalid extension plist"):
                extension_process_names(str(ipa_path))

    def test_running_and_spawned_extensions_are_attached_and_swept(self):
        device = FakeProcessDevice()
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertLogs("ipakeep.frida", level="INFO"):
                watch_extensions(
                    device,
                    {"Notify"},
                    str(Path(__file__).with_name("ipakeep_dump.js")),
                    temp_dir,
                    [],
                    0.01,
                )

        self.assertEqual(device.attached_during_callback, [])
        self.assertEqual(device.attached, [43, 42])
        self.assertEqual(device.resumed, [43, 44])
        self.assertFalse(device.gating)
        self.assertTrue(device.session.script.sweeps >= 1)
        self.assertTrue(device.session.detached)

    def test_spawn_identifier_path_matches_by_basename(self):
        self.assertTrue(
            is_extension_process("/private/var/containers/X/Notify.appex/Notify", {"Notify"})
        )
        self.assertFalse(is_extension_process("/usr/libexec/other", {"Notify"}))

    def test_extension_bundles_report_identifier_and_executable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ipa_path = Path(temp_dir) / "app.ipa"
            with zipfile.ZipFile(ipa_path, "w") as ipa:
                ipa.writestr(
                    "Payload/Example.app/PlugIns/Notify.appex/Info.plist",
                    plistlib.dumps(
                        {"CFBundleExecutable": "Notify", "CFBundleIdentifier": "com.x.Notify"}
                    ),
                )
            self.assertEqual(extension_bundles(str(ipa_path)), [("com.x.Notify", "Notify")])

    def test_only_extensions_not_seen_running_are_launched(self):
        bundles = [("com.x.Notify", "Notify"), ("com.x.Widget", "Widget"), ("", "Nameless")]
        self.assertEqual(bundles_to_launch(bundles, {"com.x.Notify"}), ["com.x.Widget"])

    def test_extension_launch_failure_is_reported_and_spawned_process_killed(self):
        class LaunchDevice:
            def __init__(self):
                self.killed = []
                self.session = FakeSession()

            def spawn(self, identifier):
                if identifier == "com.x.Broken":
                    raise RuntimeError("unable to launch extension")
                return 77

            def attach(self, pid):
                return self.session

            def resume(self, pid):
                pass

            def kill(self, pid):
                self.killed.append(pid)

        device = LaunchDevice()
        with tempfile.TemporaryDirectory() as temp_dir:
            agent = Path(temp_dir) / "agent.js"
            agent.write_text("agent", encoding="utf-8")
            with self.assertLogs("ipakeep.frida", level="INFO") as capture:
                failed = launch_extensions(
                    device, ["com.x.Broken", "com.x.Widget"], str(agent), temp_dir, [], 0
                )

        log = "\n".join(capture.output)
        self.assertEqual(failed, ["com.x.Broken"])
        self.assertIn("unable to launch extension", log)
        self.assertIn("frida.extensions.not_dumped", log)
        self.assertEqual(device.killed, [77])
        self.assertTrue(device.session.detached)
        self.assertEqual(device.session.script.sweeps, 1)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_agent_dumps_regions_after_ios_clears_cryptid(self):
        script = Path(__file__).with_name("test_ipakeep_dump.js")
        subprocess.run([shutil.which("node"), str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
