"""Tests for the dependency-free target selection in the Frida runner."""

import shutil
import subprocess
import sys
import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

sys.modules["frida"] = ModuleType("frida")
from ipakeep_dump import (
    attach_target,
    extension_process_names,
    is_extension_process,
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
        self.exports_sync = SimpleNamespace(arm=lambda: "bundle-root", sweep=self.sweep)

    def on(self, _event, _callback):
        pass

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

    def on(self, _event, callback):
        self.spawn_handler = callback

    def off(self, _event, callback):
        self.spawn_handler = None

    def enable_spawn_gating(self):
        self.gating = True
        self.spawn_handler(SimpleNamespace(pid=43, identifier="com.example.Notify"))
        self.spawn_handler(SimpleNamespace(pid=44, identifier="com.other.App"))

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
            watch_extensions(
                device,
                {"Notify"},
                str(Path(__file__).with_name("ipakeep_dump.js")),
                temp_dir,
                [],
                0.01,
            )

        self.assertEqual(device.attached, [43, 42])
        self.assertEqual(device.resumed, [43, 44])
        self.assertFalse(device.gating)
        self.assertTrue(device.session.script.sweeps >= 1)
        self.assertTrue(device.session.detached)

    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_agent_dumps_regions_after_ios_clears_cryptid(self):
        script = Path(__file__).with_name("test_ipakeep_dump.js")
        subprocess.run([shutil.which("node"), str(script)], check=True)


if __name__ == "__main__":
    unittest.main()
