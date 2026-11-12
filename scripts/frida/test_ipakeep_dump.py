"""Tests for the dependency-free target selection in the Frida runner."""

import sys
import unittest
from types import ModuleType, SimpleNamespace

sys.modules["frida"] = ModuleType("frida")
from ipakeep_dump import attach_target


class FakeDevice:
    def __init__(self, applications):
        self.applications = applications

    def enumerate_applications(self):
        return self.applications


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


if __name__ == "__main__":
    unittest.main()
