"""Dependency-free tests for the installed bundle puller."""

from io import BytesIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import runpy
import sys
import tempfile
import unittest
import zipfile

frida = ModuleType("frida")
frida.get_usb_device = lambda **_kwargs: None
frida.InvalidOperationError = type("InvalidOperationError", (Exception,), {})
frida.NotSupportedError = type("NotSupportedError", (Exception,), {})
frida.TransportError = type("TransportError", (Exception,), {})
sys.modules["frida"] = frida

import ipakeep_pull
from ipakeep_pull import LOGGER, app_bundle_path, archive_name, copy_file, main, pull, walk


class FakeAPI:
    def __init__(self):
        self.entries = {
            "/Applications/Demo.app": [
                {"name": "z.txt", "kind": "file"},
                {"name": "Frameworks", "kind": "dir"},
                {"name": "link", "kind": "symlink"},
            ],
            "/Applications/Demo.app/Frameworks": [{"name": "A", "kind": "file"}],
        }
        self.files = {
            "/Applications/Demo.app/z.txt": b"last",
            "/Applications/Demo.app/Frameworks/A": b"first",
        }

    def list_directory(self, path):
        return self.entries[path.rstrip("/")]

    def file_size(self, path):
        return len(self.files[path])

    def read_chunk(self, path, offset, size):
        return self.files[path][offset : offset + size]


class FakeSession:
    def __init__(self, api=None):
        self.api = api or FakeAPI()
        self.detached = False

    def create_script(self, _source):
        return SimpleNamespace(load=lambda: None, exports_sync=self.api)

    def detach(self):
        self.detached = True


class FakeDevice:
    def __init__(self, path="/Applications/Demo.app"):
        self.path = path
        self.session = FakeSession()
        self.attachments = []

    def enumerate_applications(self, **_kwargs):
        if self.path is None:
            return []
        return [SimpleNamespace(parameters={"path": self.path})]

    def attach(self, pid):
        self.attachments.append(pid)
        return self.session


class PullTests(unittest.TestCase):
    def test_app_bundle_path_requires_an_installed_bundle(self):
        with self.assertRaisesRegex(ValueError, "not installed"):
            app_bundle_path(FakeDevice(None), "com.example.missing")
        with self.assertRaisesRegex(ValueError, "not installed"):
            app_bundle_path(FakeDevice(""), "com.example.missing")
        device = FakeDevice(" /Applications/Demo.app///")
        self.assertEqual(app_bundle_path(device, "com.example.demo"), " /Applications/Demo.app")

    def test_walk_sorts_recurses_and_skips_non_regular_files(self):
        device = FakeDevice()
        with self.assertLogs(LOGGER, level="WARNING") as capture:
            result = list(walk(device.session.api, "/Applications/Demo.app"))
        self.assertEqual(result, ["Frameworks/A", "z.txt"])
        self.assertIn("frida.pull.skipped", capture.output[0])

    def test_archive_name_uses_bundle_basename(self):
        self.assertEqual(
            archive_name("/Applications/Demo.app", "Frameworks/A"),
            "Payload/Demo.app/Frameworks/A",
        )

    def test_copy_file_handles_chunks_empty_files_and_short_reads(self):
        api = FakeAPI()
        sink = BytesIO()
        with patch.object(ipakeep_pull, "CHUNK", 2):
            self.assertEqual(copy_file(api, "/Applications/Demo.app/z.txt", sink), 4)
        self.assertEqual(sink.getvalue(), b"last")

        class EmptyFile:
            def file_size(self, _path):
                return 0

        self.assertEqual(copy_file(EmptyFile(), "/empty", BytesIO()), 0)

        class ShortRead:
            def file_size(self, _path):
                return 1

            def read_chunk(self, _path, _offset, _size):
                return b""

        with self.assertRaisesRegex(IOError, "short read"):
            copy_file(ShortRead(), "/partial", BytesIO())

    def test_pull_writes_archive_and_detaches(self):
        device = FakeDevice()
        with tempfile.TemporaryDirectory() as directory:
            script_path = Path(directory) / "ipakeep_pull.js"
            script_path.write_text("// test", encoding="utf-8")
            output = str(Path(directory) / "Demo.ipa")
            with patch.object(ipakeep_pull, "HERE", directory):
                self.assertEqual(pull(device, "com.example.demo", output), 2)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), [
                    "Payload/Demo.app/Frameworks/A",
                    "Payload/Demo.app/z.txt",
                ])
                self.assertEqual(archive.read("Payload/Demo.app/z.txt"), b"last")
        self.assertEqual(device.attachments, [0])
        self.assertTrue(device.session.detached)

    def test_pull_detaches_when_script_loading_fails(self):
        device = FakeDevice()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ipakeep_pull, "HERE", directory):
                with self.assertRaises(FileNotFoundError):
                    pull(device, "com.example.demo", str(Path(directory) / "out.ipa"))
        self.assertTrue(device.session.detached)

    def test_main_runs_and_maps_supported_frida_errors(self):
        with patch.object(sys, "argv", ["ipakeep_pull.py", "--out", "out.ipa", "com.example.demo"]):
            with patch.object(frida, "get_usb_device", return_value=FakeDevice()):
                with patch.object(ipakeep_pull, "pull", return_value=2):
                    self.assertEqual(main(), 0)

        for error in (
            ValueError("missing"),
            frida.InvalidOperationError("invalid"),
            frida.NotSupportedError("unsupported"),
            frida.TransportError("disconnected"),
        ):
            with (
                patch.object(sys, "argv", ["ipakeep_pull.py", "--out", "out.ipa", "com.example.demo"]),
                patch.object(frida, "get_usb_device", return_value=FakeDevice()),
                patch.object(ipakeep_pull, "pull", side_effect=error),
                patch.object(LOGGER, "error") as log_error,
            ):
                self.assertEqual(main(), 2)
                log_error.assert_called_once()
                self.assertIn("frida.pull.failed", log_error.call_args.args[0])

    def test_module_entrypoint_exits_with_main_result(self):
        with tempfile.TemporaryDirectory() as directory:
            output = str(Path(directory) / "Demo.ipa")
            with (
                patch.object(sys, "argv", ["ipakeep_pull.py", "--out", output, "com.example.demo"]),
                patch.object(frida, "get_usb_device", return_value=FakeDevice()),
                self.assertRaises(SystemExit) as exit_code,
            ):
                runpy.run_path(str(Path(__file__).with_name("ipakeep_pull.py")), run_name="__main__")
        self.assertEqual(exit_code.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
