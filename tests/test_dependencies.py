"""Dependency checks: Python version guard and pyserial install/upgrade."""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from unittest import mock

import root_tool
from ascent_root import protocol
from ascent_root.ui import UI


def make_ui() -> UI:
    return UI(color=False)


def quiet_ensure(ui: UI, auto: bool = True) -> None:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        root_tool.ensure_pyserial(ui, auto)


class Completed:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode


class version_parse_tests(unittest.TestCase):
    def test_plain_versions(self) -> None:
        self.assertEqual(protocol.parse_pyserial_version("3.5"), (3, 5))
        self.assertEqual(protocol.parse_pyserial_version("2.7"), (2, 7))
        self.assertEqual(protocol.parse_pyserial_version("3.10.1"), (3, 10))

    def test_surrounding_noise(self) -> None:
        self.assertEqual(protocol.parse_pyserial_version(" v3.5 "), (3, 5))
        self.assertEqual(protocol.parse_pyserial_version("3.5.post1"), (3, 5))

    def test_unparseable_values(self) -> None:
        for value in (None, "", "unknown", "3", "v"):
            self.assertIsNone(protocol.parse_pyserial_version(value), value)

    def test_supported_boundaries(self) -> None:
        with mock.patch.object(protocol, "pyserial_version", return_value="3.5"):
            self.assertTrue(protocol.pyserial_supported())
        with mock.patch.object(protocol, "pyserial_version", return_value="3.4"):
            self.assertFalse(protocol.pyserial_supported())
        with mock.patch.object(protocol, "pyserial_version", return_value="4.0"):
            self.assertTrue(protocol.pyserial_supported())
        with mock.patch.object(protocol, "pyserial_version", return_value="weird"):
            self.assertIsNone(protocol.pyserial_supported())
        with mock.patch.object(protocol, "pyserial_version", return_value=None):
            self.assertIsNone(protocol.pyserial_supported())


class python_guard_tests(unittest.TestCase):
    def test_current_interpreter_passes(self) -> None:
        root_tool._check_python_version(tuple(sys.version_info))

    def test_old_interpreter_is_rejected(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            root_tool._check_python_version((3, 9, 7))
        self.assertEqual(caught.exception.code, 1)
        message = stderr.getvalue()
        self.assertIn("3.10", message)
        self.assertIn("3.9.7", message)
        self.assertIn(root_tool.PYTHON_DOWNLOAD, message)


class ensure_pyserial_tests(unittest.TestCase):
    def test_supported_version_is_left_alone(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", True),
            mock.patch.object(protocol, "pyserial_supported", return_value=True),
            mock.patch.object(protocol, "pyserial_version", return_value="3.5"),
            mock.patch("subprocess.run") as run,
        ):
            quiet_ensure(make_ui())
        run.assert_not_called()

    def test_missing_serial_is_installed(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", False),
            mock.patch.object(protocol, "reload_pyserial", return_value=True),
            mock.patch.object(protocol, "pyserial_supported", return_value=True),
            mock.patch.object(protocol, "pyserial_version", return_value="3.5"),
            mock.patch("subprocess.run", return_value=Completed(0)) as run,
        ):
            quiet_ensure(make_ui())

        command = run.call_args.args[0]
        self.assertEqual(command[:3], [sys.executable, "-m", "pip"])
        self.assertIn("install", command)
        self.assertIn("pyserial>=3.5", command)

    def test_missing_serial_declined(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", False),
            mock.patch("builtins.input", return_value="n"),
            mock.patch("subprocess.run") as run,
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui(), auto=False)
        run.assert_not_called()
        self.assertIn("pip install", str(caught.exception))

    def test_old_serial_is_upgraded(self) -> None:
        versions = iter(["3.4", "3.5"])
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", True),
            mock.patch.object(protocol, "pyserial_supported", side_effect=[False, True]),
            mock.patch.object(protocol, "pyserial_version", side_effect=lambda: next(versions)),
            mock.patch.object(protocol, "reload_pyserial", return_value=True) as reload,
            mock.patch("subprocess.run", return_value=Completed(0)) as run,
        ):
            quiet_ensure(make_ui())

        command = run.call_args.args[0]
        self.assertIn("--upgrade", command)
        self.assertIn("pyserial>=3.5", command)
        reload.assert_called_once()

    def test_old_serial_declined(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", True),
            mock.patch.object(protocol, "pyserial_supported", return_value=False),
            mock.patch.object(protocol, "pyserial_version", return_value="3.4"),
            mock.patch("builtins.input", return_value="n"),
            mock.patch("subprocess.run") as run,
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui(), auto=False)
        run.assert_not_called()
        self.assertIn("pip install", str(caught.exception))

    def test_unknown_version_only_warns(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", True),
            mock.patch.object(protocol, "pyserial_supported", return_value=None),
            mock.patch.object(protocol, "pyserial_version", return_value=None),
            mock.patch("subprocess.run") as run,
        ):
            quiet_ensure(make_ui())
        run.assert_not_called()

    def test_pip_failure_is_reported(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", False),
            mock.patch("subprocess.run", return_value=Completed(1)),
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui())
        self.assertIn("manually", str(caught.exception))

    def test_pip_cannot_run_is_reported(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", False),
            mock.patch("subprocess.run", side_effect=OSError("no pip")),
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui())
        self.assertIn("no pip", str(caught.exception))

    def test_reimport_failure_is_reported(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", False),
            mock.patch.object(protocol, "reload_pyserial", return_value=False),
            mock.patch("subprocess.run", return_value=Completed(0)),
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui())
        self.assertIn("cannot be imported", str(caught.exception))

    def test_upgrade_that_did_not_take_effect_is_reported(self) -> None:
        with (
            mock.patch.object(protocol, "HAS_PYSERIAL", True),
            mock.patch.object(protocol, "pyserial_supported", side_effect=[False, False]),
            mock.patch.object(protocol, "pyserial_version", return_value="3.4"),
            mock.patch.object(protocol, "reload_pyserial", return_value=True),
            mock.patch("subprocess.run", return_value=Completed(0)),
            self.assertRaises(root_tool.ToolkitError) as caught,
        ):
            quiet_ensure(make_ui())
        self.assertIn("still older", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
