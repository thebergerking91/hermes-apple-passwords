"""CLI behavior without a macOS bridge or Hermes installation."""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]


class BridgeError(Exception):
    pass


class CliTests(unittest.TestCase):
    def setUp(self):
        # Load only cli.py so tests have no dependency on Hermes or apwlib.
        package = types.ModuleType("applepw_cli_test")
        package.__path__ = [str(PLUGIN_DIR)]
        backend = types.ModuleType("applepw_cli_test.backend")
        backend.BridgeError = BridgeError

        def parse_reference(ref):
            if not ref.startswith("applepw://"):
                raise BridgeError("invalid reference")
            return ref

        backend.parse_reference = parse_reference
        source = types.ModuleType("applepw_cli_test.source")
        source.BridgeError = BridgeError
        source.fetch_values = lambda mapping: {name: "secret$\\word\nline2" for name in mapping}
        source.resolve_reference = lambda _ref: "secret$\\word\nline2"
        source.bridge_status = lambda: {"running": True, "paired": True}
        source.list_accounts = lambda domain: [
            {"domain": domain, "username": "alice", "password": "never-list-this"}
        ]
        self.source = source
        for name, module in (
            ("applepw_cli_test", package),
            ("applepw_cli_test.backend", backend),
            ("applepw_cli_test.source", source),
        ):
            self.addCleanup(sys.modules.pop, name, None)
            sys.modules[name] = module
        spec = importlib.util.spec_from_file_location("applepw_cli_test.cli", PLUGIN_DIR / "cli.py")
        self.cli = importlib.util.module_from_spec(spec)
        self.addCleanup(sys.modules.pop, spec.name, None)
        sys.modules[spec.name] = self.cli
        spec.loader.exec_module(self.cli)
        self.parser = argparse.ArgumentParser()
        self.cli.setup_cli(self.parser)

    def call(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.cli.handle_cli(self.parser.parse_args(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_read_requires_explicit_reveal(self):
        code, output, error = self.call("read", "applepw://x/alice/password")
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertNotIn("secret", error)
        self.assertEqual(
            self.call("read", "applepw://x/alice/password", "--reveal"),
            (0, "secret$\\word\nline2\n", ""),
        )

    def test_status_and_list_only_emit_metadata(self):
        self.assertEqual(self.call("status"), (0, "Bridge: running\nPairing: paired\n", ""))
        self.assertEqual(self.call("list", "example.com"), (0, "example.com\talice\n", ""))

    def test_run_passes_secrets_only_in_minimal_environment(self):
        with patch.dict(os.environ, {"UNRELATED_API_KEY": "must-not-inherit"}):
            with patch.object(self.cli.subprocess, "run", return_value=types.SimpleNamespace(returncode=7)) as run:
                code, output, error = self.call(
                    "run", "--env", "TOKEN=applepw://x/alice/password", "--", "program", "argument"
                )
        self.assertEqual((code, output, error), (7, "", ""))
        args, kwargs = run.call_args
        self.assertEqual(args, (["program", "argument"],))
        self.assertEqual(kwargs["env"]["TOKEN"], "secret$\\word\nline2")
        self.assertNotIn("UNRELATED_API_KEY", kwargs["env"])
        self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)

    def test_run_failure_does_not_log_value_or_exception(self):
        def fail(_argv, **_kwargs):
            raise OSError("secret$\\word\nline2")

        with patch.object(self.cli.subprocess, "run", side_effect=fail):
            code, output, error = self.call(
                "run", "--env", "TOKEN=applepw://x/alice/password", "--", "missing"
            )
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertNotIn("secret", error)
        self.assertNotIn("TOKEN", error)

    def test_sanitized_bridge_error_is_shown_without_value(self):
        def fail(_reference):
            raise self.source.BridgeError("Apple Passwords pairing has expired; pair again.")

        with patch.object(self.source, "resolve_reference", side_effect=fail):
            code, output, error = self.call("read", "applepw://x/alice/password", "--reveal")
        self.assertEqual((code, output), (1, ""))
        self.assertIn("pair again", error)
        self.assertNotIn("secret", error)

    def test_inject_is_private_exclusive_and_substitutes_literal_values(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            output_path = Path(directory) / "output"
            input_path.write_text("token={{ applepw://x/alice/password }}", encoding="utf-8")
            code, output, error = self.call(
                "inject", "--input", str(input_path), "--output", str(output_path)
            )
            self.assertEqual((code, error), (0, ""))
            self.assertNotIn("secret", output)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "token=secret$\\word\nline2")
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
            code, output, error = self.call(
                "inject", "--input", str(input_path), "--output", str(output_path)
            )
            self.assertEqual(code, 1)
            self.assertEqual(output, "")
            self.assertNotIn("secret", error)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "token=secret$\\word\nline2")

    def test_inject_rejects_malformed_placeholder_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input"
            output_path = Path(directory) / "output"
            input_path.write_text("token={{ applepw://x/alice/password }", encoding="utf-8")
            code, output, error = self.call(
                "inject", "--input", str(input_path), "--output", str(output_path)
            )
            self.assertEqual(code, 1)
            self.assertEqual(output, "")
            self.assertIn("malformed", error)
            self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
