"""Secret-source contract tests with a fake local bridge."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]
HERMES_ROOT = PLUGIN_DIR.parent / "hermes-upstream"
if HERMES_ROOT.is_dir():
    sys.path.insert(0, str(HERMES_ROOT))


class BackendError(Exception):
    def __init__(self, kind="ref_invalid", message="invalid"):
        self.kind = kind
        super().__init__(message)


class SourceTests(unittest.TestCase):
    def setUp(self):
        package = types.ModuleType("applepw_source_test")
        package.__path__ = [str(PLUGIN_DIR)]
        backend = types.ModuleType("applepw_source_test.backend")
        backend.BridgeError = BackendError
        backend.parse_reference = lambda ref: ref if isinstance(ref, str) and ref.startswith("applepw://") else (_ for _ in ()).throw(BackendError())
        backend.normalize_domain = lambda domain: domain.lower().strip()
        backend.pair = lambda: {"paired": True}
        sys.modules[package.__name__] = package
        sys.modules[package.__name__ + ".backend"] = backend
        self.addCleanup(sys.modules.pop, package.__name__, None)
        self.addCleanup(sys.modules.pop, package.__name__ + ".backend", None)
        spec = importlib.util.spec_from_file_location(package.__name__ + ".source", PLUGIN_DIR / "source.py")
        self.source = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.source
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(self.source)

    @staticmethod
    def response(value, *, ok=True, kind=None, code=0):
        payload = {"ok": ok, "result": value} if ok else {"ok": False, "kind": kind or "internal", "error": "raw detail"}
        return subprocess.CompletedProcess([], code, json.dumps(payload), "raw stderr must not escape")

    def test_source_metadata_and_disabled_default(self):
        source = self.source.ApplePasswordsSource()
        self.assertEqual((source.name, source.scheme, source.shape, source.api_version),
                         ("apple_passwords", "applepw", "mapped", 1))
        self.assertFalse(source.is_enabled({"enabled": 1}))
        self.assertFalse(source.override_existing({}))
        self.assertEqual(source.fetch({}, Path("/tmp/home")).secrets, {})

    def test_fetch_validates_full_mapping_before_running_bridge(self):
        source = self.source.ApplePasswordsSource()
        with patch.object(self.source, "run_secret_cli") as runner:
            result = source.fetch({"enabled": True, "env": {
                "GOOD_KEY": "applepw://example.com/alice/password",
                "BAD NAME": "applepw://example.com/alice/password",
            }}, Path("/tmp/home"))
        runner.assert_not_called()
        self.assertEqual(result.secrets, {})
        self.assertEqual(result.error_kind.value, "ref_invalid")

    def test_fetch_is_all_or_none_and_sends_python_backend_argv(self):
        source = self.source.ApplePasswordsSource()
        calls = []

        def bridge(argv, **kwargs):
            calls.append((argv, kwargs))
            if "alice" in argv[-1]:
                return self.response("first-secret")
            return self.response(None, ok=False, kind="auth_failed", code=1)

        with patch.object(self.source, "run_secret_cli", side_effect=bridge):
            result = source.fetch({"enabled": True, "env": {
                "FIRST": "applepw://example.com/alice/password",
                "SECOND": "applepw://example.com/bob/password",
            }}, Path("/tmp/home"))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call[0][0] == sys.executable for call in calls))
        self.assertTrue(all(call[0][1].endswith("backend.py") for call in calls))
        self.assertEqual(result.secrets, {})
        self.assertEqual(result.error_kind.value, "auth_failed")
        self.assertNotIn("raw", result.error)

    def test_fetch_success_and_arbitrary_helper_mapping(self):
        with patch.object(self.source, "run_secret_cli", return_value=self.response("secret-value")):
            values = self.source.fetch_values({"0": "applepw://example.com/alice/password"})
        self.assertEqual(values, {"0": "secret-value"})

    def test_status_list_and_pair_return_sanitized_shapes(self):
        with patch.object(self.source, "run_secret_cli", return_value=self.response({"running": True, "paired": True})):
            self.assertEqual(self.source.bridge_status(), {"running": True, "paired": True})
        with patch.object(self.source, "run_secret_cli", return_value=self.response([
            {"domain": "example.com", "username": "alice", "password": "must-drop"}])):
            self.assertEqual(self.source.list_accounts("EXAMPLE.COM"), [{"domain": "example.com", "username": "alice"}])
        with patch.object(self.source.sys.stdin, "isatty", return_value=True), \
             patch.object(self.source.sys.stdout, "isatty", return_value=True), \
             patch.object(self.source.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(self.source.pair_interactive(), {"paired": True})
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], "pair")
        self.assertNotIn("SECRET", run.call_args.kwargs["env"])

    def test_error_kind_enum_and_status_strict_bools(self):
        self.assertEqual(self.source._error_kind(self.source.ErrorKind.AUTH_FAILED),
                         self.source.ErrorKind.AUTH_FAILED)
        with patch.object(self.source, "run_secret_cli", return_value=self.response(
                {"running": "false", "bridge": "yes", "paired": False})):
            self.assertEqual(self.source.bridge_status(), {"paired": False})

    def test_whitespace_password_is_preserved_and_nul_rejected(self):
        with patch.object(self.source, "run_secret_cli", return_value=self.response("  \n")):
            self.assertEqual(self.source.resolve_reference("applepw://example.com/alice/password"), "  \n")
        with patch.object(self.source, "run_secret_cli", return_value=self.response("bad\0value")):
            with self.assertRaises(self.source.BridgeError) as raised:
                self.source.resolve_reference("applepw://example.com/alice/password")
        self.assertEqual(raised.exception.kind, self.source.ErrorKind.EMPTY_VALUE)

    @unittest.skipUnless((PLUGIN_DIR / "backend.py").is_file(), "backend.py is still being authored")
    def test_real_backend_json_protocol_status_and_invalid_reference(self):
        # Read-only status and syntactically invalid input exercise the real worker without
        # pairing or asking it to reveal a credential.
        safe_env = {key: os.environ[key] for key in
                    ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL")
                    if key in os.environ}
        for operation, args in (("status", []), ("resolve", ["https://example.com"])):
            proc = subprocess.run([sys.executable, str(PLUGIN_DIR / "backend.py"), operation, *args],
                                  env=safe_env, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=15, check=False)
            payload = json.loads(proc.stdout)
            self.assertIsInstance(payload, dict)
            self.assertIsInstance(payload.get("ok"), bool)
            if operation == "resolve":
                self.assertFalse(payload["ok"])
                self.assertEqual(payload.get("kind"), "ref_invalid")

    def test_timeout_is_clamped(self):
        source = self.source.ApplePasswordsSource()
        self.assertEqual(source.fetch_timeout_seconds({"timeout_seconds": 900}), 120)
        self.assertEqual(source.fetch_timeout_seconds({"timeout_seconds": "bad"}), 45)


if __name__ == "__main__":
    unittest.main()
