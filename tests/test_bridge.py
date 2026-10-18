"""Worker-launcher (bridge.py) contract tests. Synthetic values only; no live vault."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]


def load_bridge():
    spec = importlib.util.spec_from_file_location("applepw_bridge_test", PLUGIN_DIR / "bridge.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def completed(payload, code=0, stderr="RAW-STDERR-SECRET"):
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.CompletedProcess([], code, text, stderr)


class FakeTTY:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


class BridgeTestCase(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()
        self.addCleanup(sys.modules.pop, "applepw_bridge_test", None)


class RunWorkerTests(BridgeTestCase):
    def run_with(self, response=None, *, side_effect=None, **kwargs):
        """Call run_worker with run_secret_cli mocked; return (result_or_exc, mock)."""
        with patch.object(self.bridge, "run_secret_cli", return_value=response, side_effect=side_effect) as runner:
            return self.bridge.run_worker(kwargs.pop("op", "status"), **kwargs), runner

    def test_argv_uses_isolated_mode_and_double_dash_before_values(self):
        with patch.object(self.bridge, "worker_extra_env", return_value={"PYTHONPATH": "/deps"}):
            result, runner = self.run_with(completed({"ok": True, "result": {"x": 1}}),
                                           op="resolve", values=["-n", "applepw://example.com/a/password"])
        self.assertEqual(result, {"x": 1})
        argv = runner.call_args.args[0]
        self.assertEqual(argv[:4], [sys.executable, "-P", str(self.bridge.WORKER), "resolve"])
        self.assertEqual(argv[4:], ["--", "-n", "applepw://example.com/a/password"])
        self.assertEqual(runner.call_args.kwargs["extra_env"],
                         {"PYTHONPATH": "/deps", "PYTHONSAFEPATH": "1"})

    def test_no_values_means_no_double_dash(self):
        _, runner = self.run_with(completed({"ok": True, "result": None}), op="status")
        self.assertEqual(runner.call_args.args[0][-1], "status")
        self.assertNotIn("--", runner.call_args.args[0])

    def test_worker_path_is_sibling_backend(self):
        self.assertEqual(self.bridge.WORKER, PLUGIN_DIR / "backend.py")

    def test_invalid_op_or_values_rejected_before_spawn(self):
        with patch.object(self.bridge, "run_secret_cli") as runner:
            for op, values in (("", ()), ("resolve", [1]), ("resolve", ["a\0b"])):
                with self.assertRaises(self.bridge.BridgeError) as raised:
                    self.bridge.run_worker(op, values)
                self.assertEqual(raised.exception.kind, "ref_invalid")
        runner.assert_not_called()

    def test_timeout_is_clamped(self):
        for requested, expected in ((0, 0.1), (-5, 0.1), (900, 60.0), (12.5, 12.5),
                                    ("junk", 30.0), (float("nan"), 30.0), (float("inf"), 30.0)):
            _, runner = self.run_with(completed({"ok": True, "result": 1}), timeout=requested)
            self.assertEqual(runner.call_args.kwargs["timeout"], expected, requested)

    def test_timeout_runtime_error_maps_to_timeout_without_leaking_text(self):
        for exc in (RuntimeError("python timed out after 30s /secret/path"),
                    subprocess.TimeoutExpired(["x"], 1)):
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.run_with(side_effect=exc)
            self.assertEqual(raised.exception.kind, "timeout")
            self.assertEqual(str(raised.exception), self.bridge.FIXED_MESSAGES["timeout"])
            self.assertNotIn("secret", str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_spawn_failure_maps_to_dependency_missing(self):
        for exc in (RuntimeError("failed to invoke python: /secret/path"), OSError("/secret/path")):
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.run_with(side_effect=exc)
            self.assertEqual(raised.exception.kind, "dependency_missing")
            self.assertNotIn("secret", str(raised.exception))

    def test_unexpected_exception_maps_to_internal(self):
        with self.assertRaises(self.bridge.BridgeError) as raised:
            self.run_with(side_effect=ValueError("boom /secret"))
        self.assertEqual(raised.exception.kind, "internal")
        self.assertNotIn("secret", str(raised.exception))

    def test_malformed_output_maps_to_internal(self):
        for stdout in ("", "not json", "[1]", "{}", '{"ok": "yes"}', "null",
                       '{"ok": true, "result": 1}\ngarbage'):
            with self.assertRaises(self.bridge.BridgeError, msg=stdout) as raised:
                self.run_with(completed(stdout))
            self.assertEqual(raised.exception.kind, "internal", stdout)

    def test_ok_true_with_nonzero_exit_is_internal(self):
        with self.assertRaises(self.bridge.BridgeError) as raised:
            self.run_with(completed({"ok": True, "result": 1}, code=1))
        self.assertEqual(raised.exception.kind, "internal")

    def test_every_worker_kind_round_trips_with_fixed_message(self):
        kinds = ("ref_invalid", "not_found", "ambiguous", "not_paired", "not_running",
                 "connection_lost", "dependency_missing", "unsupported_platform",
                 "empty_value", "auth_failed", "internal")
        for kind in kinds:
            self.assertIn(kind, self.bridge.FIXED_MESSAGES)
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.run_with(completed({"ok": False, "kind": kind, "error": "RAW-UPSTREAM-TEXT"}, code=1))
            self.assertEqual(raised.exception.kind, kind)
            self.assertEqual(str(raised.exception), self.bridge.FIXED_MESSAGES[kind])
        self.assertIn("timeout", self.bridge.FIXED_MESSAGES)

    def test_unknown_kind_maps_to_internal(self):
        for payload in ({"ok": False, "kind": "totally_new"}, {"ok": False}, {"ok": False, "kind": 7},
                        {"ok": False, "kind": "timeout-ish"}):
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.run_with(completed(payload, code=1))
            self.assertEqual(raised.exception.kind, "internal")
            self.assertEqual(str(raised.exception), self.bridge.FIXED_MESSAGES["internal"])

    def test_stderr_never_appears_in_errors(self):
        for payload, code in (({"ok": False, "kind": "not_found"}, 1), ("garbage", 0), ("", 1)):
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.run_with(completed(payload, code=code, stderr="RAW-STDERR-SECRET"))
            self.assertNotIn("RAW-STDERR-SECRET", str(raised.exception))
            self.assertNotIn("RAW-STDERR-SECRET", repr(raised.exception))

    def test_messages_are_fixed_and_pair_hints_present(self):
        error = self.bridge.BridgeError("not_such_kind")
        self.assertEqual(error.kind, "internal")
        self.assertIn("hermes apple-passwords pair", self.bridge.FIXED_MESSAGES["not_paired"])
        self.assertIn("hermes pm repair", self.bridge.FIXED_MESSAGES["dependency_missing"])


class DependencyTests(BridgeTestCase):
    def test_dependency_paths_ordered_deduped_parent_dirs(self):
        def fake_spec(name):
            if name == "apwlib":
                return types.SimpleNamespace(submodule_search_locations=["/site/apwlib"], origin="/site/apwlib/__init__.py",
                                             has_location=True)
            if name == "chauffeur":
                return types.SimpleNamespace(submodule_search_locations=None, origin="/other/chauffeur.py",
                                             has_location=True)
            if name == "websockets":
                return types.SimpleNamespace(submodule_search_locations=["/site/websockets"],
                                             origin="/site/websockets/__init__.py", has_location=True)
            return None

        with patch.object(self.bridge.importlib.util, "find_spec", side_effect=fake_spec):
            self.assertEqual(self.bridge.dependency_paths(), ["/site", "/other"])
            self.assertEqual(self.bridge.worker_extra_env(), {"PYTHONPATH": os.pathsep.join(["/site", "/other"])})
            self.assertTrue(self.bridge.dependency_available())

    def test_missing_dependencies_yield_empty_env_and_unavailable(self):
        with patch.object(self.bridge.importlib.util, "find_spec", return_value=None):
            self.assertEqual(self.bridge.dependency_paths(), [])
            self.assertEqual(self.bridge.worker_extra_env(), {})
            self.assertFalse(self.bridge.dependency_available())

    def test_find_spec_errors_are_swallowed(self):
        with patch.object(self.bridge.importlib.util, "find_spec", side_effect=ValueError("bad spec")):
            self.assertEqual(self.bridge.dependency_paths(), [])
            self.assertFalse(self.bridge.dependency_available())


class RealSubprocessRegressionTests(BridgeTestCase):
    """B2: Hermes strips PYTHONPATH from helper CLIs; the dependency dirs must reach the worker."""

    def test_worker_can_import_apwlib_via_explicit_dependency_paths(self):
        with tempfile.TemporaryDirectory() as deps_dir, tempfile.TemporaryDirectory() as script_dir:
            package = Path(deps_dir) / "apwlib"
            package.mkdir()
            (package / "__init__.py").write_text(textwrap.dedent("""
                class Daemon:
                    def __init__(self, auto_start=False):
                        pass
                    def status(self):
                        return {"running": True, "bridge": True, "paired": True}
            """))
            worker = Path(script_dir) / "fake_worker.py"
            worker.write_text(textwrap.dedent("""
                import json, sys
                import apwlib
                status = apwlib.Daemon(auto_start=False).status()
                print(json.dumps({"ok": True, "result": {
                    "dependency": True, "argv": sys.argv[1:], "where": apwlib.__file__, **status}}))
            """))

            # Negative control: a bare child with no PYTHONPATH cannot import the fake apwlib.
            bare_env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR") if k in os.environ}
            control = subprocess.run([sys.executable, "-P", str(worker), "status"], env=bare_env,
                                     capture_output=True, text=True, timeout=30, check=False)
            self.assertNotEqual(control.returncode, 0)

            inserted = False
            try:
                with patch.dict(os.environ):
                    os.environ.pop("PYTHONPATH", None)
                    self.assertNotIn("PYTHONPATH", os.environ)
                    sys.path.insert(0, deps_dir)
                    inserted = True
                    importlib.invalidate_caches()
                    sys.modules.pop("apwlib", None)

                    self.assertTrue(self.bridge.dependency_available())
                    self.assertEqual(self.bridge.dependency_paths()[0], deps_dir)

                    # REAL run_worker -> REAL run_secret_cli (env stripped) -> fake worker script.
                    with patch.object(self.bridge, "WORKER", worker):
                        result = self.bridge.run_worker("status", timeout=30)
            finally:
                if inserted and deps_dir in sys.path:
                    sys.path.remove(deps_dir)
                sys.modules.pop("apwlib", None)
                importlib.invalidate_caches()

        self.assertEqual({k: result[k] for k in ("dependency", "running", "bridge", "paired")},
                         {"dependency": True, "running": True, "bridge": True, "paired": True})
        self.assertEqual(result["argv"], ["status"])
        self.assertTrue(result["where"].startswith(deps_dir))


class PairInteractiveTests(BridgeTestCase):
    def test_refuses_without_a_terminal(self):
        for stdin_tty, stdout_tty in ((False, True), (True, False), (False, False)):
            with patch.object(self.bridge.sys, "stdin", FakeTTY(stdin_tty)), \
                 patch.object(self.bridge.sys, "stdout", FakeTTY(stdout_tty)), \
                 patch.object(self.bridge.subprocess, "run") as run:
                with self.assertRaises(self.bridge.BridgeError) as raised:
                    self.bridge.pair_interactive()
            run.assert_not_called()
            self.assertEqual(raised.exception.kind, "internal")
            self.assertEqual(str(raised.exception), "Pairing requires an interactive local terminal.")

    def pair_with(self, response=None, side_effect=None):
        env = {"PATH": "/usr/bin", "HOME": "/home/x", "TERM": "xterm", "OPENAI_API_KEY": "must-not-leak",
               "PYTHONPATH": "/leaky"}
        with patch.object(self.bridge.sys, "stdin", FakeTTY(True)), \
             patch.object(self.bridge.sys, "stdout", FakeTTY(True)), \
             patch.dict(os.environ, env, clear=True), \
             patch.object(self.bridge, "worker_extra_env", return_value={"PYTHONPATH": "/deps"}), \
             patch.object(self.bridge.subprocess, "run", return_value=response, side_effect=side_effect) as run:
            return self.bridge.pair_interactive(), run

    def test_success_uses_allowlisted_env_and_attached_terminal(self):
        result, run = self.pair_with(completed({"ok": True, "result": {"paired": True}}))
        self.assertIsNone(result)
        self.assertEqual(run.call_args.args[0], [sys.executable, "-P", str(self.bridge.WORKER), "pair"])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin", "HOME": "/home/x", "TERM": "xterm",
                                         "PYTHONPATH": "/deps", "PYTHONSAFEPATH": "1"})
        self.assertIsNone(kwargs["stdin"])
        self.assertIsNone(kwargs["stderr"])
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["timeout"], 240)

    def test_daemon_inherits_safe_path_env_and_fixed_cwd_not_current_dir(self):
        # The worker's detached `python -m apwlib.daemon` inherits env + cwd; neither may
        # let an untrusted current directory shadow stdlib/apwlib modules.
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as untrusted:
            os.chdir(untrusted)
            try:
                _, run = self.pair_with(completed({"ok": True, "result": {"paired": True}}))
                here = os.getcwd()
            finally:
                os.chdir(original)
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["PYTHONSAFEPATH"], "1")
        self.assertIn("cwd", kwargs)
        self.assertNotEqual(os.path.realpath(kwargs["cwd"]), os.path.realpath(here))
        self.assertTrue(os.path.isabs(kwargs["cwd"]))

    def test_safe_cwd_falls_back_to_root_when_home_missing(self):
        with patch.object(self.bridge.os.path, "expanduser", return_value="/nonexistent-applepw-home"):
            self.assertEqual(self.bridge._safe_cwd(), "/")
        with patch.object(self.bridge.os.path, "expanduser", return_value="~"):
            self.assertEqual(self.bridge._safe_cwd(), "/")
        with tempfile.TemporaryDirectory() as home:
            with patch.object(self.bridge.os.path, "expanduser", return_value=home):
                self.assertEqual(self.bridge._safe_cwd(), home)

    def test_failure_kind_is_mapped(self):
        with self.assertRaises(self.bridge.BridgeError) as raised:
            self.pair_with(completed({"ok": False, "kind": "auth_failed"}, code=1))
        self.assertEqual(raised.exception.kind, "auth_failed")

    def test_timeout_spawn_and_malformed_failures(self):
        cases = ((subprocess.TimeoutExpired(["x"], 240), "timeout"),
                 (OSError("/secret/path"), "dependency_missing"))
        for exc, kind in cases:
            with self.assertRaises(self.bridge.BridgeError) as raised:
                self.pair_with(side_effect=exc)
            self.assertEqual(raised.exception.kind, kind)
            self.assertNotIn("secret", str(raised.exception))
        with self.assertRaises(self.bridge.BridgeError) as raised:
            self.pair_with(completed("garbage", code=1))
        self.assertEqual(raised.exception.kind, "internal")


if __name__ == "__main__":
    unittest.main()
