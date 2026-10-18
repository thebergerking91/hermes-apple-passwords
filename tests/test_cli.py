"""CLI behavior without a macOS bridge, a Hermes installation, or any live vault.

``backend``, ``bridge`` and ``source`` are replaced by fake modules in a synthetic package, and the
config wrappers ``cli._load_config`` / ``cli._save_config`` are patched, so nothing here touches a
real config file or Apple Passwords.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]
SECRET = "secret$\\word\nline2"
REF = "applepw://example.com/alice/password"
REF2 = "applepw://example.com/alice/otp"
REF3 = "applepw://example.com/alice/token"
REF4 = "applepw://example.org/bob%40example.org/password"
PKG = "applepw_cli_test"

FIXED = {
    "ref_invalid": "Invalid Apple Passwords reference.",
    "not_found": "No matching saved login was found.",
    "ambiguous": "More than one saved login matched.",
    "not_paired": "Apple Passwords is not paired; run `hermes apple-passwords pair` locally.",
    "internal": "Apple Passwords bridge operation failed.",
}


class BridgeError(RuntimeError):
    def __init__(self, kind, message=None):
        self.kind = kind
        super().__init__(message or FIXED.get(kind, FIXED["internal"]))


class BackendBridgeError(RuntimeError):
    """The worker module has its own BridgeError class; the CLI must handle both."""

    def __init__(self, kind):
        self.kind = kind
        super().__init__(FIXED.get(kind, FIXED["internal"]))


def fake_normalize_domain(value):
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "." not in value
        or any(ch in value for ch in "/:@ ?#*")
    ):
        raise BackendBridgeError("ref_invalid")
    return value.lower()


def fake_validate_reference(ref):
    if not isinstance(ref, str) or not ref.startswith("applepw://") or ref.count("/") != 4:
        raise BridgeError("ref_invalid")
    return ref


class CliTestCase(unittest.TestCase):
    def setUp(self):
        package = types.ModuleType(PKG)
        package.__path__ = [str(PLUGIN_DIR)]

        backend = types.ModuleType(f"{PKG}.backend")
        backend.BridgeError = BackendBridgeError
        backend.normalize_domain = fake_normalize_domain

        bridge = types.ModuleType(f"{PKG}.bridge")
        bridge.BridgeError = BridgeError
        bridge.FIXED_MESSAGES = dict(FIXED)
        bridge.pair_interactive = MagicMock()
        bridge.dependency_available = lambda: True

        source = types.ModuleType(f"{PKG}.source")
        source.validate_reference = MagicMock(side_effect=fake_validate_reference)
        source.resolve_references = MagicMock(
            side_effect=lambda refs, *, timeout=45.0: ({ref: SECRET for ref in refs}, {})
        )
        source.resolve_reference = MagicMock(return_value=SECRET)
        source.is_startup_reference = MagicMock(side_effect=lambda ref: not ref.endswith("/otp"))
        source.bridge_status = MagicMock(
            return_value={"dependency": True, "running": True, "bridge": True, "paired": True}
        )
        source.list_accounts = MagicMock(
            return_value=[
                {"host": "example.com", "hosts": ["example.com"], "username": "alice", "has_otp": True}
            ]
        )
        self.backend, self.bridge, self.source = backend, bridge, source

        for name, module in (
            (PKG, package),
            (f"{PKG}.backend", backend),
            (f"{PKG}.bridge", bridge),
            (f"{PKG}.source", source),
        ):
            self.addCleanup(sys.modules.pop, name, None)
            sys.modules[name] = module
        spec = importlib.util.spec_from_file_location(f"{PKG}.cli", PLUGIN_DIR / "cli.py")
        self.cli = importlib.util.module_from_spec(spec)
        self.addCleanup(sys.modules.pop, spec.name, None)
        sys.modules[spec.name] = self.cli
        spec.loader.exec_module(self.cli)

        # Fake config store: loads return copies, so only _save_config persists anything.
        self.cfg: dict = {}
        self.saves: list[dict] = []
        patcher = patch.multiple(self.cli, _load_config=self._load, _save_config=self._save)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.parser = argparse.ArgumentParser()
        self.cli.setup_cli(self.parser)

    def _load(self):
        return copy.deepcopy(self.cfg)

    def _save(self, cfg):
        self.cfg = copy.deepcopy(cfg)
        self.saves.append(copy.deepcopy(cfg))

    def call(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = self.cli.handle_cli(self.parser.parse_args(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def apw(self, key=None, default=None):
        section = self.cfg.get("secrets", {}).get("apple_passwords", {})
        return section if key is None else section.get(key, default)

    def vault(self):
        return self.cfg.get("vault", {}).get("apple_passwords", {})

    def enable(self, env=None, **extra):
        self.cfg = {"secrets": {"apple_passwords": {"enabled": True, "env": env or {}, **extra}}}


# ---------------------------------------------------------------------------
# Parser shape / Hermes integration regression (bug B1)
# ---------------------------------------------------------------------------

class ParserShapeTests(CliTestCase):
    SUBCOMMANDS = [
        ["setup"],
        ["setup", "--timeout", "30", "--no-override"],
        ["status"],
        ["set", "TOKEN", REF],
        ["remove", "TOKEN"],
        ["sync"],
        ["disable"],
        ["pair"],
        ["list", "example.com"],
        ["read", REF, "--reveal"],
        ["run", "--env", f"X={REF}", "--", "/usr/bin/true"],
        ["inject", "--input", "a", "--output", "b"],
        ["vault", "status"],
        ["vault", "add", "example.com"],
        ["vault", "remove", "example.com"],
        ["vault", "enable"],
        ["vault", "disable"],
    ]

    def hermes_parser(self):
        top = argparse.ArgumentParser(prog="hermes")
        subs = top.add_subparsers(dest="command")
        plugin = subs.add_parser("apple-passwords")
        self.cli.setup_cli(plugin)
        plugin.set_defaults(func=self.cli.handle_cli)  # what Hermes's main() does
        return top

    def test_hermes_command_and_func_survive_every_subcommand(self):
        top = self.hermes_parser()
        for argv in self.SUBCOMMANDS:
            with self.subTest(argv=argv):
                ns = top.parse_args(["apple-passwords", *argv])
                self.assertEqual(ns.command, "apple-passwords")
                self.assertIs(ns.func, self.cli.handle_cli)
                self.assertEqual(ns.applepw_command, argv[0])

    def test_run_child_argv_under_hermes_shape(self):
        ns = self.hermes_parser().parse_args(
            ["apple-passwords", "run", "--env", f"X={REF}", "--", "/usr/bin/true"]
        )
        self.assertEqual(ns.command, "apple-passwords")
        argv = [a for a in ns.child_argv if a != "--"][:]
        self.assertEqual(argv, ["/usr/bin/true"])
        self.assertEqual(ns.env, [f"X={REF}"])

    def test_vault_subcommand_dest_is_distinct(self):
        ns = self.hermes_parser().parse_args(["apple-passwords", "vault", "add", "example.com"])
        self.assertEqual((ns.command, ns.applepw_command, ns.applepw_vault_command), ("apple-passwords", "vault", "add"))

    def test_plugin_never_claims_hermes_destinations(self):
        # The standalone parser must not define `command` or `func` at all.
        for argv in self.SUBCOMMANDS:
            with self.subTest(argv=argv):
                ns = self.parser.parse_args(argv)
                self.assertFalse(hasattr(ns, "command"))
                self.assertFalse(hasattr(ns, "func"))

    def test_subcommand_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parser.parse_args([])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parser.parse_args(["vault"])

    def test_unknown_command_namespace_fails_closed(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = self.cli.handle_cli(argparse.Namespace(applepw_command="bogus"))
        self.assertEqual(code, 1)
        self.assertIn("unknown", err.getvalue())

    def test_main_parses_and_dispatches(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(self.cli.main(["list", "example.com"]), 0)
        self.assertIn("alice", stdout.getvalue())

    def test_config_wrappers_import_hermes_lazily(self):
        fake_cfg = types.ModuleType("hermes_cli.config")
        fake_cfg.load_config = MagicMock(return_value={"loaded": True})
        fake_cfg.save_config = MagicMock()
        fake_pkg = types.ModuleType("hermes_cli")
        fake_pkg.__path__ = []
        fake_pkg.config = fake_cfg
        spec = importlib.util.spec_from_file_location(f"{PKG}.cli_fresh", PLUGIN_DIR / "cli.py")
        fresh = importlib.util.module_from_spec(spec)
        self.addCleanup(sys.modules.pop, spec.name, None)
        sys.modules[spec.name] = fresh
        spec.loader.exec_module(fresh)  # importing the CLI must not import hermes_cli
        with patch.dict(sys.modules, {"hermes_cli": fake_pkg, "hermes_cli.config": fake_cfg}):
            self.assertEqual(fresh._load_config(), {"loaded": True})
            fresh._save_config({"x": 1})
        fake_cfg.save_config.assert_called_once_with({"x": 1})


# ---------------------------------------------------------------------------
# setup / status / set / remove / sync / disable
# ---------------------------------------------------------------------------

class SetupTests(CliTestCase):
    def test_setup_from_empty_config_writes_defaults(self):
        code, out, err = self.call("setup")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(
            self.apw(),
            {"enabled": True, "env": {}, "override_existing": True, "timeout_seconds": 45, "cache_ttl_seconds": 300},
        )
        self.assertEqual(len(self.saves), 1)
        self.assertIn("enabled", out.lower())

    def test_setup_preserves_existing_env_map_and_other_config(self):
        self.cfg = {
            "other": {"keep": 1},
            "secrets": {
                "onepassword": {"enabled": True},
                "apple_passwords": {
                    "enabled": False,
                    "env": {"TOKEN": REF},
                    "timeout_seconds": 20,
                    "cache_ttl_seconds": 10,
                },
            },
        }
        self.assertEqual(self.call("setup")[0], 0)
        self.assertEqual(self.apw("env"), {"TOKEN": REF})
        self.assertIs(self.apw("enabled"), True)
        self.assertEqual(self.apw("timeout_seconds"), 20)  # only defaulted when absent
        self.assertEqual(self.apw("cache_ttl_seconds"), 10)
        self.assertEqual(self.cfg["other"], {"keep": 1})
        self.assertEqual(self.cfg["secrets"]["onepassword"], {"enabled": True})

    def test_setup_timeout_and_no_override(self):
        self.assertEqual(self.call("setup", "--timeout", "30", "--no-override")[0], 0)
        self.assertEqual(self.apw("timeout_seconds"), 30)
        self.assertIs(self.apw("override_existing"), False)
        self.assertEqual(self.call("setup", "--timeout", "2.5")[0], 0)
        self.assertEqual(self.apw("timeout_seconds"), 2.5)
        self.assertIs(self.apw("override_existing"), False)  # not silently flipped
        self.assertEqual(self.call("setup", "--override")[0], 0)
        self.assertIs(self.apw("override_existing"), True)

    def test_setup_rerun_keeps_deliberate_override_false(self):
        self.enable({"A": REF}, override_existing=False)
        self.assertEqual(self.call("setup", "--timeout", "30")[0], 0)
        self.assertIs(self.apw("override_existing"), False)
        self.assertEqual(self.apw("timeout_seconds"), 30)
        self.assertEqual(self.call("setup")[0], 0)
        self.assertIs(self.apw("override_existing"), False)

    def test_setup_rerun_keeps_override_true_and_defaults_when_absent(self):
        self.enable({"A": REF}, override_existing=True)
        self.assertEqual(self.call("setup", "--timeout", "30")[0], 0)
        self.assertIs(self.apw("override_existing"), True)
        self.enable({"A": REF})
        self.assertEqual(self.call("setup")[0], 0)
        self.assertIs(self.apw("override_existing"), True)

    def test_setup_override_flag_flips_false_to_true(self):
        self.enable({}, override_existing=False)
        self.assertEqual(self.call("setup", "--override")[0], 0)
        self.assertIs(self.apw("override_existing"), True)

    def test_setup_override_flags_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parser.parse_args(["setup", "--override", "--no-override"])

    def test_setup_rejects_bad_timeout_without_saving(self):
        for bad in ("0", "-1", "121", "nan", "inf"):
            with self.subTest(timeout=bad):
                code, _out, err = self.call("setup", "--timeout", bad)
                self.assertEqual(code, 1)
                self.assertIn("--timeout", err)
        self.assertEqual(self.saves, [])

    def test_setup_replaces_non_dict_env(self):
        self.cfg = {"secrets": {"apple_passwords": {"env": ["junk"]}}}
        self.assertEqual(self.call("setup")[0], 0)
        self.assertEqual(self.apw("env"), {})

    def test_setup_hints_for_missing_dependency_and_pairing(self):
        self.source.bridge_status.return_value = {
            "dependency": False, "running": False, "bridge": False, "paired": False,
        }
        code, out, _ = self.call("setup")
        self.assertEqual(code, 0)
        self.assertIn("hermes pm repair", out)
        self.assertNotIn("hermes apple-passwords pair", out)
        self.assertIn("apwlib: missing", out)

        self.source.bridge_status.return_value = {
            "dependency": True, "running": False, "bridge": False, "paired": False,
        }
        code, out, _ = self.call("setup")
        self.assertEqual(code, 0)
        self.assertIn("Next: run `hermes apple-passwords pair` in this terminal.", out)
        self.assertNotIn("pm repair", out)

    def test_setup_paired_prints_no_pairing_hint(self):
        _code, out, _ = self.call("setup")
        self.assertNotIn("Next: run", out)

    def test_setup_survives_status_probe_failure(self):
        self.source.bridge_status.side_effect = BridgeError("internal")
        code, out, _ = self.call("setup")
        self.assertEqual(code, 0)
        self.assertIs(self.apw("enabled"), True)
        self.assertIn("unavailable", out)


class StatusTests(CliTestCase):
    def test_status_unconfigured(self):
        code, out, err = self.call("status")
        self.assertEqual((code, err), (0, ""))
        for line in (
            "Enabled: no", "Mappings: 0", "Override existing: yes", "Timeout (s): 45",
            "Cache TTL (s): 300", "Vault backend: disabled", "Vault domains: none",
            "apwlib: installed", "Bridge: running", "Pairing: paired",
        ):
            self.assertIn(line, out)
        self.assertIn("hermes apple-passwords setup", out)
        self.assertEqual(self.saves, [])

    def test_status_lists_env_names_only_never_refs_or_values(self):
        self.enable({"TOKEN": REF, "B_KEY": "applepw://other.org/bob%40x/password"}, override_existing=False,
                    timeout_seconds=12, cache_ttl_seconds=0)
        self.cfg["vault"] = {"apple_passwords": {"enabled": True, "domains": ["b.com", "a.com", "bad domain"]}}
        code, out, err = self.call("status")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("Enabled: yes", out)
        self.assertIn("Mappings: 2", out)
        self.assertLess(out.index("B_KEY"), out.index("TOKEN"))
        self.assertIn("Override existing: no", out)
        self.assertIn("Timeout (s): 12", out)
        self.assertIn("Cache TTL (s): 0", out)
        self.assertIn("Vault backend: enabled", out)
        self.assertIn("Vault domains: a.com, b.com", out)
        self.assertNotIn("applepw://", out)
        self.assertNotIn("alice", out)
        self.assertNotIn("secret$", out)
        self.source.resolve_references.assert_not_called()
        self.source.resolve_reference.assert_not_called()

    def test_status_override_matches_hermes_truthiness(self):
        for value, expected in ((None, "no"), (0, "no"), (False, "no"), ("", "no"),
                                (True, "yes"), (1, "yes"), ("yes", "yes")):
            with self.subTest(value=value):
                self.enable({}, override_existing=value)
                _code, out, _ = self.call("status")
                self.assertIn(f"Override existing: {expected}", out)

    def test_status_enabled_without_mappings_suggests_set(self):
        self.enable()
        _code, out, _ = self.call("status")
        self.assertIn("hermes apple-passwords set", out)

    def test_status_distinguishes_missing_apwlib_from_stopped_bridge(self):
        self.source.bridge_status.return_value = {
            "dependency": False, "running": False, "bridge": False, "paired": False,
        }
        _code, out, _ = self.call("status")
        self.assertIn("apwlib: missing", out)
        self.source.bridge_status.return_value = {
            "dependency": True, "running": False, "bridge": False, "paired": False,
        }
        _code, out, _ = self.call("status")
        self.assertIn("apwlib: installed", out)
        self.assertIn("Bridge: stopped", out)
        self.assertIn("Pairing: not paired", out)

    def test_status_probe_failure_still_exits_zero(self):
        self.source.bridge_status.side_effect = RuntimeError(SECRET)
        code, out, err = self.call("status")
        self.assertEqual(code, 0)
        self.assertNotIn("secret$", out + err)
        self.assertIn("unavailable", out)

    def test_status_tolerates_malformed_config(self):
        self.cfg = {"secrets": {"apple_passwords": "oops"}, "vault": []}
        self.assertEqual(self.call("status")[0], 0)


class SetRemoveDisableTests(CliTestCase):
    def test_set_writes_mapping(self):
        code, out, err = self.call("set", "GITHUB_TOKEN", REF)
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(self.apw("env"), {"GITHUB_TOKEN": REF})
        self.assertIn("GITHUB_TOKEN", out)
        self.assertIn("disabled", out)  # integration not yet enabled -> note
        self.assertEqual(len(self.saves), 1)

    def test_set_preserves_other_mappings_and_enabled_state(self):
        self.enable({"A": REF})
        self.assertEqual(self.call("set", "B", REF3)[0], 0)
        self.assertEqual(self.apw("env"), {"A": REF, "B": REF3})
        self.assertIs(self.apw("enabled"), True)
        _code, out, _ = self.call("set", "A", REF3)
        self.assertEqual(self.apw("env")["A"], REF3)
        self.assertNotIn("disabled", out)

    def test_set_refuses_one_time_code_reference(self):
        code, out, err = self.call("set", "TOTP", REF2)
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(
            err,
            "Apple Passwords: one-time codes can't be startup secrets; "
            "use `hermes apple-passwords run` or `read` instead\n",
        )
        self.assertEqual(self.saves, [])
        self.assertEqual(self.apw(), {})
        self.source.is_startup_reference.assert_called_with(REF2)

    def test_set_refusal_keeps_existing_mapping(self):
        self.enable({"A": REF})
        self.assertEqual(self.call("set", "A", REF2)[0], 1)
        self.assertEqual(self.apw("env"), {"A": REF})
        self.assertEqual(self.saves, [])

    def test_set_falls_back_to_otp_suffix_without_source_helper(self):
        del self.source.is_startup_reference
        code, _out, err = self.call("set", "TOTP", REF2)
        self.assertEqual(code, 1)
        self.assertIn("one-time codes", err)
        self.assertEqual(self.saves, [])
        self.assertEqual(self.call("set", "OK", REF)[0], 0)
        self.assertEqual(self.apw("env"), {"OK": REF})

    def test_set_replaces_non_dict_env(self):
        self.cfg = {"secrets": {"apple_passwords": {"env": "junk"}}}
        self.assertEqual(self.call("set", "A", REF)[0], 0)
        self.assertEqual(self.apw("env"), {"A": REF})

    def test_set_rejects_invalid_env_names_before_saving(self):
        for name in ("1BAD", "has-dash", "has space", "a=b", "é"):
            with self.subTest(name=name):
                code, _out, err = self.call("set", name, REF)
                self.assertEqual(code, 1)
                self.assertIn("Apple Passwords:", err)
        self.assertEqual(self.saves, [])

    def test_set_rejects_invalid_reference_with_fixed_message(self):
        code, out, err = self.call("set", "TOKEN", "https://example.com")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, f"Apple Passwords: {FIXED['ref_invalid']}\n")
        self.assertEqual(self.saves, [])

    def test_set_stores_the_validated_reference(self):
        self.source.validate_reference.side_effect = lambda ref: ref.strip()
        self.assertEqual(self.call("set", "TOKEN", "applepw://example.com/alice/password")[0], 0)
        self.assertEqual(self.apw("env")["TOKEN"], "applepw://example.com/alice/password")

    def test_remove_deletes_only_named_mapping(self):
        self.enable({"A": REF, "B": REF2})
        code, out, _ = self.call("remove", "A")
        self.assertEqual(code, 0)
        self.assertIn("A", out)
        self.assertEqual(self.apw("env"), {"B": REF2})
        self.assertIs(self.apw("enabled"), True)

    def test_remove_missing_errors_without_saving(self):
        self.enable({"A": REF})
        code, out, err = self.call("remove", "NOPE")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("NOPE is not mapped", err)
        self.assertEqual(self.saves, [])
        self.cfg = {}
        self.assertEqual(self.call("remove", "A")[0], 1)
        self.assertEqual(self.saves, [])

    def test_disable_flips_enabled_and_keeps_mappings(self):
        self.enable({"A": REF})
        code, out, _ = self.call("disable")
        self.assertEqual(code, 0)
        self.assertIs(self.apw("enabled"), False)
        self.assertEqual(self.apw("env"), {"A": REF})
        self.assertIn("Disabled", out)

    def test_disable_without_prior_config(self):
        self.assertEqual(self.call("disable")[0], 0)
        self.assertIs(self.apw("enabled"), False)


class SyncTests(CliTestCase):
    def test_sync_reports_would_export_without_values(self):
        self.enable({"B": REF4, "A": REF})
        code, out, err = self.call("sync")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("A\twould export\n", out)
        self.assertIn("B\twould export\n", out)
        self.assertLess(out.index("A\t"), out.index("B\t"))
        self.assertNotIn("secret", out)
        self.assertNotIn("word", out)
        self.assertEqual(self.saves, [])
        refs = self.source.resolve_references.call_args.args[0]
        self.assertEqual(sorted(refs), sorted([REF, REF4]))  # one batch

    def test_sync_does_not_modify_os_environ(self):
        self.enable({"APPLEPW_SYNC_PROBE": REF})
        os.environ.pop("APPLEPW_SYNC_PROBE", None)
        self.call("sync")
        self.assertNotIn("APPLEPW_SYNC_PROBE", os.environ)

    def test_sync_already_set_respects_override_existing(self):
        self.enable({"PRESET_VAR": REF}, override_existing=False)
        with patch.dict(os.environ, {"PRESET_VAR": "live-value"}):
            code, out, _ = self.call("sync")
            self.assertEqual(code, 0)
            self.assertIn("PRESET_VAR\tskip (already set)", out)
            self.assertNotIn("live-value", out)
            self.enable({"PRESET_VAR": REF}, override_existing=True)
            _code, out, _ = self.call("sync")
            self.assertIn("PRESET_VAR\twould export", out)
            self.assertNotIn("live-value", out)

    def test_sync_override_defaults_to_true(self):
        self.enable({"PRESET_VAR": REF})
        with patch.dict(os.environ, {"PRESET_VAR": "x"}):
            _code, out, _ = self.call("sync")
        self.assertIn("PRESET_VAR\twould export", out)

    def test_sync_override_matches_hermes_truthiness(self):
        # Hermes: bool(cfg.get("override_existing", True)) -> null/0 mean False.
        with patch.dict(os.environ, {"PRESET_VAR": "live-value"}):
            for value, expected in ((None, "skip (already set)"), (0, "skip (already set)"),
                                    (False, "skip (already set)"), (1, "would export"),
                                    (True, "would export")):
                with self.subTest(value=value):
                    self.enable({"PRESET_VAR": REF}, override_existing=value)
                    _code, out, _ = self.call("sync")
                    self.assertIn(f"PRESET_VAR\t{expected}", out)

    def test_sync_empty_string_env_counts_as_not_set(self):
        self.enable({"PRESET_VAR": REF}, override_existing=False)
        with patch.dict(os.environ, {"PRESET_VAR": ""}):
            code, out, _ = self.call("sync")
        self.assertEqual(code, 0)
        self.assertIn("PRESET_VAR\twould export", out)
        self.assertNotIn("skip", out)

    def test_sync_unresolved_exits_1_with_fixed_message(self):
        self.enable({"A": REF, "B": REF4})
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: (
            {REF: SECRET}, {REF4: "not_found"},
        )
        code, out, err = self.call("sync")
        self.assertEqual(code, 1)
        self.assertIn("A\twould export", out)
        self.assertIn(f"B\tunresolved: {FIXED['not_found']}", out)
        self.assertNotIn("secret", out + err)

    def test_sync_reports_otp_mapping_as_unresolved_and_never_resolves_it(self):
        # Startup skips one-time codes, so sync must not claim it would export one.
        self.enable({"A": REF, "CODE": REF2})
        code, out, _ = self.call("sync")
        self.assertEqual(code, 1)
        self.assertIn("A\twould export", out)
        self.assertIn("CODE\tunresolved: one-time codes can't be startup secrets", out)
        self.assertEqual(self.source.resolve_references.call_args.args[0], [REF])

    def test_sync_unknown_error_kind_falls_back_to_internal_message(self):
        self.enable({"A": REF})
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: ({}, {REF: "weird"})
        code, out, _ = self.call("sync")
        self.assertEqual(code, 1)
        self.assertIn(f"A\tunresolved: {FIXED['internal']}", out)

    def test_sync_global_failure_exits_1_with_stderr_message(self):
        self.enable({"A": REF})
        self.source.resolve_references.side_effect = BridgeError("not_paired")
        code, out, err = self.call("sync")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, f"Apple Passwords: {FIXED['not_paired']}\n")

    def test_sync_invalid_config_entries_are_unresolved_not_sent_to_worker(self):
        self.enable({"GOOD": REF, "BAD": "https://example.com", "1NO": REF, "NONSTR": 5})
        code, out, _ = self.call("sync")
        self.assertEqual(code, 1)
        self.assertIn("GOOD\twould export", out)
        self.assertIn(f"BAD\tunresolved: {FIXED['ref_invalid']}", out)
        self.assertIn("1NO\tunresolved:", out)
        self.assertIn("NONSTR\tunresolved:", out)
        self.assertEqual(self.source.resolve_references.call_args.args[0], [REF])

    def test_sync_all_invalid_skips_worker_entirely(self):
        self.enable({"BAD": "nope"})
        code, _out, _ = self.call("sync")
        self.assertEqual(code, 1)
        self.source.resolve_references.assert_not_called()

    def test_sync_disabled_fails(self):
        self.cfg = {"secrets": {"apple_passwords": {"enabled": False, "env": {"A": REF}}}}
        code, out, err = self.call("sync")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("disabled", err)
        self.source.resolve_references.assert_not_called()

    def test_sync_no_mappings_is_ok(self):
        self.enable()
        code, out, _ = self.call("sync")
        self.assertEqual(code, 0)
        self.assertIn("set", out)
        self.source.resolve_references.assert_not_called()

    def test_sync_uses_clamped_configured_timeout(self):
        for configured, expected in ((20, 20.0), (500, 120.0), ("bad", 45.0), (-3, 45.0), (True, 45.0)):
            with self.subTest(configured=configured):
                self.enable({"A": REF}, timeout_seconds=configured)
                self.call("sync")
                self.assertEqual(self.source.resolve_references.call_args.kwargs["timeout"], expected)


# ---------------------------------------------------------------------------
# pair / list / read
# ---------------------------------------------------------------------------

class PairListReadTests(CliTestCase):
    def test_pair_delegates_to_bridge(self):
        self.assertEqual(self.call("pair"), (0, "Pairing complete.\n", ""))
        self.bridge.pair_interactive.assert_called_once_with()

    def test_pair_failure_prints_message_and_fails(self):
        self.bridge.pair_interactive.side_effect = BridgeError(
            "internal", "Pairing requires an interactive local terminal."
        )
        code, out, err = self.call("pair")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, "Apple Passwords: Pairing requires an interactive local terminal.\n")

    def test_list_prints_host_username_otp(self):
        self.source.list_accounts.return_value = [
            {"host": "example.com", "hosts": ["example.com"], "username": "alice", "has_otp": True, "password": "never"},
            {"host": "example.com", "hosts": ["example.com"], "username": "bob", "has_otp": False},
        ]
        code, out, err = self.call("list", "example.com")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, "example.com\talice\totp\nexample.com\tbob\t-\n")
        self.assertNotIn("never", out)
        self.source.list_accounts.assert_called_once_with("example.com")

    def test_list_normalizes_domain_before_lookup(self):
        self.call("list", "Example.COM")
        self.source.list_accounts.assert_called_once_with("example.com")

    def test_list_notes_sibling_hosts(self):
        self.source.list_accounts.return_value = [
            {"host": "login.example.com", "hosts": ["login.example.com"], "username": "alice", "has_otp": False},
        ]
        code, out, _ = self.call("list", "example.com")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("login.example.com\talice\t-\n"))
        self.assertTrue(out.endswith("References must use the exact saved host shown in the first column.\n"))

    def test_list_notes_when_extra_saved_hosts_differ(self):
        self.source.list_accounts.return_value = [
            {"host": "example.com", "hosts": ["example.com", "www.example.com"], "username": "alice", "has_otp": False},
        ]
        _code, out, _ = self.call("list", "example.com")
        self.assertIn("References must use the exact saved host", out)

    def test_list_no_note_for_exact_hosts(self):
        _code, out, _ = self.call("list", "example.com")
        self.assertNotIn("References must use", out)

    def test_list_empty_keeps_stdout_clean(self):
        self.source.list_accounts.return_value = []
        code, out, err = self.call("list", "example.com")
        self.assertEqual((code, out), (0, ""))
        self.assertIn("No saved logins", err)

    def test_list_escapes_control_characters_in_metadata(self):
        self.source.list_accounts.return_value = [
            {"host": "example.com", "hosts": ["example.com"], "username": "a\tb\nfake.com\tx\t-", "has_otp": False},
        ]
        _code, out, _ = self.call("list", "example.com")
        self.assertEqual(out.count("\n"), 1)
        self.assertEqual(out.count("\t"), 2)
        self.assertIn("\\x09", out)

    def test_list_rejects_malformed_rows(self):
        self.source.list_accounts.return_value = [{"host": 1, "username": "x"}]
        code, out, err = self.call("list", "example.com")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("invalid account metadata", err)

    def test_list_invalid_domain_uses_fixed_message(self):
        code, out, err = self.call("list", "http://example.com/path")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, f"Apple Passwords: {FIXED['ref_invalid']}\n")
        self.source.list_accounts.assert_not_called()

    def test_list_bridge_error(self):
        self.source.list_accounts.side_effect = BridgeError("not_paired")
        code, _out, err = self.call("list", "example.com")
        self.assertEqual(code, 1)
        self.assertIn("pair", err)

    def test_read_requires_explicit_reveal(self):
        code, output, error = self.call("read", REF)
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertNotIn("secret", error)
        self.assertIn("--reveal", error)
        self.source.resolve_reference.assert_not_called()
        self.assertEqual(self.call("read", REF, "--reveal"), (0, SECRET + "\n", ""))

    def test_read_validates_reference_first(self):
        code, output, error = self.call("read", "bogus", "--reveal")
        self.assertEqual((code, output), (1, ""))
        self.assertIn(FIXED["ref_invalid"], error)
        self.source.resolve_reference.assert_not_called()

    def test_sanitized_bridge_error_is_shown_without_value(self):
        self.source.resolve_reference.side_effect = BridgeError("not_found")
        code, output, error = self.call("read", REF, "--reveal")
        self.assertEqual((code, output), (1, ""))
        self.assertIn(FIXED["not_found"], error)
        self.assertNotIn("secret", error)

    def test_unexpected_exception_text_is_never_shown(self):
        self.source.resolve_reference.side_effect = RuntimeError(SECRET)
        code, output, error = self.call("read", REF, "--reveal")
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(error, "Apple Passwords: operation failed\n")

    def test_backend_class_bridge_error_is_handled(self):
        self.source.resolve_reference.side_effect = BackendBridgeError("not_found")
        code, _output, error = self.call("read", REF, "--reveal")
        self.assertEqual(code, 1)
        self.assertIn(FIXED["not_found"], error)

    def test_keyboard_interrupt_returns_130(self):
        self.bridge.pair_interactive.side_effect = KeyboardInterrupt()
        self.assertEqual(self.call("pair")[0], 130)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

class RunTests(CliTestCase):
    def run_ok(self, *argv, rc=0):
        with patch.object(self.cli.subprocess, "run", return_value=types.SimpleNamespace(returncode=rc)) as run:
            result = self.call(*argv)
        return result, run

    def test_run_passes_secrets_only_in_minimal_environment(self):
        with patch.dict(os.environ, {"UNRELATED_API_KEY": "must-not-inherit", "PATH": "/usr/bin", "HOME": "/h"}):
            (code, output, error), run = self.run_ok(
                "run", "--env", f"TOKEN={REF}", "--", "program", "argument", rc=7
            )
        self.assertEqual((code, output, error), (7, "", ""))
        args, kwargs = run.call_args
        self.assertEqual(args, (["program", "argument"],))
        self.assertEqual(kwargs["env"]["TOKEN"], SECRET)
        self.assertEqual(kwargs["env"]["PATH"], "/usr/bin")
        self.assertNotIn("UNRELATED_API_KEY", kwargs["env"])
        self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)

    def test_run_show_output_inherits_streams(self):
        _result, run = self.run_ok("run", "--show-output", "--", "program")
        self.assertIsNone(run.call_args.kwargs["stdout"])
        self.assertIsNone(run.call_args.kwargs["stderr"])

    def test_run_without_env_does_not_call_worker(self):
        (code, _o, _e), run = self.run_ok("run", "--", "program")
        self.assertEqual(code, 0)
        self.source.resolve_references.assert_not_called()
        run.assert_called_once()

    def test_run_strips_exactly_one_leading_double_dash(self):
        _result, run = self.run_ok("run", "--", "program", "--", "x")
        self.assertEqual(run.call_args.args[0], ["program", "--", "x"])

    def test_run_child_flags_are_not_parsed_as_ours(self):
        _result, run = self.run_ok("run", "--", "program", "--env", "A=b", "--show-output")
        self.assertEqual(run.call_args.args[0], ["program", "--env", "A=b", "--show-output"])

    def test_run_accepts_program_without_double_dash(self):
        _result, run = self.run_ok("run", "--env", f"T={REF}", "program", "arg")
        self.assertEqual(run.call_args.args[0], ["program", "arg"])

    def test_run_requires_executable(self):
        for argv in (("run",), ("run", "--"), ("run", "--env", f"T={REF}", "--")):
            with self.subTest(argv=argv):
                (code, out, err), run = self.run_ok(*argv)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("requires", err)
                run.assert_not_called()
        self.source.resolve_references.assert_not_called()

    def test_run_denylist_rejects_base_env_and_loader_variables(self):
        for name in ("PATH", "HOME", "USER", "TMPDIR", "SHELL", "TERM", "LANG",
                     "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH"):
            with self.subTest(name=name):
                (code, out, err), run = self.run_ok("run", "--env", f"{name}={REF}", "--", "program")
                self.assertEqual((code, out), (1, ""))
                self.assertIn("Apple Passwords:", err)
                self.assertNotIn("secret", err)
                run.assert_not_called()
        self.source.resolve_references.assert_not_called()

    def test_run_allows_names_that_merely_resemble_denied_ones(self):
        for name in ("LDAP_PASSWORD", "DYLDX", "MY_PATH", "path"):
            with self.subTest(name=name):
                (code, _o, _e), run = self.run_ok("run", "--env", f"{name}={REF}", "--", "program")
                self.assertEqual(code, 0)
                self.assertEqual(run.call_args.kwargs["env"][name], SECRET)

    def test_run_rejects_malformed_or_duplicate_env(self):
        for assignment in ("NOEQUALS", "=REF", "1BAD=" + REF, "A=", "bad-name=" + REF):
            with self.subTest(assignment=assignment):
                (code, _o, err), run = self.run_ok("run", "--env", assignment, "--", "program")
                self.assertEqual(code, 1)
                self.assertIn("NAME=REF", err)
                run.assert_not_called()
        (code, _o, err), run = self.run_ok("run", "--env", f"A={REF}", "--env", f"A={REF2}", "--", "program")
        self.assertEqual(code, 1)
        run.assert_not_called()

    def test_run_rejects_invalid_reference_before_resolving(self):
        (code, _o, err), run = self.run_ok("run", "--env", "A=https://example.com", "--", "program")
        self.assertEqual(code, 1)
        self.assertIn(FIXED["ref_invalid"], err)
        self.source.resolve_references.assert_not_called()
        run.assert_not_called()

    def test_run_per_ref_failure_aborts_before_subprocess(self):
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: (
            {REF: SECRET}, {REF2: "ambiguous"},
        )
        (code, out, err), run = self.run_ok("run", "--env", f"A={REF}", "--env", f"B={REF2}", "--", "program")
        self.assertEqual((code, out), (1, ""))
        self.assertEqual(err, f"Apple Passwords: {FIXED['ambiguous']}\n")
        run.assert_not_called()

    def test_run_global_failure_aborts_before_subprocess(self):
        self.source.resolve_references.side_effect = BridgeError("not_paired")
        (code, _o, err), run = self.run_ok("run", "--env", f"A={REF}", "--", "program")
        self.assertEqual(code, 1)
        self.assertIn("pair", err)
        run.assert_not_called()

    def test_run_resolves_once_for_shared_references(self):
        _result, run = self.run_ok("run", "--env", f"A={REF}", "--env", f"B={REF}", "--", "program")
        self.assertEqual(self.source.resolve_references.call_args.args[0], [REF])
        env = run.call_args.kwargs["env"]
        self.assertEqual((env["A"], env["B"]), (SECRET, SECRET))

    def test_run_failure_does_not_log_value_or_exception(self):
        with patch.object(self.cli.subprocess, "run", side_effect=OSError(SECRET)):
            code, output, error = self.call("run", "--env", f"TOKEN={REF}", "--", "missing")
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertNotIn("secret", error)
        self.assertNotIn("TOKEN", error)

    def test_run_maps_signal_death_to_shell_style_code(self):
        (code, _o, _e), _run = self.run_ok("run", "--", "program", rc=-9)
        self.assertEqual(code, 137)


# ---------------------------------------------------------------------------
# inject
# ---------------------------------------------------------------------------

class InjectTests(CliTestCase):
    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.inp = self.dir / "input"
        self.out = self.dir / "output"

    def inject(self, template: str | bytes):
        if isinstance(template, bytes):
            self.inp.write_bytes(template)
        else:
            self.inp.write_text(template, encoding="utf-8")
        return self.call("inject", "--input", str(self.inp), "--output", str(self.out))

    def test_inject_is_private_exclusive_and_substitutes_literal_values(self):
        code, output, error = self.inject(f"token={{{{ {REF} }}}}")
        self.assertEqual((code, error), (0, ""))
        self.assertNotIn("secret", output)
        self.assertEqual(self.out.read_text(encoding="utf-8"), f"token={SECRET}")
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o600)
        code, output, error = self.call("inject", "--input", str(self.inp), "--output", str(self.out))
        self.assertEqual(code, 1)
        self.assertEqual(output, "")
        self.assertNotIn("secret", error)
        self.assertEqual(self.out.read_text(encoding="utf-8"), f"token={SECRET}")

    def test_inject_resolves_each_unique_reference_once_in_one_batch(self):
        self.inject(f"a={{{{{REF}}}}} b={{{{ {REF} }}}} c={{{{ {REF2} }}}}")
        self.source.resolve_references.assert_called_once()
        self.assertEqual(self.source.resolve_references.call_args.args[0], [REF, REF2])
        self.assertEqual(self.out.read_text(encoding="utf-8"), f"a={SECRET} b={SECRET} c={SECRET}")

    def test_inject_distinct_values_land_in_the_right_places(self):
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: (
            {REF: "ONE", REF2: "TWO"}, {},
        )
        self.inject(f"{{{{ {REF2} }}}}-{{{{ {REF} }}}}")
        self.assertEqual(self.out.read_text(encoding="utf-8"), "TWO-ONE")

    def test_inject_value_that_looks_like_a_placeholder_is_not_reexpanded(self):
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: (
            {REF: f"{{{{ {REF2} }}}}"}, {},
        )
        self.inject(f"{{{{ {REF} }}}}")
        self.assertEqual(self.out.read_text(encoding="utf-8"), f"{{{{ {REF2} }}}}")

    def test_inject_without_placeholders_copies_and_skips_worker(self):
        code, _o, _e = self.inject("plain text\n")
        self.assertEqual(code, 0)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "plain text\n")
        self.source.resolve_references.assert_not_called()

    def test_inject_rejects_malformed_placeholder_before_writing(self):
        for template in (f"token={{{{ {REF} }}", f"token={{{{ {REF}", "x {{ applepw://"):
            with self.subTest(template=template):
                code, output, error = self.inject(template)
                self.assertEqual(code, 1)
                self.assertEqual(output, "")
                self.assertIn("malformed", error)
                self.assertFalse(self.out.exists())
        self.source.resolve_references.assert_not_called()

    def test_inject_invalid_reference_fails_before_output_exists(self):
        code, _o, error = self.inject("{{ applepw://example.com/only-two }}")
        self.assertEqual(code, 1)
        self.assertIn(FIXED["ref_invalid"], error)
        self.assertFalse(self.out.exists())

    def test_inject_per_ref_failure_fails_before_output_exists(self):
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: (
            {REF: SECRET}, {REF2: "not_found"},
        )
        code, output, error = self.inject(f"{{{{ {REF} }}}} {{{{ {REF2} }}}}")
        self.assertEqual((code, output), (1, ""))
        self.assertEqual(error, f"Apple Passwords: {FIXED['not_found']}\n")
        self.assertNotIn("secret", error)
        self.assertFalse(self.out.exists())

    def test_inject_global_failure_fails_before_output_exists(self):
        self.source.resolve_references.side_effect = BridgeError("not_paired")
        code, _o, error = self.inject(f"{{{{ {REF} }}}}")
        self.assertEqual(code, 1)
        self.assertIn("pair", error)
        self.assertFalse(self.out.exists())

    def test_inject_missing_value_fails_closed(self):
        self.source.resolve_references.side_effect = lambda refs, *, timeout=45.0: ({}, {})
        code, _o, _e = self.inject(f"{{{{ {REF} }}}}")
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists())

    def test_inject_rejects_stdio_dash(self):
        for argv in (("-", str(self.out)), (str(self.inp), "-")):
            with self.subTest(argv=argv):
                code, _o, err = self.call("inject", "--input", argv[0], "--output", argv[1])
                self.assertEqual(code, 1)
                self.assertIn("file paths", err)

    def test_inject_size_cap_and_encoding(self):
        code, _o, err = self.inject(b"a" * (1024 * 1024 + 1))
        self.assertEqual(code, 1)
        self.assertIn("1 MiB", err)
        code, _o, err = self.inject(b"\xff\xfe\x00bad")
        self.assertEqual(code, 1)
        self.assertIn("UTF-8", err)
        code, _o, err = self.call("inject", "--input", str(self.dir / "absent"), "--output", str(self.out))
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists())
        # Exactly at the cap is accepted.
        self.assertEqual(self.inject(b"a" * (1024 * 1024))[0], 0)

    def test_inject_refuses_symlink_output_and_leaves_target_alone(self):
        target = self.dir / "target"
        target.write_text("original", encoding="utf-8")
        self.out.symlink_to(target)
        code, _o, err = self.inject(f"{{{{ {REF} }}}}")
        self.assertEqual(code, 1)
        self.assertEqual(target.read_text(encoding="utf-8"), "original")
        self.assertNotIn("secret", err)

    def test_inject_unwritable_output_directory_fails_without_value(self):
        self.inp.write_text(f"{{{{ {REF} }}}}", encoding="utf-8")
        code, _o, err = self.call("inject", "--input", str(self.inp), "--output", str(self.dir / "no" / "such" / "out"))
        self.assertEqual(code, 1)
        self.assertIn("could not create the output file", err)
        self.assertNotIn("secret", err)


# ---------------------------------------------------------------------------
# vault
# ---------------------------------------------------------------------------

class VaultTests(CliTestCase):
    def test_vault_add_normalizes_sorts_and_dedupes(self):
        self.assertEqual(self.call("vault", "add", "Zeta.com")[0], 0)
        self.assertEqual(self.call("vault", "add", "alpha.COM")[0], 0)
        code, out, _ = self.call("vault", "add", "zeta.com")
        self.assertEqual(code, 0)
        self.assertEqual(self.vault()["domains"], ["alpha.com", "zeta.com"])
        self.assertIn("Restart Hermes sessions", out)

    def test_vault_add_rejects_invalid_domain_without_saving(self):
        for bad in ("localhost", "https://example.com", "a b.com", "user@example.com"):
            with self.subTest(domain=bad):
                code, out, err = self.call("vault", "add", bad)
                self.assertEqual((code, out), (1, ""))
                self.assertIn("Apple Passwords:", err)
        self.assertEqual(self.saves, [])

    def test_vault_remove(self):
        self.cfg = {"vault": {"apple_passwords": {"enabled": True, "domains": ["a.com", "b.com"]}}}
        code, _o, _e = self.call("vault", "remove", "A.com")
        self.assertEqual(code, 0)
        self.assertEqual(self.vault(), {"enabled": True, "domains": ["b.com"]})

    def test_vault_remove_unknown_errors_without_saving(self):
        self.cfg = {"vault": {"apple_passwords": {"domains": ["a.com"]}}}
        code, out, err = self.call("vault", "remove", "c.com")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("c.com is not configured", err)
        self.assertEqual(self.saves, [])

    def test_vault_enable_with_domains(self):
        self.cfg = {"vault": {"apple_passwords": {"domains": ["a.com"]}}}
        code, out, _ = self.call("vault", "enable")
        self.assertEqual(code, 0)
        self.assertIs(self.vault()["enabled"], True)
        self.assertEqual(self.vault()["domains"], ["a.com"])
        self.assertNotIn("Warning", out)

    def test_vault_enable_without_domains_warns_but_succeeds(self):
        code, out, _ = self.call("vault", "enable")
        self.assertEqual(code, 0)
        self.assertIs(self.vault()["enabled"], True)
        self.assertEqual(self.vault()["domains"], [])
        self.assertIn("Warning", out)
        self.assertIn("vault add", out)

    def test_vault_disable_keeps_domains(self):
        self.cfg = {"vault": {"apple_passwords": {"enabled": True, "domains": ["a.com"]}}}
        self.assertEqual(self.call("vault", "disable")[0], 0)
        self.assertIs(self.vault()["enabled"], False)
        self.assertEqual(self.vault()["domains"], ["a.com"])

    def test_vault_status_reads_only(self):
        self.cfg = {"vault": {"apple_passwords": {"enabled": True, "domains": ["b.com", "a.com"]}}}
        code, out, _ = self.call("vault", "status")
        self.assertEqual(code, 0)
        self.assertIn("enabled", out)
        self.assertIn("a.com, b.com", out)
        self.assertIn("Restart Hermes sessions for vault changes to apply.", out)
        self.assertEqual(self.saves, [])

    def test_vault_status_when_unconfigured(self):
        _code, out, _ = self.call("vault", "status")
        self.assertIn("disabled", out)
        self.assertIn("Domains: none", out)

    def test_vault_edits_preserve_unrelated_config(self):
        self.cfg = {
            "vault": {"onepassword": {"enabled": True}, "apple_passwords": {"enabled": False}},
            "secrets": {"apple_passwords": {"enabled": True, "env": {"A": REF}}},
        }
        self.call("vault", "add", "a.com")
        self.assertEqual(self.cfg["vault"]["onepassword"], {"enabled": True})
        self.assertEqual(self.cfg["secrets"]["apple_passwords"]["env"], {"A": REF})
        self.assertIs(self.vault()["enabled"], False)

    def test_vault_replaces_malformed_sections(self):
        self.cfg = {"vault": {"apple_passwords": {"domains": "a.com"}}}
        self.assertEqual(self.call("vault", "add", "b.com")[0], 0)
        self.assertEqual(self.vault()["domains"], ["b.com"])
        self.cfg = {"vault": "junk"}
        self.assertEqual(self.call("vault", "enable")[0], 0)
        self.assertIs(self.vault()["enabled"], True)


if __name__ == "__main__":
    unittest.main()
