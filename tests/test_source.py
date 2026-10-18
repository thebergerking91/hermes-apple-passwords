"""Secret-source contract tests (fake backend module, patched worker; synthetic values only)."""

from __future__ import annotations

import importlib.util
import math
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]
PKG = "applepw_source_test"

REF_A = "applepw://example.com/alice/password"
REF_B = "applepw://example.com/bob/password"
HOME = Path("/tmp/applepw-test-home")


class FakeBackendError(Exception):
    def __init__(self, kind="ref_invalid"):
        self.kind = kind
        super().__init__("invalid")


def fake_parse_reference(ref):
    if not isinstance(ref, str) or not ref.startswith("applepw://") or ref != ref.strip():
        raise FakeBackendError()
    return types.SimpleNamespace(ref=ref, field=ref.rsplit("/", 1)[-1])


def load_modules():
    package = types.ModuleType(PKG)
    package.__path__ = [str(PLUGIN_DIR)]
    backend = types.ModuleType(PKG + ".backend")
    backend.BridgeError = FakeBackendError
    backend.parse_reference = fake_parse_reference

    def normalize_domain(domain):
        if not isinstance(domain, str) or "." not in domain or domain != domain.strip():
            raise FakeBackendError()
        return domain.lower()

    backend.normalize_domain = normalize_domain
    sys.modules[package.__name__] = package
    sys.modules[backend.__name__] = backend
    loaded = {}
    for name in ("bridge", "source"):
        spec = importlib.util.spec_from_file_location(f"{PKG}.{name}", PLUGIN_DIR / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        loaded[name] = module
    return loaded["bridge"], loaded["source"]


class SourceTestCase(unittest.TestCase):
    def setUp(self):
        self.bridge, self.source = load_modules()
        for name in ("", ".backend", ".bridge", ".source"):
            self.addCleanup(sys.modules.pop, PKG + name, None)
        self.source.clear_cache()
        self.addCleanup(self.source.clear_cache)
        self.ErrorKind = self.source.ErrorKind
        self.instance = self.source.ApplePasswordsSource()

    def worker(self, values=None, errors=None, *, raises=None):
        """Patch bridge.run_worker + dependency_available; returns the run_worker mock."""
        values, errors = values or {}, errors or {}
        patcher = patch.object(self.bridge, "run_worker",
                               side_effect=raises,
                               return_value={"values": values, "errors": errors})
        mock = patcher.start()
        self.addCleanup(patcher.stop)
        dep = patch.object(self.bridge, "dependency_available", return_value=True)
        dep.start()
        self.addCleanup(dep.stop)
        return mock

    def cfg(self, **overrides):
        base = {"enabled": True, "env": {"FIRST": REF_A}}
        base.update(overrides)
        return base

    def fetch(self, cfg):
        return self.instance.fetch(cfg, HOME)


class MetadataTests(SourceTestCase):
    def test_metadata_matches_spec(self):
        s = self.instance
        self.assertEqual((s.name, s.label, s.shape, s.scheme, s.api_version),
                         ("apple_passwords", "Apple Passwords", "mapped", "applepw", 1))
        self.assertTrue(s.override_existing_default)
        self.assertTrue(s.override_existing({}))
        self.assertFalse(s.override_existing({"override_existing": False}))
        self.assertTrue(s.override_existing({"override_existing": True}))

    def test_is_enabled_requires_literal_true(self):
        for value in (1, "true", "yes", None, False, [1]):
            self.assertFalse(self.instance.is_enabled({"enabled": value}), value)
        self.assertFalse(self.instance.is_enabled(None))
        self.assertFalse(self.instance.is_enabled("enabled"))
        self.assertTrue(self.instance.is_enabled({"enabled": True}))

    def test_config_schema_keys_and_defaults(self):
        schema = self.instance.config_schema()
        self.assertEqual(set(schema), {"enabled", "env", "override_existing", "timeout_seconds",
                                       "cache_ttl_seconds"})
        self.assertIs(schema["override_existing"]["default"], True)
        self.assertEqual(schema["timeout_seconds"]["default"], 45)
        self.assertEqual(schema["cache_ttl_seconds"]["default"], 300)

    def test_timeout_clamping(self):
        t = self.instance.fetch_timeout_seconds
        self.assertEqual(t({}), 45)
        self.assertEqual(t({"timeout_seconds": 900}), 120)
        self.assertEqual(t({"timeout_seconds": 120}), 120)
        self.assertEqual(t({"timeout_seconds": 10}), 10)
        self.assertEqual(t({"timeout_seconds": 0.5}), 0.5)
        for bad in ("bad", None, 0, -3, float("nan"), float("inf"), float("-inf"), True, [1], {}):
            self.assertEqual(t({"timeout_seconds": bad}), 45, bad)
        self.assertEqual(t(None), 45)

    def test_remediation_text(self):
        K, s = self.ErrorKind, self.instance
        pair = "Run `hermes apple-passwords pair` in a local terminal."
        mapped = {"env": {"TOKEN": "applepw://example.com/alice/password"}}
        for kind in (K.AUTH_EXPIRED, K.NOT_CONFIGURED, K.AUTH_FAILED):
            self.assertEqual(s.remediation(kind, mapped), pair)
        # With no usable mappings, NOT_CONFIGURED means "map something", not "pair".
        for cfg in ({}, {"env": {}}, {"env": {"BAD NAME": "applepw://example.com/a/password"}}):
            hint = s.remediation(K.NOT_CONFIGURED, cfg)
            self.assertIn("hermes apple-passwords set", hint)
            self.assertNotIn("pair", hint)
        self.assertIn("hermes pm repair", s.remediation(K.BINARY_MISSING, {}))
        self.assertIn("hermes apple-passwords list DOMAIN", s.remediation(K.REF_INVALID, {}))
        self.assertTrue(s.remediation(K.TIMEOUT, {}))
        self.assertEqual(s.remediation(None, {}), "")

    def test_error_kind_mapping(self):
        K, m = self.ErrorKind, self.source.to_error_kind
        expected = {"not_paired": K.AUTH_EXPIRED, "not_running": K.NOT_CONFIGURED,
                    "connection_lost": K.NETWORK, "dependency_missing": K.BINARY_MISSING,
                    "unsupported_platform": K.NOT_CONFIGURED, "ref_invalid": K.REF_INVALID,
                    "not_found": K.REF_INVALID, "ambiguous": K.REF_INVALID,
                    "empty_value": K.EMPTY_VALUE, "auth_failed": K.AUTH_FAILED,
                    "timeout": K.TIMEOUT, "internal": K.INTERNAL}
        for kind, want in expected.items():
            self.assertEqual(m(kind), want, kind)
        for junk in ("whatever", "", None, 3):
            self.assertEqual(m(junk), K.INTERNAL)


class FetchConfigTests(SourceTestCase):
    def test_invalid_config_fails_not_configured_without_worker(self):
        mock = self.worker()
        for cfg in (None, "x", ["enabled"], 5):
            result = self.fetch(cfg)
            self.assertEqual(result.error_kind, self.ErrorKind.NOT_CONFIGURED, cfg)
            self.assertEqual(result.secrets, {})
        for enabled in ("true", 1, None, "yes"):
            result = self.fetch({"enabled": enabled, "env": {"A": REF_A}})
            self.assertEqual(result.error_kind, self.ErrorKind.NOT_CONFIGURED, enabled)
        mock.assert_not_called()

    def test_disabled_is_empty_ok_and_never_touches_worker(self):
        mock = self.worker()
        for cfg in ({}, {"enabled": False, "env": {"A": REF_A}}):
            result = self.fetch(cfg)
            self.assertTrue(result.ok)
            self.assertEqual((result.secrets, result.warnings), ({}, []))
        mock.assert_not_called()

    def test_no_valid_entries_fails_not_configured_with_warnings(self):
        mock = self.worker()
        for env in (None, {}, "nope", ["A"]):
            result = self.fetch({"enabled": True, "env": env})
            self.assertEqual(result.error_kind, self.ErrorKind.NOT_CONFIGURED)
            self.assertIn("hermes apple-passwords set", result.error)
        result = self.fetch({"enabled": True, "env": {"BAD NAME": REF_A, "OK": "https://example.com"}})
        self.assertEqual(result.error_kind, self.ErrorKind.NOT_CONFIGURED)
        self.assertEqual(len(result.warnings), 2)
        mock.assert_not_called()

    def test_invalid_entries_become_warnings_and_valid_ones_resolve(self):
        mock = self.worker({REF_A: "alpha-secret"})
        env = {"GOOD": REF_A, "BAD NAME": REF_A, "1BAD": REF_A, "TRAIL\n": REF_A,
               "NOT_REF": "op://vault/item/field", "NONSTR": 5, 7: REF_A, "PADDED": " " + REF_A}
        result = self.fetch({"enabled": True, "env": env})
        self.assertTrue(result.ok)
        self.assertEqual(result.secrets, {"GOOD": "alpha-secret"})
        self.assertEqual(len(result.warnings), 7)
        self.assertTrue(all(w.startswith("Skipping ") for w in result.warnings))
        self.assertFalse(any("alice" in w for w in result.warnings))
        mock.assert_called_once()

    def test_otp_refs_are_skipped_with_warning_not_startup_mapped(self):
        otp = "applepw://example.com/alice/otp"
        mock = self.worker({REF_A: "alpha-secret", otp: "123456"})
        result = self.fetch({"enabled": True, "env": {"GOOD": REF_A, "CODE": otp}})
        self.assertTrue(result.ok)
        self.assertEqual(result.secrets, {"GOOD": "alpha-secret"})
        self.assertEqual(result.warnings, ["Skipping CODE: one-time codes can't be startup secrets; "
                                           "use `hermes apple-passwords run` or `read` instead"])
        mock.assert_called_once_with("resolve", [REF_A], timeout=30)

    def test_only_otp_mapping_fails_not_configured_without_worker(self):
        mock = self.worker()
        result = self.fetch({"enabled": True, "env": {"CODE": "applepw://example.com/alice/otp"}})
        self.assertEqual(result.error_kind, self.ErrorKind.NOT_CONFIGURED)
        self.assertEqual(len(result.warnings), 1)
        mock.assert_not_called()

    def test_dependency_missing_fails_binary_missing_without_worker(self):
        with patch.object(self.bridge, "dependency_available", return_value=False), \
             patch.object(self.bridge, "run_worker") as run:
            result = self.fetch(self.cfg())
        run.assert_not_called()
        self.assertEqual(result.error_kind, self.ErrorKind.BINARY_MISSING)
        self.assertEqual(result.secrets, {})
        self.assertIn("hermes pm repair", self.instance.remediation(result.error_kind, {}))


class FetchResolveTests(SourceTestCase):
    def test_single_batched_worker_call_with_unique_refs_and_clamped_timeout(self):
        mock = self.worker({REF_A: "alpha-secret", REF_B: "bravo-secret"})
        env = {"ONE": REF_A, "TWO": REF_B, "ONE_AGAIN": REF_A}
        result = self.fetch(self.cfg(env=env))
        mock.assert_called_once_with("resolve", [REF_A, REF_B], timeout=30)
        self.assertEqual(result.secrets, {"ONE": "alpha-secret", "TWO": "bravo-secret",
                                          "ONE_AGAIN": "alpha-secret"})
        self.assertEqual(result.warnings, [])
        self.assertEqual((result.applied, result.skipped), ([], []))

    def test_worker_timeout_uses_smaller_of_30_and_budget(self):
        mock = self.worker({REF_A: "alpha-secret"})
        self.fetch(self.cfg(timeout_seconds=12))
        self.assertEqual(mock.call_args.kwargs["timeout"], 12)
        self.fetch(self.cfg(timeout_seconds=900, cache_ttl_seconds=0))
        self.assertEqual(mock.call_args.kwargs["timeout"], 30)

    def test_partial_success_gives_secrets_and_warnings(self):
        self.worker({REF_A: "alpha-secret"}, {REF_B: "not_found"})
        result = self.fetch(self.cfg(env={"GOOD": REF_A, "MISSING": REF_B}))
        self.assertTrue(result.ok)
        self.assertEqual(result.secrets, {"GOOD": "alpha-secret"})
        self.assertEqual(result.warnings, ["MISSING: " + self.bridge.FIXED_MESSAGES["not_found"]])

    def test_all_failed_fails_with_first_error_kind(self):
        self.worker({}, {REF_A: "ambiguous", REF_B: "not_found"})
        result = self.fetch(self.cfg(env={"ZETA": REF_B, "ALPHA": REF_A}))
        self.assertEqual(result.secrets, {})
        self.assertEqual(result.error_kind, self.ErrorKind.REF_INVALID)
        self.assertTrue(result.error.startswith("ALPHA: "))
        self.assertIn(self.bridge.FIXED_MESSAGES["ambiguous"], result.error)

    def test_all_failed_empty_value_and_auth_kinds_map(self):
        for worker_kind, expected in (("empty_value", self.ErrorKind.EMPTY_VALUE),
                                      ("auth_failed", self.ErrorKind.AUTH_FAILED),
                                      ("bogus", self.ErrorKind.INTERNAL)):
            self.source.clear_cache()
            self.worker({}, {REF_A: worker_kind})
            result = self.fetch(self.cfg())
            self.assertEqual(result.error_kind, expected, worker_kind)

    def test_global_bridge_errors_map_to_error_kinds(self):
        K = self.ErrorKind
        for kind, expected in (("not_paired", K.AUTH_EXPIRED), ("not_running", K.NOT_CONFIGURED),
                               ("connection_lost", K.NETWORK), ("dependency_missing", K.BINARY_MISSING),
                               ("unsupported_platform", K.NOT_CONFIGURED), ("timeout", K.TIMEOUT),
                               ("auth_failed", K.AUTH_FAILED), ("internal", K.INTERNAL)):
            self.source.clear_cache()
            self.worker(raises=self.bridge.BridgeError(kind))
            result = self.fetch(self.cfg())
            self.assertEqual(result.error_kind, expected, kind)
            self.assertEqual(result.error, self.bridge.FIXED_MESSAGES[kind])
            self.assertEqual(result.secrets, {})

    def test_malformed_worker_result_is_internal(self):
        for payload in (None, [], {"values": {}}, {"values": [], "errors": {}}, "x"):
            self.source.clear_cache()
            with patch.object(self.bridge, "dependency_available", return_value=True), \
                 patch.object(self.bridge, "run_worker", return_value=payload):
                result = self.fetch(self.cfg())
            self.assertEqual(result.error_kind, self.ErrorKind.INTERNAL, payload)

    def test_bad_values_are_treated_as_empty_and_missing_refs_as_internal(self):
        self.worker({REF_A: "", REF_B: "nul\0byte"}, {})
        result = self.fetch(self.cfg(env={"A": REF_A, "B": REF_B}))
        self.assertEqual(result.error_kind, self.ErrorKind.EMPTY_VALUE)
        self.worker({}, {})
        self.source.clear_cache()
        result = self.fetch(self.cfg())
        self.assertEqual(result.error_kind, self.ErrorKind.INTERNAL)

    def test_whitespace_only_edges_preserved(self):
        self.worker({REF_A: "  padded value\n"})
        self.assertEqual(self.fetch(self.cfg()).secrets, {"FIRST": "  padded value\n"})

    def test_unexpected_exception_never_escapes_fetch(self):
        self.worker(raises=ZeroDivisionError("boom /secret/path"))
        result = self.fetch(self.cfg())
        self.assertEqual(result.error_kind, self.ErrorKind.INTERNAL)
        self.assertNotIn("secret", result.error)

    def test_fetch_never_writes_os_environ(self):
        self.worker({REF_A: "alpha-secret"})
        before = dict(os.environ)
        result = self.fetch(self.cfg(env={"APPLEPW_TEST_NEVER_SET": REF_A}))
        self.assertEqual(result.secrets, {"APPLEPW_TEST_NEVER_SET": "alpha-secret"})
        self.assertNotIn("APPLEPW_TEST_NEVER_SET", os.environ)
        self.assertEqual(dict(os.environ), before)


class CacheTests(SourceTestCase):
    def test_second_fetch_hits_cache(self):
        mock = self.worker({REF_A: "alpha-secret"})
        first = self.fetch(self.cfg())
        second = self.fetch(self.cfg())
        self.assertEqual(mock.call_count, 1)
        self.assertEqual(second.secrets, first.secrets)
        second.secrets["FIRST"] = "mutated"
        self.assertEqual(self.fetch(self.cfg()).secrets, {"FIRST": "alpha-secret"})

    def test_cache_miss_on_different_mapping_or_home(self):
        mock = self.worker({REF_A: "alpha-secret", REF_B: "bravo-secret"})
        self.fetch(self.cfg())
        self.fetch(self.cfg(env={"FIRST": REF_B}))
        self.instance.fetch(self.cfg(), Path("/tmp/other-home"))
        self.assertEqual(mock.call_count, 3)

    def test_ttl_zero_or_negative_disables_cache_read_and_write(self):
        mock = self.worker({REF_A: "alpha-secret"})
        for ttl in (0, -1):
            self.fetch(self.cfg(cache_ttl_seconds=ttl))
            self.fetch(self.cfg(cache_ttl_seconds=ttl))
        self.assertEqual(mock.call_count, 4)
        # nothing was stored by the disabled runs
        self.fetch(self.cfg())
        self.assertEqual(mock.call_count, 5)

    def test_ttl_expiry(self):
        mock = self.worker({REF_A: "alpha-secret"})
        clock = [1000.0]
        with patch.object(self.source.time, "monotonic", side_effect=lambda: clock[0]):
            self.fetch(self.cfg(cache_ttl_seconds=60))
            clock[0] += 59
            self.fetch(self.cfg(cache_ttl_seconds=60))
            self.assertEqual(mock.call_count, 1)
            clock[0] += 2
            self.fetch(self.cfg(cache_ttl_seconds=60))
            self.assertEqual(mock.call_count, 2)

    def test_non_finite_or_garbage_ttl_falls_back_to_default(self):
        mock = self.worker({REF_A: "alpha-secret"})
        for ttl in ("junk", float("nan"), None):
            self.source.clear_cache()
            mock.reset_mock()
            self.fetch(self.cfg(cache_ttl_seconds=ttl))
            self.fetch(self.cfg(cache_ttl_seconds=ttl))
            self.assertEqual(mock.call_count, 1, ttl)

    def test_partial_and_failed_results_are_not_cached(self):
        mock = self.worker({REF_A: "alpha-secret"}, {REF_B: "not_found"})
        env = {"GOOD": REF_A, "MISSING": REF_B}
        self.fetch(self.cfg(env=env))
        self.fetch(self.cfg(env=env))
        self.assertEqual(mock.call_count, 2)
        mock = self.worker(raises=self.bridge.BridgeError("not_paired"))
        self.fetch(self.cfg())
        self.fetch(self.cfg())
        self.assertEqual(mock.call_count, 2)

    def test_clear_cache_forces_refetch(self):
        mock = self.worker({REF_A: "alpha-secret"})
        self.fetch(self.cfg())
        self.source.clear_cache()
        self.fetch(self.cfg())
        self.assertEqual(mock.call_count, 2)

    def test_cache_is_memory_only(self):
        self.worker({REF_A: "alpha-secret"})
        with patch("builtins.open", side_effect=AssertionError("disk write")), \
             patch.object(Path, "write_text", side_effect=AssertionError("disk write")):
            self.fetch(self.cfg())
            self.fetch(self.cfg())


class HelperTests(SourceTestCase):
    def test_is_startup_reference_false_for_otp_and_invalid(self):
        is_startup = self.source.is_startup_reference
        self.assertTrue(is_startup(REF_A))
        self.assertTrue(is_startup("applepw://example.com/alice/username"))
        self.assertFalse(is_startup("applepw://example.com/alice/otp"))
        for bad in ("", "https://example.com", None, 3):
            self.assertFalse(is_startup(bad))

    def test_otp_still_resolvable_via_resolve_reference(self):
        otp = "applepw://example.com/alice/otp"
        self.worker({otp: "123456"})
        self.assertEqual(self.source.resolve_reference(otp), "123456")

    def test_validate_reference(self):
        self.assertEqual(self.source.validate_reference(REF_A), REF_A)
        for bad in ("", "https://example.com", " " + REF_A, None, 3, "applepw://" + "a" * 2100):
            with self.assertRaises(self.source.BridgeError) as raised:
                self.source.validate_reference(bad)
            self.assertEqual(raised.exception.kind, "ref_invalid")

    def test_resolve_references_batches_dedupes_and_validates_first(self):
        mock = self.worker({REF_A: "alpha-secret"}, {REF_B: "ambiguous"})
        values, errors = self.source.resolve_references([REF_A, REF_B, REF_A], timeout=20)
        mock.assert_called_once_with("resolve", [REF_A, REF_B], timeout=20)
        self.assertEqual((values, errors), ({REF_A: "alpha-secret"}, {REF_B: "ambiguous"}))
        mock.reset_mock()
        with self.assertRaises(self.source.BridgeError):
            self.source.resolve_references([REF_A, "bogus"])
        mock.assert_not_called()
        self.assertEqual(self.source.resolve_references([]), ({}, {}))
        mock.assert_not_called()

    def test_resolve_references_propagates_global_failure(self):
        self.worker(raises=self.bridge.BridgeError("not_paired"))
        with self.assertRaises(self.source.BridgeError) as raised:
            self.source.resolve_references([REF_A])
        self.assertEqual(raised.exception.kind, "not_paired")

    def test_resolve_reference_single(self):
        self.worker({REF_A: "  alpha-secret "})
        self.assertEqual(self.source.resolve_reference(REF_A), "  alpha-secret ")
        self.worker({}, {REF_A: "not_found"})
        with self.assertRaises(self.source.BridgeError) as raised:
            self.source.resolve_reference(REF_A)
        self.assertEqual(raised.exception.kind, "not_found")

    def test_bridge_status_strict_bools_and_no_spawn_without_dependency(self):
        with patch.object(self.bridge, "dependency_available", return_value=False), \
             patch.object(self.bridge, "run_worker") as run:
            self.assertEqual(self.source.bridge_status(),
                             {"dependency": False, "running": False, "bridge": False, "paired": False})
        run.assert_not_called()
        with patch.object(self.bridge, "dependency_available", return_value=True), \
             patch.object(self.bridge, "run_worker",
                          return_value={"dependency": True, "running": "yes", "bridge": 1, "paired": True}):
            self.assertEqual(self.source.bridge_status(),
                             {"dependency": True, "running": False, "bridge": False, "paired": True})
        with patch.object(self.bridge, "dependency_available", return_value=True), \
             patch.object(self.bridge, "run_worker", return_value="bad"):
            with self.assertRaises(self.source.BridgeError) as raised:
                self.source.bridge_status()
        self.assertEqual(raised.exception.kind, "internal")

    def test_list_accounts_normalizes_domain_and_sanitizes_rows(self):
        rows = [{"host": "login.example.com", "hosts": ["login.example.com", 5, ""], "username": "alice",
                 "has_otp": True, "password": "must-drop"},
                {"host": "example.com", "username": "bob", "has_otp": "yes"}]
        with patch.object(self.bridge, "run_worker", return_value=rows) as run:
            out = self.source.list_accounts("EXAMPLE.com")
        run.assert_called_once_with("list", ["example.com"])
        self.assertEqual(out, [
            {"host": "login.example.com", "hosts": ["login.example.com"], "username": "alice", "has_otp": True},
            {"host": "example.com", "hosts": ["example.com"], "username": "bob", "has_otp": False}])

    def test_list_accounts_rejects_bad_domain_and_bad_shapes(self):
        with patch.object(self.bridge, "run_worker") as run:
            with self.assertRaises(self.source.BridgeError) as raised:
                self.source.list_accounts("nodots")
            self.assertEqual(raised.exception.kind, "ref_invalid")
            run.assert_not_called()
        for bad in ("x", {}, [1], [{"host": 3, "username": "a"}], [{"host": "a.com", "username": None}]):
            with patch.object(self.bridge, "run_worker", return_value=bad):
                with self.assertRaises(self.source.BridgeError) as raised:
                    self.source.list_accounts("example.com")
            self.assertEqual(raised.exception.kind, "internal")


if __name__ == "__main__":
    unittest.main()
