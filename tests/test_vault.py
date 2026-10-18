"""Browser-vault login backend tests against the REAL Hermes vault code.

Only ``bridge`` / ``backend`` (fake modules) and the config source are
substituted; ``agent.vault_backends`` and ``tools.browser_vault_tool`` are
Hermes's own. Synthetic values only; HERMES_HOME points at a temp dir.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PLUGIN_DIR = Path(__file__).resolve().parents[1]
for _root in (PLUGIN_DIR.parent / "hermes-upstream", Path.home() / ".hermes" / "hermes-agent"):
    if (_root / "agent" / "vault_backends").is_dir() and str(_root) not in sys.path:
        sys.path.insert(0, str(_root))
        break

try:
    import agent.vault_backends as hermes_pkg
    import agent.vault_backends.base as hermes_base
    import agent.vault_store as hermes_store
    import tools.browser_vault_tool as browser_vault_tool
    HERMES_OK = True
except Exception:  # pragma: no cover - Hermes not importable in this environment
    HERMES_OK = False


SECRET = "synthetic-password-VALUE-1"
OTP = "123456"


class FakeBridgeError(RuntimeError):
    FIXED = {
        "not_paired": "Apple Passwords is not paired.",
        "not_running": "The Apple Passwords daemon is not running.",
        "ambiguous": "More than one Apple Passwords login matches.",
        "timeout": "The Apple Passwords bridge timed out.",
    }

    def __init__(self, kind="internal"):
        self.kind = kind
        super().__init__(self.FIXED.get(kind, "Apple Passwords bridge failed."))


def fake_normalize_domain(value):
    if (not isinstance(value, str) or not value or value != value.strip() or value.endswith(".")
            or "." not in value or any(c in value for c in "/:@ ") or value.replace(".", "").isdigit()):
        raise FakeBridgeError("ref_invalid")
    return value.lower()


def row(host, username, *, hosts=None, otp=False):
    return {"host": host, "hosts": hosts or [host], "username": username, "has_otp": otp}


@unittest.skipUnless(HERMES_OK, "Hermes vault modules are not importable")
class VaultBackendTests(unittest.TestCase):
    def setUp(self):
        name = "applepw_vault_test"
        package = types.ModuleType(name)
        package.__path__ = [str(PLUGIN_DIR)]
        bridge = types.ModuleType(name + ".bridge")
        bridge.BridgeError = FakeBridgeError
        bridge.FIXED_MESSAGES = dict(FakeBridgeError.FIXED)
        bridge.dependency_available = lambda: True
        bridge.run_worker = lambda *a, **k: (_ for _ in ()).throw(AssertionError("unexpected worker call"))
        fake_backend = types.ModuleType(name + ".backend")
        fake_backend.BridgeError = FakeBridgeError
        fake_backend.normalize_domain = fake_normalize_domain
        self.bridge = bridge
        for mod in (package, bridge, fake_backend):
            sys.modules[mod.__name__] = mod
            self.addCleanup(sys.modules.pop, mod.__name__, None)
        spec = importlib.util.spec_from_file_location(name + ".vault", PLUGIN_DIR / "vault.py")
        self.vault = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.vault
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(self.vault)

        self.original_base = hermes_base.enabled_backends
        self.original_pkg = hermes_pkg.enabled_backends
        self.addCleanup(self._restore_hermes)
        self.addCleanup(self.vault.uninstall)  # runs before _restore_hermes (LIFO)

        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        env = patch.dict(os.environ, {"HERMES_HOME": home.name})
        env.start()
        self.addCleanup(env.stop)
        # No real 1Password / Bitwarden CLI on the test machine should influence the backend list.
        no_cli = patch.object(hermes_base, "is_installed", return_value=False)
        no_cli.start()
        self.addCleanup(no_cli.stop)

        self.section = {"enabled": True, "domains": ["example.com"]}
        cfg = patch.object(self.vault, "vault_config", side_effect=lambda: self.section)
        cfg.start()
        self.addCleanup(cfg.stop)

    def _restore_hermes(self):
        # Belt and braces: whatever happened, leave Hermes unwrapped.
        hermes_base.enabled_backends = self.original_base
        hermes_pkg.enabled_backends = self.original_pkg

    # ── helpers ────────────────────────────────────────────────────────────
    def worker(self, rows=None, values=None, errors=None, raises=None):
        calls = []

        def run_worker(op, values_=(), **kwargs):
            calls.append((op, list(values_)))
            if raises is not None:
                raise raises
            if op == "vault-list":
                return list(rows or [])
            if op == "resolve":
                return {"values": dict(values or {}), "errors": dict(errors or {})}
            raise AssertionError(op)

        patcher = patch.object(self.bridge, "run_worker", side_effect=run_worker)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def apple_backend(self):
        return next((b for b in hermes_pkg.enabled_backends() if b.name == "apple_passwords"), None)

    # ── install / uninstall ────────────────────────────────────────────────
    def test_install_is_idempotent_and_uninstall_restores_originals(self):
        self.assertTrue(self.vault.install())
        wrapped_base, wrapped_pkg = hermes_base.enabled_backends, hermes_pkg.enabled_backends
        self.assertTrue(wrapped_base._applepw_wrapped)
        self.assertTrue(wrapped_pkg._applepw_wrapped)
        self.assertIsNot(wrapped_base, self.original_base)
        self.assertTrue(self.vault.install())
        self.assertIs(hermes_base.enabled_backends, wrapped_base)
        self.assertIs(hermes_pkg.enabled_backends, wrapped_pkg)
        self.assertIs(wrapped_base.__wrapped__, self.original_base)  # no double wrapping
        self.vault.uninstall()
        self.assertIs(hermes_base.enabled_backends, self.original_base)
        self.assertIs(hermes_pkg.enabled_backends, self.original_pkg)
        self.assertIsNone(self.apple_backend())

    def test_install_returns_false_when_hermes_lacks_expected_attrs(self):
        with patch.object(hermes_base, "LoginBackend", None):
            self.assertFalse(self.vault.install())
        self.assertIs(hermes_base.enabled_backends, self.original_base)
        with patch.object(hermes_pkg, "enabled_backends", None):
            self.assertFalse(self.vault.install())
        self.assertIs(hermes_base.enabled_backends, self.original_base)  # nothing half-wrapped

        class NotAMeta:
            id = "x"
        with patch.object(hermes_store, "VaultItemMeta", NotAMeta):
            self.assertFalse(self.vault.install())
        self.assertIs(hermes_base.enabled_backends, self.original_base)
        self.assertIs(hermes_pkg.enabled_backends, self.original_pkg)
        self.assertTrue(self.vault.install())  # recovers once Hermes looks right again

    def test_install_never_raises_when_import_fails(self):
        with patch("importlib.import_module", side_effect=ImportError("boom")):
            self.assertFalse(self.vault.install())

    # ── backend presence ───────────────────────────────────────────────────
    def test_backend_present_only_when_enabled_with_valid_domains(self):
        self.vault.install()
        self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local", "apple_passwords"])
        self.assertEqual([b.name for b in hermes_base.enabled_backends()], ["local", "apple_passwords"])
        for section in ({}, {"enabled": False, "domains": ["example.com"]}, {"enabled": "true", "domains": ["example.com"]},
                        {"enabled": True}, {"enabled": True, "domains": []}, {"enabled": True, "domains": "example.com"},
                        {"enabled": True, "domains": ["not a domain", "http://example.com", 5, None]}):
            with self.subTest(section=section):
                self.section = section
                self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local"])
        self.vault.uninstall()
        self.section = {"enabled": True, "domains": ["example.com"]}
        self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local"])

    def test_invalid_domains_are_dropped_and_valid_ones_normalized(self):
        self.vault.install()
        self.section = {"enabled": True, "domains": ["Example.COM", "bad domain", "example.com", "b.org"]}
        self.assertEqual(self.apple_backend().domains, ["b.org", "example.com"])

    def test_backend_contract_attributes_and_backend_for_handle(self):
        self.vault.install()
        backend = self.apple_backend()
        self.assertIsInstance(backend, hermes_base.LoginBackend)
        self.assertEqual((backend.name, backend.display_name, backend.prefix, backend.needs_unlock),
                         ("apple_passwords", "Apple Passwords", "applepw:", False))
        self.assertTrue(backend.is_unlocked())
        found = hermes_base.backend_for_handle("applepw:example.com/alice")
        self.assertEqual(found.name, "apple_passwords")
        self.assertEqual(hermes_pkg.backend_for_handle("vault_abc").name, "local")
        self.assertIsNone(hermes_base.backend_for_handle("zz:other"))
        self.section = {}
        self.assertIsNone(hermes_base.backend_for_handle("applepw:example.com/alice"))

    # ── listing through the real browser_vault tool ────────────────────────
    def test_browser_vault_list_shows_scoped_metadata_without_passwords(self):
        calls = self.worker(rows=[
            row("example.com", "alice@example.com", otp=True),
            row("login.example.com", "bob", hosts=["login.example.com", "www.example.com", "evil.com"]),
            row("evil.com", "mallory"),
            row("notexample.com", "mallory2"),
            row("example.com.evil.org", "mallory3"),
            {"host": "example.com", "hosts": ["example.com"], "username": "", "has_otp": False},
            {"host": "example.com", "username": "x/y"},
            "garbage",
        ], values={"applepw://example.com/alice%40example.com/password": SECRET})
        self.vault.install()
        out = browser_vault_tool.browser_vault_list()
        self.assertNotIn(SECRET, out)
        self.assertNotIn('"password', out.lower())  # no password-bearing key anywhere
        data = json.loads(out)
        self.assertTrue(data["success"])
        mine = {i["handle"]: i for i in data["items"] if i["backend"] == "apple_passwords"}
        self.assertEqual(set(mine), {"applepw:example.com/alice%40example.com", "applepw:login.example.com/bob",
                                     "applepw:example.com/x%2Fy"})
        alice = mine["applepw:example.com/alice%40example.com"]
        self.assertEqual((alice["identifier"], alice["identifier_type"], alice["origin"], alice["kind"]),
                         ("alice@example.com", "email", "https://example.com", "login"))
        self.assertEqual(alice["two_factor"], "automatic")
        bob = mine["applepw:login.example.com/bob"]
        self.assertEqual(bob["identifier_type"], "username")
        self.assertEqual(bob["allowed_origins"], ["https://login.example.com", "https://www.example.com"])
        self.assertNotIn("evil.com", out)
        self.assertEqual(calls, [("vault-list", ["example.com"])])  # list never resolves secrets
        self.assertNotIn("errors", data)

    def test_list_drops_rows_with_colliding_handles_instead_of_merging(self):
        # Two Apple entries mapping to the same handle would resolve as ambiguous
        # and may carry different origin sets: neither is listed (no merge, no pick).
        self.worker(rows=[row("example.com", "alice"), row("example.com", "alice"),
                          row("example.com", "carol"), row("example.com", "alice"),
                          row("login.example.com", "alice")])
        self.vault.install()
        ids = sorted(m.id for m in self.apple_backend().list_items())
        self.assertEqual(ids, ["applepw:example.com/carol", "applepw:login.example.com/alice"])

    def test_cross_entry_rows_sharing_user_keep_separate_origins(self):
        # Reviewer M1: entry A [example.com, a.example.com], entry C [example.com,
        # c.example.com], same username, vault domains a.* and c.* only.
        self.section = {"enabled": True, "domains": ["a.example.com", "c.example.com"]}
        self.worker(rows=[
            row("example.com", "u", hosts=["example.com", "a.example.com"]),
            row("example.com", "u", hosts=["example.com", "c.example.com"]),
        ])
        self.vault.install()
        items = {m.id: m for m in self.apple_backend().list_items()}
        self.assertEqual(set(items), {"applepw:a.example.com/u", "applepw:c.example.com/u"})
        self.assertEqual(items["applepw:a.example.com/u"].allowed_origins, ("https://a.example.com",))
        self.assertEqual(items["applepw:c.example.com/u"].allowed_origins, ("https://c.example.com",))
        data = json.loads(browser_vault_tool.browser_vault_list())
        mine = {i["handle"]: i for i in data["items"] if i["backend"] == "apple_passwords"}
        # The tool omits allowed_origins when it is just the item's own origin.
        for host in ("a.example.com", "c.example.com"):
            entry = mine[f"applepw:{host}/u"]
            self.assertEqual(entry["origin"], f"https://{host}")
            self.assertEqual(entry.get("allowed_origins", [entry["origin"]]), [f"https://{host}"])

    def test_cross_entry_rows_with_same_first_in_scope_host_are_both_dropped(self):
        self.section = {"enabled": True, "domains": ["a.example.com", "c.example.com"]}
        self.worker(rows=[
            row("a.example.com", "u", hosts=["a.example.com", "c.example.com"]),
            row("a.example.com", "u", hosts=["a.example.com"]),
            row("c.example.com", "other", hosts=["c.example.com"]),
        ])
        self.vault.install()
        self.assertEqual([m.id for m in self.apple_backend().list_items()],
                         ["applepw:c.example.com/other"])

    def test_allowed_origins_never_include_hosts_outside_the_rows_own_hosts(self):
        self.section = {"enabled": True, "domains": ["example.com"]}
        rows = [
            row("a.example.com", "u1", hosts=["a.example.com", "www.example.com", "evil.com"]),
            row("b.example.com", "u1", hosts=["b.example.com"]),
            row("z.example.com", "u2", hosts=["z.example.com", "m.example.com"]),
            row("x.example.com", "u2", hosts=["x.example.com"]),
        ]
        self.worker(rows=rows)
        self.vault.install()
        own = {}
        for r in rows:
            own[(sorted(h for h in r["hosts"] if h.endswith("example.com"))[0], r["username"])] = {
                f"https://{h}" for h in r["hosts"] if h.endswith("example.com")}
        items = self.apple_backend().list_items()
        self.assertEqual(len(items), 4)
        for m in items:
            host, _, user = m.id[len("applepw:"):].partition("/")
            self.assertEqual(set(m.allowed_origins), own[(host, user)])
            self.assertEqual(m.origin, f"https://{host}")
            self.assertIn(m.origin, m.allowed_origins)
            self.assertEqual(list(m.allowed_origins), sorted(m.allowed_origins))
        self.assertNotIn("https://evil.com", {o for m in items for o in m.allowed_origins})

    def test_list_failures_become_fixed_runtime_errors(self):
        self.vault.install()
        self.worker(raises=FakeBridgeError("not_paired"))
        with self.assertRaises(RuntimeError) as ctx:
            self.apple_backend().list_items()
        self.assertIn("hermes apple-passwords pair", str(ctx.exception))
        data = json.loads(browser_vault_tool.browser_vault_list())
        self.assertEqual(data["errors"][0]["backend"], "apple_passwords")
        self.assertIn("pair", data["errors"][0]["error"])
        self.assertEqual(data["items"], [])

        with patch.object(self.bridge, "dependency_available", return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                self.apple_backend().list_items()
        self.assertIn("apwlib is not installed", str(ctx.exception))
        self.assertIn("hermes pm repair", str(ctx.exception))

        self.worker(raises=RuntimeError(f"leaky upstream detail {SECRET}"))
        with self.assertRaises(RuntimeError) as ctx:
            self.apple_backend().list_items()
        self.assertNotIn(SECRET, str(ctx.exception))
        self.assertNotIn("upstream", str(ctx.exception))

        with patch.object(self.bridge, "run_worker", return_value="not a list"):
            with self.assertRaises(RuntimeError):
                self.apple_backend().list_items()

    # ── get_meta / handle parsing / scope ──────────────────────────────────
    def test_get_meta_returns_matching_item_and_narrows_domains(self):
        self.section = {"enabled": True, "domains": ["example.com", "other.org"]}
        calls = self.worker(rows=[row("login.example.com", "a b@c.com", otp=True)])
        self.vault.install()
        backend = self.apple_backend()
        handle = "applepw:login.example.com/a%20b%40c.com"
        meta = backend.get_meta(handle)
        self.assertEqual((meta.id, meta.identifier, meta.has_otp), (handle, "a b@c.com", True))
        self.assertEqual(meta.allowed_origins, ("https://login.example.com",))
        self.assertEqual(calls, [("vault-list", ["example.com"])])
        self.assertIsNone(backend.get_meta("applepw:login.example.com/someone-else"))

    def test_handle_parse_and_scope_rejection(self):
        calls = self.worker(rows=[row("example.com", "alice")], values={})
        self.vault.install()
        backend = self.apple_backend()
        bad_handles = [
            "applepw:evil.com/alice",            # out of scope
            "applepw:notexample.com/alice",      # suffix without dot boundary
            "applepw:example.com.evil.org/alice",
            "applepw:Example.com/alice",         # non-canonical host
            "applepw:example.com",               # no user
            "applepw:example.com/",
            "applepw:example.com/a/b",
            "applepw:example.com/a%2",           # malformed escape
            "applepw:example.com/%ff",           # invalid UTF-8
            "applepw:example.com/a%00b",         # control char
            "applepw:example.com/%41",           # non-canonical encoding
            "applepw:1.2.3.4/alice",
            "applepw:example.com:443/alice",
            "applepw:user@example.com/alice",
            "applepw:/alice",
            "applepw://example.com/alice/password",
            "vault_abc", "", None, 5,
        ]
        for handle in bad_handles:
            with self.subTest(handle=handle):
                self.assertIsNone(backend.get_meta(handle))
                with self.assertRaises(RuntimeError):
                    backend.resolve_password(handle)
                self.assertIsNone(backend.resolve_otp(handle))
        self.assertEqual(calls, [])  # nothing reached the worker

    # ── secrets ────────────────────────────────────────────────────────────
    def test_resolve_password_builds_exact_ref_and_returns_value(self):
        ref = "applepw://login.example.com/a%2Fb%40c.com%20x/password"
        calls = self.worker(values={ref: SECRET})
        self.vault.install()
        backend = self.apple_backend()
        handle = "applepw:login.example.com/a%2Fb%40c.com%20x"
        self.assertEqual(backend.resolve_password(handle), SECRET)
        self.assertEqual(calls, [("resolve", [ref])])
        # Hex-case variants of the encoding normalise to the same reference.
        calls.clear()
        self.assertEqual(backend.resolve_password("applepw:login.example.com/a%2fb%40c.com%20x"), SECRET)
        self.assertEqual(calls, [("resolve", [ref])])

    def test_resolve_password_failures_are_fixed_and_secret_free(self):
        ref = "applepw://example.com/alice/password"
        handle = "applepw:example.com/alice"
        self.vault.install()
        backend = self.apple_backend()

        self.worker(raises=FakeBridgeError("not_paired"))
        with self.assertRaises(RuntimeError) as ctx:
            backend.resolve_password(handle)
        self.assertIn("hermes apple-passwords pair", str(ctx.exception))

        self.worker(raises=FakeBridgeError("timeout"))
        with self.assertRaises(RuntimeError) as ctx:
            backend.resolve_password(handle)
        self.assertEqual(str(ctx.exception), FakeBridgeError.FIXED["timeout"])

        self.worker(values={ref: SECRET}, errors={ref: "ambiguous"})
        with self.assertRaises(RuntimeError) as ctx:
            backend.resolve_password(handle)
        self.assertEqual(str(ctx.exception), FakeBridgeError.FIXED["ambiguous"])
        self.assertNotIn(SECRET, str(ctx.exception))

        self.worker(raises=ValueError(f"unexpected {SECRET}"))
        with self.assertRaises(RuntimeError) as ctx:
            backend.resolve_password(handle)
        self.assertNotIn(SECRET, str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertTrue(ctx.exception.__suppress_context__)

        for bad in (None, {}, {"values": {}}, {"values": {ref: ""}}, {"values": {ref: 5}}, {"values": {ref: "a\x00b"}}, []):
            with self.subTest(result=bad):
                with patch.object(self.bridge, "run_worker", return_value=bad):
                    with self.assertRaises(RuntimeError):
                        backend.resolve_password(handle)

    def test_resolve_otp_success_and_any_failure_is_none(self):
        ref = "applepw://example.com/alice/otp"
        handle = "applepw:example.com/alice"
        calls = self.worker(values={ref: f" {OTP}\n"})
        self.vault.install()
        backend = self.apple_backend()
        self.assertEqual(backend.resolve_otp(handle), OTP)
        self.assertEqual(calls, [("resolve", [ref])])
        self.worker(raises=FakeBridgeError("not_paired"))
        self.assertIsNone(backend.resolve_otp(handle))
        self.worker(raises=RuntimeError(SECRET))
        self.assertIsNone(backend.resolve_otp(handle))
        self.worker(errors={ref: "not_found"})
        self.assertIsNone(backend.resolve_otp(handle))
        self.worker(values={ref: "   "})
        self.assertIsNone(backend.resolve_otp(handle))

    # ── wrapper robustness ─────────────────────────────────────────────────
    def test_wrapper_swallows_our_failures_and_keeps_original_backends(self):
        self.vault.install()
        with patch.object(self.vault, "vault_config", side_effect=RuntimeError("config boom")):
            self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local"])
            self.assertEqual([b.name for b in hermes_base.enabled_backends()], ["local"])
            self.assertIsNone(hermes_base.backend_for_handle("applepw:example.com/alice"))
            self.assertTrue(json.loads(browser_vault_tool.browser_vault_list())["success"])
        with patch.object(self.vault, "make_backend", side_effect=ValueError("ctor boom")):
            self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local"])
        with patch.object(self.vault, "vault_config", return_value="not a dict"):
            self.assertEqual([b.name for b in hermes_pkg.enabled_backends()], ["local"])

    def test_wrapper_does_not_swallow_failures_of_the_original(self):
        sentinel = RuntimeError("original failed")
        with patch.object(hermes_base, "enabled_backends", side_effect=sentinel):
            self.vault.install()
            with self.assertRaises(RuntimeError) as ctx:
                hermes_base.enabled_backends()
            self.assertIs(ctx.exception, sentinel)
            self.vault.uninstall()

    def test_wrapper_adds_exactly_one_backend_and_respects_existing_one(self):
        self.vault.install()
        for fn in (hermes_pkg.enabled_backends, hermes_base.enabled_backends):
            self.assertEqual([b.name for b in fn()].count("apple_passwords"), 1)
        # A uninstalled-then-orphaned wrapper degrades to pass-through.
        stale = hermes_pkg.enabled_backends
        self.vault.uninstall()
        self.assertEqual([b.name for b in stale()], ["local"])

    def test_vault_config_reads_nested_section(self):
        import hermes_cli.config as hermes_config
        original = self._original_vault_config()  # the class-level patch only covers self.vault
        with patch.object(hermes_config, "load_config_readonly") as loader:
            loader.return_value = {"vault": {"apple_passwords": {"enabled": True, "domains": ["a.com"]}}}
            self.assertEqual(original(), {"enabled": True, "domains": ["a.com"]})
            for junk in ({"vault": {"apple_passwords": "junk"}}, {"vault": None}, {"vault": "x"}, {}, None):
                loader.return_value = junk
                self.assertEqual(original(), {})

    def _original_vault_config(self):
        spec = importlib.util.spec_from_file_location("applepw_vault_test.vault_pristine", PLUGIN_DIR / "vault.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(module)
        return module.vault_config


if __name__ == "__main__":
    unittest.main()
