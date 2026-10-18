"""Offline checks for the standalone Apple Passwords worker (contract v0.2).

No apwlib, no live vault: clients and daemons are injected fakes, and all
values are synthetic.
"""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


BACKEND_PATH = Path(__file__).resolve().parents[1] / "backend.py"
spec = importlib.util.spec_from_file_location("apple_passwords_backend", BACKEND_PATH)
backend = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = backend
spec.loader.exec_module(backend)


# ---- fake apwlib exception classes (the worker maps by class NAME) ----------------

class SessionError(Exception):
    pass


class NotPairedError(SessionError):
    pass


class DaemonNotRunningError(SessionError):
    pass


class DaemonStartError(Exception):  # real apwlib: ApwError subclass, not SessionError
    pass


class ApwError(Exception):
    pass


class ServerError(ApwError):
    pass


class CustomSessionError(SessionError):  # a SessionError subclass unknown to the worker
    pass


def caused(exc):
    """Return exc as if raised ``from OSError(...)`` (apwlib's transport-drop shape)."""
    exc.__cause__ = OSError("transport dropped")
    return exc


UPSTREAM_SECRET = "upstream-secret-text-hunter2"
PW = "synthetic-password-1"
ALICE = "alice@example.com"


# ---- fakes ----------------------------------------------------------------------

def pw(domain, username=ALICE, password=PW, sites=None):
    """Fake PasswordEntry: domain is sites[0] in real apwlib."""
    return SimpleNamespace(username=username, domain=domain, password=password,
                           title=None, sites=list(sites if sites is not None else [domain]))


def otp(domain, username=ALICE, code="123456", source=None):
    return SimpleNamespace(username=username, domain=domain, code=code, source=source)


class FakeClient:
    def __init__(self, passwords=(), otps=(), otp_list=None, raises=None):
        self.passwords = list(passwords)
        self.otps = list(otps)
        self.otp_list = list(otps) if otp_list is None else list(otp_list)
        self.raises = dict(raises or {})
        self.calls = []

    def _maybe_raise(self, name):
        if name in self.raises:
            raise self.raises[name]

    def get_password(self, url, username=None):
        self.calls.append(("get_password", url, username))
        self._maybe_raise("get_password")
        rows = self.passwords
        if username is not None:  # mimic Apple's server-side narrowing
            rows = [r for r in rows if r.username == username]
        return list(rows)

    def get_otp(self, url):
        self.calls.append(("get_otp", url))
        self._maybe_raise("get_otp")
        return list(self.otps)

    def list_otp(self, url):
        self.calls.append(("list_otp", url))
        self._maybe_raise("list_otp")
        return list(self.otp_list)


class FakeDaemon:
    def __init__(self, info=None, status_exc=None, paired_after_verify=True, verify_exc=None,
                 start_exc=None, challenge_exc=None):
        self.info = info if info is not None else {"running": True, "bridge": True, "paired": False}
        self.status_exc = status_exc
        self.paired_after_verify = paired_after_verify
        self.verify_exc = verify_exc
        self.start_exc = start_exc
        self.challenge_exc = challenge_exc
        self.calls = []

    def status(self):
        self.calls.append("status")
        if self.status_exc:
            raise self.status_exc
        return self.info

    def start(self):
        self.calls.append("start")
        if self.start_exc:
            raise self.start_exc

    def request_challenge(self):
        self.calls.append("request_challenge")
        if self.challenge_exc:
            raise self.challenge_exc

    def verify_challenge(self, pin):
        self.calls.append(("verify_challenge", pin))
        if self.verify_exc:
            raise self.verify_exc
        return self.paired_after_verify


def ref(host="example.com", user=ALICE, field="password"):
    from urllib.parse import quote
    return f"applepw://{host}/{quote(user, safe='')}/{field}"


def run_main(argv, client=None, daemon=None):
    """Run backend.main with an optional fake client; return (code, payload, raw stdout)."""
    out = io.StringIO()
    patches = []
    if client is not None:
        patches.append(mock.patch.object(backend, "_client", lambda: client))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        stack.enter_context(contextlib.redirect_stdout(out))
        code = backend.main(argv)
    raw = out.getvalue()
    return code, json.loads(raw), raw


# ---- reference / domain validation (kept from v0.1) -------------------------------

INVALID_URIS = [
    "applepw://example.com/alice%40example.com/password?x=1",
    "applepw://alice@example.com/u/password",
    "applepw://example.com:443/u/password",
    "applepw://127.0.0.1/u/password",
    "applepw://example.com/u%2/password",
    "applepw://example.com/u/%70assword/extra",
    "applepw://example.com//password",
    "applepw://example.com/u/token",
    "applepw://example.com/u%00x/password",
    "applepw://foo.example.com.evil.org/u/password#frag",
    "applepw://localhost/u/password",
    "applepw://example.com/u/x/password",
    "https://example.com/u/password",
    "",
    " applepw://example.com/u/password",
]


class ValidationTests(unittest.TestCase):
    def test_invalid_reference(self):
        for uri in INVALID_URIS:
            with self.subTest(uri=uri), self.assertRaises(backend.BridgeError) as caught:
                backend.parse_reference(uri)
            self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_non_string_reference(self):
        with self.assertRaises(backend.BridgeError):
            backend.parse_reference(None)

    def test_encoded_username(self):
        parsed = backend.parse_reference("applepw://example.com/alice%2Btest%40example.com/password")
        self.assertEqual(parsed, backend.Reference("example.com", "alice+test@example.com", "password"))
        for field in ("password", "username", "otp"):
            self.assertEqual(backend.parse_reference(ref(field=field)).field, field)

    def test_encoded_slash_in_username_roundtrips(self):
        parsed = backend.parse_reference(ref(user="a/b@example.com"))
        self.assertEqual(parsed.username, "a/b@example.com")

    def test_reference_host_is_lowercased(self):
        # v0.1 behaviour kept: an upper-case host parses and is normalised to lower case.
        self.assertEqual(backend.parse_reference("applepw://Example.COM/u/password").domain, "example.com")

    def test_normalize_domain(self):
        self.assertEqual(backend.normalize_domain("Example.COM"), "example.com")
        for bad in ("example", "example.com.", " example.com", "1.2.3.4", "a..com", "-a.com",
                    "https://example.com", "exa mple.com", "example.com/x", "", "a.b.123"):
            with self.subTest(bad=bad), self.assertRaises(backend.BridgeError) as caught:
                backend.normalize_domain(bad)
            self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_bridge_error_kinds(self):
        self.assertEqual(backend.BridgeError("not_found").kind, "not_found")
        self.assertEqual(backend.BridgeError("made-up").kind, "internal")
        self.assertNotIn("hunter2", str(backend.BridgeError("internal")))


class SavedHostTests(unittest.TestCase):
    def test_saved_host_forms(self):
        self.assertEqual(backend._saved_host("Login.Example.com"), "login.example.com")
        self.assertEqual(backend._saved_host("https://login.example.com/path?q=1"), "login.example.com")
        self.assertEqual(backend._saved_host("http://example.com:8080/"), "example.com")
        for bad in ("ftp://example.com", "https://", "example.com/path", "", None, 5, "127.0.0.1",
                    "https://127.0.0.1/", "localhost"):
            with self.subTest(bad=bad):
                self.assertIsNone(backend._saved_host(bad))


# ---- status ----------------------------------------------------------------------

class StatusTests(unittest.TestCase):
    def test_status_with_daemon(self):
        d = FakeDaemon({"running": True, "bridge": True, "paired": True, "browser": "x", "browser_pid": 1})
        self.assertEqual(backend.status(d),
                         {"dependency": True, "running": True, "bridge": True, "paired": True})

    def test_status_strict_bools_and_partial(self):
        d = FakeDaemon({"running": True, "bridge": "yes", "paired": 1})
        self.assertEqual(backend.status(d),
                         {"dependency": True, "running": True, "bridge": False, "paired": False})

    def test_status_daemon_stopped(self):
        d = FakeDaemon({"running": False, "bridge": False, "paired": False})
        self.assertEqual(backend.status(d),
                         {"dependency": True, "running": False, "bridge": False, "paired": False})

    def test_status_daemon_raises_is_not_a_failure(self):
        d = FakeDaemon(status_exc=DaemonNotRunningError(UPSTREAM_SECRET))
        self.assertEqual(backend.status(d),
                         {"dependency": True, "running": False, "bridge": False, "paired": False})

    def test_status_non_dict_is_internal(self):
        with self.assertRaises(backend.BridgeError) as caught:
            backend.status(FakeDaemon(info=["nope"]))
        self.assertEqual(caught.exception.kind, "internal")

    def test_status_never_calls_mutating_daemon_methods(self):
        d = FakeDaemon()
        backend.status(d)
        self.assertEqual(d.calls, ["status"])

    def test_main_status_with_apwlib_missing(self):
        with mock.patch.dict(sys.modules, {"apwlib": None}):  # makes `import apwlib` raise ImportError
            code, payload, raw = run_main(["status"])
        self.assertEqual(code, 0)
        self.assertEqual(payload, {"ok": True, "result": {
            "dependency": False, "running": False, "bridge": False, "paired": False}})
        self.assertEqual(raw.count("\n"), 1)

    def test_main_status_with_fake_apwlib(self):
        made = []

        class Daemon(FakeDaemon):
            def __init__(self, *args, **kwargs):
                super().__init__({"running": True, "bridge": True, "paired": False})
                made.append((args, kwargs))

        fake_module = SimpleNamespace(Daemon=Daemon)
        with mock.patch.dict(sys.modules, {"apwlib": fake_module}), \
                mock.patch.object(backend.sys, "platform", "darwin"):
            code, payload, _ = run_main(["status"])
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"],
                         {"dependency": True, "running": True, "bridge": True, "paired": False})
        self.assertEqual(made, [((), {"auto_start": False})])

    def test_status_non_darwin_reports_dependency_only(self):
        fake_module = SimpleNamespace(Daemon=FakeDaemon)
        with mock.patch.dict(sys.modules, {"apwlib": fake_module}), \
                mock.patch.object(backend.sys, "platform", "linux"):
            self.assertEqual(backend.status(), {
                "dependency": True, "running": False, "bridge": False, "paired": False})


# ---- list ------------------------------------------------------------------------

class ListTests(unittest.TestCase):
    def test_list_shows_sibling_hosts_with_host_and_hosts(self):
        client = FakeClient([
            pw("login.example.com", sites=["login.example.com", "https://www.example.com/signin"]),
            pw("example.com", username="bob"),
            pw("shop.example.com", username="carol", sites=["shop.example.com"]),
        ])
        rows = backend.list_accounts("example.com", client)
        self.assertEqual(rows, [
            {"host": "example.com", "hosts": ["example.com"], "username": "bob", "has_otp": False},
            {"host": "login.example.com", "hosts": ["login.example.com", "www.example.com"],
             "username": ALICE, "has_otp": False},
            {"host": "shop.example.com", "hosts": ["shop.example.com"], "username": "carol",
             "has_otp": False},
        ])
        self.assertEqual(client.calls[0], ("get_password", "example.com", None))

    def test_list_sorted_by_host_then_username(self):
        client = FakeClient([pw("b.example.com", "zed"), pw("a.example.com", "yan"),
                             pw("a.example.com", "abe"), pw("b.example.com", "ann")])
        rows = backend.list_accounts("example.com", client)
        self.assertEqual([(r["host"], r["username"]) for r in rows], [
            ("a.example.com", "abe"), ("a.example.com", "yan"),
            ("b.example.com", "ann"), ("b.example.com", "zed")])

    def test_list_dedupes_by_host_and_username_and_merges_hosts(self):
        client = FakeClient([
            pw("example.com", sites=["example.com", "https://www.example.com"]),
            pw("example.com", sites=["example.com", "https://m.example.com"], password="other"),
        ])
        rows = backend.list_accounts("example.com", client)
        self.assertEqual(rows, [{"host": "example.com", "username": ALICE, "has_otp": False,
                                 "hosts": ["example.com", "m.example.com", "www.example.com"]}])

    def test_host_is_first_parseable_saved_host(self):
        client = FakeClient([pw("", sites=["not a host", "https://z.example.com/", "a.example.com"])])
        rows = backend.list_accounts("example.com", client)
        self.assertEqual(rows[0]["host"], "z.example.com")
        self.assertEqual(rows[0]["hosts"], ["a.example.com", "z.example.com"])

    def test_list_drops_unparseable_hosts_and_empty_usernames(self):
        client = FakeClient([
            pw("", sites=[]), pw("localhost", sites=["localhost", "https://10.0.0.1/"]),
            pw("example.com", username=""), pw("example.com", username=None),
            pw("example.com", username="keeper"),
        ])
        rows = backend.list_accounts("example.com", client)
        self.assertEqual([r["username"] for r in rows], ["keeper"])

    def test_list_has_otp_requires_exact_host(self):
        client = FakeClient(
            passwords=[pw("login.example.com", "alice"), pw("login.example.com", "bob"),
                       pw("other.example.com", "carol"), pw("example.com", "dave")],
            otps=[otp("login.example.com", "alice"),      # exact host
                  otp("example.com", "bob"),               # parent domain of login.example.com: NOT exact
                  otp("example.com", "carol"),             # parent of other.example.com: NOT exact
                  otp("login.example.com", "dave")])       # child of dave's host: NOT exact
        rows = {r["username"]: r["has_otp"] for r in backend.list_accounts("example.com", client)}
        self.assertEqual(rows, {"alice": True, "bob": False, "carol": False, "dave": False})
        self.assertIn(("list_otp", "example.com"), client.calls)

    def test_list_has_otp_requires_same_username(self):
        client = FakeClient([pw("example.com", "alice")], otps=[otp("example.com", "someone-else")])
        self.assertFalse(backend.list_accounts("example.com", client)[0]["has_otp"])

    def test_list_has_otp_ignores_unparseable_and_sibling_hosts(self):
        client = FakeClient([pw("a.example.com", "alice")],
                            otps=[otp("not a host", "alice"), otp("b.example.com", "alice"), otp("", "alice")])
        self.assertFalse(backend.list_accounts("example.com", client)[0]["has_otp"])

    def test_list_otp_failure_does_not_fail_list(self):
        for exc in (NotPairedError(UPSTREAM_SECRET), SessionError(), ApwError("x"), ValueError("y"),
                    RuntimeError("z")):
            with self.subTest(exc=type(exc).__name__):
                client = FakeClient([pw("example.com")], otps=[otp("example.com")],
                                    raises={"list_otp": exc})
                rows = backend.list_accounts("example.com", client)
                self.assertEqual(rows, [{"host": "example.com", "hosts": ["example.com"],
                                         "username": ALICE, "has_otp": False}])

    def test_list_otp_non_list_result_is_tolerated(self):
        client = FakeClient([pw("example.com")])
        client.list_otp = lambda url: None
        self.assertFalse(backend.list_accounts("example.com", client)[0]["has_otp"])

    def test_list_empty(self):
        client = FakeClient([])
        self.assertEqual(backend.list_accounts("example.com", client), [])
        self.assertNotIn(("list_otp", "example.com"), client.calls)

    def test_list_never_emits_secrets(self):
        client = FakeClient([pw("example.com", password=PW)], otps=[otp("example.com", code="987654")])
        blob = json.dumps(backend.list_accounts("example.com", client))
        self.assertNotIn(PW, blob)
        self.assertNotIn("987654", blob)
        self.assertEqual(set(backend.list_accounts("example.com", client)[0]),
                         {"host", "hosts", "username", "has_otp"})

    def test_list_validates_domain(self):
        for bad in ("example", "https://example.com", "1.2.3.4"):
            with self.subTest(bad=bad), self.assertRaises(backend.BridgeError) as caught:
                backend.list_accounts(bad, FakeClient())
            self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_list_get_password_failure_propagates_with_kind(self):
        client = FakeClient(raises={"get_password": NotPairedError(UPSTREAM_SECRET)})
        with self.assertRaises(backend.BridgeError) as caught:
            backend.list_accounts("example.com", client)
        self.assertEqual(caught.exception.kind, "not_paired")
        self.assertNotIn(UPSTREAM_SECRET, str(caught.exception))

    def test_list_non_list_payload_is_internal(self):
        client = FakeClient()
        client.get_password = lambda url, username=None: {"not": "a list"}
        with self.assertRaises(backend.BridgeError) as caught:
            backend.list_accounts("example.com", client)
        self.assertEqual(caught.exception.kind, "internal")


class VaultListTests(unittest.TestCase):
    def test_union_over_domains_deduped_and_sorted(self):
        class PerDomain(FakeClient):
            def get_password(self, url, username=None):
                self.calls.append(("get_password", url, username))
                return {
                    "example.com": [pw("login.example.com", "zed"), pw("example.com", "amy")],
                    "other.org": [pw("login.other.org", "bob"), pw("login.example.com", "zed")],
                }[url]

            def list_otp(self, url):
                self.calls.append(("list_otp", url))
                return [otp("login.other.org", "bob")] if url == "other.org" else []

        client = PerDomain()
        rows = backend.vault_list(["other.org", "example.com", "example.com"], client)
        self.assertEqual([(r["host"], r["username"], r["has_otp"]) for r in rows], [
            ("example.com", "amy", False),
            ("login.example.com", "zed", False),
            ("login.other.org", "bob", True),
        ])
        self.assertEqual(set(rows[0]), {"host", "hosts", "username", "has_otp"})
        # duplicate domain queried once
        self.assertEqual(client.calls.count(("get_password", "example.com", None)), 1)

    def test_one_row_per_entry_never_unions_hosts(self):
        # Two entries share (host, username) but save different extra hosts: they stay
        # separate rows, so neither can claim the other's hosts.
        client = FakeClient([
            pw("example.com", sites=["example.com", "https://a.example.com"], password="pw-a"),
            pw("example.com", sites=["example.com", "https://c.example.com"], password="pw-c"),
        ])
        rows = backend.vault_list(["example.com"], client)
        self.assertEqual(rows, [
            {"host": "example.com", "hosts": ["a.example.com", "example.com"], "username": ALICE,
             "has_otp": False},
            {"host": "example.com", "hosts": ["c.example.com", "example.com"], "username": ALICE,
             "has_otp": False},
        ])
        # `list` (display) still merges them.
        merged = backend.list_accounts("example.com", client)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["hosts"], ["a.example.com", "c.example.com", "example.com"])

    def test_vault_list_rows_are_sorted_deterministically(self):
        entries = [
            pw("b.example.com", "zed"),
            pw("a.example.com", ALICE, sites=["a.example.com", "https://z.example.com"]),
            pw("a.example.com", ALICE, sites=["a.example.com", "https://m.example.com"]),
            pw("a.example.com", "abe"),
        ]
        expected = backend.vault_list(["example.com"], FakeClient(entries))
        self.assertEqual([(r["host"], r["username"], r["hosts"]) for r in expected], [
            ("a.example.com", "abe", ["a.example.com"]),
            ("a.example.com", ALICE, ["a.example.com", "m.example.com"]),
            ("a.example.com", ALICE, ["a.example.com", "z.example.com"]),
            ("b.example.com", "zed", ["b.example.com"]),
        ])
        self.assertEqual(backend.vault_list(["example.com"], FakeClient(list(reversed(entries)))), expected)

    def test_vault_list_has_otp_is_per_entry_hosts(self):
        client = FakeClient(
            [pw("a.example.com", ALICE), pw("b.example.com", ALICE)],
            otps=[otp("a.example.com", ALICE)])
        rows = backend.vault_list(["example.com"], client)
        self.assertEqual([(r["host"], r["has_otp"]) for r in rows],
                         [("a.example.com", True), ("b.example.com", False)])

    def test_vault_list_has_otp_false_for_parent_domain_otp(self):
        client = FakeClient([pw("www.example.com", ALICE)], otps=[otp("example.com", ALICE)])
        rows = backend.vault_list(["example.com"], client)
        self.assertEqual([(r["host"], r["has_otp"]) for r in rows], [("www.example.com", False)])

    def test_same_entry_from_two_domains_dedupes_and_ors_otp(self):
        class Two(FakeClient):
            def get_password(self, url, username=None):
                return [pw("a.example.com", ALICE, sites=["a.example.com", "https://b.other.org"])]

            def list_otp(self, url):
                return [otp("a.example.com", ALICE)] if url == "example.com" else []

        rows = backend.vault_list(["example.com", "other.org"], Two())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hosts"], ["a.example.com", "b.other.org"])
        self.assertTrue(rows[0]["has_otp"])

    def test_vault_list_invalid_domain(self):
        with self.assertRaises(backend.BridgeError) as caught:
            backend.vault_list(["example.com", "bad"], FakeClient())
        self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_vault_list_via_main(self):
        client = FakeClient([pw("example.com")])
        code, payload, _ = run_main(["vault-list", "--", "example.com"], client=client)
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"], [{"host": "example.com", "hosts": ["example.com"],
                                              "username": ALICE, "has_otp": False}])


# ---- resolve ---------------------------------------------------------------------

class ResolveTests(unittest.TestCase):
    def test_password_username_and_otp(self):
        client = FakeClient([pw("example.com")], otps=[otp("example.com", code="654321")])
        out = backend.resolve_many([ref(field="password"), ref(field="username"), ref(field="otp")], client)
        self.assertEqual(out, {"values": {ref(field="password"): PW, ref(field="username"): ALICE,
                                          ref(field="otp"): "654321"}, "errors": {}})

    def test_username_is_passed_to_get_password(self):
        other = pw("example.com", "bob", password="bob-pw")
        client = FakeClient([other, pw("example.com")])
        out = backend.resolve_many([ref()], client)
        self.assertEqual(out["values"], {ref(): PW})
        self.assertIn(("get_password", "example.com", ALICE), client.calls)
        self.assertNotIn(("get_password", "example.com", None), client.calls)

    def test_username_with_special_characters_roundtrip(self):
        user = "alice+test@example.com"
        client = FakeClient([pw("example.com", user)])
        self.assertEqual(backend.resolve_many([ref(user=user)], client)["values"], {ref(user=user): PW})
        self.assertIn(("get_password", "example.com", user), client.calls)

    def test_exact_host_only(self):
        client = FakeClient([pw("foo.example.com", password="wrong")])
        out = backend.resolve_many([ref("bar.example.com")], client)
        self.assertEqual(out, {"values": {}, "errors": {ref("bar.example.com"): "not_found"}})

    def test_match_through_sites_list_and_url_form(self):
        client = FakeClient([pw("login.example.com", sites=["login.example.com", "https://www.example.com/x"])])
        out = backend.resolve_many([ref("www.example.com"), ref("login.example.com")], client)
        self.assertEqual(out["values"], {ref("www.example.com"): PW, ref("login.example.com"): PW})

    def test_missing_is_not_found(self):
        out = backend.resolve_many([ref()], FakeClient([]))
        self.assertEqual(out["errors"], {ref(): "not_found"})
        self.assertEqual(out["values"], {})

    def test_wrong_username_is_not_found(self):
        # Fake that ignores the narrowing argument: worker must still check exact username.
        client = FakeClient([pw("example.com", "bob")])
        client.get_password = lambda url, username=None: [pw("example.com", "bob")]
        self.assertEqual(backend.resolve_many([ref()], client)["errors"], {ref(): "not_found"})

    def test_duplicates_are_ambiguous_for_password_and_username(self):
        client = FakeClient([pw("example.com", password="one"), pw("example.com", password="two")])
        out = backend.resolve_many([ref(field="password"), ref(field="username")], client)
        self.assertEqual(out["errors"], {ref(field="password"): "ambiguous",
                                         ref(field="username"): "ambiguous"})
        self.assertEqual(out["values"], {})

    def test_same_entry_listing_two_hosts_is_still_one_match(self):
        client = FakeClient([pw("example.com", sites=["example.com", "https://example.com/other"])])
        self.assertEqual(backend.resolve_many([ref()], client)["values"], {ref(): PW})

    def test_empty_and_invalid_password_values(self):
        for value in (None, "", "bad\0nul", 12345):
            with self.subTest(value=value):
                client = FakeClient([pw("example.com", password=value)])
                out = backend.resolve_many([ref()], client)
                self.assertEqual(out["errors"], {ref(): "empty_value"})
                self.assertEqual(out["values"], {})

    def test_username_field_ignores_missing_password(self):
        client = FakeClient([pw("example.com", password=None)])
        self.assertEqual(backend.resolve_many([ref(field="username")], client)["values"],
                         {ref(field="username"): ALICE})

    def test_ref_invalid_per_ref(self):
        out = backend.resolve_many(["not-a-ref", "applepw://example.com/u/token", ref()],
                                   FakeClient([pw("example.com")]))
        self.assertEqual(out["errors"], {"not-a-ref": "ref_invalid",
                                         "applepw://example.com/u/token": "ref_invalid"})
        self.assertEqual(out["values"], {ref(): PW})

    def test_non_string_ref_is_invalid_op(self):
        with self.assertRaises(backend.BridgeError) as caught:
            backend.resolve_many([None], FakeClient())
        self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_mixed_per_ref_results_via_main(self):
        client = FakeClient(
            passwords=[pw("example.com"),
                       pw("dup.example.org", "d", password="a"), pw("dup.example.org", "d", password="b"),
                       pw("empty.example.net", "e", password="")],
            otps=[])
        refs = [ref(), "bogus", ref("missing.example.com"), ref("dup.example.org", "d"),
                ref("empty.example.net", "e"), ref(field="otp")]
        code, payload, raw = run_main(["resolve", "--", *refs], client=client)
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["values"], {ref(): PW})
        self.assertEqual(payload["result"]["errors"], {
            "bogus": "ref_invalid",
            ref("missing.example.com"): "not_found",
            ref("dup.example.org", "d"): "ambiguous",
            ref("empty.example.net", "e"): "empty_value",
            ref(field="otp"): "not_found",
        })
        self.assertEqual(raw.count("\n"), 1)

    def test_generic_failure_for_one_ref_is_per_ref_internal(self):
        class Selective(FakeClient):
            def get_password(self, url, username=None):
                self.calls.append(("get_password", url, username))
                if url == "bad.example.com":
                    raise exc_to_raise
                return super().get_password(url, username)

        good, bad = ref("good.example.com"), ref("bad.example.com")
        for exc_to_raise in (ApwError(UPSTREAM_SECRET), ServerError(UPSTREAM_SECRET),
                             ValueError(UPSTREAM_SECRET), KeyError("x")):
            with self.subTest(exc=type(exc_to_raise).__name__):
                client = Selective([pw("good.example.com")])
                code, payload, raw = run_main(["resolve", "--", bad, good], client=client)
                self.assertEqual(code, 0)
                self.assertEqual(payload["result"], {"values": {good: PW}, "errors": {bad: "internal"}})
                self.assertNotIn(UPSTREAM_SECRET, raw)

    def test_unexpected_shape_for_one_ref_is_per_ref_internal(self):
        class Shape(FakeClient):
            def get_password(self, url, username=None):
                if url == "bad.example.com":
                    return {"not": "a list"}
                return super().get_password(url, username)

        good, bad = ref("good.example.com"), ref("bad.example.com")
        out = backend.resolve_many([bad, good], Shape([pw("good.example.com")]))
        self.assertEqual(out, {"values": {good: PW}, "errors": {bad: "internal"}})

    def test_session_failures_remain_global_in_resolve(self):
        cases = [(NotPairedError("x"), "not_paired"), (DaemonNotRunningError("x"), "not_running"),
                 (DaemonStartError("x"), "not_running"), (SessionError("x"), "not_running"),
                 (caused(SessionError("x")), "connection_lost")]
        for exc, kind in cases:
            with self.subTest(exc=type(exc).__name__, kind=kind):
                client = FakeClient([pw("example.com")], raises={"get_password": exc})
                with self.assertRaises(backend.BridgeError) as caught:
                    backend.resolve_many([ref()], client)
                self.assertEqual(caught.exception.kind, kind)

    def test_duplicate_refs_processed_once(self):
        client = FakeClient([pw("example.com")])
        out = backend.resolve_many([ref(), ref()], client)
        self.assertEqual(out["values"], {ref(): PW})
        self.assertEqual(len(client.calls), 1)

    def test_query_results_are_cached_within_a_run(self):
        client = FakeClient([pw("example.com")], otps=[otp("example.com")])
        backend.resolve_many([ref(field="password"), ref(field="username"),
                              ref(field="otp"), ref(field="otp")], client)
        self.assertEqual(client.calls.count(("get_password", "example.com", ALICE)), 1)
        self.assertEqual(client.calls.count(("get_otp", "example.com")), 1)
        backend.resolve_many([ref("a.example.com"), ref("b.example.com")], client)
        self.assertEqual(client.calls.count(("get_password", "a.example.com", ALICE)), 1)

    def test_different_usernames_are_separate_queries(self):
        client = FakeClient([pw("example.com"), pw("example.com", "bob", password="bob-pw")])
        out = backend.resolve_many([ref(), ref(user="bob")], client)
        self.assertEqual(out["values"], {ref(): PW, ref(user="bob"): "bob-pw"})
        self.assertEqual([c for c in client.calls if c[0] == "get_password"],
                         [("get_password", "example.com", ALICE), ("get_password", "example.com", "bob")])

    def test_client_not_created_when_all_refs_invalid(self):
        with mock.patch.object(backend, "_client", side_effect=AssertionError("client created")):
            out = backend.resolve_many(["bogus"])
        self.assertEqual(out, {"values": {}, "errors": {"bogus": "ref_invalid"}})

    def test_no_secret_in_error_results(self):
        client = FakeClient([pw("example.com", password=PW), pw("example.com", password="second-" + PW)])
        out = backend.resolve_many([ref()], client)
        self.assertNotIn(PW, json.dumps(out))


class ResolveOtpTests(unittest.TestCase):
    def test_exact_host_match(self):
        client = FakeClient(otps=[otp("example.com", code="111111")])
        self.assertEqual(backend.resolve_many([ref(field="otp")], client)["values"],
                         {ref(field="otp"): "111111"})
        self.assertEqual(client.calls, [("get_otp", "example.com")])

    def test_www_ref_refused_when_otp_saved_on_bare_host(self):
        client = FakeClient(otps=[otp("example.com", code="222222")])
        out = backend.resolve_many([ref("www.example.com", field="otp")], client)
        self.assertEqual(out["values"], {})
        self.assertEqual(out["errors"], {ref("www.example.com", field="otp"): "not_found"})

    def test_subdomain_ref_refused_for_otp_saved_on_parent(self):
        client = FakeClient(otps=[otp("example.com", code="222222")])
        out = backend.resolve_many([ref("a.example.com", field="otp")], client)
        self.assertEqual(out["values"], {})
        self.assertEqual(out["errors"], {ref("a.example.com", field="otp"): "not_found"})

    def test_deep_subdomain_ref_refused_for_otp_saved_on_parent(self):
        client = FakeClient(otps=[otp("example.com", code="222222")])
        out = backend.resolve_many([ref("a.b.example.com", field="otp")], client)
        self.assertEqual(out["errors"], {ref("a.b.example.com", field="otp"): "not_found"})

    def test_exact_subdomain_host_resolves(self):
        client = FakeClient(otps=[otp("login.example.com", code="444444"), otp("example.com", code="222222")])
        self.assertEqual(backend.resolve_many([ref("login.example.com", field="otp")], client)["values"],
                         {ref("login.example.com", field="otp"): "444444"})

    def test_child_or_sibling_domain_does_not_match(self):
        client = FakeClient(otps=[otp("deep.login.example.com"), otp("other.example.com")])
        out = backend.resolve_many([ref("login.example.com", field="otp")], client)
        self.assertEqual(out["errors"], {ref("login.example.com", field="otp"): "not_found"})

    def test_suffix_without_dot_boundary_does_not_match(self):
        client = FakeClient(otps=[otp("ample.com")])
        out = backend.resolve_many([ref("example.com", field="otp")], client)
        self.assertEqual(out["errors"], {ref(field="otp"): "not_found"})

    def test_username_must_match_exactly(self):
        client = FakeClient(otps=[otp("example.com", "bob")])
        self.assertEqual(backend.resolve_many([ref(field="otp")], client)["errors"],
                         {ref(field="otp"): "not_found"})

    def test_ambiguous_otp(self):
        client = FakeClient(otps=[otp("login.example.com", code="1"), otp("https://login.example.com/", code="2")])
        out = backend.resolve_many([ref("login.example.com", field="otp")], client)
        self.assertEqual(out["errors"], {ref("login.example.com", field="otp"): "ambiguous"})
        self.assertEqual(out["values"], {})

    def test_empty_code(self):
        for code in (None, "", "12\x003"):
            with self.subTest(code=code):
                client = FakeClient(otps=[otp("example.com", code=code)])
                self.assertEqual(backend.resolve_many([ref(field="otp")], client)["errors"],
                                 {ref(field="otp"): "empty_value"})

    def test_otp_url_form_domain(self):
        client = FakeClient(otps=[otp("https://example.com/", code="333333")])
        self.assertEqual(backend.resolve_many([ref(field="otp")], client)["values"],
                         {ref(field="otp"): "333333"})


# ---- global failure mapping -------------------------------------------------------

EXC_KINDS = [
    (NotPairedError, "not_paired"),
    (DaemonNotRunningError, "not_running"),
    (DaemonStartError, "not_running"),
    (SessionError, "not_running"),  # no __cause__: daemon replied INVALID_SESSION
    (CustomSessionError, "not_running"),
    (ApwError, "internal"),
    (ValueError, "internal"),
    (KeyError, "internal"),
]


class FailureMappingTests(unittest.TestCase):
    def test_mapping_by_class_name_for_each_op(self):
        for exc_class, kind in EXC_KINDS:
            for method, argv in (("get_password", ["list", "--", "example.com"]),
                                 ("get_password", ["vault-list", "--", "example.com"]),
                                 ("get_password", ["resolve", "--", ref()]),
                                 ("get_otp", ["resolve", "--", ref(field="otp")])):
                with self.subTest(exc=exc_class.__name__, argv=argv[0], method=method):
                    client = FakeClient([pw("example.com")], otps=[otp("example.com")],
                                        raises={method: exc_class(UPSTREAM_SECRET + PW)})
                    code, payload, raw = run_main(argv, client=client)
                    if argv[0] == "resolve" and kind == "internal":
                        # generic failures are per-reference in resolve, not global
                        self.assertEqual(code, 0)
                        self.assertEqual(payload["result"]["values"], {})
                        self.assertEqual(set(payload["result"]["errors"].values()), {"internal"})
                    else:
                        self.assertEqual(code, 1)
                        self.assertEqual(payload, {"ok": False, "kind": kind})
                    self.assertNotIn(UPSTREAM_SECRET, raw)
                    self.assertNotIn(PW, raw)
                    self.assertEqual(raw.count("\n"), 1)

    def test_session_error_cause_decides_connection_lost(self):
        for exc_class in (SessionError, CustomSessionError):
            with self.subTest(exc=exc_class.__name__, cause=False):
                self.assertEqual(backend._translate_failure(exc_class("x")).kind, "not_running")
            with self.subTest(exc=exc_class.__name__, cause=True):
                self.assertEqual(backend._translate_failure(caused(exc_class("x"))).kind, "connection_lost")
        # raised with a real ``from`` (and with ``from None``) as apwlib does
        try:
            try:
                raise OSError("boom")
            except OSError as inner:
                raise SessionError("lost") from inner
        except SessionError as exc:
            self.assertEqual(backend._translate_failure(exc).kind, "connection_lost")
        try:
            try:
                raise OSError("boom")
            except OSError:
                raise SessionError("invalid session") from None
        except SessionError as exc:
            self.assertEqual(backend._translate_failure(exc).kind, "not_running")

    def test_specific_subclasses_ignore_cause(self):
        self.assertEqual(backend._translate_failure(caused(NotPairedError("x"))).kind, "not_paired")
        self.assertEqual(backend._translate_failure(caused(DaemonNotRunningError("x"))).kind, "not_running")
        self.assertEqual(backend._translate_failure(caused(DaemonStartError("x"))).kind, "not_running")

    def test_connection_lost_through_each_op(self):
        for method, argv in (("get_password", ["list", "--", "example.com"]),
                             ("get_password", ["vault-list", "--", "example.com"]),
                             ("get_password", ["resolve", "--", ref()]),
                             ("get_otp", ["resolve", "--", ref(field="otp")])):
            with self.subTest(argv=argv[0], method=method):
                client = FakeClient([pw("example.com")], otps=[otp("example.com")],
                                    raises={method: caused(SessionError(UPSTREAM_SECRET))})
                code, payload, raw = run_main(argv, client=client)
                self.assertEqual((code, payload), (1, {"ok": False, "kind": "connection_lost"}))
                self.assertNotIn(UPSTREAM_SECRET, raw)

    def test_subclass_resolution_uses_most_specific_name(self):
        class Custom(NotPairedError):
            pass
        self.assertEqual(backend._translate_failure(Custom()).kind, "not_paired")

    def test_global_failure_aborts_resolve_even_after_successes(self):
        class Flaky(FakeClient):
            def get_password(self, url, username=None):
                if url == "second.example.com":
                    raise caused(SessionError(UPSTREAM_SECRET))
                return super().get_password(url, username)

        client = Flaky([pw("example.com")])
        code, payload, raw = run_main(["resolve", "--", ref(), ref("second.example.com")], client=client)
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "connection_lost"}))
        self.assertNotIn(PW, raw)

    def test_client_unavailable_kinds(self):
        with mock.patch.object(backend.sys, "platform", "linux"):
            code, payload, _ = run_main(["resolve", "--", ref()])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "unsupported_platform"}))
        with mock.patch.object(backend.sys, "platform", "darwin"), \
                mock.patch.dict(sys.modules, {"apwlib": None}):
            code, payload, _ = run_main(["list", "--", "example.com"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "dependency_missing"}))

    def test_client_factory_uses_safe_constructor_args(self):
        made = []

        class ApplePasswords:
            def __init__(self, *args, **kwargs):
                made.append((args, kwargs))

        with mock.patch.object(backend.sys, "platform", "darwin"), \
                mock.patch.dict(sys.modules, {"apwlib": SimpleNamespace(ApplePasswords=ApplePasswords)}):
            client = backend._client()
        self.assertIsInstance(client, ApplePasswords)
        self.assertEqual(made, [((), {"auto_start": False, "pin_provider": None})])

    def test_client_constructor_failure_is_mapped(self):
        class ApplePasswords:
            def __init__(self, **kwargs):
                raise DaemonNotRunningError(UPSTREAM_SECRET)

        with mock.patch.object(backend.sys, "platform", "darwin"), \
                mock.patch.dict(sys.modules, {"apwlib": SimpleNamespace(ApplePasswords=ApplePasswords)}):
            code, payload, raw = run_main(["list", "--", "example.com"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "not_running"}))
        self.assertNotIn(UPSTREAM_SECRET, raw)

    def test_unexpected_exception_in_dispatch_is_internal_without_text(self):
        with mock.patch.object(backend, "execute", side_effect=RuntimeError(UPSTREAM_SECRET)):
            code, payload, raw = run_main(["status"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "internal"}))
        self.assertNotIn(UPSTREAM_SECRET, raw)

    def test_failure_payload_has_only_ok_and_kind(self):
        code, payload, _ = run_main(["resolve", "--", ref()],
                                    client=FakeClient(raises={"get_password": NotPairedError("x")}))
        self.assertEqual(set(payload), {"ok", "kind"})
        self.assertIn(payload["kind"], backend._ERRORS)

    def test_no_secret_in_any_failure_payload(self):
        client = FakeClient([pw("example.com")], raises={"get_password": SessionError(PW + UPSTREAM_SECRET)})
        for argv in (["list", "--", "example.com"], ["vault-list", "--", "example.com"],
                     ["resolve", "--", ref()], ["bogus"], ["list"], []):
            with self.subTest(argv=argv):
                _, _, raw = run_main(argv, client=client)
                self.assertNotIn(PW, raw)
                self.assertNotIn(UPSTREAM_SECRET, raw)


# ---- main / dispatch ---------------------------------------------------------------

class MainTests(unittest.TestCase):
    def test_unknown_op(self):
        code, payload, raw = run_main(["frobnicate"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "ref_invalid"}))
        self.assertEqual(raw.count("\n"), 1)

    def test_no_args(self):
        code, payload, _ = run_main([])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "ref_invalid"}))

    def test_bad_arity(self):
        for argv in (["list"], ["list", "--"], ["list", "--", "a.com", "b.com"], ["vault-list"],
                     ["vault-list", "--"], ["resolve"], ["resolve", "--"], ["status", "--", "x"],
                     ["pair", "--", "x"], ["list", "example.com"], ["resolve", ref()],
                     ["status", "extra"]):
            with self.subTest(argv=argv):
                code, payload, _ = run_main(argv, client=FakeClient())
                self.assertEqual((code, payload), (1, {"ok": False, "kind": "ref_invalid"}))

    def test_values_after_separator_may_start_with_dashes(self):
        code, payload, _ = run_main(["resolve", "--", "--weird", ref()], client=FakeClient([pw("example.com")]))
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"]["errors"], {"--weird": "ref_invalid"})
        self.assertEqual(payload["result"]["values"], {ref(): PW})

    def test_list_via_main_json_shape(self):
        client = FakeClient([pw("login.example.com", sites=["login.example.com", "https://example.com"])],
                            otps=[otp("example.com")])
        code, payload, raw = run_main(["list", "--", "Example.com"], client=client)
        self.assertEqual(code, 0)
        self.assertEqual(payload, {"ok": True, "result": [{
            "host": "login.example.com", "hosts": ["example.com", "login.example.com"],
            "username": ALICE, "has_otp": True}]})
        self.assertEqual(raw.count("\n"), 1)
        self.assertNotIn(PW, raw)

    def test_execute_exports(self):
        self.assertEqual(backend.execute("status", [], client=FakeDaemon({"running": True})),
                         {"dependency": True, "running": True, "bridge": False, "paired": False})
        self.assertEqual(backend.execute("list", ["example.com"], client=FakeClient([pw("example.com")]))[0]["host"],
                         "example.com")
        with self.assertRaises(backend.BridgeError) as caught:
            backend.execute("nope", [])
        self.assertEqual(caught.exception.kind, "ref_invalid")
        with self.assertRaises(backend.BridgeError):
            backend.execute("list", [5])

    def test_main_uses_sys_argv_by_default(self):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["backend.py", "nope"]), contextlib.redirect_stdout(out):
            self.assertEqual(backend.main(), 1)
        self.assertEqual(json.loads(out.getvalue()), {"ok": False, "kind": "ref_invalid"})


# ---- pair --------------------------------------------------------------------------

class PairTests(unittest.TestCase):
    def setUp(self):
        for patcher in (mock.patch.object(backend.sys, "platform", "darwin"),
                        mock.patch.object(backend, "_interactive", lambda: True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_requires_tty(self):
        with mock.patch.object(backend, "_interactive", lambda: False), \
                mock.patch.object(backend.getpass, "getpass", side_effect=AssertionError("prompted")):
            d = FakeDaemon()
            with self.assertRaises(backend.BridgeError) as caught:
                backend.pair(d)
        self.assertEqual(caught.exception.kind, "internal")
        self.assertEqual(d.calls, [])

    def test_interactive_check_uses_stdin_and_stderr(self):
        # setUp overrides backend._interactive; exercise the real one from a fresh load.
        real = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real)
        with mock.patch.object(real.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
                mock.patch.object(real.sys, "stderr", SimpleNamespace(isatty=lambda: False)):
            self.assertFalse(real._interactive())
        with mock.patch.object(real.sys, "stdin", SimpleNamespace(isatty=lambda: True)), \
                mock.patch.object(real.sys, "stderr", SimpleNamespace(isatty=lambda: True)):
            self.assertTrue(real._interactive())
        with mock.patch.object(real.sys, "stdin", SimpleNamespace(isatty=lambda: False)), \
                mock.patch.object(real.sys, "stderr", SimpleNamespace(isatty=lambda: True)):
            self.assertFalse(real._interactive())

    def test_non_tty_via_main_is_internal(self):
        with mock.patch.object(backend, "_interactive", lambda: False):
            code, payload, _ = run_main(["pair"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "internal"}))

    def test_non_darwin(self):
        with mock.patch.object(backend.sys, "platform", "linux"), self.assertRaises(backend.BridgeError) as caught:
            backend.pair(FakeDaemon())
        self.assertEqual(caught.exception.kind, "unsupported_platform")

    def test_already_paired_skips_challenge(self):
        d = FakeDaemon({"running": True, "bridge": True, "paired": True})
        with mock.patch.object(backend.getpass, "getpass", side_effect=AssertionError("prompted")):
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertEqual(d.calls, ["start", "status"])

    def test_full_flow_prompts_on_stderr_only(self):
        d = FakeDaemon()
        seen = {}

        def fake_getpass(prompt="", stream=None):
            seen["prompt"], seen["stream"] = prompt, stream
            return "123456"

        with mock.patch.object(backend.getpass, "getpass", fake_getpass):
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertIs(seen["stream"], sys.stderr)
        self.assertEqual(d.calls, ["start", "status", "request_challenge", ("verify_challenge", "123456")])

    def test_bad_pin_format_never_reaches_verify(self):
        for pin in ("12345", "1234567", "abcdef", "12 456", "", "１２３４５６"):
            with self.subTest(pin=pin):
                d = FakeDaemon()
                with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: pin), \
                        self.assertRaises(backend.BridgeError) as caught:
                    backend.pair(d)
                self.assertEqual(caught.exception.kind, "auth_failed")
                self.assertFalse(any(isinstance(c, tuple) for c in d.calls))

    def test_rejected_pin(self):
        d = FakeDaemon(paired_after_verify=False)
        with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: "123456"), \
                self.assertRaises(backend.BridgeError) as caught:
            backend.pair(d)
        self.assertEqual(caught.exception.kind, "auth_failed")

    def test_rejected_pin_retries_with_fresh_challenge_then_succeeds(self):
        # Live finding: a PIN typed into the wrong window is rejected; the command should
        # ask for a new PIN instead of exiting.
        d = FakeDaemon()
        results = iter([False, True])
        d.verify_challenge = lambda pin: (d.calls.append(("verify_challenge", pin)), next(results))[1]
        pins = iter(["111111", "222222"])
        with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: next(pins)), \
                mock.patch.object(backend.sys, "stderr", io.StringIO()) as err:
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertEqual(d.calls.count("request_challenge"), 2)
        self.assertIn("type the newest", err.getvalue())

    def test_rejected_pin_gives_up_after_three_attempts(self):
        d = FakeDaemon(paired_after_verify=False)
        with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: "123456"), \
                mock.patch.object(backend.sys, "stderr", io.StringIO()), \
                self.assertRaises(backend.BridgeError) as caught:
            backend.pair(d)
        self.assertEqual(caught.exception.kind, "auth_failed")
        self.assertEqual(d.calls.count("request_challenge"), 3)

    def _stateful_daemon(self, states):
        """FakeDaemon whose raw status reports a sequence of handshake states."""
        d = FakeDaemon()
        feed = iter(states)
        last = {"state": None}

        def send_raw(message):
            assert message == {"op": "status"}
            last["state"] = next(feed, last["state"])
            return {"running": True, "bridge": True, "paired": False, "pairing_state": last["state"]}

        d._send_raw = send_raw
        return d

    def test_waits_for_slow_helper_before_prompting(self):
        # Cold bridge: apwlib gives up waiting after 10 s; the plugin keeps waiting for MSG1Set.
        d = self._stateful_daemon(["ChallengeSent"] * 5 + ["MSG1Set"])
        order = []
        d_verify = d.verify_challenge
        d.verify_challenge = lambda pin: (order.append("verify"), d_verify(pin))[1]

        def fake_getpass(*_a, **_k):
            order.append(("prompt", d.calls.count("request_challenge")))
            return "123456"

        import time as time_module
        with mock.patch.object(time_module, "sleep", lambda s: None), \
                mock.patch.object(backend.getpass, "getpass", fake_getpass), \
                mock.patch.object(backend.sys, "stderr", io.StringIO()) as err:
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertEqual(order, [("prompt", 1), "verify"])
        self.assertIn("macOS is ready for the PIN", err.getvalue())

    def test_rechallenges_once_when_helper_never_gets_ready(self):
        d = self._stateful_daemon(["ChallengeSent"] * 10_000)
        clock = {"t": 0.0}

        def fake_monotonic():
            clock["t"] += 5.0
            return clock["t"]

        import time as time_module
        with mock.patch.object(time_module, "sleep", lambda s: None), \
                mock.patch.object(time_module, "monotonic", fake_monotonic), \
                mock.patch.object(backend.getpass, "getpass", lambda *a, **k: "123456"), \
                mock.patch.object(backend.sys, "stderr", io.StringIO()) as err:
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertEqual(d.calls.count("request_challenge"), 2)
        self.assertIn("requesting a new PIN", err.getvalue())
        self.assertIn("not ready", err.getvalue())

    def test_unobservable_state_keeps_apwlib_behaviour(self):
        d = FakeDaemon()  # no _send_raw: older/other apwlib
        with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: "123456"), \
                mock.patch.object(backend.sys, "stderr", io.StringIO()):
            self.assertEqual(backend.pair(d), {"paired": True})
        self.assertEqual(d.calls, ["start", "status", "request_challenge", ("verify_challenge", "123456")])

    def test_apwlib_errors_are_mapped(self):
        cases = [
            ({"start_exc": DaemonStartError(UPSTREAM_SECRET)}, "not_running"),
            ({"challenge_exc": NotPairedError(UPSTREAM_SECRET)}, "not_paired"),
            ({"verify_exc": SessionError(UPSTREAM_SECRET)}, "not_running"),
            ({"verify_exc": caused(SessionError(UPSTREAM_SECRET))}, "connection_lost"),
            ({"verify_exc": ValueError(UPSTREAM_SECRET)}, "internal"),
        ]
        for kwargs, kind in cases:
            with self.subTest(kind=kind):
                d = FakeDaemon(**kwargs)
                with mock.patch.object(backend.getpass, "getpass", lambda *a, **k: "123456"), \
                        self.assertRaises(backend.BridgeError) as caught:
                    backend.pair(d)
                self.assertEqual(caught.exception.kind, kind)
                self.assertNotIn(UPSTREAM_SECRET, str(caught.exception))

    def test_pair_creates_daemon_without_autostart(self):
        made = []

        class Daemon(FakeDaemon):
            def __init__(self, *args, **kwargs):
                super().__init__({"running": True, "bridge": True, "paired": True})
                made.append((args, kwargs))

        with mock.patch.dict(sys.modules, {"apwlib": SimpleNamespace(Daemon=Daemon)}):
            code, payload, _ = run_main(["pair"])
        self.assertEqual((code, payload), (0, {"ok": True, "result": {"paired": True}}))
        self.assertEqual(made, [((), {"auto_start": False})])

    def test_pair_dependency_missing(self):
        with mock.patch.dict(sys.modules, {"apwlib": None}):
            code, payload, _ = run_main(["pair"])
        self.assertEqual((code, payload), (1, {"ok": False, "kind": "dependency_missing"}))


# ---- standalone-script properties ---------------------------------------------------

class StandaloneTests(unittest.TestCase):
    def test_module_level_imports_are_stdlib_only(self):
        tree = ast.parse(BACKEND_PATH.read_text())
        names = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        self.assertTrue(names)
        self.assertLessEqual(names, set(sys.stdlib_module_names), names - set(sys.stdlib_module_names))

    def test_apwlib_imported_only_inside_functions(self):
        tree = ast.parse(BACKEND_PATH.read_text())
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertNotIn("apwlib", ast.dump(node))

    def test_script_prints_single_json_line_for_unknown_op(self):
        proc = subprocess.run([sys.executable, "-P", str(BACKEND_PATH), "nope"],
                              capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout.count("\n"), 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "kind": "ref_invalid"})

    def test_prints_inside_op_do_not_corrupt_stdout(self):
        class Noisy(FakeClient):
            def get_password(self, url, username=None):
                print("NOISE from apwlib on stdout")
                sys.stdout.write("more noise\n")
                return super().get_password(url, username)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(backend, "_client", lambda: Noisy([pw("example.com")])), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = backend.main(["resolve", "--", ref()])
        self.assertEqual(code, 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {"ok": True, "result": {"values": {ref(): PW}, "errors": {}}})
        self.assertIn("NOISE", err.getvalue())

    def test_prints_before_failure_do_not_corrupt_stdout(self):
        class Noisy(FakeClient):
            def get_password(self, url, username=None):
                print("NOISE")
                raise NotPairedError(UPSTREAM_SECRET)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(backend, "_client", lambda: Noisy()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = backend.main(["list", "--", "example.com"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue()), {"ok": False, "kind": "not_paired"})
        self.assertEqual(out.getvalue().count("\n"), 1)

    def test_script_subprocess_stdout_is_one_json_line_despite_prints(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "apwlib"
            pkg.mkdir()
            (pkg / "__init__.py").write_text(
                "import sys\n"
                "class ApplePasswords:\n"
                "    def __init__(self, **kw):\n"
                "        print('chatty import-time banner')\n"
                "    def get_password(self, url, username=None):\n"
                "        print('chatty on stdout')\n"
                "        return []\n"
                "    def list_otp(self, url):\n"
                "        return []\n")
            env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": tmp}
            code = ("import sys; sys.platform = 'darwin'; sys.argv = ['backend.py', 'resolve', '--', "
                    "'applepw://example.com/u/password']; import runpy; "
                    f"runpy.run_path({str(BACKEND_PATH)!r}, run_name='__main__')")
            proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                                  timeout=30, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count("\n"), 1, proc.stdout)
        self.assertEqual(json.loads(proc.stdout),
                         {"ok": True, "result": {"values": {}, "errors": {"applepw://example.com/u/password": "not_found"}}})
        self.assertIn("chatty on stdout", proc.stderr)

    def test_script_resolve_with_only_invalid_refs_needs_no_apwlib(self):
        proc = subprocess.run([sys.executable, "-P", str(BACKEND_PATH), "resolve", "--", "bogus"],
                              capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout),
                         {"ok": True, "result": {"values": {}, "errors": {"bogus": "ref_invalid"}}})


if __name__ == "__main__":
    unittest.main()
