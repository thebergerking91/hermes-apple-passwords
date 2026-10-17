"""Offline checks for the narrow Apple Passwords backend boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location("apple_passwords_backend", Path(__file__).parents[1] / "backend.py")
backend = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = backend
spec.loader.exec_module(backend)


class Client:
    def __init__(self, passwords=(), otps=()):
        self.passwords = list(passwords)
        self.otps = list(otps)

    def get_password(self, domain):
        return self.passwords

    def get_otp(self, domain):
        return self.otps


def row(domain, username="alice@example.com", password="secret", sites=None):
    return SimpleNamespace(domain=domain, username=username, password=password, sites=sites or [])


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
]


class BackendTests(unittest.TestCase):
    def test_invalid_reference(self):
        for uri in INVALID_URIS:
            with self.subTest(uri=uri), self.assertRaises(backend.BridgeError) as caught:
                backend.parse_reference(uri)
            self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_encoded_username_and_exact_saved_host(self):
        ref = "applepw://example.com/alice%2Btest%40example.com/password"
        self.assertEqual(backend.parse_reference(ref), backend.Reference("example.com", "alice+test@example.com", "password"))
        client = Client([row("other.example.com", "alice+test@example.com", "wrong"),
                         row("https://example.com/login", "alice+test@example.com", "right")])
        self.assertEqual(backend.resolve(ref, client), "right")

    def test_registrable_domain_sibling_is_not_matched(self):
        client = Client([row("foo.example.com", password="wrong")])
        with self.assertRaises(backend.BridgeError):
            backend.resolve("applepw://bar.example.com/alice%40example.com/password", client)

    def test_duplicate_exact_accounts_fail_closed(self):
        client = Client([row("example.com", password="one"), row("example.com", password="two")])
        with self.assertRaises(backend.BridgeError) as caught:
            backend.resolve("applepw://example.com/alice%40example.com/password", client)
        self.assertEqual(caught.exception.kind, "ref_invalid")

    def test_list_discloses_only_metadata_and_deduplicates(self):
        client = Client([row("example.com"), row("https://example.com/a", password="other"),
                         row("sibling.example.com", username="bob", password="third")])
        self.assertEqual(backend.list_accounts("example.com", client), [
            {"domain": "example.com", "username": "alice@example.com"}])

    def test_otp_and_username_fields(self):
        client = Client([row("example.com")], [SimpleNamespace(domain="example.com", username="alice@example.com", code="123456")])
        self.assertEqual(backend.resolve("applepw://example.com/alice%40example.com/username", client), "alice@example.com")
        self.assertEqual(backend.resolve("applepw://example.com/alice%40example.com/otp", client), "123456")

    def test_upstream_error_is_sanitized(self):
        class Broken(Client):
            def get_password(self, domain):
                raise ValueError("secret from upstream")
        with self.assertRaises(backend.BridgeError) as caught:
            backend.list_accounts("example.com", Broken())
        self.assertNotIn("secret from upstream", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
