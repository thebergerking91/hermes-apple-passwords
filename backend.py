"""Small, fail-closed worker for live Apple Passwords requests via apwlib.

The caller owns process isolation. This module never starts or pairs the bridge
while resolving secrets; pairing is an explicit interactive operation.
"""

from __future__ import annotations

import getpass
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes, urlsplit


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FIELDS = frozenset({"password", "username", "otp"})
_ERRORS = {
    "ref_invalid": "Invalid Apple Passwords reference.",
    "binary_missing": "Apple Passwords bridge is unavailable.",
    "not_configured": "Apple Passwords bridge is not configured.",
    "auth_expired": "Apple Passwords pairing has expired; pair again.",
    "auth_failed": "Apple Passwords rejected the request.",
    "empty_value": "Apple Passwords returned an empty value.",
    "internal": "Apple Passwords bridge operation failed.",
}


class BridgeError(RuntimeError):
    def __init__(self, kind: str, message: str | None = None):
        self.kind = kind if kind in _ERRORS else "internal"
        super().__init__(message or _ERRORS[self.kind])


@dataclass(frozen=True)
class Reference:
    domain: str
    username: str
    field: str


def normalize_domain(value: str) -> str:
    """Validate a bare DNS host (not a URL, IP address, or wildcard)."""
    if not isinstance(value, str) or len(value) > 253 or not value or value != value.strip():
        raise BridgeError("ref_invalid")
    host = value.lower()
    if host.endswith(".") or "." not in host or any(not _LABEL.fullmatch(x) for x in host.split(".")):
        raise BridgeError("ref_invalid")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise BridgeError("ref_invalid")
    if host.split(".")[-1].isdigit():
        raise BridgeError("ref_invalid")
    return host


def _decode_username(encoded: str) -> str:
    if not encoded or "/" in encoded or not re.fullmatch(r"(?:%[0-9A-Fa-f]{2}|[^%])*", encoded):
        raise BridgeError("ref_invalid")
    try:
        username = unquote_to_bytes(encoded).decode("utf-8", "strict")
    except (ValueError, UnicodeDecodeError):
        raise BridgeError("ref_invalid") from None
    if not username or len(username) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in username):
        raise BridgeError("ref_invalid")
    return username


def parse_reference(value: str) -> Reference:
    if (not isinstance(value, str) or not value or len(value) > 2048 or "?" in value or "#" in value
            or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise BridgeError("ref_invalid")
    try:
        uri = urlsplit(value)
        if uri.scheme != "applepw" or not uri.netloc or uri.query or uri.fragment:
            raise BridgeError("ref_invalid")
        if uri.netloc.lower() != uri.hostname or uri.port is not None:
            raise BridgeError("ref_invalid")
        domain = normalize_domain(uri.netloc)
        segments = uri.path.split("/")
        if len(segments) != 3 or segments[0] != "" or segments[2] not in _FIELDS:
            raise BridgeError("ref_invalid")
        return Reference(domain, _decode_username(segments[1]), segments[2])
    except (ValueError, TypeError):
        raise BridgeError("ref_invalid") from None


def _saved_host(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if "://" in value:
            parsed = urlsplit(value)
            if parsed.scheme not in ("https", "http") or not parsed.hostname:
                return None
            return normalize_domain(parsed.hostname)
        return normalize_domain(value)
    except (BridgeError, ValueError):
        return None


def _matches(entry: object, domain: str, username: str) -> bool:
    if getattr(entry, "username", None) != username:
        return False
    candidates = [getattr(entry, "domain", None)]
    sites = getattr(entry, "sites", None)
    if isinstance(sites, (tuple, list)):
        candidates.extend(sites)
    return any(_saved_host(candidate) == domain for candidate in candidates)


def _client():
    if sys.platform != "darwin":
        raise BridgeError("not_configured", "Apple Passwords requires macOS.")
    try:
        from apwlib import ApplePasswords
    except ImportError:
        raise BridgeError("binary_missing") from None
    return ApplePasswords(auto_start=False, pin_provider=None)


def _translate_failure(exc: Exception) -> BridgeError:
    # Never include an upstream exception: protocol errors may contain sites or values.
    name = type(exc).__name__
    if name in ("NotPairedError", "SessionError"):
        return BridgeError("auth_expired")
    if name == "DaemonNotRunningError":
        return BridgeError("not_configured")
    if name == "DaemonStartError":
        return BridgeError("binary_missing")
    return BridgeError("internal")


def _read(client: object, method: str, domain: str) -> list[object]:
    try:
        rows = getattr(client, method)(domain)
    except Exception as exc:
        raise _translate_failure(exc) from None
    if not isinstance(rows, list):
        raise BridgeError("internal")
    return rows


def list_accounts(domain: str, client: object | None = None) -> list[dict[str, str]]:
    domain = normalize_domain(domain)
    client = client if client is not None else _client()
    rows = _read(client, "get_password", domain)
    # The query returns secret-bearing objects. Only account metadata crosses this boundary.
    accounts: set[tuple[str, str]] = set()
    for row in rows:
        username = getattr(row, "username", None)
        if isinstance(username, str) and username and _matches(row, domain, username):
            accounts.add((domain, username))
    return [{"domain": site, "username": user} for site, user in sorted(accounts)]


def resolve(reference: str, client: object | None = None) -> str:
    ref = parse_reference(reference)
    client = client if client is not None else _client()
    method = "get_otp" if ref.field == "otp" else "get_password"
    matches = [row for row in _read(client, method, ref.domain)
               if _matches(row, ref.domain, ref.username)]
    # A registrable-domain search can return distinct saved hosts or duplicates.
    if len(matches) != 1:
        raise BridgeError("ref_invalid" if matches else "empty_value")
    value = getattr(matches[0], "code" if ref.field == "otp" else ref.field, None)
    if not isinstance(value, str) or not value or "\0" in value:
        raise BridgeError("empty_value")
    return value


def status(daemon: object | None = None) -> dict[str, bool]:
    if sys.platform != "darwin" and daemon is None:
        return {"running": False, "bridge": False, "paired": False}
    if daemon is None:
        try:
            from apwlib import Daemon
            daemon = Daemon(auto_start=False)
        except ImportError:
            return {"running": False, "bridge": False, "paired": False}
    try:
        info = daemon.status()
    except Exception:
        return {"running": False, "bridge": False, "paired": False}
    if not isinstance(info, dict):
        raise BridgeError("internal")
    return {key: info.get(key) is True for key in ("running", "bridge", "paired")}


def pair() -> dict[str, bool]:
    if sys.platform != "darwin":
        raise BridgeError("not_configured", "Apple Passwords requires macOS.")
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise BridgeError("not_configured", "Pairing requires an interactive terminal.")
    try:
        from apwlib import Daemon
    except ImportError:
        raise BridgeError("binary_missing") from None
    try:
        daemon = Daemon(auto_start=False)
        daemon.start()
        if status(daemon)["paired"]:
            return {"paired": True}
        daemon.request_challenge()
        pin = getpass.getpass("Enter the six-digit PIN shown by macOS: ", stream=sys.stderr)
        if not re.fullmatch(r"[0-9]{6}", pin) or not daemon.verify_challenge(pin):
            raise BridgeError("auth_failed")
        return {"paired": True}
    except BridgeError:
        raise
    except Exception as exc:
        raise _translate_failure(exc) from None


def execute(operation: str, argument: str | None = None, *, client: object | None = None) -> object:
    if operation == "status" and argument is None:
        return status(client)
    if operation == "list" and argument is not None:
        return list_accounts(argument, client)
    if operation == "resolve" and argument is not None:
        return resolve(argument, client)
    if operation == "pair" and argument is None:
        return pair()
    raise BridgeError("ref_invalid")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if len(argv) not in (1, 2):
            raise BridgeError("ref_invalid")
        result = execute(argv[0], argv[1] if len(argv) == 2 else None)
        payload = {"ok": True, "result": result}
        code = 0
    except BridgeError as exc:
        payload = {"ok": False, "kind": exc.kind, "error": str(exc)}
        code = 1
    except Exception:
        payload = {"ok": False, "kind": "internal", "error": _ERRORS["internal"]}
        code = 1
    print(json.dumps(payload, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
