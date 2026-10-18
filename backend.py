"""Standalone worker for live Apple Passwords requests via apwlib (contract v0.2).

Invoked as ``python -P backend.py OP [-- VALUE ...]``. It prints exactly one JSON
line on stdout: ``{"ok": true, "result": ...}`` (exit 0) or
``{"ok": false, "kind": KIND}`` (exit 1). Failure payloads never carry upstream
exception text, stderr, or secret values.

Only the standard library is imported at module level (the worker runs in a
stripped environment); ``apwlib`` is imported lazily inside functions. The worker
never starts the daemon or pairs while resolving; pairing is the explicit,
interactive ``pair`` operation.
"""

from __future__ import annotations

import contextlib
import getpass
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes, urlsplit


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_FIELDS = frozenset({"password", "username", "otp"})

# Fixed, value-free text per worker kind (used for exception messages only; the
# JSON failure payload carries just the kind).
_ERRORS = {
    "ref_invalid": "Invalid Apple Passwords reference.",
    "not_found": "No matching Apple Passwords entry was found.",
    "ambiguous": "More than one matching Apple Passwords entry was found.",
    "not_paired": "Apple Passwords is not paired; run `hermes apple-passwords pair`.",
    "not_running": "The Apple Passwords bridge is not running.",
    "connection_lost": "The Apple Passwords bridge connection was lost.",
    "dependency_missing": "The apwlib dependency is not installed.",
    "unsupported_platform": "Apple Passwords requires macOS.",
    "empty_value": "Apple Passwords returned an empty value.",
    "auth_failed": "Apple Passwords rejected the pairing PIN.",
    "internal": "Apple Passwords bridge operation failed.",
}
# Session/daemon/dependency/platform failures abort a whole resolve; any other
# failure while looking up one reference is reported for that reference only.
_GLOBAL_KINDS = frozenset({"not_paired", "not_running", "connection_lost", "dependency_missing",
                           "unsupported_platform"})
# apwlib exception class name -> worker kind (checked along the MRO, most specific first).
# A bare ``SessionError`` is resolved separately in _translate_failure (see there).
_EXC_KINDS = {
    "NotPairedError": "not_paired",
    "DaemonNotRunningError": "not_running",
    "DaemonStartError": "not_running",
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


# --------------------------------------------------------------------------- validation

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


# --------------------------------------------------------------------------- helpers

def _saved_host(value: object) -> str | None:
    """Normalized host from a bare host or http(s) URL; None when unparseable."""
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


def _entry_hosts(entry: object) -> list[str]:
    """Parseable saved hosts of a PasswordEntry, in order (domain first), deduped."""
    candidates = [getattr(entry, "domain", None)]
    sites = getattr(entry, "sites", None)
    if isinstance(sites, (tuple, list)):
        candidates.extend(sites)
    hosts: list[str] = []
    for candidate in candidates:
        host = _saved_host(candidate)
        if host is not None and host not in hosts:
            hosts.append(host)
    return hosts


def _translate_failure(exc: BaseException) -> BridgeError:
    """Map an exception to a BridgeError by class name. Never keeps upstream text."""
    if isinstance(exc, BridgeError):
        return exc
    for cls in type(exc).__mro__:
        kind = _EXC_KINDS.get(cls.__name__)
        if kind is not None:
            return BridgeError(kind)
        if cls.__name__ == "SessionError":
            # apwlib raises ``SessionError(...) from exc`` when the transport drops; a
            # SessionError with no cause is the daemon replying INVALID_SESSION, i.e.
            # the extension/bridge is not connected.
            return BridgeError("connection_lost" if exc.__cause__ is not None else "not_running")
    return BridgeError("internal")


def _client():
    if sys.platform != "darwin":
        raise BridgeError("unsupported_platform")
    try:
        from apwlib import ApplePasswords
    except ImportError:
        raise BridgeError("dependency_missing") from None
    try:
        return ApplePasswords(auto_start=False, pin_provider=None)
    except Exception as exc:
        raise _translate_failure(exc) from None


def _call(method, *args) -> list[object]:
    try:
        rows = method(*args)
    except Exception as exc:
        raise _translate_failure(exc) from None
    if not isinstance(rows, list):
        raise BridgeError("internal")
    return rows


class _Queries:
    """Per-run client access with a result cache (same query hits Apple once)."""

    def __init__(self, client: object | None):
        self._client = client
        self._cache: dict[tuple, list[object]] = {}

    @property
    def client(self) -> object:
        if self._client is None:
            self._client = _client()
        return self._client

    def passwords(self, host: str, username: str | None = None) -> list[object]:
        key = ("pw", host, username)
        if key not in self._cache:
            method = self.client.get_password
            self._cache[key] = _call(method, host) if username is None else _call(method, host, username)
        return self._cache[key]

    def otp(self, host: str) -> list[object]:
        key = ("otp", host)
        if key not in self._cache:
            self._cache[key] = _call(self.client.get_otp, host)
        return self._cache[key]

    def otp_listing(self, host: str) -> list[object]:
        key = ("otp-list", host)
        if key not in self._cache:
            self._cache[key] = _call(self.client.list_otp, host)
        return self._cache[key]


# --------------------------------------------------------------------------- status / list

def status(daemon: object | None = None) -> dict[str, bool]:
    """Daemon state; dependency=false (others false) when apwlib cannot be imported."""
    off = {"running": False, "bridge": False, "paired": False}
    if daemon is None:
        try:
            from apwlib import Daemon
        except ImportError:
            return {"dependency": False, **off}
        if sys.platform != "darwin":
            return {"dependency": True, **off}
        try:
            daemon = Daemon(auto_start=False)
        except Exception:
            return {"dependency": True, **off}
    try:
        info = daemon.status()
    except Exception:
        return {"dependency": True, **off}
    if not isinstance(info, dict):
        raise BridgeError("internal")
    return {"dependency": True, **{key: info.get(key) is True for key in off}}


def _rows_for(domain: str, queries: _Queries) -> dict[tuple[str, str], dict]:
    """Metadata rows keyed by (host, username) for one registrable-domain query."""
    entries = queries.passwords(domain)
    merged: dict[tuple[str, str], dict] = {}
    for entry in entries:
        username = getattr(entry, "username", None)
        if not isinstance(username, str) or not username:
            continue
        hosts = _entry_hosts(entry)
        if not hosts:
            continue
        slot = merged.setdefault((hosts[0], username), {"host": hosts[0], "username": username, "hosts": set()})
        slot["hosts"].update(hosts)
    if not merged:
        return {}
    try:
        otp_entries = queries.otp_listing(domain)
    except Exception:  # best effort: a failing OTP listing must not fail the list
        otp_entries = []
    otp_hosts: dict[str, set[str]] = {}
    for item in otp_entries:
        user = getattr(item, "username", None)
        host = _saved_host(getattr(item, "domain", None))
        if isinstance(user, str) and host is not None:
            otp_hosts.setdefault(user, set()).add(host)
    for slot in merged.values():
        wanted = otp_hosts.get(slot["username"], set())
        slot["has_otp"] = any(h in wanted for h in slot["hosts"])
    return merged


def _finish(rows: dict[tuple[str, str], dict]) -> list[dict]:
    return [{"host": slot["host"], "hosts": sorted(slot["hosts"]), "username": slot["username"],
             "has_otp": bool(slot["has_otp"])}
            for _, slot in sorted(rows.items())]


def list_accounts(domain: str, client: object | None = None) -> list[dict]:
    domain = normalize_domain(domain)
    return _finish(_rows_for(domain, _Queries(client)))


def _entry_rows_for(domain: str, queries: _Queries) -> list[dict]:
    """One row per Apple entry (no merging across entries) for one domain query."""
    entries = queries.passwords(domain)
    rows: list[dict] = []
    for entry in entries:
        username = getattr(entry, "username", None)
        if not isinstance(username, str) or not username:
            continue
        hosts = _entry_hosts(entry)
        if hosts:
            rows.append({"host": hosts[0], "username": username, "hosts": set(hosts)})
    if not rows:
        return []
    try:
        otp_entries = queries.otp_listing(domain)
    except Exception:  # best effort: a failing OTP listing must not fail the list
        otp_entries = []
    otp_hosts: dict[str, set[str]] = {}
    for item in otp_entries:
        user = getattr(item, "username", None)
        host = _saved_host(getattr(item, "domain", None))
        if isinstance(user, str) and host is not None:
            otp_hosts.setdefault(user, set()).add(host)
    for row in rows:
        wanted = otp_hosts.get(row["username"], set())
        row["has_otp"] = any(h in wanted for h in row["hosts"])
    return rows


def vault_list(domains, client: object | None = None) -> list[dict]:
    """One row per Apple entry. Never unions hosts across entries: a consumer that fills
    by ``hosts`` membership must only see the hosts that one entry really saves."""
    wanted = sorted({normalize_domain(d) for d in domains})
    queries = _Queries(client)
    earlier: dict[tuple[str, str, tuple[str, ...]], dict] = {}  # rows from previous domain queries
    out: list[dict] = []
    for domain in wanted:
        current: dict[tuple[str, str, tuple[str, ...]], dict] = {}
        for row in _entry_rows_for(domain, queries):
            hosts = sorted(row["hosts"])
            key = (row["host"], row["username"], tuple(hosts))
            if key in earlier:  # the same entry already returned by an earlier domain query
                earlier[key]["has_otp"] = earlier[key]["has_otp"] or bool(row["has_otp"])
                continue
            item = {"host": row["host"], "hosts": hosts, "username": row["username"],
                    "has_otp": bool(row["has_otp"])}
            out.append(item)
            current.setdefault(key, item)
        earlier.update({k: v for k, v in current.items() if k not in earlier})
    out.sort(key=lambda r: (r["host"], r["username"], r["hosts"]))
    return out


# --------------------------------------------------------------------------- resolve

def _resolve_one(ref: Reference, queries: _Queries) -> str:
    if ref.field == "otp":
        matches = []
        for item in queries.otp(ref.domain):
            host = _saved_host(getattr(item, "domain", None))
            if getattr(item, "username", None) == ref.username and host == ref.domain:
                matches.append(item)
        value = _single(matches).code
    else:
        matches = [entry for entry in queries.passwords(ref.domain, ref.username)
                   if getattr(entry, "username", None) == ref.username
                   and ref.domain in _entry_hosts(entry)]
        entry = _single(matches)
        value = ref.username if ref.field == "username" else getattr(entry, "password", None)
    if not isinstance(value, str) or not value or "\0" in value:
        raise BridgeError("empty_value")
    return value


def _single(matches: list) -> object:
    if not matches:
        raise BridgeError("not_found")
    if len(matches) > 1:
        raise BridgeError("ambiguous")
    return matches[0]


def resolve_many(refs, client: object | None = None) -> dict:
    values: dict[str, str] = {}
    errors: dict[str, str] = {}
    queries = _Queries(client)
    for ref in refs:
        if not isinstance(ref, str):
            raise BridgeError("ref_invalid")
        if ref in values or ref in errors:
            continue
        try:
            values[ref] = _resolve_one(parse_reference(ref), queries)
        except Exception as exc:
            failure = _translate_failure(exc)
            if failure.kind in _GLOBAL_KINDS:
                raise failure from None
            errors[ref] = failure.kind
    return {"values": values, "errors": errors}


# --------------------------------------------------------------------------- pair

def _interactive() -> bool:
    try:
        return bool(sys.stdin.isatty() and sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


def pair(daemon: object | None = None) -> dict[str, bool]:
    if sys.platform != "darwin":
        raise BridgeError("unsupported_platform")
    if not _interactive():
        raise BridgeError("internal", "Pairing requires an interactive terminal.")
    if daemon is None:
        try:
            from apwlib import Daemon as daemon_class
        except ImportError:
            raise BridgeError("dependency_missing") from None
    else:
        daemon_class = None
    try:
        if daemon is None:
            daemon = daemon_class(auto_start=False)
        daemon.start()
        info = daemon.status()
        if isinstance(info, dict) and info.get("paired") is True:
            return {"paired": True}
        for attempt in range(1, _PAIR_ATTEMPTS + 1):
            _start_handshake(daemon)
            pin = getpass.getpass("Enter the six-digit PIN shown by macOS: ", stream=sys.stderr)
            if isinstance(pin, str) and re.fullmatch(r"[0-9]{6}", pin) and daemon.verify_challenge(pin):
                return {"paired": True}
            if attempt < _PAIR_ATTEMPTS:
                _say("That PIN was not accepted. macOS will show a new PIN; type the newest one.")
        raise BridgeError("auth_failed")
    except BridgeError:
        raise
    except Exception as exc:
        raise _translate_failure(exc) from None


_PAIR_ATTEMPTS = 3
_CHALLENGES = 3
# apwlib's request_challenge already waits up to 10 s for MSG1Set; this is only extra grace.
_HANDSHAKE_READY_TIMEOUT = 3.0
_HANDSHAKE_POLL = 0.25


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _pairing_state(daemon: object) -> str | None:
    """The bridge's raw handshake state, or None when this apwlib can't report it.

    apwlib's public ``status()`` drops ``pairing_state``, so read the daemon's own status
    reply. Missing support degrades to the previous behaviour (prompt immediately)."""
    send = getattr(daemon, "_send_raw", None)
    if not callable(send):
        return None
    try:
        reply = send({"op": "status"})
    except Exception:
        return None
    state = reply.get("pairing_state") if isinstance(reply, dict) else None
    return state if isinstance(state, str) else None


def _start_handshake(daemon: object) -> None:
    """Ask macOS for a PIN and return only once the handshake can accept it.

    apwlib waits at most 10 s for the ``MSG1Set`` state and then lets the caller continue;
    a PIN submitted before ``MSG1Set`` wedges the handshake. Measured live on a freshly
    started bridge: the first challenge makes macOS show a PIN but the handshake never
    leaves ``NotInSession`` (still there after 40 s), while an immediate second challenge
    reaches ``MSG1Set`` in 0.1 s. So re-request promptly instead of waiting longer."""
    import time

    started = time.monotonic()
    _say("Asking macOS for a pairing PIN. Wait for the prompt below before typing it.")
    for challenge in range(1, _CHALLENGES + 1):
        daemon.request_challenge()
        deadline = time.monotonic() + _HANDSHAKE_READY_TIMEOUT
        state = _pairing_state(daemon)
        if state is None:
            return  # can't observe the handshake; behave like apwlib's own CLI
        while state != "MSG1Set" and time.monotonic() < deadline:
            time.sleep(_HANDSHAKE_POLL)
            state = _pairing_state(daemon)
        if state == "MSG1Set":
            _say(f"macOS is ready for the PIN (after {time.monotonic() - started:.1f} s).")
            return
        if challenge == 1:
            _say("The first PIN after the bridge starts doesn't work; ignore it. Requesting a new PIN...")
        elif challenge < _CHALLENGES:
            _say("macOS is still not ready; requesting another PIN...")
    _say("macOS did not get ready. Type the newest PIN anyway, or run pair again.")


# --------------------------------------------------------------------------- dispatch

def execute(op: str, values=(), *, client: object | None = None) -> object:
    values = list(values)
    if any(not isinstance(v, str) for v in values):
        raise BridgeError("ref_invalid")
    if op == "status" and not values:
        return status(client)
    if op == "pair" and not values:
        return pair(client)
    if op == "list" and len(values) == 1:
        return list_accounts(values[0], client)
    if op == "vault-list" and values:
        return vault_list(values, client)
    if op == "resolve" and values:
        return resolve_many(values, client)
    raise BridgeError("ref_invalid")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv:
            raise BridgeError("ref_invalid")
        rest = argv[1:]
        if rest and rest[0] != "--":
            raise BridgeError("ref_invalid")
        # Anything apwlib/chauffeur prints while the op runs goes to stderr, so the single
        # JSON line below is the only thing on the real stdout.
        with contextlib.redirect_stdout(sys.stderr):
            result = execute(argv[0], rest[1:])
        payload, code = {"ok": True, "result": result}, 0
    except (Exception, KeyboardInterrupt) as exc:
        payload, code = {"ok": False, "kind": _translate_failure(exc).kind}, 1
    print(json.dumps(payload, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
